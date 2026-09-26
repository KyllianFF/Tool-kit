<#
    Toolkit - Features / Duplicate files

    The same video downloaded twice, the photo folder copied "to be safe", the
    installer kept in three places: duplicates pile up in the folders a person
    actually uses, not in Windows. This finds them in the account's own
    folders - Desktop, Documents, Downloads, Pictures, Videos, Music - and says
    how much space the extra copies take.

    It compares in stages so it stays quick: only files of the same size can
    be the same, then a hash of their first bytes, and only files that still
    match are hashed whole. OneDrive files kept online only are skipped, since
    reading them would download them. Nothing is deleted: the report shows the
    copies and leaves the choice.
#>

<#
.SYNOPSIS
    The folders a person keeps files in, for this account.

.OUTPUTS
    System.String[] of the folders that exist.
#>
function Get-TkPersonalFolder {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $folders = @(
        [Environment]::GetFolderPath('Desktop')
        [Environment]::GetFolderPath('MyDocuments')
        [Environment]::GetFolderPath('MyPictures')
        [Environment]::GetFolderPath('MyVideos')
        [Environment]::GetFolderPath('MyMusic')
    )

    # Downloads has no SpecialFolder; its known folder is kept in the registry.
    try {
        $downloads = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
        if ($downloads) { $folders += [Environment]::ExpandEnvironmentVariables($downloads) }
    }
    catch {
        $folders += Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads'
    }

    return @($folders | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique)
}

<#
.SYNOPSIS
    Lists the files under some folders, skipping what cannot be read and what lives only online.

.DESCRIPTION
    Walks the folders itself rather than asking for everything at once, so a
    folder it cannot open is skipped instead of ending the walk. Links and
    junctions are not followed, so a folder is not counted twice. A file whose
    content is only in the cloud (OneDrive files on demand) is left out, since
    opening it would download it.

    The inner folders of tools are not entered: a Git repository keeps its own
    copies of files (LFS objects), node_modules and virtual environments
    repeat the same packages. Those copies belong to the tool; deleting one by
    hand breaks it.

.PARAMETER Path
    The folders to walk.

.PARAMETER MinimumSize
    Smaller files are left out: they are many and their copies cost little.

.PARAMETER MaxFiles
    A bound, so a huge tree cannot keep the report busy for ever.

.PARAMETER ExcludeFolder
    Folder names never entered.

.OUTPUTS
    PSCustomObject with Files (Path, Length), Skipped (online-only files),
    Truncated (whether MaxFiles was reached).
#>
function Get-TkFileInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Path,

        [Parameter()]
        [long] $MinimumSize = 1MB,

        [Parameter()]
        [int] $MaxFiles = 200000,

        [Parameter()]
        [string[]] $ExcludeFolder = @('.git', '.svn', '.hg', 'node_modules', '.venv', 'venv', '__pycache__',
                                      'site-packages', '.gradle', '.m2', '.nuget', '.tox', '.yarn', '.pnpm-store')
    )

    # Offline, recall on open and recall on data access: the content is not on the disk.
    $cloudOnly = 0x1000 -bor 0x40000 -bor 0x400000
    $reparse   = [int] [System.IO.FileAttributes]::ReparsePoint

    $files     = New-Object System.Collections.Generic.List[object]
    $skipped   = 0
    $truncated = $false
    $pending   = New-Object System.Collections.Generic.Stack[string]

    foreach ($root in $Path) { $pending.Push($root) }

    while ($pending.Count -gt 0 -and -not $truncated) {

        $folder = $pending.Pop()

        try {
            $directory = New-Object System.IO.DirectoryInfo($folder)

            foreach ($child in $directory.EnumerateDirectories()) {
                if (([int] $child.Attributes -band $reparse) -ne 0) { continue }
                if ($ExcludeFolder -contains $child.Name) { continue }
                $pending.Push($child.FullName)
            }

            foreach ($file in $directory.EnumerateFiles()) {

                $attributes = [int] $file.Attributes

                if (($attributes -band $cloudOnly) -ne 0) { $skipped++; continue }
                if (($attributes -band $reparse) -ne 0)   { continue }
                if ($file.Length -lt $MinimumSize)          { continue }

                $files.Add([pscustomobject] @{ Path = $file.FullName; Length = $file.Length })

                if ($files.Count -ge $MaxFiles) { $truncated = $true; break }
            }
        }
        catch {
            # A folder that cannot be read is skipped; the rest is still walked.
            $null = $_
        }
    }

    return [pscustomobject] @{ Files = @($files.ToArray()); Skipped = $skipped; Truncated = $truncated }
}

<#
.SYNOPSIS
    Hashes a file, whole or only its first bytes.

.OUTPUTS
    System.String, or $null when the file cannot be read.
#>
function Get-TkFileHashPart {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [long] $Bytes = 0
    )

    $sha    = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null

    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')

        if ($Bytes -gt 0) {
            $buffer = New-Object byte[] ([math]::Min($Bytes, $stream.Length))
            $read   = $stream.Read($buffer, 0, $buffer.Length)
            $hash   = $sha.ComputeHash($buffer, 0, $read)
        }
        else {
            $hash = $sha.ComputeHash($stream)
        }

        return ([BitConverter]::ToString($hash) -replace '-', '')
    }
    catch {
        return $null
    }
    finally {
        if ($stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

<#
.SYNOPSIS
    Groups the files that are the same, in stages.

.DESCRIPTION
    Pure apart from the hashing, which is passed in so it can be replaced in a
    test: same size first, then the same first bytes, then the same content.
    A file that cannot be read drops out of its group.

.PARAMETER File
    Objects with Path and Length.

.PARAMETER Hasher
    A script block taking a path and a byte count (0 for the whole file) and
    returning a hash, or $null when the file cannot be read.

.OUTPUTS
    PSCustomObject[] with Hash, Length, Files and Wasted (the space the extra
    copies take), the most wasteful first.
#>
function Group-TkDuplicateFile {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $File = @(),
        [Parameter(Mandatory)] [scriptblock] $Hasher
    )

    $stage = {
        param($candidates, $bytes)

        $byHash = @{}

        foreach ($candidate in $candidates) {
            $key = & $Hasher $candidate.Path $bytes
            if (-not $key) { continue }
            if (-not $byHash.ContainsKey($key)) { $byHash[$key] = New-Object System.Collections.Generic.List[object] }
            $byHash[$key].Add($candidate)
        }

        foreach ($key in $byHash.Keys) {
            if ($byHash[$key].Count -gt 1) {
                , @{ Key = $key; Files = @($byHash[$key].ToArray()) }
            }
        }
    }

    $groups = New-Object System.Collections.Generic.List[object]

    foreach ($sameSize in ($File | Where-Object { $_ } | Group-Object Length | Where-Object { $_.Count -gt 1 })) {

        foreach ($sameStart in @(& $stage @($sameSize.Group) 65536)) {

            foreach ($same in @(& $stage @($sameStart.Files) 0)) {

                $length = [long] $same.Files[0].Length

                $groups.Add([pscustomobject] @{
                    Hash   = $same.Key
                    Length = $length
                    Files  = @($same.Files | ForEach-Object { $_.Path } | Sort-Object)
                    Wasted = $length * ($same.Files.Count - 1)
                })
            }
        }
    }

    return @($groups.ToArray() | Sort-Object Wasted -Descending)
}

<#
.SYNOPSIS
    Sums the duplicates up by the folders that hold them.

.DESCRIPTION
    Pure. Four hundred identical photos read better as one line - these two
    folders hold the same 400 files - than as four hundred groups. Each group
    is filed under the set of folders its copies sit in.

.PARAMETER Group
    The groups from Group-TkDuplicateFile.

.OUTPUTS
    PSCustomObject[] with Folders, Files (how many files have a copy there)
    and Wasted, the most wasteful first.
#>
function Get-TkDuplicateFolderSet {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Group = @()
    )

    $sets = @{}

    foreach ($entry in ($Group | Where-Object { $_ })) {

        $folders = @($entry.Files | ForEach-Object { Split-Path -Path $_ -Parent } | Sort-Object -Unique)
        $key     = $folders -join '|'

        if (-not $sets.ContainsKey($key)) {
            $sets[$key] = [pscustomobject] @{ Folders = $folders; Files = 0; Wasted = [long] 0 }
        }

        $sets[$key].Files  += 1
        $sets[$key].Wasted += [long] $entry.Wasted
    }

    return @($sets.Values | Sort-Object Wasted -Descending)
}

<#
.SYNOPSIS
    Finds the duplicate files in the account's own folders.

.PARAMETER Path
    The folders to look in. The personal folders when not given.

.OUTPUTS
    PSCustomObject with Folders, Scanned, Skipped, Truncated, Groups, Sets
    (the duplicates summed up by folder) and Wasted (bytes).
#>
function Get-TkDuplicateFileReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string[]] $Path,

        [Parameter()]
        [long] $MinimumSize = 1MB
    )

    if (-not $Path) {
        $Path = Get-TkPersonalFolder
    }

    $inventory = Get-TkFileInventory -Path $Path -MinimumSize $MinimumSize
    $groups    = @(Group-TkDuplicateFile -File $inventory.Files -Hasher {
        param($filePath, $bytes)
        Get-TkFileHashPart -Path $filePath -Bytes $bytes
    })

    return [pscustomobject] @{
        Folders   = @($Path)
        Scanned   = @($inventory.Files).Count
        Skipped   = $inventory.Skipped
        Truncated = $inventory.Truncated
        Groups    = $groups
        Sets      = @(Get-TkDuplicateFolderSet -Group $groups)
        Wasted    = [long] (@($groups | Measure-Object -Property Wasted -Sum).Sum)
    }
}
