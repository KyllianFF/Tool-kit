<#
    Toolkit - Features / Migration package and import

    The export writes each personal folder under the name of the Windows
    folder it came from (Desktop, Documents, Pictures...), and a manifest,
    migration.json, that says so. The import reads it back and lets each
    folder land wherever that folder really lives on the new machine: the
    Documents of this account, or a OneDrive, iCloud Drive, Google Drive or
    Dropbox folder, or any folder chosen by hand.

    Nothing that is already on the new machine is overwritten. A file that
    exists at the destination with other content is left as it is, and listed
    as a conflict, so an import can never destroy work done in the meantime.
#>

<#
.SYNOPSIS
    The personal folders of this account, by their Windows name.

.DESCRIPTION
    Read from User Shell Folders, where Windows keeps where each folder
    really is: moved by OneDrive folder backup, redirected by a policy, or
    left in the profile.

.OUTPUTS
    PSCustomObject[] with Key, Path and Exists.
#>
function Get-TkKnownFolder {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $values = [ordered] @{
        Desktop   = 'Desktop'
        Documents = 'Personal'
        Pictures  = 'My Pictures'
        Videos    = 'My Video'
        Music     = 'My Music'
        Downloads = '{374DE290-123F-4565-9164-39C4925E467B}'
    }

    $fallback = @{
        Desktop   = [Environment]::GetFolderPath('Desktop')
        Documents = [Environment]::GetFolderPath('MyDocuments')
        Pictures  = [Environment]::GetFolderPath('MyPictures')
        Videos    = [Environment]::GetFolderPath('MyVideos')
        Music     = [Environment]::GetFolderPath('MyMusic')
        Downloads = Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads'
    }

    $shell = try { Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop } catch { $null }

    return @(foreach ($key in $values.Keys) {
        $raw  = if ($shell -and $shell.PSObject.Properties[$values[$key]]) { [string] $shell.($values[$key]) } else { '' }
        $path = if ($raw) { [Environment]::ExpandEnvironmentVariables($raw).TrimEnd('\') } else { $fallback[$key] }

        [pscustomobject] @{ Key = $key; Path = $path; Exists = [bool] ($path -and (Test-Path -LiteralPath $path -PathType Container)) }
    })
}

<#
.SYNOPSIS
    Builds the manifest of an export.

.DESCRIPTION
    Pure. Later sections (applications, pins, bookmarks) are added beside
    the folders by the steps that export them.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
function New-TkMigrationManifest {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Plan = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Result = @(),
        [Parameter()] [string] $Computer = $env:COMPUTERNAME,
        [Parameter()] [string] $User = $env:USERNAME
    )

    $folders = foreach ($step in ($Plan | Where-Object { $_ })) {
        $outcome = @($Result | Where-Object { $_.Name -eq $step.Name }) | Select-Object -First 1
        [ordered] @{
            key        = [string] $step.Name
            folder     = [string] $step.Name
            sourcePath = [string] $step.Source
            bytes      = [long] $step.Bytes
            status     = $(if ($step.Skip) { 'skipped: {0}' -f $step.Skip } elseif ($outcome -and $outcome.Ok) { 'copied' } elseif ($outcome) { 'incomplete' } else { 'not copied' })
        }
    }

    return [ordered] @{
        schema        = 'toolkit-migration'
        schemaVersion = 1
        computer      = $Computer
        user          = $User
        created       = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        folders       = @($folders)
    }
}

<#
.SYNOPSIS
    Writes migration.json at the root of the package.

.OUTPUTS
    System.String, the path written, or empty.
#>
function Save-TkMigrationManifest {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Plan,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Result = @()
    )

    $first = @($Plan | Where-Object { $_ }) | Select-Object -First 1
    if (-not $first) { return '' }

    $root = Split-Path -Path $first.Target -Parent
    $path = [System.IO.Path]::Combine($root, 'migration.json')

    if (-not $PSCmdlet.ShouldProcess($path, 'Write the migration manifest')) {
        return ''
    }

    $manifest = New-TkMigrationManifest -Plan $Plan -Result $Result

    try {
        [System.IO.File]::WriteAllText($path, ($manifest | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        return $path
    }
    catch {
        Write-TkLog -Level Warning -Category 'Migration' -Message ('The manifest could not be written: {0}' -f $_.Exception.Message)
        return ''
    }
}

<#
.SYNOPSIS
    Reads a migration package: its manifest, or its folder names when it has none.

.DESCRIPTION
    A package made before the manifest existed still imports: its folders
    are matched to the Windows folders by name. A folder whose name matches
    none is offered too, without a default destination. The manifest is
    data from another machine: each folder it names must be a plain name
    inside the package, never a path that leads out of it.

.PARAMETER Path
    The package folder: the one holding migration.json, Documents, Desktop...

.OUTPUTS
    PSCustomObject with Root, Computer, User, Created, FromManifest, Folders
    (Key, Name, Source, Bytes) and Error.
#>
function Read-TkMigrationPackage {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Path
    )

    $root   = $Path.Trim().TrimEnd('\')
    $failed = { param($message) [pscustomobject] @{ Root = $root; Computer = ''; User = ''; Created = ''; FromManifest = $false; Folders = @(); Error = $message } }

    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) {
        return (& $failed 'Choose the folder of the package: the one the export created, named Migration-<PC>-<user>-<date>.')
    }

    $keys     = @('Desktop', 'Documents', 'Pictures', 'Videos', 'Music', 'Downloads')
    $manifest = [System.IO.Path]::Combine($root, 'migration.json')

    if (Test-Path -LiteralPath $manifest -PathType Leaf) {

        try {
            $data = [System.IO.File]::ReadAllText($manifest) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            return (& $failed 'migration.json is not valid JSON.')
        }

        if ([string] $data.schema -ne 'toolkit-migration') {
            return (& $failed 'migration.json is not a toolkit migration manifest.')
        }

        $folders = foreach ($entry in @($data.folders)) {
            $name = [string] $entry.folder
            if ($name -notmatch '^[A-Za-z0-9 ._-]{1,64}$' -or $name -match '^\.+$') { continue }

            $source = [System.IO.Path]::Combine($root, $name)
            if (-not (Test-Path -LiteralPath $source -PathType Container)) { continue }

            [pscustomobject] @{
                Key    = $(if ($keys -contains [string] $entry.key) { [string] $entry.key } else { '' })
                Name   = $name
                Source = $source
                Bytes  = [long] $entry.bytes
            }
        }

        return [pscustomobject] @{
            Root = $root; Computer = [string] $data.computer; User = [string] $data.user; Created = [string] $data.created
            FromManifest = $true; Folders = @($folders); Error = ''
        }
    }

    $folders = foreach ($directory in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
        $key = @($keys | Where-Object { $_ -eq $directory.Name }) | Select-Object -First 1
        [pscustomobject] @{ Key = [string] $key; Name = $directory.Name; Source = $directory.FullName; Bytes = [long] -1 }
    }

    if (@($folders).Count -eq 0) {
        return (& $failed 'The folder holds no folder to import.')
    }

    return [pscustomobject] @{ Root = $root; Computer = ''; User = ''; Created = ''; FromManifest = $false; Folders = @($folders); Error = '' }
}

<#
.SYNOPSIS
    The cloud folders on this account: OneDrive, iCloud Drive, Google Drive, Dropbox.

.DESCRIPTION
    Each is where its sync client keeps the files, so a folder imported
    under it is uploaded by that client. The locations are passed in, so the
    detection can be tested without the clients installed.

.OUTPUTS
    PSCustomObject[] with Name and Path.
#>
function Get-TkCloudRoot {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [string] $UserProfile = $env:USERPROFILE,
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA,
        [Parameter()] [AllowEmptyCollection()] [string[]] $OneDrive = @(Get-TkOneDriveRoot),
        [Parameter()] [AllowEmptyCollection()] [string[]] $DriveRoot = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady } | ForEach-Object { $_.Name }),
        [Parameter()] [scriptblock] $FolderExists = { param($path) Test-Path -LiteralPath $path -PathType Container },
        [Parameter()] [scriptblock] $ReadText = { param($path) try { [System.IO.File]::ReadAllText($path) } catch { '' } }
    )

    $roots = New-Object System.Collections.Generic.List[object]
    $add   = { param($name, $path) if ($path -and (& $FolderExists $path) -and -not @($roots | Where-Object { $_.Path -eq $path }).Count) { $roots.Add([pscustomobject] @{ Name = $name; Path = $path.TrimEnd('\') }) } }

    foreach ($folder in ($OneDrive | Where-Object { $_ })) {
        & $add (Split-Path -Path $folder -Leaf) $folder
    }

    & $add 'iCloud Drive' ([System.IO.Path]::Combine($UserProfile, 'iCloudDrive'))

    # Google Drive for desktop mounts a drive letter holding "My Drive"
    # (translated in some languages); the older client kept a profile folder.
    foreach ($drive in ($DriveRoot | Where-Object { $_ })) {
        foreach ($name in @('My Drive', 'Mon Drive', 'Mi unidad', 'Meine Ablage')) {
            & $add 'Google Drive' ([System.IO.Path]::Combine($drive, $name))
        }
    }
    & $add 'Google Drive' ([System.IO.Path]::Combine($UserProfile, 'Google Drive'))

    # Dropbox writes where its folders are in info.json.
    $info = & $ReadText ([System.IO.Path]::Combine($LocalAppData, 'Dropbox\info.json'))
    if ($info) {
        try {
            $data = $info | ConvertFrom-Json -ErrorAction Stop
            foreach ($kind in @('personal', 'business')) {
                if ($data.PSObject.Properties[$kind] -and $data.$kind.path) {
                    & $add ('Dropbox ({0})' -f $kind) ([string] $data.$kind.path)
                }
            }
        }
        catch {
            $null = $_
        }
    }
    & $add 'Dropbox' ([System.IO.Path]::Combine($UserProfile, 'Dropbox'))

    return @($roots.ToArray())
}

<#
.SYNOPSIS
    Plans the import: each folder of the package, where it goes, and what is wrong.

.DESCRIPTION
    Pure apart from the drive check made by Test-TkMigrationDestination. A
    folder with no destination is left out. A destination inside the
    package, inside Windows or on a drive that is not there is refused.

.PARAMETER Package
    From Read-TkMigrationPackage.

.PARAMETER Target
    Destination by folder name.

.OUTPUTS
    PSCustomObject with Steps (Name, Key, Source, Target, Bytes) and Errors.
#>
function New-TkMigrationImportPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Package,
        [Parameter(Mandatory)] [hashtable] $Target,
        [Parameter()] [scriptblock] $DriveExists = { param($root) Test-Path -LiteralPath $root }
    )

    $steps  = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $seen   = @{}

    foreach ($folder in @($Package.Folders)) {

        $destination = ([string] $Target[$folder.Name]).Trim().TrimEnd('\')
        if (-not $destination) { continue }

        $problem = Test-TkMigrationDestination -Destination $destination -Source @($Package.Root) -DriveExists $DriveExists
        if ($problem) {
            $errors.Add(('{0}: {1}' -f $folder.Name, $problem))
            continue
        }

        if ($seen.ContainsKey($destination.ToLowerInvariant())) {
            $errors.Add(('{0} and {1} go to the same folder; give each its own.' -f $seen[$destination.ToLowerInvariant()], $folder.Name))
            continue
        }
        $seen[$destination.ToLowerInvariant()] = $folder.Name

        $steps.Add([pscustomobject] @{ Name = $folder.Name; Key = $folder.Key; Source = $folder.Source; Target = $destination; Bytes = $folder.Bytes })
    }

    return [pscustomobject] @{ Steps = @($steps.ToArray()); Errors = @($errors.ToArray()) }
}

<#
.SYNOPSIS
    Lists the files an import would not copy because the destination already has another version.

.DESCRIPTION
    A file is the same when its size and its time match, as robocopy judges
    it (two seconds of tolerance, for FAT and network drives). A file that
    differs is a conflict: the import leaves the destination copy alone.

.OUTPUTS
    PSCustomObject with New, Same and Conflicts (Source, Target, SourceBytes,
    TargetBytes, SourceTime, TargetTime).
#>
function Find-TkMigrationConflict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter()] [int] $MaxFiles = 500000
    )

    $conflicts = New-Object System.Collections.Generic.List[object]
    $new       = 0
    $same      = 0
    $count     = 0
    $reparse   = [int] [System.IO.FileAttributes]::ReparsePoint

    # The relative path is carried down the walk rather than cut off each full
    # path: a root given in its short 8.3 form (KYLLIA~1) comes back long from
    # the enumeration, and cutting by length then pointed at the wrong files.
    $pending = New-Object System.Collections.Generic.Stack[object]
    $pending.Push(@((New-Object System.IO.DirectoryInfo($Source)), ''))

    while ($pending.Count -gt 0 -and $count -lt $MaxFiles) {

        $pair      = $pending.Pop()
        $directory = $pair[0]
        $relative  = $pair[1]

        try {
            foreach ($child in $directory.EnumerateDirectories()) {
                if (([int] $child.Attributes -band $reparse) -ne 0) { continue }
                $pending.Push(@($child, [System.IO.Path]::Combine($relative, $child.Name)))
            }

            foreach ($here in $directory.EnumerateFiles()) {

                $count++
                $destination = [System.IO.Path]::Combine($Target, $relative, $here.Name)

                if (-not [System.IO.File]::Exists($destination)) {
                    $new++
                    continue
                }

                $there = New-Object System.IO.FileInfo($destination)

                if ($there.Length -eq $here.Length -and [math]::Abs(($there.LastWriteTimeUtc - $here.LastWriteTimeUtc).TotalSeconds) -le 2) {
                    $same++
                    continue
                }

                $conflicts.Add([pscustomobject] @{
                    Source      = $here.FullName
                    Target      = $destination
                    SourceBytes = $here.Length
                    TargetBytes = $there.Length
                    SourceTime  = $here.LastWriteTime
                    TargetTime  = $there.LastWriteTime
                })
            }
        }
        catch {
            # A folder that cannot be read is skipped; robocopy reports it in its log.
            $null = $_
        }
    }

    return [pscustomobject] @{ New = $new; Same = $same; Conflicts = @($conflicts.ToArray()) }
}

<#
.SYNOPSIS
    Copies the package folders to their destinations, never overwriting anything.

.DESCRIPTION
    robocopy with /XC /XN /XO: a file already at the destination, newer,
    older or changed, is left alone; only files that are not there yet are
    copied. A log per folder is written in the toolkit log folder.

.OUTPUTS
    PSCustomObject[] with Name, Ok, Text and Log.
#>
function Import-TkMigrationFolder {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [object[]] $Step,
        [Parameter()] [string] $LogFolder = (Get-TkContext).LogRoot
    )

    $results = New-Object System.Collections.Generic.List[object]
    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'

    foreach ($item in ($Step | Where-Object { $_ })) {

        if (-not $PSCmdlet.ShouldProcess($item.Target, ('Import {0}' -f $item.Source))) {
            continue
        }

        $log = [System.IO.Path]::Combine($LogFolder, ('import-{0}-{1}.log' -f $item.Name, $stamp))

        try {
            New-Item -ItemType Directory -Path $item.Target -Force -ErrorAction Stop | Out-Null

            $run = Invoke-TkProcess -FilePath 'robocopy.exe' -TimeoutSeconds 0 -ArgumentList @(
                $item.Source, $item.Target, '/E', '/COPY:DAT', '/DCOPY:DAT', '/XC', '/XN', '/XO', '/R:1', '/W:1', '/XJ', '/MT:8', '/NP', ('/LOG:{0}' -f $log)
            )

            $exit = ConvertFrom-TkRobocopyExit -Code $run.ExitCode
            $results.Add([pscustomobject] @{ Name = $item.Name; Ok = $exit.Ok; Text = $exit.Text; Log = $log })
        }
        catch {
            $results.Add([pscustomobject] @{ Name = $item.Name; Ok = $false; Text = $_.Exception.Message; Log = '' })
        }
    }

    Add-TkJournalEntry -Name 'Migration package imported' -Category 'Migration' -Detail (
        (@($results | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Text })) -join '; '
    )

    return @($results.ToArray())
}
