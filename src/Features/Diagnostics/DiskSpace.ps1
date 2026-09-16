<#
    Toolkit - Features / Diagnostics / Disk space

    Answering "where did the disk go" without a third-party tool: how full each
    drive is, the biggest folders and files on the system drive, and the caches
    that are safe to empty, each with its current size.

    Nothing here deletes anything. The scan only reads sizes, skips the folders
    it is refused and the reparse points that would send it in circles or count
    a folder twice, and reports what it found so a person decides what to remove.
#>

<#
.SYNOPSIS
    Adds up the size of everything under a path, safely.

.DESCRIPTION
    Walks the tree with an explicit stack rather than recursion, so a deep tree
    cannot overflow. A folder that cannot be read is skipped, and a reparse
    point (a junction or a symbolic link) is not followed, so nothing is counted
    twice and no loop is possible.

.PARAMETER Path
    The folder or file to measure.

.OUTPUTS
    System.Int64, the total number of bytes, or 0 when the path does not exist.
#>
function Measure-TkPathSize {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [long] 0
    }

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue

    if ($null -eq $item) {
        return [long] 0
    }

    if ($item -is [System.IO.FileInfo]) {
        return [long] $item.Length
    }

    $total = [long] 0
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $stack.Push($item)

    while ($stack.Count -gt 0) {

        $dir = $stack.Pop()

        try {
            $entries = $dir.GetFileSystemInfos()
        }
        catch {
            continue
        }

        foreach ($entry in $entries) {

            if ($entry -is [System.IO.DirectoryInfo]) {

                if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
                    continue
                }

                $stack.Push($entry)
            }
            else {
                $total += [long] $entry.Length
            }
        }
    }

    return $total
}

<#
.SYNOPSIS
    Reports how full each fixed drive is.

.DESCRIPTION
    Reads the ready fixed drives, and judges each one: a drive with less than a
    tenth of its space or less than 5 GB free is a problem, less than a fifth is
    a warning. Removable and network drives are left out.

.OUTPUTS
    PSCustomObject[] with Name, Label, Format, TotalBytes, FreeBytes, UsedBytes,
    FreePercent and Severity.
#>
function Get-TkDriveSpace {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object {
        $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady
    }

    $result = foreach ($drive in $drives) {

        $total = [long] $drive.TotalSize
        $free  = [long] $drive.AvailableFreeSpace
        $used  = $total - $free
        $percent = if ($total -gt 0) { [math]::Round(($free / $total) * 100, 1) } else { 0 }

        $severity = if ($percent -lt 10 -or $free -lt 5GB) { 'Fail' }
                    elseif ($percent -lt 20) { 'Warning' }
                    else { 'Pass' }

        [pscustomobject] @{
            Name        = $drive.Name.TrimEnd('\')
            Label       = $drive.VolumeLabel
            Format      = $drive.DriveFormat
            TotalBytes  = $total
            FreeBytes   = $free
            UsedBytes   = $used
            FreePercent = $percent
            Severity    = $severity
        }
    }

    return @($result)
}

<#
.SYNOPSIS
    Finds the biggest folders and files under a path.

.DESCRIPTION
    One walk of the tree adds up each top-level folder and, at the same time,
    keeps the largest files seen. Folders that cannot be read are skipped and
    reparse points are not followed, so the scan is safe to run on a whole drive
    without administrator rights, seeing simply less where it is refused.

.PARAMETER Path
    The folder to scan, such as C:\.

.PARAMETER TopFolders
    How many of the biggest top-level folders to keep.

.PARAMETER TopFiles
    How many of the biggest files to keep.

.OUTPUTS
    PSCustomObject with Root, TotalBytes, Folders and Files.
#>
function Get-TkDiskUsageScan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [int] $TopFolders = 15,

        [Parameter()]
        [int] $TopFiles = 20
    )

    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

    if ($root -isnot [System.IO.DirectoryInfo]) {
        throw ('{0} is not a folder.' -f $Path)
    }

    $totals    = @{}
    $files     = New-Object System.Collections.Generic.List[pscustomobject]
    $minKept   = [long] 0
    $totalSize = [long] 0

    # A node carries the directory and the name of the top-level folder it
    # belongs to, so every file can be attributed without a second pass.
    $stack = New-Object System.Collections.Generic.Stack[pscustomobject]
    $stack.Push([pscustomobject] @{ Dir = $root; Top = $null })

    $rootBucket = '(files in the root)'

    while ($stack.Count -gt 0) {

        $node = $stack.Pop()

        try {
            $entries = $node.Dir.GetFileSystemInfos()
        }
        catch {
            continue
        }

        foreach ($entry in $entries) {

            if ($entry -is [System.IO.DirectoryInfo]) {

                if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
                    continue
                }

                $top = if ($node.Top) { $node.Top } else { $entry.Name }
                $stack.Push([pscustomobject] @{ Dir = $entry; Top = $top })
                continue
            }

            $length = [long] $entry.Length
            $top     = if ($node.Top) { $node.Top } else { $rootBucket }

            if ($totals.ContainsKey($top)) { $totals[$top] += $length } else { $totals[$top] = $length }
            $totalSize += $length

            # Keep only the largest files, replacing the smallest kept once full.
            if ($files.Count -lt $TopFiles) {
                $files.Add([pscustomobject] @{ Path = $entry.FullName; Bytes = $length })
                if ($files.Count -eq $TopFiles) {
                    $minKept = ($files | Measure-Object -Property Bytes -Minimum).Minimum
                }
            }
            elseif ($length -gt $minKept) {
                $smallest = $files | Sort-Object Bytes | Select-Object -First 1
                [void] $files.Remove($smallest)
                $files.Add([pscustomobject] @{ Path = $entry.FullName; Bytes = $length })
                $minKept = ($files | Measure-Object -Property Bytes -Minimum).Minimum
            }
        }
    }

    $folders = @($totals.GetEnumerator() |
                 Sort-Object -Property Value -Descending |
                 Select-Object -First $TopFolders |
                 ForEach-Object { [pscustomobject] @{ Name = $_.Key; Bytes = [long] $_.Value } })

    return [pscustomobject] @{
        Root       = $root.FullName
        TotalBytes = $totalSize
        Folders    = $folders
        Files      = @($files | Sort-Object -Property Bytes -Descending)
    }
}

<#
.SYNOPSIS
    Lists the caches that are safe to empty, with the size of each.

.DESCRIPTION
    The well-known temporary and cache locations Windows and Disk Cleanup treat
    as disposable, each measured as it is now. The base folders are parameters so
    the list can be tested without reading the real machine; by default they come
    from the environment. Nothing is deleted: the sizes say what could be freed.

.PARAMETER LocalAppData
    The current user's local application data folder.

.PARAMETER WindowsDir
    The Windows folder.

.PARAMETER ProgramData
    The ProgramData folder.

.PARAMETER SystemDrive
    The system drive, such as C:.

.PARAMETER Temp
    The user's temporary folder.

.OUTPUTS
    PSCustomObject[] with Name, Path, Bytes, Exists, Scope and Note.
#>
function Get-TkCleanupCandidate {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA,
        [Parameter()] [string] $WindowsDir   = $env:windir,
        [Parameter()] [string] $ProgramData  = $env:ProgramData,
        [Parameter()] [string] $SystemDrive  = $env:SystemDrive,
        [Parameter()] [string] $Temp         = $env:TEMP
    )

    $definitions = @(
        [pscustomobject] @{ Name = 'Your temporary files';        Path = $Temp;                                                          Scope = 'User';   Note = 'Files programs left in your %TEMP% folder.' }
        [pscustomobject] @{ Name = 'Windows temporary files';     Path = (Join-Path $WindowsDir 'Temp');                                 Scope = 'System'; Note = 'The system-wide temporary folder.' }
        [pscustomobject] @{ Name = 'Windows Update cache';        Path = (Join-Path $WindowsDir 'SoftwareDistribution\Download');        Scope = 'System'; Note = 'Update files already installed; Windows rebuilds this as needed.' }
        [pscustomobject] @{ Name = 'Delivery Optimization cache'; Path = (Join-Path $WindowsDir 'SoftwareDistribution\DeliveryOptimization'); Scope = 'System'; Note = 'Peer-to-peer update cache.' }
        [pscustomobject] @{ Name = 'Windows.old';                 Path = (Join-Path $SystemDrive '\Windows.old');                        Scope = 'System'; Note = 'The previous Windows, kept after an upgrade. Removing it undoes the option to roll back.' }
        [pscustomobject] @{ Name = 'Recycle Bin';                 Path = (Join-Path $SystemDrive '\$Recycle.Bin');                       Scope = 'System'; Note = 'Deleted files still recoverable until emptied.' }
        [pscustomobject] @{ Name = 'Thumbnail and icon cache';    Path = (Join-Path $LocalAppData 'Microsoft\Windows\Explorer');         Scope = 'User';   Note = 'Explorer rebuilds these on demand.' }
        [pscustomobject] @{ Name = 'Internet cache';              Path = (Join-Path $LocalAppData 'Microsoft\Windows\INetCache');        Scope = 'User';   Note = 'Cached web content from legacy components.' }
        [pscustomobject] @{ Name = 'Application crash dumps';     Path = (Join-Path $LocalAppData 'CrashDumps');                         Scope = 'User';   Note = 'Memory dumps written when an application crashed.' }
        [pscustomobject] @{ Name = 'Error reporting queue';       Path = (Join-Path $ProgramData 'Microsoft\Windows\WER');               Scope = 'System'; Note = 'Reports queued for Windows Error Reporting.' }
        [pscustomobject] @{ Name = 'System crash dump';           Path = (Join-Path $WindowsDir 'MEMORY.DMP');                           Scope = 'System'; Note = 'The full memory dump from the last blue screen.' }
        [pscustomobject] @{ Name = 'Minidumps';                   Path = (Join-Path $WindowsDir 'Minidump');                             Scope = 'System'; Note = 'The small dumps from blue screens.' }
    )

    $result = foreach ($definition in $definitions) {

        $exists = $definition.Path -and (Test-Path -LiteralPath $definition.Path)
        $bytes  = if ($exists) { Measure-TkPathSize -Path $definition.Path } else { [long] 0 }

        [pscustomobject] @{
            Name   = $definition.Name
            Path   = $definition.Path
            Bytes  = $bytes
            Exists = [bool] $exists
            Scope  = $definition.Scope
            Note   = $definition.Note
        }
    }

    return @($result)
}
