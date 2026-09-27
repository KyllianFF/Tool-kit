<#
    Toolkit - Features / Migration: pins

    The folders pinned to Quick Access, the jump lists of each application,
    the taskbar and the Start menu are files and one registry key in the
    profile, not settings Windows carries over. The export copies them into
    the package; the import puts them back, after saving the ones already on
    the new machine, and restarts Explorer so it reads them.

    The taskbar key is imported from a .reg file, so that file is read with
    the toolkit's .reg parser first and refused unless every key in it is the
    taskbar key: a package can never write anywhere else in the registry.
#>

<#
.SYNOPSIS
    Where Windows keeps the pins of this account.

.OUTPUTS
    PSCustomObject with Automatic, Custom, Taskbar, TaskbandKey and Start.
#>
function Get-TkPinLocation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string] $AppData = $env:APPDATA,
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA
    )

    return [pscustomobject] @{
        Automatic   = [System.IO.Path]::Combine($AppData, 'Microsoft\Windows\Recent\AutomaticDestinations')
        Custom      = [System.IO.Path]::Combine($AppData, 'Microsoft\Windows\Recent\CustomDestinations')
        Taskbar     = [System.IO.Path]::Combine($AppData, 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
        TaskbandKey = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband'
        Start       = [System.IO.Path]::Combine($LocalAppData, 'Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState')
    }
}

<#
.SYNOPSIS
    Says whether a .reg file touches the taskbar key and nothing else.

.DESCRIPTION
    Pure. The file must parse without error, and every key it writes must be
    the taskbar key or one under it; a deletion is refused.

.OUTPUTS
    System.Boolean
#>
function Test-TkTaskbandRegFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        # The hive the file must stay in: this account, or another account's mounted hive.
        [Parameter()] [string] $Hive = 'HKEY_CURRENT_USER'
    )

    $read = ConvertFrom-TkRegFile -Text $Text
    $key  = '{0}\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' -f $Hive.TrimEnd('\')

    if (-not $read.HasHeader -or @($read.Errors).Count -gt 0 -or @($read.Entries).Count -eq 0) {
        return $false
    }

    foreach ($entry in $read.Entries) {
        if ($entry.Action -notin @('Key', 'Value')) { return $false }
        if ($entry.Key -ne $key -and -not $entry.Key.StartsWith($key + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }

    return $true
}

<#
.SYNOPSIS
    Copies the files of a folder that match a filter, and counts them.

.OUTPUTS
    System.Int32
#>
function Copy-TkPinFile {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [string] $From,
        [Parameter(Mandatory)] [string] $To,
        [Parameter(Mandatory)] [string] $Filter,
        [Parameter()] [switch] $KeepExisting
    )

    if (-not (Test-Path -LiteralPath $From -PathType Container)) { return 0 }

    New-Item -ItemType Directory -Path $To -Force | Out-Null
    $count = 0

    foreach ($file in (Get-ChildItem -LiteralPath $From -Filter $Filter -File -ErrorAction SilentlyContinue)) {
        $target = [System.IO.Path]::Combine($To, $file.Name)
        if ($KeepExisting -and (Test-Path -LiteralPath $target)) { continue }
        try {
            [System.IO.File]::Copy($file.FullName, $target, $true)
            $count++
        }
        catch {
            Write-TkLog -Level Warning -Category 'Migration' -Message ('{0} could not be copied: {1}' -f $file.Name, $_.Exception.Message)
        }
    }

    return $count
}

<#
.SYNOPSIS
    Copies the pins of this account into the package.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary, the manifest section.
#>
function Export-TkMigrationPin {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Root
    )

    $folder = [System.IO.Path]::Combine($Root, 'pins')

    if (-not $PSCmdlet.ShouldProcess($folder, 'Copy the pins')) {
        return [ordered] @{}
    }

    $where = Get-TkPinLocation
    New-Item -ItemType Directory -Path $folder -Force | Out-Null

    $automatic = Copy-TkPinFile -From $where.Automatic -To ([System.IO.Path]::Combine($folder, 'AutomaticDestinations')) -Filter '*.automaticDestinations-ms'
    $custom    = Copy-TkPinFile -From $where.Custom -To ([System.IO.Path]::Combine($folder, 'CustomDestinations')) -Filter '*.customDestinations-ms'
    $taskbar   = Copy-TkPinFile -From $where.Taskbar -To ([System.IO.Path]::Combine($folder, 'TaskBar')) -Filter '*.lnk'

    $taskband = [System.IO.Path]::Combine($folder, 'Taskband.reg')
    [void] (Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('export', $where.TaskbandKey, $taskband, '/y') -TimeoutSeconds 30)

    $start = $false
    $startFile = [System.IO.Path]::Combine($where.Start, 'start2.bin')
    if (Test-Path -LiteralPath $startFile) {
        try {
            [System.IO.File]::Copy($startFile, [System.IO.Path]::Combine($folder, 'start2.bin'), $true)
            $start = $true
        }
        catch {
            Write-TkLog -Level Warning -Category 'Migration' -Message ('The Start menu pins could not be copied: {0}' -f $_.Exception.Message)
        }
    }

    return [ordered] @{
        quickAccess   = (Test-Path -LiteralPath ([System.IO.Path]::Combine($folder, 'AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms')))
        jumpLists     = $automatic + $custom
        taskbar       = $taskbar
        taskband      = (Test-Path -LiteralPath $taskband)
        start         = $start
        sourceProfile = $env:USERPROFILE
    }
}

<#
.SYNOPSIS
    Reads the pins part of a package, from its fixed file names.

.OUTPUTS
    PSCustomObject with Folder, Automatic, Custom, Taskbar, Taskband, Start and SourceProfile, or $null.
#>
function Read-TkMigrationPin {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter()] [AllowEmptyString()] [string] $SourceProfile = ''
    )

    $folder = [System.IO.Path]::Combine($Root, 'pins')
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return $null }

    $count = { param($sub, $filter) @(Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($folder, $sub)) -Filter $filter -File -ErrorAction SilentlyContinue).Count }

    return [pscustomobject] @{
        Folder        = $folder
        Automatic     = & $count 'AutomaticDestinations' '*.automaticDestinations-ms'
        Custom        = & $count 'CustomDestinations' '*.customDestinations-ms'
        Taskbar       = & $count 'TaskBar' '*.lnk'
        Taskband      = (Test-Path -LiteralPath ([System.IO.Path]::Combine($folder, 'Taskband.reg')))
        Start         = (Test-Path -LiteralPath ([System.IO.Path]::Combine($folder, 'start2.bin')))
        SourceProfile = $SourceProfile
    }
}

<#
.SYNOPSIS
    Puts the pins of a package back, after saving the ones already here.

.DESCRIPTION
    The pins of this account are copied to a dated folder in the toolkit
    data folder first, so the import can be undone by copying them back.
    Explorer and the Start menu are stopped while the files are replaced,
    since they write them when they close, and Explorer is started again.
    Taskbar shortcuts already here are kept; the taskbar key is imported
    only if its file touches that key alone.

.OUTPUTS
    PSCustomObject with Ok, Backup and Lines.
#>
function Import-TkMigrationPin {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter()] [AllowEmptyString()] [string] $SourceProfile = '',
        [Parameter()] [string] $BackupRoot = (Get-TkContext).DataRoot,
        [Parameter()] [pscustomobject] $Location = (Get-TkPinLocation),
        [Parameter()] [scriptblock] $StopShell = { Stop-Process -Name 'StartMenuExperienceHost', 'explorer' -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 800 },
        [Parameter()] [scriptblock] $StartShell = { Start-Sleep -Milliseconds 500; if (-not (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) { Start-Process -FilePath 'explorer.exe' } }
    )

    $pins = Read-TkMigrationPin -Root $Root -SourceProfile $SourceProfile
    if (-not $pins) {
        return [pscustomobject] @{ Ok = $false; Backup = ''; Lines = @('The package holds no pins.') }
    }

    if (-not $PSCmdlet.ShouldProcess('the pins of this account', 'Replace, after a backup')) {
        return [pscustomobject] @{ Ok = $false; Backup = ''; Lines = @('Cancelled.') }
    }

    $where  = $Location
    $backup = [System.IO.Path]::Combine($BackupRoot, ('pins-backup-{0:yyyyMMdd-HHmmss}' -f (Get-Date)))
    $lines  = New-Object System.Collections.Generic.List[string]

    # --- The pins already here, saved first -------------------------------
    [void] (Copy-TkPinFile -From $where.Automatic -To ([System.IO.Path]::Combine($backup, 'AutomaticDestinations')) -Filter '*.automaticDestinations-ms')
    [void] (Copy-TkPinFile -From $where.Custom -To ([System.IO.Path]::Combine($backup, 'CustomDestinations')) -Filter '*.customDestinations-ms')
    [void] (Copy-TkPinFile -From $where.Taskbar -To ([System.IO.Path]::Combine($backup, 'TaskBar')) -Filter '*.lnk')
    [void] (Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('export', $where.TaskbandKey, ([System.IO.Path]::Combine($backup, 'Taskband.reg')), '/y') -TimeoutSeconds 30)
    if (Test-Path -LiteralPath ([System.IO.Path]::Combine($where.Start, 'start2.bin'))) {
        Copy-Item -LiteralPath ([System.IO.Path]::Combine($where.Start, 'start2.bin')) -Destination $backup -ErrorAction SilentlyContinue
    }

    $taskbandFile = [System.IO.Path]::Combine($pins.Folder, 'Taskband.reg')
    $taskbandOk   = $pins.Taskband -and (Test-TkTaskbandRegFile -Text ([System.IO.File]::ReadAllText($taskbandFile)))
    if ($pins.Taskband -and -not $taskbandOk) {
        $lines.Add('The taskbar key in the package was refused: its .reg file touches more than the taskbar key.')
    }

    # --- Replaced with Explorer and the Start menu closed -------------------
    & $StopShell

    try {
        $automatic = Copy-TkPinFile -From ([System.IO.Path]::Combine($pins.Folder, 'AutomaticDestinations')) -To $where.Automatic -Filter '*.automaticDestinations-ms'
        $custom    = Copy-TkPinFile -From ([System.IO.Path]::Combine($pins.Folder, 'CustomDestinations')) -To $where.Custom -Filter '*.customDestinations-ms'
        $taskbar   = Copy-TkPinFile -From ([System.IO.Path]::Combine($pins.Folder, 'TaskBar')) -To $where.Taskbar -Filter '*.lnk' -KeepExisting

        if ($taskbandOk) {
            $run = Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('import', $taskbandFile) -TimeoutSeconds 30
            if ($run.ExitCode -ne 0) { $lines.Add('The taskbar key could not be imported.') }
        }

        if ($pins.Start -and (Test-Path -LiteralPath $where.Start -PathType Container)) {
            [System.IO.File]::Copy([System.IO.Path]::Combine($pins.Folder, 'start2.bin'), [System.IO.Path]::Combine($where.Start, 'start2.bin'), $true)
            $lines.Add('Start menu pins put back.')
        }

        $lines.Insert(0, ('{0} Quick Access and jump list file(s), {1} taskbar shortcut(s) put back.' -f ($automatic + $custom), $taskbar))
    }
    finally {
        & $StartShell
    }

    if ($pins.SourceProfile -and $pins.SourceProfile -ne $env:USERPROFILE) {
        $lines.Add(('Pins to folders of the old profile ({0}) still point there: pin them again from their new place.' -f $pins.SourceProfile))
    }

    $lines.Add(('The pins that were here are saved in {0}.' -f $backup))

    Add-TkJournalEntry -Name 'Migration pins put back' -Category 'Migration' -Detail (($lines.ToArray()) -join ' ')

    return [pscustomobject] @{ Ok = $true; Backup = $backup; Lines = @($lines.ToArray()) }
}
