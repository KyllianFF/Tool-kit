<#
    Toolkit - Features / Migration and new PC

    Before a machine is reinstalled or replaced, what the user loses is
    rarely the files everyone thinks of: it is the mapped drives, the
    printers, the Outlook archive in a PST, the bookmarks of a browser nobody
    signed in to, the email signature, and the data drive that stays
    encrypted after the reinstall because nobody kept its recovery key.

    This lists what to carry over, checks what a reinstall depends on, and
    copies the user folders to another drive with robocopy. The readers are
    read only. The copy writes only to the destination chosen; the driver
    export runs elevated through the per-action UAC path.
#>

<#
.SYNOPSIS
    The network drives this account maps, and the commands that map them again.

.OUTPUTS
    PSCustomObject[] with Letter, Path and Command.
#>
function Get-TkMappedDrive {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(Get-ChildItem -LiteralPath 'HKCU:\Network' -ErrorAction SilentlyContinue | ForEach-Object {
        $path = [string] (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).RemotePath
        if ($path) {
            [pscustomobject] @{
                Letter  = ('{0}:' -f $_.PSChildName.ToUpperInvariant())
                Path    = $path
                Command = ('net use {0}: "{1}" /persistent:yes' -f $_.PSChildName.ToUpperInvariant(), $path)
            }
        }
    })
}

<#
.SYNOPSIS
    Sorts the printers into those to add again and those Windows brings back.

.DESCRIPTION
    Pure. Virtual printers (PDF, XPS, OneNote, fax) are left out. A shared
    printer is added again from its \\server\name; a printer on a TCP/IP port
    from its address; one found by discovery (WSD) appears again by itself on
    the same network.

.PARAMETER Printer
    Objects with Name, Type, PortName and DriverName, as Get-Printer returns them.

.OUTPUTS
    PSCustomObject[] with Name, Kind, Where and Command.
#>
function ConvertTo-TkPrinterCarryOver {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Printer = @()
    )

    $virtual = 'PDF|XPS|OneNote|Fax|Send To|Microsoft Shared Fax'

    $rows = foreach ($item in ($Printer | Where-Object { $_ })) {

        $name = [string] $item.Name
        $port = [string] $item.PortName

        if ($name -match $virtual -or [string] $item.DriverName -match $virtual -or $port -match '^(PORTPROMPT:|nul:|FILE:|XPSPort:|SHRFAX:)$') {
            continue
        }

        if ([string] $item.Type -eq 'Connection' -or $name -like '\\*') {
            [pscustomobject] @{ Name = $name; Kind = 'Shared'; Where = $name; Command = ('Add-Printer -ConnectionName "{0}"' -f $name) }
        }
        elseif ($port -match '^WSD') {
            [pscustomobject] @{ Name = $name; Kind = 'Discovered (WSD)'; Where = 'found on the network'; Command = '' }
        }
        elseif ($port -match '(?<ip>\d{1,3}(\.\d{1,3}){3})') {
            [pscustomobject] @{ Name = $name; Kind = 'Network (TCP/IP)'; Where = $Matches['ip']; Command = ('Add-PrinterPort -Name "IP_{0}" -PrinterHostAddress "{0}"  # then add the printer with its driver' -f $Matches['ip']) }
        }
        elseif ($port -match '^USB') {
            [pscustomobject] @{ Name = $name; Kind = 'USB'; Where = $port; Command = '' }
        }
        else {
            [pscustomobject] @{ Name = $name; Kind = 'Other'; Where = $port; Command = '' }
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Finds the Outlook data files, browser bookmarks and signatures of this account.

.OUTPUTS
    PSCustomObject with Pst, Browsers and Signatures.
#>
function Get-TkMigrationUserData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $documents = [Environment]::GetFolderPath('MyDocuments')

    # PST files hold mail that exists nowhere else; OST files are a cache of
    # the mailbox and are rebuilt, so they are not listed.
    $pst = @(foreach ($folder in @((Join-Path $documents 'Outlook Files'), (Join-Path $env:LOCALAPPDATA 'Microsoft\Outlook'))) {
        Get-ChildItem -LiteralPath $folder -Filter '*.pst' -File -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject] @{ Path = $_.FullName; Length = $_.Length } }
    })

    $browsers = New-Object System.Collections.Generic.List[object]
    foreach ($browser in @(
        @{ Name = 'Microsoft Edge'; Root = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'); File = 'Bookmarks' }
        @{ Name = 'Google Chrome';  Root = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'); File = 'Bookmarks' }
        @{ Name = 'Brave';          Root = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'); File = 'Bookmarks' }
        @{ Name = 'Mozilla Firefox'; Root = (Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'); File = 'places.sqlite' }
    )) {
        $profiles = @(Get-ChildItem -LiteralPath $browser.Root -Directory -ErrorAction SilentlyContinue |
                      Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $browser.File) })
        if ($profiles.Count -gt 0) {
            $browsers.Add([pscustomobject] @{ Name = $browser.Name; Profiles = $profiles.Count })
        }
    }

    $signatures = @(Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Microsoft\Signatures') -Filter '*.htm' -File -ErrorAction SilentlyContinue).Count

    return [pscustomobject] @{ Pst = $pst; Browsers = @($browsers.ToArray()); Signatures = $signatures }
}

<#
.SYNOPSIS
    The folders OneDrive keeps, so they are not copied twice.

.OUTPUTS
    System.String[]
#>
function Get-TkOneDriveRoot {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $roots = @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer)
    $roots += @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue |
                ForEach-Object { [string] (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).UserFolder })

    return @($roots | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } | Select-Object -Unique)
}

<#
.SYNOPSIS
    Says whether a path lies inside one of some folders.

.OUTPUTS
    System.Boolean
#>
function Test-TkPathUnder {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Path,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Root = @()
    )

    $full = $Path.TrimEnd('\') + '\'

    foreach ($folder in ($Root | Where-Object { $_ })) {
        if ($full.StartsWith($folder.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Measures the personal folders and says which ones OneDrive already keeps.

.OUTPUTS
    PSCustomObject[] with Name, Path, Bytes, Files, InOneDrive, CloudOnly and Truncated.
#>
function Get-TkUserFolderSize {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $oneDrive = Get-TkOneDriveRoot

    return @(foreach ($folder in (Get-TkPersonalFolder)) {
        $inventory = Get-TkFileInventory -Path $folder -MinimumSize 0 -ExcludeFolder @() -MaxFiles 300000

        [pscustomobject] @{
            Name       = Split-Path -Path $folder -Leaf
            Path       = $folder
            Bytes      = [long] (@($inventory.Files) | Measure-Object -Property Length -Sum).Sum
            Files      = @($inventory.Files).Count
            InOneDrive = (Test-TkPathUnder -Path $folder -Root $oneDrive)
            CloudOnly  = $inventory.Skipped
            Truncated  = $inventory.Truncated
        }
    })
}

<#
.SYNOPSIS
    Names the state the Shell reports for a BitLocker volume.

.DESCRIPTION
    Pure. System.Volume.BitLockerProtection is readable without administrator
    rights, unlike Get-BitLockerVolume. Protected means a key is needed to
    open the drive elsewhere: a drive waiting for activation, or suspended,
    keeps its key in clear on the volume and opens anywhere.

.OUTPUTS
    PSCustomObject with State, Encrypted and Protected.
#>
function ConvertFrom-TkBitLockerShellState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    # State, encrypted, protected.
    $known = @{
        1 = @('on', $true, $true); 2 = @('off', $false, $false); 3 = @('encrypting', $true, $true); 4 = @('decrypting', $true, $true)
        5 = @('suspended', $true, $false); 6 = @('on, locked', $true, $true); 8 = @('encrypted, waiting for activation', $true, $false)
    }

    $number = 0
    if ($null -ne $Value -and [int]::TryParse([string] $Value, [ref] $number) -and $known.ContainsKey($number)) {
        return [pscustomobject] @{ State = $known[$number][0]; Encrypted = $known[$number][1]; Protected = $known[$number][2] }
    }

    return [pscustomobject] @{ State = 'unknown'; Encrypted = $false; Protected = $false }
}

<#
.SYNOPSIS
    Reads what a reinstall depends on: activation and BitLocker.

.OUTPUTS
    PSCustomObject with Activation (Status, Channel, FirmwareKey) and Volumes
    (Drive, State, Encrypted, Protected, System).
#>
function Get-TkReinstallState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $activation = [pscustomobject] @{ Status = -1; Channel = ''; FirmwareKey = $false }

    try {
        $product = Get-CimInstance -ClassName SoftwareLicensingProduct `
                                   -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" `
                                   -Property 'LicenseStatus', 'ProductKeyChannel' -ErrorAction Stop | Select-Object -First 1
        # Only whether the firmware holds a key: the key itself is never read out.
        $service = Get-CimInstance -ClassName SoftwareLicensingService -Property 'OA3xOriginalProductKeyDescription' -ErrorAction Stop

        $activation = [pscustomobject] @{
            Status      = $(if ($product) { [int] $product.LicenseStatus } else { -1 })
            Channel     = [string] $(if ($product) { $product.ProductKeyChannel } else { '' })
            FirmwareKey = [bool] $service.OA3xOriginalProductKeyDescription
        }
    }
    catch {
        $null = $_
    }

    $volumes = New-Object System.Collections.Generic.List[object]

    try {
        $shell  = New-Object -ComObject Shell.Application
        $system = $env:SystemDrive.TrimEnd('\').ToUpperInvariant()

        foreach ($drive in ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -in @('Fixed', 'Removable') -and $_.IsReady })) {
            $letter = $drive.Name.TrimEnd('\').ToUpperInvariant()
            $item   = $shell.NameSpace(17).ParseName($letter)
            $state  = ConvertFrom-TkBitLockerShellState -Value $(if ($item) { $item.ExtendedProperty('System.Volume.BitLockerProtection') } else { $null })

            $volumes.Add([pscustomobject] @{ Drive = $letter; State = $state.State; Encrypted = $state.Encrypted; Protected = $state.Protected; System = ($letter -eq $system) })
        }
    }
    catch {
        $null = $_
    }

    return [pscustomobject] @{ Activation = $activation; Volumes = @($volumes.ToArray()) }
}

<#
.SYNOPSIS
    Judges what a reinstall depends on.

.DESCRIPTION
    Pure. The risk is not the system drive, which a reinstall wipes anyway,
    but a data drive encrypted with BitLocker: after the reinstall it no
    longer unlocks by itself, and without its recovery key its data is gone.

.OUTPUTS
    PSCustomObject[] with Severity, Heading, Detail and Note.
#>
function ConvertTo-TkReinstallFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $State
    )

    $finding = { param($severity, $heading, $detail, $note) [pscustomobject] @{ Severity = $severity; Heading = $heading; Detail = $detail; Note = $note } }

    $activation = $State.Activation
    $channel    = [string] $activation.Channel

    if ($activation.Status -ne 1) {
        & $finding 'Warning' 'Windows is not activated' $channel 'Sort the activation out before the reinstall: afterwards there is nothing left to compare it with.'
    }
    elseif ($channel -match '^OEM' -or $activation.FirmwareKey) {
        & $finding 'Pass' 'Windows reactivates by itself' $channel 'The licence is tied to this hardware (a key in the firmware, or a digital licence): reinstalling the same edition activates again with no key to type.'
    }
    elseif ($channel -match '^Retail') {
        & $finding 'Info' 'A retail licence' $channel 'It reactivates from the digital licence if it is linked to a Microsoft account (Settings, Activation); otherwise keep the product key that came with it before reinstalling.'
    }
    elseif ($channel -match '^Volume') {
        & $finding 'Info' 'An organisation licence' $channel 'KMS or a MAK key activates it: the organisation reactivates it after a reinstall.'
    }
    else {
        & $finding 'Info' 'Activation channel unknown' $channel ''
    }

    foreach ($volume in @($State.Volumes)) {

        if (-not $volume.Encrypted) {
            continue
        }

        if ($volume.System) {
            & $finding 'Info' ('{0} (Windows) is encrypted with BitLocker' -f $volume.Drive) $volume.State 'A reinstall wipes it. Copy what lives on it first; the new installation encrypts again on its own.'
        }
        elseif (-not $volume.Protected) {
            & $finding 'Info' ('{0} is encrypted, but its key is kept in clear' -f $volume.Drive) $volume.State 'BitLocker protection is not on, so the drive opens anywhere, after a reinstall too. Once protection is turned on, its recovery key has to be kept.'
        }
        else {
            & $finding 'Warning' ('{0} is encrypted with BitLocker: keep its recovery key' -f $volume.Drive) $volume.State ('After a reinstall this drive no longer unlocks by itself. Without its 48-digit recovery key its data is lost. Find it at aka.ms/myrecoverykey (Microsoft account), in Entra ID or Active Directory, or save it now with: manage-bde -protectors -get {0}' -f $volume.Drive)
        }
    }
}

<#
.SYNOPSIS
    Gathers everything the carry-over list needs.

.OUTPUTS
    PSCustomObject with Drives, Printers, UserData and Folders.
#>
function Get-TkMigrationInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    [void] (Import-TkCommandModule -Command @('Get-Printer'))

    $printers = @(try { Get-Printer -ErrorAction Stop | Select-Object Name, Type, PortName, DriverName } catch { @() })

    return [pscustomobject] @{
        Drives   = @(Get-TkMappedDrive)
        Printers = @(ConvertTo-TkPrinterCarryOver -Printer $printers)
        UserData = Get-TkMigrationUserData
        Folders  = @(Get-TkUserFolderSize)
    }
}

<#
.SYNOPSIS
    Checks a destination for the copy or the driver export.

.DESCRIPTION
    Pure apart from the drive check. An absolute path on a drive that exists,
    not inside a folder being copied, not in Windows or Program Files.

.OUTPUTS
    System.String, empty when the destination is acceptable, else the reason.
#>
function Test-TkMigrationDestination {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Destination,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Source = @(),
        [Parameter()] [scriptblock] $DriveExists = { param($root) Test-Path -LiteralPath $root }
    )

    $path = $Destination.Trim().TrimEnd('\')

    if (-not $path) {
        return 'Choose where to copy to, ideally an external drive.'
    }

    if ($path -notmatch '^[A-Za-z]:(\\|$)' -and $path -notmatch '^\\\\[^\\]+\\[^\\]+') {
        return 'The destination must be a full path, such as E:\Backup or \\server\share\backup.'
    }

    if ($path -match '[<>"|?*]' -or $path -match '\\\.\.(\\|$)') {
        return 'The destination holds characters a folder name cannot have.'
    }

    $system = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ }
    if (Test-TkPathUnder -Path $path -Root $system) {
        return 'Not inside Windows, Program Files or ProgramData.'
    }

    foreach ($folder in ($Source | Where-Object { $_ })) {
        if (Test-TkPathUnder -Path $path -Root @($folder)) {
            return ('The destination is inside {0}, which is copied: it would copy into itself.' -f $folder)
        }
    }

    $root = if ($path -match '^[A-Za-z]:') { $path.Substring(0, 2) + '\' } else { $path }
    if (-not (& $DriveExists $root)) {
        return ('{0} is not available.' -f $root)
    }

    return ''
}

<#
.SYNOPSIS
    Plans the copy of the personal folders: where each goes, and which are skipped.

.DESCRIPTION
    Pure. A folder OneDrive already keeps is skipped: copying it would
    download every file kept online only, and it comes back by signing in to
    OneDrive on the new machine.

.PARAMETER Folder
    From Get-TkUserFolderSize: Name, Path, Bytes, InOneDrive.

.PARAMETER Destination
    The destination root.

.PARAMETER Label
    The name of the folder created under the destination.

.OUTPUTS
    PSCustomObject[] with Name, Source, Target, Bytes and Skip.
#>
function New-TkMigrationCopyPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Folder = @(),
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [string] $Label
    )

    $root = Join-Path -Path $Destination.Trim().TrimEnd('\') -ChildPath $Label

    return @(foreach ($item in ($Folder | Where-Object { $_ })) {
        [pscustomobject] @{
            Name   = $item.Name
            Source = $item.Path
            Target = Join-Path -Path $root -ChildPath $item.Name
            Bytes  = [long] $item.Bytes
            Skip   = $(if ($item.InOneDrive) { 'kept by OneDrive' } else { '' })
        }
    })
}

<#
.SYNOPSIS
    Reads what a robocopy exit code means.

.OUTPUTS
    PSCustomObject with Ok and Text.
#>
function ConvertFrom-TkRobocopyExit {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $Code
    )

    if ($Code -ge 8) {
        return [pscustomobject] @{ Ok = $false; Text = ('some files could not be copied (robocopy code {0}); the log says which' -f $Code) }
    }

    $text = if ($Code -eq 0) { 'nothing new to copy' } elseif ($Code -band 1) { 'copied' } else { 'done' }
    if ($Code -band 2) { $text += ', extra files at the destination left alone' }
    if ($Code -band 4) { $text += ', some files differ and were checked' }

    return [pscustomobject] @{ Ok = $true; Text = $text }
}

<#
.SYNOPSIS
    Copies the planned folders with robocopy.

.DESCRIPTION
    Writes only under the destination. Attributes and timestamps are kept,
    junctions are not followed, a file that fails is retried once, and files
    kept online only (the offline attribute) are left out so nothing is
    downloaded. A log per folder is written beside the copy.

.OUTPUTS
    PSCustomObject[] with Name, Ok, Text and Log.
#>
function Copy-TkMigrationFolder {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [object[]] $Plan
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($step in ($Plan | Where-Object { $_ -and -not $_.Skip })) {

        if (-not $PSCmdlet.ShouldProcess($step.Target, ('Copy {0}' -f $step.Source))) {
            continue
        }

        $log = '{0}.log' -f $step.Target

        try {
            New-Item -ItemType Directory -Path (Split-Path -Path $step.Target -Parent) -Force -ErrorAction Stop | Out-Null

            $run = Invoke-TkProcess -FilePath 'robocopy.exe' -TimeoutSeconds 0 -ArgumentList @(
                $step.Source, $step.Target, '/E', '/COPY:DAT', '/DCOPY:DAT', '/R:1', '/W:1', '/XJ', '/XA:O', '/MT:8', '/NP', ('/LOG:{0}' -f $log)
            )

            $exit = ConvertFrom-TkRobocopyExit -Code $run.ExitCode
            $results.Add([pscustomobject] @{ Name = $step.Name; Ok = $exit.Ok; Text = $exit.Text; Log = $log })
        }
        catch {
            $results.Add([pscustomobject] @{ Name = $step.Name; Ok = $false; Text = $_.Exception.Message; Log = '' })
        }
    }

    Add-TkJournalEntry -Name 'User folders copied' -Category 'Migration' -Detail (
        (@($results | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Text })) -join '; '
    )

    return @($results.ToArray())
}

<#
.SYNOPSIS
    Exports the third-party drivers of this machine to a folder.

.DESCRIPTION
    Needs administrator rights: it runs in the elevated worker, which checks
    the destination again. pnputil copies each driver package with its INF,
    ready to be added back with pnputil /add-driver <folder>\*.inf /subdirs.

.OUTPUTS
    PSCustomObject with Ok, Message and Count.
#>
function Export-TkDriverPackage {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Destination
    )

    $problem = Test-TkMigrationDestination -Destination $Destination

    if ($problem) {
        return [pscustomobject] @{ Ok = $false; Message = $problem; Count = 0 }
    }

    $target = Join-Path -Path $Destination.Trim().TrimEnd('\') -ChildPath ('Drivers-{0}-{1:yyyyMMdd}' -f $env:COMPUTERNAME, (Get-Date))

    if (-not $PSCmdlet.ShouldProcess($target, 'Export the drivers')) {
        return [pscustomobject] @{ Ok = $false; Message = 'Cancelled.'; Count = 0 }
    }

    $stopwatch = Start-TkOperation -Name 'Export drivers' -Category 'Migration'

    try {
        New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null
        $run   = Invoke-TkProcess -FilePath (Join-Path $env:SystemRoot 'System32\pnputil.exe') -ArgumentList @('/export-driver', '*', $target) -TimeoutSeconds 900
        $count = @(Get-ChildItem -LiteralPath $target -Directory -ErrorAction SilentlyContinue).Count
        $ok    = ($run.ExitCode -eq 0 -and $count -gt 0)
        $text  = if ($ok) { '{0} driver package(s) exported to {1}. Add them back with: pnputil /add-driver "{1}\*.inf" /subdirs /install' -f $count, $target }
                 else { 'The driver export failed (pnputil code {0}).' -f $run.ExitCode }
    }
    catch {
        $ok    = $false
        $count = 0
        $text  = 'The driver export failed: {0}' -f $_.Exception.Message
    }

    Stop-TkOperation -Name 'Export drivers' -Stopwatch $stopwatch -Category 'Migration' -Success $ok

    return [pscustomobject] @{ Ok = $ok; Message = $text; Count = $count }
}

<#
.SYNOPSIS
    The catalogue applications installed on this machine, for a configuration profile.

.PARAMETER InstalledId
    The winget identifiers installed, from Get-TkInstalledPackageId.

.OUTPUTS
    System.String[] of catalogue application ids.
#>
function Get-TkInstalledCatalogApplication {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $InstalledId = @()
    )

    $installed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $InstalledId) { if ($id) { [void] $installed.Add($id) } }

    return @((Import-TkCatalog -Name 'applications').applications |
             Where-Object { $installed.Contains([string] $_.packageId) } |
             ForEach-Object { [string] $_.id })
}
