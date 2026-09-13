<#
    Toolkit - Features / System inventory

    Read only hardware and operating system facts. Everything here works as a
    standard user, which is deliberate: the first thing a technician does on
    an unknown machine is identify it, and that must not require a UAC prompt.
#>

<#
.SYNOPSIS
    Collects the identity of the machine.

.DESCRIPTION
    Pulls manufacturer, model, serial number, asset tag, BIOS version and
    chassis type from SMBIOS through CIM. Values that OEMs leave unprogrammed
    are normalised to a single placeholder by Format-TkValue.

.OUTPUTS
    PSCustomObject
#>
function Get-TkMachineIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $computer  = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'
    $bios      = Get-TkCimInstanceSafe -ClassName 'Win32_BIOS'
    $board     = Get-TkCimInstanceSafe -ClassName 'Win32_BaseBoard'
    $enclosure = Get-TkCimInstanceSafe -ClassName 'Win32_SystemEnclosure'
    $product   = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystemProduct'

    # Chassis type tells a laptop from a desktop from a virtual machine, which
    # changes which advice and which vendor page is relevant.
    $chassis = 'Unknown'

    if ($enclosure -and $enclosure.ChassisTypes) {
        $chassis = ConvertFrom-TkChassisType -Code ([int] ($enclosure.ChassisTypes | Select-Object -First 1))
    }

    return [pscustomobject]@{
        ComputerName     = $env:COMPUTERNAME
        Manufacturer     = Format-TkValue $computer.Manufacturer
        Model            = Format-TkValue $computer.Model
        SystemFamily     = Format-TkValue $computer.SystemFamily
        SerialNumber     = Format-TkValue $bios.SerialNumber
        AssetTag         = Format-TkValue $enclosure.SMBIOSAssetTag
        Uuid             = Format-TkValue $product.UUID
        BaseBoard        = Format-TkValue $board.Product
        BaseBoardSerial  = Format-TkValue $board.SerialNumber
        BiosVendor       = Format-TkValue $bios.Manufacturer
        BiosVersion      = Format-TkValue $bios.SMBIOSBIOSVersion
        BiosReleaseDate  = Format-TkBiosDate -Value $bios.ReleaseDate
        ChassisType      = $chassis
        IsVirtual        = Test-TkIsVirtualMachine -ComputerSystem $computer
        Domain           = Format-TkValue $computer.Domain
        PartOfDomain     = [bool] $computer.PartOfDomain
        LoggedOnUser     = Format-TkValue $computer.UserName
    }
}

<#
.SYNOPSIS
    Collects operating system facts.

.OUTPUTS
    PSCustomObject
#>
function Get-TkOperatingSystemInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $os = Get-TkCimInstanceSafe -ClassName 'Win32_OperatingSystem'

    # DisplayVersion (23H2, 24H2) only exists in the registry, not in CIM.
    $registryPath   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVersion = Get-TkRegistryValue -Path $registryPath -Name 'DisplayVersion'
    $ubr            = Get-TkRegistryValue -Path $registryPath -Name 'UBR'

    $build = $os.BuildNumber

    if ($ubr) {
        $build = '{0}.{1}' -f $os.BuildNumber, $ubr
    }

    $uptime = $null

    if ($os.LastBootUpTime) {
        $uptime = (Get-Date) - $os.LastBootUpTime
    }

    return [pscustomobject]@{
        Caption         = Format-TkValue $os.Caption
        DisplayVersion  = Format-TkValue $displayVersion
        Build           = Format-TkValue $build
        Architecture    = Format-TkValue $os.OSArchitecture
        InstallDate     = $os.InstallDate
        LastBoot        = $os.LastBootUpTime
        UptimeText      = Format-TkTimeSpan -Value $uptime
        Locale          = Format-TkValue (Get-Culture).Name
        TimeZone        = Format-TkValue (Get-TimeZone -ErrorAction SilentlyContinue).Id
        Activation      = Get-TkActivationStatus
        PowerShell      = $PSVersionTable.PSVersion.ToString()
    }
}

<#
.SYNOPSIS
    Collects processor, memory, storage and graphics facts.

.OUTPUTS
    PSCustomObject
#>
function Get-TkHardwareInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $cpu      = Get-TkCimInstanceSafe -ClassName 'Win32_Processor'
    $computer = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'

    # --- Memory modules ---------------------------------------------------
    $memoryModules = @()

    foreach ($stick in (Get-TkCimInstanceSafe -ClassName 'Win32_PhysicalMemory' -All)) {

        $memoryModules += [pscustomobject]@{
            Slot         = Format-TkValue $stick.DeviceLocator
            Capacity     = Format-TkBytes -Bytes $stick.Capacity
            SpeedMHz     = $stick.ConfiguredClockSpeed
            Manufacturer = Format-TkValue $stick.Manufacturer
            PartNumber   = Format-TkValue ($stick.PartNumber)
        }
    }

    # --- Physical disks ---------------------------------------------------
    $disks = @()

    foreach ($disk in (Get-TkCimInstanceSafe -ClassName 'MSFT_PhysicalDisk' -Namespace 'Root\Microsoft\Windows\Storage' -All)) {

        $disks += [pscustomobject]@{
            Name       = Format-TkValue $disk.FriendlyName
            Size       = Format-TkBytes -Bytes $disk.Size
            MediaType  = ConvertFrom-TkMediaType -Code $disk.MediaType
            BusType    = ConvertFrom-TkBusType   -Code $disk.BusType
            Health     = ConvertFrom-TkDiskHealth -Value $disk.HealthStatus
        }
    }

    # --- Logical volumes --------------------------------------------------
    # The columns the reports have always printed, from the one volume reader.
    $volumes = @(Get-TkVolumeUsage | Select-Object -Property Drive, Label, FileSystem, Size, Free, UsedPercent)

    # --- Graphics ---------------------------------------------------------
    $graphics = @()

    foreach ($gpu in (Get-TkCimInstanceSafe -ClassName 'Win32_VideoController' -All)) {

        $graphics += [pscustomobject]@{
            Name          = Format-TkValue $gpu.Name
            DriverVersion = Format-TkValue $gpu.DriverVersion
            DriverDate    = Format-TkBiosDate -Value $gpu.DriverDate
            Resolution    = if ($gpu.CurrentHorizontalResolution) {
                                '{0} x {1}' -f $gpu.CurrentHorizontalResolution, $gpu.CurrentVerticalResolution
                            }
                            else { 'Not available' }
        }
    }

    return [pscustomobject]@{
        CpuName        = Format-TkValue ($cpu | Select-Object -First 1).Name
        CpuCores       = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
        CpuThreads     = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        CpuMaxClockMHz = ($cpu | Select-Object -First 1).MaxClockSpeed
        TotalMemory    = Format-TkBytes -Bytes $computer.TotalPhysicalMemory
        MemoryModules  = $memoryModules
        Disks          = $disks
        Volumes        = $volumes
        Graphics       = $graphics
    }
}

<#
.SYNOPSIS
    Judges how full a volume is.

.DESCRIPTION
    The one place these thresholds live. The storage diagnostic, the disk bar
    on the System page and the storage tile on the Dashboard all ask here, so
    the three can never disagree about the same drive.

    Below twelve percent free Windows starts to run short of room for updates,
    the page file and restore points; below five, those start to fail.

.PARAMETER FreePercent
    Free space as a percentage of the volume.

.OUTPUTS
    PSCustomObject with Severity and Note.
#>
function Get-TkFreeSpaceAssessment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [double] $FreePercent
    )

    if ($FreePercent -lt 5) {
        return [pscustomobject] @{ Severity = 'Fail'; Note = 'Critically full. Updates and restore points will fail.' }
    }

    if ($FreePercent -lt 12) {
        return [pscustomobject] @{ Severity = 'Warning'; Note = 'Low. Windows needs headroom for servicing.' }
    }

    return [pscustomobject] @{ Severity = 'Pass'; Note = '' }
}

<#
.SYNOPSIS
    Turns logical disk records into volume usage, with a judgement on each.

.DESCRIPTION
    Kept apart from the CIM query, so the arithmetic, a volume that reports no
    size and the thresholds can all be tested without a disk.

.PARAMETER LogicalDisk
    Objects shaped like Win32_LogicalDisk: DeviceID, VolumeName, FileSystem,
    Size and FreeSpace.

.OUTPUTS
    PSCustomObject[]
#>
function ConvertTo-TkVolumeUsage {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $LogicalDisk
    )

    $result = @()

    foreach ($disk in $LogicalDisk) {

        $size = [double] $disk.Size
        $free = [double] $disk.FreeSpace

        $usedPercent = 0.0
        $freePercent = 0.0

        if ($size -gt 0) {
            $usedPercent = [math]::Round((($size - $free) / $size) * 100, 1)
            $freePercent = [math]::Round(($free / $size) * 100, 1)
        }

        # A volume with no size is a card reader with nothing in it, not a
        # full disk. Judging it would raise an alarm about an empty slot.
        $assessment = if ($size -gt 0) { Get-TkFreeSpaceAssessment -FreePercent $freePercent }
                      else { [pscustomobject] @{ Severity = 'Info'; Note = 'The volume reports no size.' } }

        $result += [pscustomobject] @{
            Drive       = [string] $disk.DeviceID
            Label       = Format-TkValue $disk.VolumeName -Placeholder '(no label)'
            FileSystem  = Format-TkValue $disk.FileSystem
            Size        = Format-TkBytes -Bytes $size
            Free        = Format-TkBytes -Bytes $free
            UsedPercent = $usedPercent
            FreePercent = $freePercent
            Severity    = $assessment.Severity
            Note        = $assessment.Note
        }
    }

    return $result
}

<#
.SYNOPSIS
    Orders volumes for display: the system drive first, then by letter.

.DESCRIPTION
    The system drive is the one that stops Windows when it fills, so it leads;
    the others follow in the order drive letters are read.

.PARAMETER Volume
    Output of Get-TkVolumeUsage.

.PARAMETER SystemDrive
    The drive to put first.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkVolumeDisplayOrder {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]] $Volume,

        [Parameter()]
        [string] $SystemDrive = $env:SystemDrive
    )

    return @($Volume |
             Where-Object { $null -ne $_ } |
             Sort-Object -Property @{ Expression = { if ([string] $_.Drive -eq $SystemDrive) { 0 } else { 1 } } },
                                   @{ Expression = { [string] $_.Drive } })
}

<#
.SYNOPSIS
    Reads the fixed volumes of this machine with their usage.

.OUTPUTS
    PSCustomObject[], as built by ConvertTo-TkVolumeUsage.
#>
function Get-TkVolumeUsage {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return (ConvertTo-TkVolumeUsage -LogicalDisk @(
        Get-TkCimInstanceSafe -ClassName 'Win32_LogicalDisk' -Filter 'DriveType=3' -All
    ))
}

<#
.SYNOPSIS
    Collects the platform security posture.

.DESCRIPTION
    Secure Boot, TPM, BitLocker, Defender and firewall state in one call.
    This is the block a technician screenshots when a machine fails a
    compliance check, so it stays together rather than spread over pages.

.OUTPUTS
    PSCustomObject
#>
function Get-TkPlatformSecurityInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Firewall, Defender and BitLocker modules, loaded one worker at a time.
    # See Import-TkCommandModule.
    [void] (Import-TkCommandModule -Command @('Get-NetFirewallProfile', 'Get-MpComputerStatus', 'Get-BitLockerVolume'))

    # --- Secure Boot ------------------------------------------------------
    # Throws on legacy BIOS machines instead of returning false, so the
    # exception is the answer.
    $secureBoot = 'Not supported (legacy BIOS)'

    try {
        $secureBoot = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' }
    }
    catch {
        # Unelevated, the cmdlet is refused before it can say anything about
        # the firmware. That used to be recognised by the word "denied" in the
        # message, which a French Windows words "Acces refuse", so every UEFI
        # machine read as legacy BIOS. Elevation is the question to ask.
        if (-not (Test-TkIsElevated)) {
            $secureBoot = 'Unknown (needs elevation)'
        }
    }

    # --- TPM --------------------------------------------------------------
    # The TPM class is only readable elevated. Without it, "not available"
    # would claim the chip is missing when it has simply not been asked.
    $tpmText = if (Test-TkIsElevated) { 'Not available' } else { 'Unknown (needs elevation)' }

    # Not asked at all unelevated. Refused, the query still waits about five
    # seconds before it gives up, and that wait, twice with BitLocker below,
    # made this the slowest card on the System page for an answer known in
    # advance.
    $tpm = if (Test-TkIsElevated) {
               Get-TkCimInstanceSafe -ClassName 'Win32_Tpm' -Namespace 'Root\CIMV2\Security\MicrosoftTpm'
           }

    if ($tpm) {
        $state   = if ($tpm.IsEnabled_InitialValue) { 'enabled' } else { 'disabled' }
        $tpmText = 'Version {0} ({1})' -f (Format-TkValue $tpm.SpecVersion), $state
    }

    # --- BitLocker --------------------------------------------------------
    # Every fixed drive, judged the way the audit judges it, so this page and
    # the audit cannot give two answers about the same machine.
    # Not asked unelevated either: Get-BitLockerVolume is refused after the same
    # five second wait as the TPM.
    $bitLocker = 'Unknown (needs elevation)'

    if (Test-TkIsElevated) {

        $bitLocker = 'Not available (unsupported edition)'

        try {
            $bitLockerVolumes = @(Get-BitLockerVolume -ErrorAction Stop)

            $removable = @(Get-TkCimInstanceSafe -ClassName 'Win32_LogicalDisk' -Filter 'DriveType = 2' -All |
                           ForEach-Object { [string] $_.DeviceID })

            $bitLocker = (ConvertTo-TkBitLockerFinding -Volume $bitLockerVolumes -RemovableMountPoint $removable).Measured
        }
        catch {
            $null = $_
        }
    }

    # --- Defender and the antivirus in charge ------------------------------
    # Defender's own state alone reads as "off" on a machine another antivirus
    # protects, which is the misreading the audit was rebuilt to stop. So the
    # product actually protecting the machine is reported first, and Defender's
    # mode beside it explains the rest.
    $defender        = 'Not available'
    $defenderRunning = $false

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        $mode = if ($status.PSObject.Properties['AMRunningMode']) { [string] $status.AMRunningMode } else { 'Mode unknown' }

        $defenderRunning = [bool] $status.RealTimeProtectionEnabled
        $defender        = '{0}, real time protection {1}' -f $mode, $(if ($defenderRunning) { 'on' } else { 'off' })
    }
    catch {
        $null = $_
    }

    $running = @(Get-TkAntivirusProduct | Where-Object { $_.RealTimeEnabled -eq $true } | ForEach-Object { $_.Name })

    # Server editions have no Security Center to list products, so Defender
    # speaks for itself there.
    $antivirus = if ($running.Count -gt 0) { $running -join ', ' }
                 elseif ($defenderRunning) { 'Microsoft Defender' }
                 else { 'None running' }

    # --- Firewall ---------------------------------------------------------
    $firewall = 'Unknown'

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $firewall = ($profiles | ForEach-Object {
            '{0}: {1}' -f $_.Name, $(if ($_.Enabled) { 'on' } else { 'OFF' })
        }) -join ' | '
    }
    catch {
        $firewall = 'Not available'
    }

    return [pscustomobject]@{
        SecureBoot = $secureBoot
        Tpm        = $tpmText
        BitLocker  = $bitLocker
        Antivirus  = $antivirus
        Defender   = $defender
        Firewall   = $firewall
    }
}

<#
.SYNOPSIS
    Wraps Get-CimInstance so a missing class never breaks a whole page.

.DESCRIPTION
    Several classes used here are optional (TPM, storage namespace) or absent
    inside virtual machines. Returning $null instead of throwing lets callers
    build a partial report, which is far more useful than an empty one.

.PARAMETER All
    Returns every instance instead of only the first one.

.OUTPUTS
    CimInstance, an array of CimInstance, or $null.
#>
function Get-TkCimInstanceSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ClassName,

        [Parameter()]
        [string] $Namespace = 'Root\CIMV2',

        [Parameter()]
        [string] $Filter,

        [Parameter()]
        [switch] $All
    )

    try {
        $parameters = @{
            ClassName   = $ClassName
            Namespace   = $Namespace
            ErrorAction = 'Stop'
        }

        if ($Filter) {
            $parameters['Filter'] = $Filter
        }

        $result = Get-CimInstance @parameters

        if ($All) {
            return @($result)
        }

        return ($result | Select-Object -First 1)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Inventory' -Message (
            'Class {0} unavailable: {1}' -f $ClassName, $_.Exception.Message
        )

        if ($All) {
            return @()
        }

        return $null
    }
}

<#
.SYNOPSIS
    Reports the Windows activation state.

.OUTPUTS
    System.String
#>
function Get-TkActivationStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        # Filtered by WMI, not in PowerShell. Unfiltered, every licensing
        # product on the machine, several hundred of them, is computed and sent
        # across: ten seconds on its own. When the Dashboard and the System
        # page asked at the same time, the second query failed outright, which
        # is how one page read "Activated" while the other read "Not
        # available". Filtered, it answers in about a tenth of a second.
        $product = Get-CimInstance -ClassName SoftwareLicensingProduct `
                                   -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" `
                                   -Property 'LicenseStatus' -ErrorAction Stop |
                   Select-Object -First 1

        if (-not $product) {
            return 'Unknown'
        }

        switch ([int] $product.LicenseStatus) {
            0 { return 'Unlicensed' }
            1 { return 'Activated' }
            2 { return 'Grace period' }
            3 { return 'Out of tolerance grace period' }
            4 { return 'Non genuine grace period' }
            5 { return 'Notification (not activated)' }
            6 { return 'Extended grace' }
            default { return 'Unknown' }
        }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Inventory' -Message (
            'The activation state could not be read: {0}' -f $_.Exception.Message
        )

        return 'Not available'
    }
}

<#
.SYNOPSIS
    Detects whether the machine is a virtual one.

.OUTPUTS
    System.Boolean
#>
function Test-TkIsVirtualMachine {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        $ComputerSystem
    )

    if (-not $ComputerSystem) {
        $ComputerSystem = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'
    }

    $signatures = @('VMware', 'VirtualBox', 'Virtual Machine', 'KVM', 'QEMU', 'Xen', 'Parallels', 'Hyper-V')
    $haystack   = '{0} {1}' -f $ComputerSystem.Manufacturer, $ComputerSystem.Model

    foreach ($signature in $signatures) {

        if ($haystack -like ('*{0}*' -f $signature)) {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Translates an SMBIOS chassis type code into a readable label.

.OUTPUTS
    System.String
#>
function ConvertFrom-TkChassisType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int] $Code
    )

    $map = @{
        1  = 'Other'         ; 2  = 'Unknown'        ; 3  = 'Desktop'
        4  = 'Low profile'   ; 5  = 'Pizza box'      ; 6  = 'Mini tower'
        7  = 'Tower'         ; 8  = 'Portable'       ; 9  = 'Laptop'
        10 = 'Notebook'      ; 11 = 'Handheld'       ; 12 = 'Docking station'
        13 = 'All in one'    ; 14 = 'Sub notebook'   ; 15 = 'Space saving'
        16 = 'Lunch box'     ; 17 = 'Main chassis'   ; 18 = 'Expansion chassis'
        21 = 'Peripheral'    ; 23 = 'Rack mount'     ; 24 = 'Sealed case PC'
        30 = 'Tablet'        ; 31 = 'Convertible'    ; 32 = 'Detachable'
    }

    if ($map.ContainsKey($Code)) {
        return $map[$Code]
    }

    return ('Type {0}' -f $Code)
}

<#
.SYNOPSIS
    Turns a physical disk health status into its name.

.DESCRIPTION
    The status arrives as a number or as a name, depending on how the Storage
    module loaded in the runspace that read it; see ConvertFrom-TkCimEnum.
    Cast to an integer, the name "Healthy" threw, and the storage reading
    failed as a whole.

.PARAMETER Value
    HealthStatus of an MSFT_PhysicalDisk.

.OUTPUTS
    System.String: Healthy, Warning, Unhealthy or Unknown.
#>
function ConvertFrom-TkDiskHealth {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    $name = ConvertFrom-TkCimEnum -Value $Value -Name @{ 0 = 'Healthy'; 1 = 'Warning'; 2 = 'Unhealthy'; 5 = 'Unknown' }

    if ($name -in @('Healthy', 'Warning', 'Unhealthy')) {
        return $name
    }

    return 'Unknown'
}

<#
.SYNOPSIS
    Translates an MSFT_PhysicalDisk media type code.

.OUTPUTS
    System.String
#>
function ConvertFrom-TkMediaType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Code
    )

    # By number or by name; see ConvertFrom-TkCimEnum.
    $name = ConvertFrom-TkCimEnum -Value $Code -Name @{ 0 = 'Unspecified'; 3 = 'HDD'; 4 = 'SSD'; 5 = 'SCM' }

    if ($name -in @('HDD', 'SSD', 'SCM')) {
        return $name
    }

    return 'Unspecified'
}

<#
.SYNOPSIS
    Translates an MSFT_PhysicalDisk bus type code.

.OUTPUTS
    System.String
#>
function ConvertFrom-TkBusType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Code
    )

    $map = @{
        1  = 'SCSI' ; 2  = 'ATAPI' ; 3  = 'ATA'  ; 4  = '1394'
        5  = 'SSA'  ; 6  = 'Fibre' ; 7  = 'USB'  ; 8  = 'RAID'
        9  = 'iSCSI'; 10 = 'SAS'   ; 11 = 'SATA' ; 12 = 'SD'
        13 = 'MMC'  ; 17 = 'NVMe'
    }

    # By number or by name; see ConvertFrom-TkCimEnum. A number this table has
    # no name for is a bus it does not know.
    $name = ConvertFrom-TkCimEnum -Value $Code -Name $map

    if ([string]::IsNullOrWhiteSpace($name) -or $name -match '^\d+$') {
        return 'Unknown'
    }

    return $name
}

<#
.SYNOPSIS
    Formats a CIM date value as a short date.

.OUTPUTS
    System.String
#>
function Format-TkBiosDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 'Not available'
    }

    try {
        return ([datetime] $Value).ToString('yyyy-MM-dd')
    }
    catch {
        return 'Not available'
    }
}

<#
.SYNOPSIS
    Formats a timespan as days, hours and minutes.

.OUTPUTS
    System.String
#>
function Format-TkTimeSpan {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 'Not available'
    }

    return '{0}d {1}h {2}m' -f $Value.Days, $Value.Hours, $Value.Minutes
}
