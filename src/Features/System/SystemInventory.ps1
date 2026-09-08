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
            Health     = switch ([int] $disk.HealthStatus) {
                             0 { 'Healthy' ; break }
                             1 { 'Warning' ; break }
                             2 { 'Unhealthy' ; break }
                             default { 'Unknown' }
                         }
        }
    }

    # --- Logical volumes --------------------------------------------------
    $volumes = @()

    foreach ($volume in (Get-TkCimInstanceSafe -ClassName 'Win32_LogicalDisk' -Filter 'DriveType=3' -All)) {

        $usedPercent = 0

        if ($volume.Size -gt 0) {
            $usedPercent = [math]::Round((($volume.Size - $volume.FreeSpace) / $volume.Size) * 100, 1)
        }

        $volumes += [pscustomobject]@{
            Drive       = $volume.DeviceID
            Label       = Format-TkValue $volume.VolumeName -Placeholder '(no label)'
            FileSystem  = Format-TkValue $volume.FileSystem
            Size        = Format-TkBytes -Bytes $volume.Size
            Free        = Format-TkBytes -Bytes $volume.FreeSpace
            UsedPercent = $usedPercent
        }
    }

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

    # --- Secure Boot ------------------------------------------------------
    # Throws on legacy BIOS machines instead of returning false, so the
    # exception is the answer.
    $secureBoot = 'Not supported (legacy BIOS)'

    try {
        $secureBoot = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' }
    }
    catch {
        # Access denied when not elevated; keep the default message otherwise.
        if ($_.Exception.Message -match 'denied|privilege') {
            $secureBoot = 'Unknown (needs elevation)'
        }
    }

    # --- TPM --------------------------------------------------------------
    $tpmText = 'Not available'

    $tpm = Get-TkCimInstanceSafe -ClassName 'Win32_Tpm' -Namespace 'Root\CIMV2\Security\MicrosoftTpm'

    if ($tpm) {
        $state   = if ($tpm.IsEnabled_InitialValue) { 'enabled' } else { 'disabled' }
        $tpmText = 'Version {0} ({1})' -f (Format-TkValue $tpm.SpecVersion), $state
    }

    # --- BitLocker --------------------------------------------------------
    $bitLocker = 'Unknown'

    try {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $bitLocker = '{0} ({1}%)' -f $volume.ProtectionStatus, $volume.EncryptionPercentage
    }
    catch {
        $bitLocker = 'Not available (needs elevation or unsupported edition)'
    }

    # --- Defender ---------------------------------------------------------
    $defender = 'Unknown'

    try {
        $status   = Get-MpComputerStatus -ErrorAction Stop
        $defender = 'Real-time: {0} | Signatures: {1}' -f
            $status.RealTimeProtectionEnabled, $status.AntivirusSignatureVersion
    }
    catch {
        $defender = 'Not available'
    }

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
            return , @($result)
        }

        return ($result | Select-Object -First 1)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Inventory' -Message (
            'Class {0} unavailable: {1}' -f $ClassName, $_.Exception.Message
        )

        if ($All) {
            return , @()
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
        $product = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
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

    switch ([int] $Code) {
        3 { return 'HDD' }
        4 { return 'SSD' }
        5 { return 'SCM' }
        default { return 'Unspecified' }
    }
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

    $key = [int] $Code

    if ($map.ContainsKey($key)) {
        return $map[$key]
    }

    return 'Unknown'
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
