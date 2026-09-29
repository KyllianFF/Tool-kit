<#
    Toolkit - Features / System: Windows 11 readiness and hardware renewal

    Two questions a machine raises once Windows 10 is out of support: can it
    run Windows 11, and should it be kept, upgraded or replaced.

    The facts are read without administrator rights, and without depending on
    the display language: the firmware type and Secure Boot state from the
    registry, the TPM from its Plug and Play hardware identifier (MSFT0101 is
    a TPM 2.0, PNP0C31 a TPM 1.2), the processor from its CPUID family, model
    and stepping, judged against data/processor-support.json.

    The judgement is a pure function of those facts, so it is tested with
    machines described by hand. What a setting in the firmware can change is
    told apart from what only new hardware can: a TPM switched off or a legacy
    BIOS boot is a setting, an unsupported processor is a replacement.
#>

<#
.SYNOPSIS
    Judges a processor against the Windows 11 processor rules.

.DESCRIPTION
    Pure. The rules come from data/processor-support.json and are read in
    order; the first one that matches decides. A rule may name the vendor
    (a regular expression on the CPUID vendor), the processor name (a
    regular expression), the family (exact or up to familyMax), the models
    (a list, or up to modelMax) and the steppings.

.PARAMETER Identifier
    The CPUID identifier as Windows records it, such as
    "Intel64 Family 6 Model 142 Stepping 10".

.OUTPUTS
    PSCustomObject with Verdict (Supported, NotSupported or Unknown), Reason,
    Family, Model and Stepping.
#>
function Get-TkProcessorSupport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Vendor = '',
        [Parameter()] [AllowEmptyString()] [string] $Identifier = '',
        [Parameter()] [AllowEmptyString()] [string] $Name = '',
        [Parameter()] [AllowNull()] [object[]] $Rules = $null
    )

    if ($null -eq $Rules) {
        $catalog = Import-TkCatalog -Name 'processor-support'
        $Rules   = if ($catalog) { @($catalog.rules) } else { @() }
    }

    $family = $null; $model = $null; $stepping = $null

    if ($Identifier -match 'Family\s+(\d+)\s+Model\s+(\d+)\s+Stepping\s+(\d+)') {
        $family   = [int] $Matches[1]
        $model    = [int] $Matches[2]
        $stepping = [int] $Matches[3]
    }

    foreach ($rule in @($Rules)) {

        if ($rule.vendor -and $Vendor -notmatch [string] $rule.vendor) { continue }
        if ($rule.name -and $Name -notmatch [string] $rule.name) { continue }

        # A rule on the CPUID numbers never matches a processor they could not be read for.
        $needsNumbers = ($null -ne $rule.family -or $null -ne $rule.familyMax -or $null -ne $rule.models -or $null -ne $rule.modelMax -or $null -ne $rule.steppings)
        if ($needsNumbers -and $null -eq $family) { continue }

        if ($null -ne $rule.family    -and $family -ne [int] $rule.family) { continue }
        if ($null -ne $rule.familyMax -and $family -gt [int] $rule.familyMax) { continue }
        if ($null -ne $rule.models    -and @($rule.models | ForEach-Object { [int] $_ }) -notcontains $model) { continue }
        if ($null -ne $rule.modelMax  -and $model -gt [int] $rule.modelMax) { continue }
        if ($null -ne $rule.steppings -and @($rule.steppings | ForEach-Object { [int] $_ }) -notcontains $stepping) { continue }

        return [pscustomobject] @{ Verdict = [string] $rule.verdict; Reason = [string] $rule.reason; Family = $family; Model = $model; Stepping = $stepping }
    }

    return [pscustomobject] @{
        Verdict  = 'Unknown'
        Reason   = 'A processor the rules do not know.'
        Family   = $family
        Model    = $model
        Stepping = $stepping
    }
}

<#
.SYNOPSIS
    Reads what the Windows 11 requirements and the renewal advice are judged on.

.DESCRIPTION
    Standard user rights are enough for every value. What cannot be read is
    left empty, and the judgement says so rather than guessing.

.OUTPUTS
    PSCustomObject with Processor, MemoryBytes, Is64BitOs, Firmware,
    SecureBoot, Tpm, SystemDisk, FirmwareDate, BatteryHealth and Os.
#>
function Get-TkHardwareFacts {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # --- Processor -----------------------------------------------------------
    $central = $null
    try { $central = Get-ItemProperty -LiteralPath 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop } catch { $null = $_ }

    $processors = @(Get-TkCimInstanceSafe -ClassName 'Win32_Processor' -All)
    $first      = $processors | Select-Object -First 1
    $name       = if ($central -and $central.ProcessorNameString) { ([string] $central.ProcessorNameString).Trim() } elseif ($first) { ([string] $first.Name).Trim() } else { '' }

    $processor = [pscustomobject] @{
        Name         = $name
        Vendor       = $(if ($central) { [string] $central.VendorIdentifier } elseif ($first) { [string] $first.Manufacturer } else { '' })
        Identifier   = $(if ($central) { [string] $central.Identifier } elseif ($first) { [string] $first.Caption } else { '' })
        Cores        = [int] (@($processors | ForEach-Object { [int] $_.NumberOfCores }) | Measure-Object -Sum).Sum
        ClockMHz     = $(if ($first) { [int] $first.MaxClockSpeed } else { 0 })
        Architecture = $(if ($first) { switch ([int] $first.Architecture) { 0 { 'x86' } 9 { 'x64' } 12 { 'ARM64' } default { 'Other' } } } else { '' })
    }

    # --- Memory: the modules, not what Windows keeps back from them -----------
    $memory = [long] (@(Get-TkCimInstanceSafe -ClassName 'Win32_PhysicalMemory' -All) | ForEach-Object { [long] $_.Capacity } | Measure-Object -Sum).Sum

    if ($memory -le 0) {
        $computer = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'
        $memory   = if ($computer) { [long] $computer.TotalPhysicalMemory } else { 0 }
    }

    # --- Firmware, Secure Boot and TPM ---------------------------------------
    $firmware = [string] $env:firmware_type

    if (-not $firmware) {
        try {
            $type     = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction Stop).PEFirmwareType
            $firmware = switch ([int] $type) { 1 { 'Legacy' } 2 { 'UEFI' } default { '' } }
        }
        catch { $null = $_ }
    }

    $secureBoot = $null
    try {
        $secureBoot = [int] (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop).UEFISecureBootEnabled -eq 1
    }
    catch { $null = $_ }

    # A TPM switched off in the firmware is not enumerated at all.
    $tpm = ''
    try {
        $ids = @(Get-CimInstance -ClassName 'Win32_PnPEntity' -Filter "PNPClass = 'SecurityDevices'" -ErrorAction Stop | ForEach-Object { @($_.HardwareID) })
        $tpm = if ($ids -match 'MSFT0101') { '2.0' } elseif ($ids -match 'PNP0C31') { '1.2' } else { 'None' }
    }
    catch { $null = $_ }

    # --- System disk -----------------------------------------------------------
    $letter    = ([string] $env:SystemDrive).TrimEnd(':')
    $partition = Get-TkCimInstanceSafe -ClassName 'MSFT_Partition' -Namespace 'Root\Microsoft\Windows\Storage' -Filter ("DriveLetter = '{0}'" -f $letter)
    $disk      = $null
    $physical  = $null
    $wear      = $null

    if ($partition) {
        $disk     = Get-TkCimInstanceSafe -ClassName 'MSFT_Disk' -Namespace 'Root\Microsoft\Windows\Storage' -Filter ('Number = {0}' -f [int] $partition.DiskNumber)
        $physical = Get-TkCimInstanceSafe -ClassName 'MSFT_PhysicalDisk' -Namespace 'Root\Microsoft\Windows\Storage' -Filter ("DeviceId = '{0}'" -f [int] $partition.DiskNumber)

        # The endurance counters answer an elevated session only.
        if ($physical) {
            try {
                $counter = Get-CimInstance -Namespace 'Root\Microsoft\Windows\Storage' -ClassName 'MSFT_StorageReliabilityCounter' -ErrorAction Stop |
                           Where-Object { $_.DeviceId -eq $physical.DeviceId } | Select-Object -First 1
                if ($counter -and $null -ne $counter.Wear) { $wear = [int] $counter.Wear }
            }
            catch { $null = $_ }
        }
    }

    $systemDisk = [pscustomobject] @{
        SizeBytes      = $(if ($disk) { [long] $disk.Size } else { [long] 0 })
        PartitionStyle = $(if ($disk) { switch ([int] $disk.PartitionStyle) { 1 { 'MBR' } 2 { 'GPT' } default { '' } } } else { '' })
        MediaType      = $(if ($physical) { ConvertFrom-TkMediaType -Code $physical.MediaType } else { '' })
        BusType        = $(if ($physical) { ConvertFrom-TkBusType -Code $physical.BusType } else { '' })
        Health         = $(if ($physical) { ConvertFrom-TkDiskHealth -Value $physical.HealthStatus } else { '' })
        WearPercent    = $wear
    }

    # --- Age, battery and Windows ----------------------------------------------
    $bios         = Get-TkCimInstanceSafe -ClassName 'Win32_BIOS'
    $firmwareDate = if ($bios -and $bios.ReleaseDate -is [datetime]) { $bios.ReleaseDate } else { $null }

    $batteryHealth = $null
    try {
        $battery = @(Get-TkBatteryState) | Where-Object { $_ -and $_.Health } | Select-Object -First 1
        if ($battery -and [string] $battery.Health -match '(\d+)') { $batteryHealth = [int] $Matches[1] }
    }
    catch { $null = $_ }

    $os = Get-TkCimInstanceSafe -ClassName 'Win32_OperatingSystem'

    return [pscustomobject] @{
        Processor     = $processor
        MemoryBytes   = $memory
        Is64BitOs     = [Environment]::Is64BitOperatingSystem
        Firmware      = $firmware
        SecureBoot    = $secureBoot
        Tpm           = $tpm
        SystemDisk    = $systemDisk
        FirmwareDate  = $firmwareDate
        BatteryHealth = $batteryHealth
        Os            = [pscustomobject] @{
            Caption = $(if ($os) { [string] $os.Caption } else { '' })
            Build   = $(if ($os) { [int] $os.BuildNumber } else { 0 })
            Server  = $(if ($os) { [int] $os.ProductType -ne 1 } else { $false })
        }
    }
}

<#
.SYNOPSIS
    Judges the facts: can this machine run Windows 11, and should it be kept, upgraded or replaced.

.DESCRIPTION
    Pure. Each check is a row with its area, what was measured, what is
    required, a severity and what to do. A row a firmware setting or a part
    can fix is marked Fixable; an unsupported processor is not, and makes
    the renewal verdict a replacement.

.PARAMETER Now
    Today, a parameter so tests do not depend on the clock.

.OUTPUTS
    PSCustomObject with Windows11 (Verdict, Summary), Renewal (Verdict,
    Summary, Actions), AgeYears, Processor and Checks.
#>
function Get-TkHardwareReadiness {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Facts,

        [Parameter()]
        [AllowNull()]
        [object[]] $Rules = $null,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $checks = New-Object System.Collections.Generic.List[object]
    $row = {
        param($area, $check, $value, $requirement, $severity, $fix, $fixable)
        $checks.Add([pscustomobject] @{
            Area = $area; Check = $check; Value = [string] $value; Requirement = $requirement
            Severity = $severity; Fix = $fix; Fixable = [bool] $fixable
        })
    }

    $gb        = { param($bytes) [math]::Round([double] $bytes / 1GB, 1) }

    # The same text on every machine, whatever its regional settings.
    $text      = { param($format, [object[]] $values) [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, $format, $values) }
    $cpu       = $Facts.Processor
    $support   = Get-TkProcessorSupport -Vendor $cpu.Vendor -Identifier $cpu.Identifier -Name $cpu.Name -Rules $Rules
    $server    = [bool] $Facts.Os.Server
    $onEleven  = [int] $Facts.Os.Build -ge 22000
    $memoryGb  = & $gb $Facts.MemoryBytes
    $diskGb    = & $gb $Facts.SystemDisk.SizeBytes
    $w11       = 'Windows 11'
    $renew     = 'Renewal'

    # --- Windows 11 ---------------------------------------------------------------
    switch ($support.Verdict) {
        'Supported'    { & $row $w11 'Processor' $cpu.Name 'On the list of supported processors' 'Pass' '' $false }
        'NotSupported' { & $row $w11 'Processor' $cpu.Name 'On the list of supported processors' 'Fail' ('{0} No setting changes it: Windows 11 on this machine means a newer processor, so new hardware.' -f $support.Reason) $false }
        default        { & $row $w11 'Processor' $cpu.Name 'On the list of supported processors' 'Warning' ('{0} Check the model against Microsoft''s lists of supported processors.' -f $support.Reason) $false }
    }

    $basics = @()
    if ($cpu.Architecture -and $cpu.Architecture -notin @('x64', 'ARM64')) { $basics += 'not 64-bit' }
    if ($cpu.Cores -gt 0 -and $cpu.Cores -lt 2) { $basics += 'a single core' }
    if ($cpu.ClockMHz -gt 0 -and $cpu.ClockMHz -lt 1000) { $basics += 'under 1 GHz' }

    & $row $w11 'Processor cores and speed' (& $text '{0} cores, {1:0.0} GHz, {2}' @($cpu.Cores, ($cpu.ClockMHz / 1000), $cpu.Architecture)) '2 cores, 1 GHz, 64-bit' `
        $(if ($basics.Count -gt 0) { 'Fail' } else { 'Pass' }) $(if ($basics.Count -gt 0) { 'The processor is {0}.' -f ($basics -join ', ') } else { '' }) $false

    & $row $w11 'Memory' (& $text '{0} GB' @($memoryGb)) '4 GB' $(if ($memoryGb -ge 3.9) { 'Pass' } else { 'Fail' }) `
        $(if ($memoryGb -lt 3.9) { 'Add memory, if the machine has a free slot and its memory is not soldered.' } else { '' }) $true

    & $row $w11 'System disk' (& $text '{0} GB' @($diskGb)) '64 GB' $(if ($Facts.SystemDisk.SizeBytes -le 0) { 'Warning' } elseif ($diskGb -ge 64) { 'Pass' } else { 'Fail' }) `
        $(if ($Facts.SystemDisk.SizeBytes -gt 0 -and $diskGb -lt 64) { 'Put in a larger SSD.' } elseif ($Facts.SystemDisk.SizeBytes -le 0) { 'The system disk could not be read.' } else { '' }) $true

    switch ([string] $Facts.Firmware) {
        'UEFI'   { & $row $w11 'Firmware' 'UEFI' 'UEFI' 'Pass' '' $true }
        'Legacy' { & $row $w11 'Firmware' 'Legacy BIOS (CSM)' 'UEFI' 'Fail' $(if ($Facts.SystemDisk.PartitionStyle -eq 'MBR') { 'Convert the system disk to GPT with mbr2gpt /convert /allowFullOS, then switch the firmware from legacy (CSM) to UEFI. Suspend BitLocker first.' } else { 'Switch the firmware from legacy (CSM) to UEFI.' }) $true }
        default  { & $row $w11 'Firmware' 'Not known' 'UEFI' 'Warning' 'The firmware type could not be read.' $true }
    }

    if ($Facts.Firmware -eq 'UEFI') {
        if ($Facts.SecureBoot -eq $true) { & $row $w11 'Secure Boot' 'On' 'Capable' 'Pass' '' $true }
        elseif ($Facts.SecureBoot -eq $false) { & $row $w11 'Secure Boot' 'Off' 'Capable' 'Warning' 'The firmware can do it: Windows 11 asks for a Secure Boot capable PC, and it protects the start of Windows. Turn it on in the firmware settings.' $true }
        else { & $row $w11 'Secure Boot' 'Not known' 'Capable' 'Warning' 'The Secure Boot state could not be read.' $true }
    }
    elseif ($Facts.Firmware -eq 'Legacy') {
        & $row $w11 'Secure Boot' 'Not available in legacy mode' 'Capable' 'Fail' 'Comes with UEFI: turn it on once the firmware boots in UEFI.' $true
    }

    switch ([string] $Facts.Tpm) {
        '2.0'   { & $row $w11 'TPM' '2.0' '2.0' 'Pass' '' $true }
        '1.2'   { & $row $w11 'TPM' '1.2' '2.0' 'Fail' 'Windows 11 needs a TPM 2.0. Some models switch to 2.0 with a firmware update from their maker.' $true }
        'None'  { & $row $w11 'TPM' 'None turned on' '2.0' 'Fail' 'Processors from 2016 on carry a TPM in their firmware (Intel PTT, AMD fTPM), often off: turn it on in the firmware settings.' $true }
        default { & $row $w11 'TPM' 'Not known' '2.0' 'Warning' 'The TPM could not be read.' $true }
    }

    if (-not $Facts.Is64BitOs) {
        & $row $w11 'Windows' '32-bit' '64-bit' 'Warning' 'Windows 11 is 64-bit only: it goes on through a clean installation, not an upgrade.' $true
    }

    # --- Renewal -------------------------------------------------------------------------
    $age = $null
    if ($Facts.FirmwareDate -is [datetime]) {
        $age = [math]::Max(0, [math]::Floor(($Now - $Facts.FirmwareDate).TotalDays / 365.25))
        & $row $renew 'Age' ('at least {0} year(s), firmware of {1:yyyy-MM}' -f $age, $Facts.FirmwareDate) '' 'Info' 'A lower bound: a firmware update makes its date later than the machine.' $false
    }

    if ($memoryGb -ge 3.9 -and $memoryGb -lt 7.5) {
        & $row $renew 'Memory' (& $text '{0} GB' @($memoryGb)) '8 GB, 16 GB for heavier work' 'Warning' 'Add memory: 8 GB is the least for Windows 11 with a browser and Office open.' $true
    }

    $media = [string] $Facts.SystemDisk.MediaType
    if ($media -eq 'HDD') {
        & $row $renew 'System disk type' 'Hard disk' 'SSD' 'Warning' 'Put an SSD in place of the hard disk: the largest speed gain for the money.' $true
    }

    $health = [string] $Facts.SystemDisk.Health
    if ($health -and $health -ne 'Healthy') {
        & $row $renew 'System disk health' $health 'Healthy' 'Fail' 'Back up now and replace the system disk: it reports itself as failing.' $true
    }

    if ($null -ne $Facts.SystemDisk.WearPercent) {
        $wear = [int] $Facts.SystemDisk.WearPercent
        & $row $renew 'SSD wear' ('{0} % of its rated endurance used' -f $wear) 'Under 80 %' $(if ($wear -ge 95) { 'Fail' } elseif ($wear -ge 80) { 'Warning' } else { 'Pass' }) `
            $(if ($wear -ge 80) { 'Replace the SSD before it reaches its rated endurance.' } else { '' }) $true
    }

    if ($null -ne $Facts.BatteryHealth) {
        $battery = [int] $Facts.BatteryHealth
        & $row $renew 'Battery' ('{0} % of its design capacity' -f $battery) 'Over 60 %' $(if ($battery -lt 40) { 'Fail' } elseif ($battery -lt 60) { 'Warning' } else { 'Pass' }) `
            $(if ($battery -lt 60) { 'Replace the battery.' } else { '' }) $true
    }

    # --- Verdicts ------------------------------------------------------------------------
    $elevenRows = @($checks | Where-Object { $_.Area -eq $w11 })
    $blocked    = @($elevenRows | Where-Object { $_.Severity -eq 'Fail' -and -not $_.Fixable })
    $toFix      = @($elevenRows | Where-Object { $_.Severity -eq 'Fail' -and $_.Fixable })
    $unsure     = @($elevenRows | Where-Object { $_.Severity -eq 'Warning' })

    $elevenVerdict = if ($server) { 'NotApplicable' }
                     elseif ($blocked.Count -gt 0) { 'NotReady' }
                     elseif ($toFix.Count -gt 0) { 'ReadyAfterChanges' }
                     elseif (@($unsure | Where-Object { $_.Check -eq 'Processor' }).Count -gt 0) { 'Check' }
                     else { 'Ready' }

    $elevenSummary = switch ($elevenVerdict) {
        'NotApplicable'     { 'Windows Server: the Windows 11 requirements do not apply.' }
        'NotReady'          { 'Windows 11 is out of reach: {0}.' -f ((@($blocked | ForEach-Object { $_.Check.ToLowerInvariant() })) -join ', ') }
        'ReadyAfterChanges' { 'Windows 11 can run here once these are changed: {0}.' -f ((@($toFix | ForEach-Object { $_.Check.ToLowerInvariant() })) -join ', ') }
        'Check'             { 'Everything else meets Windows 11; the processor is one the rules do not know.' }
        default             { 'This machine meets the Windows 11 requirements.' }
    }

    if (-not $server -and $onEleven -and $elevenVerdict -in @('NotReady', 'ReadyAfterChanges')) {
        $elevenSummary += ' It runs Windows 11 all the same, on hardware Microsoft does not guarantee updates for.'
    }
    elseif (-not $server -and -not $onEleven -and [int] $Facts.Os.Build -gt 0) {
        $elevenSummary += ' Windows 10 has had no security update since 14 October 2025, outside the paid Extended Security Updates.'
    }

    $actions = @($checks | Where-Object { $_.Fix -and $_.Fixable -and $_.Severity -in @('Fail', 'Warning') } | ForEach-Object { $_.Fix } | Select-Object -Unique)

    $renewalVerdict = if ($support.Verdict -eq 'NotSupported' -and -not $server) { 'Replace' }
                      elseif ($actions.Count -gt 0) { 'Upgrade' }
                      else { 'Keep' }

    $renewalSummary = switch ($renewalVerdict) {
        'Replace' { 'Replace it: its processor cannot run Windows 11, and no part or setting changes that.' }
        'Upgrade' { 'Keep it, with the changes below.' }
        default   { 'Keep it: nothing to change.' }
    }

    if ($null -ne $age) {
        $renewalSummary += ' The firmware is dated {0:yyyy-MM}, so the machine is at least {1} year(s) old.' -f $Facts.FirmwareDate, $age
    }

    return [pscustomobject] @{
        Windows11 = [pscustomobject] @{ Verdict = $elevenVerdict; Summary = $elevenSummary }
        Renewal   = [pscustomobject] @{ Verdict = $renewalVerdict; Summary = $renewalSummary; Actions = $actions }
        AgeYears  = $age
        Processor = $support
        Checks    = @($checks.ToArray())
    }
}

<#
.SYNOPSIS
    Reads this machine and judges it: Windows 11 readiness and renewal.

.OUTPUTS
    PSCustomObject from Get-TkHardwareReadiness, with Facts.
#>
function Get-TkHardwareReadinessReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $facts  = Get-TkHardwareFacts
    $result = Get-TkHardwareReadiness -Facts $facts

    $result | Add-Member -NotePropertyName 'Facts' -NotePropertyValue $facts
    return $result
}
