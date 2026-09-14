<#
    Toolkit - Features / Attack surface controls

    What an attacker who already runs code on the machine can reach next: a
    signed but vulnerable driver to get into the kernel, memory integrity
    that would stop it, Defender exclusions wide enough to hide a payload in,
    a print spooler running for no printer, NTLM sessions without NTLMv2
    protection, and domain passwords cached for offline sign-in.

    Like the rest of the audit, each control reads the machine and hands the
    values to a ConvertTo function that judges them, so the judgement is
    tested without the machine.
#>

# ---------------------------------------------------------------------------
# Kernel
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads what Device Guard says about memory integrity.

.DESCRIPTION
    In the service lists of Win32_DeviceGuard, 2 is memory integrity
    (hypervisor-protected code integrity). In the available properties, 1 is
    hypervisor support, without which memory integrity cannot run at all.

.OUTPUTS
    PSCustomObject with MemoryIntegrityRunning, MemoryIntegrityConfigured and
    HypervisorAvailable, or $null when Device Guard does not answer.
#>
function Get-TkDeviceGuardState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        $guard = Get-CimInstance -ClassName 'Win32_DeviceGuard' -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop |
                 Select-Object -First 1
    }
    catch {
        return $null
    }

    if (-not $guard) {
        return $null
    }

    return [pscustomobject] @{
        MemoryIntegrityRunning    = (@($guard.SecurityServicesRunning) -contains 2)
        MemoryIntegrityConfigured = (@($guard.SecurityServicesConfigured) -contains 2)
        HypervisorAvailable       = (@($guard.AvailableSecurityProperties) -contains 1)
    }
}

<#
.SYNOPSIS
    Judges the Microsoft vulnerable driver blocklist.

.DESCRIPTION
    The blocklist stops signed drivers Microsoft knows to be exploitable from
    loading. Attackers bring exactly those drivers to reach the kernel and
    switch security products off from there. Memory integrity enforces the
    blocklist whatever the switch says.

    Since Windows 11 22H2 the blocklist is on by default, but Microsoft
    describes that default for clean installs and devices it chooses, so a
    missing value is not read as on.

.PARAMETER Value
    VulnerableDriverBlocklistEnable, or $null when absent.

.PARAMETER Build
    The Windows build number.

.PARAMETER MemoryIntegrityRunning
    Whether memory integrity runs.
#>
function ConvertTo-TkDriverBlocklistFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowNull()] $Value,
        [Parameter()] [int] $Build = [Environment]::OSVersion.Version.Build,
        [Parameter()] [bool] $MemoryIntegrityRunning = $false
    )

    if ($MemoryIntegrityRunning) {

        return New-TkAuditFinding -Id 'DRV-001' -Name 'Vulnerable driver blocklist' -Category 'Platform' `
            -Status 'Pass' -Measured 'Enforced by memory integrity' `
            -Detail 'Memory integrity applies the blocklist whatever its switch says, so a known vulnerable driver cannot load.'
    }

    if ([string] $Value -eq '1') {

        return New-TkAuditFinding -Id 'DRV-001' -Name 'Vulnerable driver blocklist' -Category 'Platform' `
            -Status 'Pass' -Measured 'On' `
            -Detail 'Windows refuses to load the signed drivers Microsoft knows attackers use to reach the kernel.'
    }

    if ([string] $Value -eq '0') {

        return New-TkAuditFinding -Id 'DRV-001' -Name 'Vulnerable driver blocklist' -Category 'Platform' `
            -Status 'Fail' -Measured 'Turned off' `
            -Detail 'The switch was turned off, usually to load a driver the blocklist refuses: an overclocking or hardware monitoring tool, or a game anti-cheat. Attackers bring the same drivers to turn security products off from the kernel.' `
            -Recommendation 'Turn the Microsoft Vulnerable Driver Blocklist back on in Windows Security, Device security, Core isolation, and replace the tool that needed it with an updated version. It applies after a restart.'
    }

    if ($Build -ge 22621) {

        return New-TkAuditFinding -Id 'DRV-001' -Name 'Vulnerable driver blocklist' -Category 'Platform' `
            -Status 'Warning' -Measured 'Not recorded' `
            -Detail 'Windows 11 turns the blocklist on by default on the devices it chooses, and nothing on this one records that choice.' `
            -Recommendation 'Check the switch in Windows Security, Device security, Core isolation. Turning it on records it.'
    }

    return New-TkAuditFinding -Id 'DRV-001' -Name 'Vulnerable driver blocklist' -Category 'Platform' `
        -Status 'Warning' -Measured 'Not set' `
        -Detail 'Before Windows 11 22H2, the blocklist is only applied with memory integrity, Smart App Control, S mode or an App Control policy.' `
        -Recommendation 'Turn on memory integrity where the hardware allows it, which applies the blocklist.'
}

<#
.SYNOPSIS
    Checks the Microsoft vulnerable driver blocklist.
#>
function Test-TkAuditDriverBlocklist {
    [CmdletBinding()]
    param()

    $value = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable'
    $guard = Get-TkDeviceGuardState

    return ConvertTo-TkDriverBlocklistFinding -Value $value -MemoryIntegrityRunning ([bool] ($guard -and $guard.MemoryIntegrityRunning))
}

<#
.SYNOPSIS
    Judges memory integrity (hypervisor-protected code integrity).

.PARAMETER State
    Output of Get-TkDeviceGuardState, or $null.
#>
function ConvertTo-TkMemoryIntegrityFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        $State
    )

    if (-not $State) {

        return New-TkAuditFinding -Id 'DRV-002' -Name 'Memory integrity' -Category 'Platform' `
            -Status 'NotAssessed' -Measured 'Not readable' `
            -Detail 'Device Guard did not answer.'
    }

    if ($State.MemoryIntegrityRunning) {

        return New-TkAuditFinding -Id 'DRV-002' -Name 'Memory integrity' -Category 'Platform' `
            -Status 'Pass' -Measured 'Running' `
            -Detail 'The hypervisor checks kernel code, so malware with administrator rights cannot load an unsigned or tampered driver, and the vulnerable driver blocklist is enforced.'
    }

    # A requirement the hardware cannot meet is reported, not marked down.
    if (-not $State.HypervisorAvailable) {

        return New-TkAuditFinding -Id 'DRV-002' -Name 'Memory integrity' -Category 'Platform' `
            -Status 'Info' -Measured 'Not supported here' -Applicable $false `
            -Detail 'Memory integrity needs virtualization support turned on in the firmware; a virtual machine also needs nested virtualization.'
    }

    if ($State.MemoryIntegrityConfigured) {

        return New-TkAuditFinding -Id 'DRV-002' -Name 'Memory integrity' -Category 'Platform' `
            -Status 'Warning' -Measured 'Turned on, not running yet' `
            -Detail 'It starts at the next restart. If it is still off after one, a driver Windows finds incompatible is stopping it.' `
            -Recommendation 'Restart, then open Core isolation in Windows Security: it names the drivers that prevent it.'
    }

    return New-TkAuditFinding -Id 'DRV-002' -Name 'Memory integrity' -Category 'Platform' `
        -Status 'Warning' -Measured 'Off' `
        -Detail 'Without it, malware running as administrator can load a driver that switches security products off from the kernel.' `
        -Recommendation 'Turn on Memory integrity in Windows Security, Device security, Core isolation. Windows lists the drivers that prevent it; update or remove them first.'
}

<#
.SYNOPSIS
    Checks whether memory integrity runs.
#>
function Test-TkMemoryIntegrity {
    [CmdletBinding()]
    param()

    return ConvertTo-TkMemoryIntegrityFinding -State (Get-TkDeviceGuardState)
}

# ---------------------------------------------------------------------------
# Antivirus exclusions
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Picks out the Defender exclusions wide enough to hide a payload in.

.DESCRIPTION
    An exclusion that names one application folder is a support decision.
    One that names a drive, a temporary or download folder, a user profile, a
    program that runs scripts, or a file type that runs code turns the
    antivirus off for everything that lands there. Attackers add exactly
    those, and so do installers that want fewer support calls.

.PARAMETER Path
    ExclusionPath entries, environment variables allowed.

.PARAMETER Process
    ExclusionProcess entries.

.PARAMETER Extension
    ExclusionExtension entries, with or without the dot.

.OUTPUTS
    PSCustomObject[] with Kind, Value and Reason.
#>
function Get-TkBroadDefenderExclusion {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $Path = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Process = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Extension = @()
    )

    $rows = @()

    foreach ($item in @($Path | Where-Object { $_ })) {

        $expanded = [Environment]::ExpandEnvironmentVariables([string] $item).Trim().TrimEnd('\')

        # The first matching rule names the reason, so the order goes from the
        # most specific folder to the widest.
        $reason = switch -Regex ($expanded) {
            '^\*?$|^[A-Za-z]:(\\\*)?$'                                      { 'a whole drive'; break }
            '\\(Temp|Tmp)(\\\*)?$'                                           { 'a temporary folder, where downloads and installers unpack'; break }
            '\\AppData(\\(Local|LocalLow|Roaming))?(\\\*)?$'                 { 'application data, where most malware installs for one user'; break }
            '\\(Downloads|Desktop)(\\\*)?$'                                  { 'a folder files arrive in from the web and mail'; break }
            '^[A-Za-z]:\\Users(\\[^\\]+)?(\\\*)?$'                           { 'user profiles'; break }
            '^[A-Za-z]:\\(Windows|Windows\\System32|ProgramData|Program Files|Program Files \(x86\))(\\\*)?$' { 'a system folder'; break }
            '^\\\\[^\\]+(\\[^\\]+)?(\\\*)?$'                                 { 'a whole server or share'; break }
        }

        if ($reason) {
            $rows += [pscustomobject] @{ Kind = 'Path'; Value = [string] $item; Reason = $reason }
        }
    }

    $hosts = @(
        'powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
        'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'explorer.exe', 'svchost.exe',
        'python.exe', 'pythonw.exe', 'node.exe', 'java.exe', 'javaw.exe', '*'
    )

    foreach ($item in @($Process | Where-Object { $_ })) {

        $leaf = (([string] $item).Trim() -split '[\\/]')[-1].ToLowerInvariant()

        if ($leaf -in $hosts) {
            $rows += [pscustomobject] @{ Kind = 'Process'; Value = [string] $item; Reason = 'a program that runs scripts or other programs: every file it opens goes unscanned' }
        }
    }

    $types = @(
        'exe', 'dll', 'sys', 'scr', 'com', 'cpl', 'msi', 'ps1', 'psm1', 'bat', 'cmd',
        'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta', 'lnk', 'iso', 'zip', '7z', 'rar', 'docm', 'xlsm', '*'
    )

    foreach ($item in @($Extension | Where-Object { $_ })) {

        $clean = ([string] $item).Trim().TrimStart('*').TrimStart('.').ToLowerInvariant()

        if ($clean -in $types -or [string] $item -eq '*') {
            $rows += [pscustomobject] @{ Kind = 'Extension'; Value = [string] $item; Reason = 'a file type that runs code, excluded wherever it is' }
        }
    }

    return $rows
}

<#
.SYNOPSIS
    Judges the Defender exclusions.

.PARAMETER DefenderActive
    Whether Defender is the antivirus protecting the machine.

.PARAMETER Mode
    The Defender running mode, named when it stands aside.

.PARAMETER Readable
    False when a policy hides the exclusions from administrators.
#>
function ConvertTo-TkDefenderExclusionFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [bool] $DefenderActive = $true,
        [Parameter()] [AllowEmptyString()] [string] $Mode = '',
        [Parameter()] [bool] $Readable = $true,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Path = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Process = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Extension = @()
    )

    if (-not $DefenderActive) {

        return New-TkAuditFinding -Id 'AV-003' -Name 'Antivirus exclusions' -Category 'Endpoint' `
            -Status 'Pass' -Measured $(if ($Mode) { 'Defender: {0}' -f $Mode } else { 'Defender not active' }) -Applicable $false `
            -Detail 'Another product owns protection, so Defender exclusions do not apply. The exclusions of that product are in its own console.'
    }

    if (-not $Readable) {

        return New-TkAuditFinding -Id 'AV-003' -Name 'Antivirus exclusions' -Category 'Endpoint' `
            -Status 'NotAssessed' -Measured 'Hidden by policy' `
            -Detail 'A policy hides the exclusions from local administrators, which is the recommended setting on a managed estate. Review them in the management console.'
    }

    $total = @($Path | Where-Object { $_ }).Count + @($Process | Where-Object { $_ }).Count + @($Extension | Where-Object { $_ }).Count

    if ($total -eq 0) {

        return New-TkAuditFinding -Id 'AV-003' -Name 'Antivirus exclusions' -Category 'Endpoint' `
            -Status 'Pass' -Measured 'None' `
            -Detail 'Defender scans everything.'
    }

    $broad = @(Get-TkBroadDefenderExclusion -Path $Path -Process $Process -Extension $Extension)

    if ($broad.Count -eq 0) {

        return New-TkAuditFinding -Id 'AV-003' -Name 'Antivirus exclusions' -Category 'Endpoint' `
            -Status 'Pass' -Measured ('{0} precise exclusion(s)' -f $total) `
            -Detail 'Every exclusion names something specific.'
    }

    $severe = @($broad | Where-Object { $_.Reason -eq 'a whole drive' -or $_.Kind -eq 'Process' -or $_.Value -eq '*' })
    $named  = (@($broad | Select-Object -First 4 | ForEach-Object { '{0} ({1})' -f $_.Value, $_.Reason })) -join '; '

    return New-TkAuditFinding -Id 'AV-003' -Name 'Antivirus exclusions' -Category 'Endpoint' `
        -Status $(if ($severe.Count -gt 0) { 'Fail' } else { 'Warning' }) -Measured ('{0} of {1} too broad' -f $broad.Count, $total) `
        -Detail ('Excluded: {0}. Attackers add exclusions like these so their files are never scanned, and installers ask for them to avoid support calls.' -f $named) `
        -Recommendation 'Remove them in Windows Security, Virus and threat protection settings, Exclusions, and ask the vendor for a precise folder or a single signed process instead. An exclusion nobody on the team added is a sign of compromise.'
}

<#
.SYNOPSIS
    Checks the Defender exclusions for ones wide enough to hide a payload.
#>
function Test-TkAuditDefenderExclusion {
    [CmdletBinding()]
    param()

    $state = Get-TkDefenderActiveState

    if (-not $state.Active) {
        return ConvertTo-TkDefenderExclusionFinding -DefenderActive $false -Mode $state.Mode
    }

    try {
        $preference = Get-MpPreference -ErrorAction Stop
    }
    catch {
        return New-TkAuditFinding -Id 'AV-003' -Name 'Antivirus exclusions' -Category 'Endpoint' `
            -Status 'NotAssessed' -Measured 'Not readable' `
            -Detail ('The Defender preferences could not be read: {0}' -f $_.Exception.Message)
    }

    $paths      = @($preference.ExclusionPath | Where-Object { $_ })
    $processes  = @($preference.ExclusionProcess | Where-Object { $_ })
    $extensions = @($preference.ExclusionExtension | Where-Object { $_ })

    # With exclusions hidden by policy, each list holds one "N/A: ..." sentence
    # instead of the entries.
    $hidden = (@($paths + $processes + $extensions | Where-Object { [string] $_ -like 'N/A*' }).Count -gt 0)

    return ConvertTo-TkDefenderExclusionFinding -Readable (-not $hidden) -Path $paths -Process $processes -Extension $extensions
}

# ---------------------------------------------------------------------------
# Print spooler
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Says whether a printer is one Windows creates rather than a device.

.PARAMETER DriverName
    The printer driver name.

.PARAMETER PortName
    The printer port name.
#>
function Test-TkVirtualPrinter {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $DriverName = '',
        [Parameter()] [AllowEmptyString()] [string] $PortName = ''
    )

    return ($PortName -match '^(PORTPROMPT:|SHRFAX:|nul:|FILE:|XPSPort:)$' -or
            $DriverName -match '^(Microsoft Print To PDF|Microsoft XPS Document Writer.*|Send to Microsoft OneNote.*|Microsoft Software Printer Driver|Microsoft Shared Fax Driver)$')
}

<#
.SYNOPSIS
    Judges whether the print spooler needs to run.

.DESCRIPTION
    The spooler runs as SYSTEM and has been the way in for a long run of
    privilege escalation and remote code execution flaws, PrintNightmare among
    them. Where only virtual printers exist, nothing needs it.

.PARAMETER Present
    Whether the service exists.

.PARAMETER Running
    Whether the service runs.

.PARAMETER StartType
    The service start type.

.PARAMETER Printer
    Win32_Printer rows, with DriverName and PortName.

.PARAMETER PrintersRead
    False when the printers could not be listed.
#>
function ConvertTo-TkSpoolerFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [bool] $Present = $true,
        [Parameter()] [bool] $Running = $false,
        [Parameter()] [AllowEmptyString()] [string] $StartType = '',
        [Parameter()] [AllowEmptyCollection()] [object[]] $Printer = @(),
        [Parameter()] [bool] $PrintersRead = $true
    )

    if (-not $Present) {

        return New-TkAuditFinding -Id 'PRN-001' -Name 'Print spooler' -Category 'Network' `
            -Status 'Pass' -Measured 'Not installed' -Applicable $false `
            -Detail 'There is no spooler to expose.'
    }

    if (-not $Running) {

        return New-TkAuditFinding -Id 'PRN-001' -Name 'Print spooler' -Category 'Network' `
            -Status 'Pass' -Measured $(if ($StartType) { 'Not running ({0})' -f $StartType } else { 'Not running' }) `
            -Detail 'The spooler answers no local or remote request.'
    }

    if (-not $PrintersRead) {

        return New-TkAuditFinding -Id 'PRN-001' -Name 'Print spooler' -Category 'Network' `
            -Status 'NotAssessed' -Measured 'Printers not readable' `
            -Detail 'The spooler runs but its printers could not be listed.'
    }

    $devices = @($Printer | Where-Object { $_ -and -not (Test-TkVirtualPrinter -DriverName ([string] $_.DriverName) -PortName ([string] $_.PortName)) })

    if ($devices.Count -gt 0) {

        return New-TkAuditFinding -Id 'PRN-001' -Name 'Print spooler' -Category 'Network' `
            -Status 'Pass' -Measured ('Running for {0} printer(s)' -f $devices.Count) `
            -Detail 'A printer is installed, so the spooler is needed here.'
    }

    return New-TkAuditFinding -Id 'PRN-001' -Name 'Print spooler' -Category 'Network' `
        -Status 'Warning' -Measured ('Running, {0} virtual printer(s) only' -f @($Printer | Where-Object { $_ }).Count) `
        -Detail 'The spooler runs as SYSTEM and has been the way in for a long run of privilege escalation and remote code execution flaws, PrintNightmare among them. With only printers such as Print to PDF, nothing here needs it.' `
        -Recommendation 'Stop and disable the spooler. Print to PDF stops working with it; start it again the day a printer is added.'
}

<#
.SYNOPSIS
    Checks whether the print spooler runs for no real printer.
#>
function Test-TkAuditPrintSpooler {
    [CmdletBinding()]
    param()

    $service = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue

    if (-not $service) {
        return ConvertTo-TkSpoolerFinding -Present $false
    }

    $running  = ($service.Status -eq 'Running')
    $printers = @()
    $read     = $true

    # Win32_Printer only answers while the spooler runs.
    if ($running) {
        try {
            $printers = @(Get-CimInstance -ClassName 'Win32_Printer' -ErrorAction Stop)
        }
        catch {
            $read = $false
        }
    }

    return ConvertTo-TkSpoolerFinding -Running $running -StartType ([string] $service.StartType) -Printer $printers -PrintersRead $read
}

# ---------------------------------------------------------------------------
# NTLM and cached credentials
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Judges the minimum session security of NTLM.

.DESCRIPTION
    NtlmMinClientSec and NtlmMinServerSec are bit fields: 0x80000 requires
    NTLMv2 session security and 0x20000000 requires 128-bit encryption. The
    Windows default, when the value is absent, is 128-bit encryption only.
    The Microsoft and CIS baselines require both bits on both sides.

.PARAMETER Client
    NtlmMinClientSec, or $null when absent.

.PARAMETER Server
    NtlmMinServerSec, or $null when absent.
#>
function ConvertTo-TkNtlmSessionFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowNull()] $Client,
        [Parameter()] [AllowNull()] $Server
    )

    $required = 0x20080000

    $effective = {
        param($value)
        if ($null -eq $value) { 0x20000000 } else { [long] $value }
    }

    $describe = {
        param($value)

        $number = & $effective $value
        $parts  = @()

        if ($number -band 0x80000) {
            $parts += 'NTLMv2'
        }

        if ($number -band 0x20000000) {
            $parts += '128-bit'
        }

        if ($parts.Count -eq 0) { 'nothing required' } else { '{0} required' -f ($parts -join ' + ') }
    }

    $safe = (((& $effective $Client) -band $required) -eq $required) -and (((& $effective $Server) -band $required) -eq $required)

    return New-TkAuditFinding -Id 'NET-004' -Name 'NTLM session security' -Category 'Network' `
        -Status $(if ($safe) { 'Pass' } else { 'Warning' }) `
        -Measured ('client: {0}; server: {1}' -f (& $describe $Client), (& $describe $Server)) `
        -Detail 'Without NTLMv2 session security, someone in the middle of an NTLM session can push it down to weaker protection. The Microsoft and CIS baselines require NTLMv2 session security and 128-bit encryption, as a client and as a server.' `
        -Recommendation $(if ($safe) { '' } else { 'Require both on the client and the server side. A very old NAS or printer that only speaks NTLMv1 stops authenticating: check for one first.' })
}

<#
.SYNOPSIS
    Checks the minimum session security of NTLM.
#>
function Test-TkNtlmSessionSecurity {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

    return ConvertTo-TkNtlmSessionFinding -Client (Get-TkRegistryValue -Path $path -Name 'NtlmMinClientSec') `
                                          -Server (Get-TkRegistryValue -Path $path -Name 'NtlmMinServerSec')
}

<#
.SYNOPSIS
    Judges how many domain sign-ins Windows caches.

.DESCRIPTION
    Windows keeps a verifier of the password of the last domain users who
    signed in, so they can sign in without reaching a domain controller.
    Anyone with administrator rights extracts them and cracks them offline.
    Only domain accounts are cached this way.

.PARAMETER Count
    CachedLogonsCount as stored (a string), or $null for the default of 10.

.PARAMETER DomainJoined
    Whether the machine is a domain member.
#>
function ConvertTo-TkCachedLogonFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowNull()] $Count,
        [Parameter()] [bool] $DomainJoined = $false
    )

    if (-not $DomainJoined) {

        return New-TkAuditFinding -Id 'CRED-004' -Name 'Cached domain sign-ins' -Category 'Credentials' `
            -Status 'Pass' -Measured 'Not joined to a domain' -Applicable $false `
            -Detail 'Only domain accounts are cached for offline sign-in.'
    }

    $number = 10
    $parsed = 0

    if ($null -ne $Count -and [int]::TryParse(([string] $Count).Trim(), [ref] $parsed)) {
        $number = $parsed
    }

    if ($number -le 4) {

        return New-TkAuditFinding -Id 'CRED-004' -Name 'Cached domain sign-ins' -Category 'Credentials' `
            -Status 'Pass' -Measured ('{0} cached' -f $number) `
            -Detail 'Few enough password verifiers are kept to limit what an administrator or a stolen disk gives away, and enough for a laptop used away from the office.'
    }

    return New-TkAuditFinding -Id 'CRED-004' -Name 'Cached domain sign-ins' -Category 'Credentials' `
        -Status 'Warning' -Measured ('{0} cached{1}' -f $number, $(if ($null -eq $Count) { ', the Windows default' } else { '' })) `
        -Detail 'Windows keeps a password verifier for each of the last domain users who signed in, so they can sign in without the network. Anyone with administrator rights extracts them and cracks them offline; on a shared machine that is many accounts at once.' `
        -Recommendation 'Lower it to 4 or fewer, as the CIS baseline asks. Keep at least 1 on a laptop, or its user cannot sign in away from the office.'
}

<#
.SYNOPSIS
    Checks how many domain sign-ins Windows caches.
#>
function Test-TkCachedLogon {
    [CmdletBinding()]
    param()

    $count  = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount'
    $system = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'

    return ConvertTo-TkCachedLogonFinding -Count $count -DomainJoined ([bool] ($system -and $system.PartOfDomain))
}
