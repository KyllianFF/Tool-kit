<#
    Toolkit - Features / Hardening checks

    The controls that decide whether an intrusion stays on one machine or
    reaches the whole estate. They are separated from the general audit
    because they are a different conversation: the audit asks whether the
    basics are on, this asks whether credential theft and lateral movement
    are actually made difficult.

    Every check reports what it found, why it matters, and what to change.
    A red marker with no explanation is how hardening advice gets ignored.
#>

<#
.SYNOPSIS
    Runs every hardening check.

.OUTPUTS
    PSCustomObject[] with Severity, Area, Name, State, Why and Fix.
#>
function Invoke-TkHardeningCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $stopwatch = Start-TkOperation -Name 'Hardening check' -Category 'Hardening'

    $checks = @(
        'Test-TkCredentialGuard',
        'Test-TkLsaProtection',
        'Test-TkAsrRules',
        'Test-TkAuditPolicy',
        'Test-TkSmbSigning',
        'Test-TkNtlmRestriction',
        'Test-TkPowerShellLogging',
        'Test-TkLaps',
        'Test-TkBitLockerEscrow',
        'Test-TkWdigest',
        'Test-TkTamperProtection'
    )

    $findings = @()

    foreach ($check in $checks) {

        try {
            $findings += & $check
        }
        catch {
            Write-TkLog -Level Warning -Category 'Hardening' -Message (
                '{0} could not run: {1}' -f $check, $_.Exception.Message
            )
        }
    }

    Stop-TkOperation -Name 'Hardening check' -Stopwatch $stopwatch -Category 'Hardening'

    $failing = @($findings | Where-Object { $_.Severity -eq 'Fail' }).Count

    Write-TkLog -Level Information -Category 'Hardening' -Message (
        '{0} controls checked, {1} failing.' -f $findings.Count, $failing
    )

    return $findings
}

<#
.SYNOPSIS
    Builds a hardening finding.

.OUTPUTS
    PSCustomObject
#>
function New-TkHardeningFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Area,
        [Parameter(Mandatory)] [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Info', 'Warning', 'Fail')]
        [string] $Severity,

        [Parameter(Mandatory)] [AllowEmptyString()] [string] $State,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Why,
        [Parameter()]          [AllowEmptyString()] [string] $Fix = ''
    )

    return [pscustomobject]@{
        Severity = $Severity
        Area     = $Area
        Name     = $Name
        State    = $State
        Why      = $Why
        Fix      = $Fix
    }
}

# ---------------------------------------------------------------------------
# Credential protection
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks whether Credential Guard is running.
#>
function Test-TkCredentialGuard {
    [CmdletBinding()]
    param()

    $running = $false
    $state   = 'Not available'

    try {
        $guard = Get-CimInstance -ClassName 'Win32_DeviceGuard' `
                                 -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop

        # 1 in SecurityServicesRunning means Credential Guard is active.
        $running = (@($guard.SecurityServicesRunning) -contains 1)

        $state = if ($running) { 'Running' }
                 elseif (@($guard.SecurityServicesConfigured) -contains 1) { 'Configured but not running' }
                 else { 'Not configured' }
    }
    catch {
        $null = $_
    }

    return New-TkHardeningFinding -Area 'Credentials' -Name 'Credential Guard' `
        -Severity $(if ($running) { 'Pass' } else { 'Warning' }) -State $state `
        -Why 'Credential Guard isolates derived credentials in virtualised memory, so a process running as SYSTEM cannot read them out of LSASS. Without it, one administrator on one machine yields hashes usable everywhere.' `
        -Fix $(if ($running) { '' } else { 'Enable it by policy: Computer Configuration, System, Device Guard, Turn On Virtualization Based Security, with Credential Guard set to enabled with UEFI lock.' })
}

<#
.SYNOPSIS
    Checks whether LSASS runs as a protected process.
#>
function Test-TkLsaProtection {
    [CmdletBinding()]
    param()

    $value = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'

    $enabled = ($value -in @(1, 2))

    return New-TkHardeningFinding -Area 'Credentials' -Name 'LSA protection (RunAsPPL)' `
        -Severity $(if ($enabled) { 'Pass' } else { 'Warning' }) `
        -State $(if ($enabled) { 'Enabled ({0})' -f $value } else { 'Disabled' }) `
        -Why 'A protected LSASS cannot be opened by an ordinary administrator process, which blocks the most direct route to credential dumping.' `
        -Fix $(if ($enabled) { '' } else { 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL to 1, then restart. Verify no security product depends on injecting into LSASS first.' })
}

<#
.SYNOPSIS
    Checks whether WDigest can still cache plain text credentials.
#>
function Test-TkWdigest {
    [CmdletBinding()]
    param()

    $value = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                                 -Name 'UseLogonCredential'

    # Absent or 0 is safe on anything current; 1 restores the old behaviour.
    $unsafe = ($value -eq 1)

    return New-TkHardeningFinding -Area 'Credentials' -Name 'WDigest credential caching' `
        -Severity $(if ($unsafe) { 'Fail' } else { 'Pass' }) `
        -State $(if ($unsafe) { 'Enabled: plain text passwords are held in memory' } else { 'Disabled' }) `
        -Why 'With UseLogonCredential set to 1, Windows keeps the plain text password in LSASS. It is the first thing an attacker sets, because it turns a hash dump into a password dump.' `
        -Fix $(if ($unsafe) { 'Set UseLogonCredential to 0 and investigate why it was ever enabled: nothing modern requires it.' } else { '' })
}

# ---------------------------------------------------------------------------
# Endpoint controls
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks how many Attack Surface Reduction rules are enforcing.
#>
function Test-TkAsrRules {
    [CmdletBinding()]
    param()

    try {
        $preference = Get-MpPreference -ErrorAction Stop

        $ids     = @($preference.AttackSurfaceReductionRules_Ids)
        $actions = @($preference.AttackSurfaceReductionRules_Actions)

        # 1 is block, 2 is audit, 6 is warn.
        $blocking = 0

        for ($i = 0; $i -lt $ids.Count; $i++) {

            if ($i -lt $actions.Count -and $actions[$i] -eq 1) {
                $blocking++
            }
        }

        $severity = if ($blocking -ge 8) { 'Pass' } elseif ($blocking -gt 0) { 'Warning' } else { 'Fail' }

        return New-TkHardeningFinding -Area 'Endpoint' -Name 'Attack Surface Reduction rules' `
            -Severity $severity -State ('{0} configured, {1} in block mode' -f $ids.Count, $blocking) `
            -Why 'ASR rules block the specific behaviours malware needs: Office spawning child processes, script interpreters launching downloaded content, credential theft from LSASS. They stop whole classes of attack without signatures.' `
            -Fix $(if ($blocking -ge 8) { '' } else { 'Deploy the standard rule set in audit mode first, review what it would have blocked, then move to block.' })
    }
    catch {
        return New-TkHardeningFinding -Area 'Endpoint' -Name 'Attack Surface Reduction rules' `
            -Severity 'Info' -State 'Defender not available' `
            -Why 'ASR is a Defender feature; a third party product may cover the same ground.'
    }
}

<#
.SYNOPSIS
    Checks whether Defender tamper protection is on.
#>
function Test-TkTamperProtection {
    [CmdletBinding()]
    param()

    try {
        $status  = Get-MpComputerStatus -ErrorAction Stop
        $enabled = [bool] $status.IsTamperProtected

        return New-TkHardeningFinding -Area 'Endpoint' -Name 'Tamper protection' `
            -Severity $(if ($enabled) { 'Pass' } else { 'Warning' }) `
            -State $(if ($enabled) { 'On' } else { 'Off' }) `
            -Why 'Tamper protection stops Defender being disabled from the registry or the command line, which is the first move of most commodity malware.' `
            -Fix $(if ($enabled) { '' } else { 'Turn it on from Windows Security, or through Intune on a managed estate.' })
    }
    catch {
        return New-TkHardeningFinding -Area 'Endpoint' -Name 'Tamper protection' `
            -Severity 'Info' -State 'Not readable' -Why 'Defender status is unavailable.'
    }
}

<#
.SYNOPSIS
    Checks whether PowerShell script block logging is on.
#>
function Test-TkPowerShellLogging {
    [CmdletBinding()]
    param()

    $scriptBlock = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                                       -Name 'EnableScriptBlockLogging'

    $transcription = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
                                         -Name 'EnableTranscripting'

    $enabled = ($scriptBlock -eq 1)

    $state = if ($enabled -and $transcription -eq 1) { 'Script block logging and transcription' }
             elseif ($enabled) { 'Script block logging only' }
             else { 'Off' }

    return New-TkHardeningFinding -Area 'Logging' -Name 'PowerShell logging' `
        -Severity $(if ($enabled) { 'Pass' } else { 'Warning' }) -State $state `
        -Why 'Script block logging records PowerShell after it has been de-obfuscated, which is the single most useful piece of telemetry on Windows during an investigation.' `
        -Fix $(if ($enabled) { '' } else { 'Enable it by policy. The Tweaks page has it under security hardening.' })
}

<#
.SYNOPSIS
    Checks whether the audit policy records what an investigation needs.
#>
function Test-TkAuditPolicy {
    [CmdletBinding()]
    param()

    if (-not (Test-TkIsElevated)) {

        return New-TkHardeningFinding -Area 'Logging' -Name 'Audit policy' `
            -Severity 'Info' -State 'Needs elevation' `
            -Why 'The effective audit policy is only readable as an administrator.'
    }

    $result = Invoke-TkProcess -FilePath 'auditpol' -ArgumentList @('/get', '/category:*') -TimeoutSeconds 30

    if ($result.ExitCode -ne 0) {

        return New-TkHardeningFinding -Area 'Logging' -Name 'Audit policy' `
            -Severity 'Info' -State 'Not readable' -Why 'auditpol did not answer.'
    }

    # Counting subcategories that record something at all is a crude measure,
    # but it separates a default installation from a configured one, which is
    # the distinction that matters.
    $lines     = $result.StandardOutput -split "`r?`n"
    $auditing  = @($lines | Where-Object { $_ -match '\s(Success|Failure|Succ.s|.chec)' }).Count

    $severity = if ($auditing -ge 20) { 'Pass' } elseif ($auditing -ge 8) { 'Warning' } else { 'Fail' }

    return New-TkHardeningFinding -Area 'Logging' -Name 'Audit policy' `
        -Severity $severity -State ('{0} subcategories recording' -f $auditing) `
        -Why 'A default Windows installation audits very little. Logon events, process creation and object access have to be turned on deliberately, and none of them can be recovered after the fact.' `
        -Fix $(if ($severity -eq 'Pass') { '' } else { 'Apply an audit policy baseline. At minimum: logon and logoff, account logon, process creation, and account management, success and failure.' })
}

# ---------------------------------------------------------------------------
# Network protocols
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks whether SMB signing is required.
#>
function Test-TkSmbSigning {
    [CmdletBinding()]
    param()

    $serverRequired = $null
    $clientRequired = $null

    try {
        $serverRequired = (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature
        $clientRequired = (Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature
    }
    catch {
        $null = $_
    }

    if ($null -eq $serverRequired) {

        return New-TkHardeningFinding -Area 'Network' -Name 'SMB signing' `
            -Severity 'Info' -State 'Not readable' -Why 'The SMB configuration could not be read.'
    }

    $both = ($serverRequired -and $clientRequired)

    return New-TkHardeningFinding -Area 'Network' -Name 'SMB signing' `
        -Severity $(if ($both) { 'Pass' } else { 'Warning' }) `
        -State ('server: {0}, client: {1}' -f $serverRequired, $clientRequired) `
        -Why 'Without required signing, an attacker who can relay authentication can act as the user against any SMB service. This is what NTLM relay attacks depend on.' `
        -Fix $(if ($both) { '' } else { 'Require signing on both the client and the server by policy. Measure the performance impact first on file servers carrying heavy load.' })
}

<#
.SYNOPSIS
    Checks whether outgoing NTLM is restricted.
#>
function Test-TkNtlmRestriction {
    [CmdletBinding()]
    param()

    $level = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'

    # 5 means send NTLMv2 only and refuse LM and NTLM.
    $safe = ($level -eq 5)

    return New-TkHardeningFinding -Area 'Network' -Name 'LAN Manager authentication level' `
        -Severity $(if ($safe) { 'Pass' } elseif ($null -eq $level) { 'Warning' } else { 'Warning' }) `
        -State $(if ($null -eq $level) { 'Not configured, using the default' } else { 'Level {0}' -f $level }) `
        -Why 'Anything below level 5 permits LM or NTLMv1 responses, which are trivially crackable when captured. Level 5 sends NTLMv2 only and refuses the rest.' `
        -Fix $(if ($safe) { '' } else { 'Set LmCompatibilityLevel to 5 by policy, after confirming no legacy appliance still needs NTLMv1.' })
}

# ---------------------------------------------------------------------------
# Recovery and administration
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks whether a local administrator password solution is in use.
#>
function Test-TkLaps {
    [CmdletBinding()]
    param()

    $windowsLaps = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction Ignore
    $legacyLaps  = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction Ignore

    $present = ($windowsLaps -or $legacyLaps)

    return New-TkHardeningFinding -Area 'Administration' -Name 'Local administrator password' `
        -Severity $(if ($present) { 'Pass' } else { 'Warning' }) `
        -State $(if ($windowsLaps) { 'Windows LAPS policy present' }
                 elseif ($legacyLaps) { 'Legacy LAPS policy present' }
                 else { 'No LAPS policy' }) `
        -Why 'A shared local administrator password is what turns one compromised workstation into all of them: the hash is the same everywhere, so it can be replayed against every machine. LAPS gives each machine its own, rotated, and escrowed in the directory.' `
        -Fix $(if ($present) { '' } else { 'Deploy Windows LAPS. It is built into current Windows and needs a schema extension plus a policy.' })
}

<#
.SYNOPSIS
    Checks whether the BitLocker recovery key is escrowed somewhere.
#>
function Test-TkBitLockerEscrow {
    [CmdletBinding()]
    param()

    try {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

        if ($volume.ProtectionStatus -ne 'On') {

            return New-TkHardeningFinding -Area 'Recovery' -Name 'BitLocker recovery key' `
                -Severity 'Fail' -State 'The system drive is not encrypted' `
                -Why 'Without encryption, a stolen laptop is a data breach rather than a hardware loss.' `
                -Fix 'Enable BitLocker and confirm the recovery key is escrowed before the machine leaves the building.'
        }

        $recoveryProtector = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })

        if ($recoveryProtector.Count -eq 0) {

            return New-TkHardeningFinding -Area 'Recovery' -Name 'BitLocker recovery key' `
                -Severity 'Fail' -State 'Encrypted, but no recovery password protector' `
                -Why 'With no recovery password, a firmware change or a TPM reset makes the data unrecoverable. There is no support path from there.' `
                -Fix 'Add a recovery password protector and back it up to the directory or to Entra ID.'
        }

        return New-TkHardeningFinding -Area 'Recovery' -Name 'BitLocker recovery key' `
            -Severity 'Pass' -State ('{0} recovery protector(s) present' -f $recoveryProtector.Count) `
            -Why 'A recovery password exists, so the volume can be unlocked after a firmware or TPM change.' `
            -Fix 'Confirm separately that it is escrowed centrally, which cannot be verified from the machine itself.'
    }
    catch {
        return New-TkHardeningFinding -Area 'Recovery' -Name 'BitLocker recovery key' `
            -Severity 'Info' -State 'Not readable' `
            -Why 'BitLocker state needs elevation, or this edition does not support it.'
    }
}
