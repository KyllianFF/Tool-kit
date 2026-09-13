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
    Toolkit - Features / Hardening controls

    The controls that decide whether an intrusion stays on one machine or
    reaches the whole estate: credential protection, logging, SMB and NTLM,
    and where the BitLocker recovery key actually lives.

    These used to be a second engine with a second finding shape and no
    identifiers, which meant BitLocker was tested twice and no control here
    could be quoted in a ticket. They are now controls of the one audit, run
    from the table in SecurityAudit.ps1 and built by New-TkAuditFinding, and
    they are the ones it classes as Full rather than Essential: each needs a
    decision, a licence or a domain behind it.
#>

# ---------------------------------------------------------------------------
# Credential protection

# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the Windows edition identifier, such as Professional or Enterprise.
#>
function Get-TkWindowsEditionId {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $value = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID'

    if ($value) {
        return [string] $value
    }

    return 'Unknown'
}

<#
.SYNOPSIS
    Says whether this edition of Windows can run Credential Guard.

.DESCRIPTION
    Enterprise, Education, IoT Enterprise and Server, with their N and LTSC
    variants. Pro cannot run it whatever is configured, and neither can Pro
    Education, whose identifier ends in Education but starts with Professional.

.PARAMETER EditionId
    Defaults to the edition of this machine.
#>
function Test-TkCredentialGuardEdition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string] $EditionId = (Get-TkWindowsEditionId)
    )

    return ($EditionId -match '^(Enterprise|Education|IoTEnterprise|Server)')
}

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

    # On an edition without Credential Guard a warning would ask for something
    # this machine cannot do. It is reported, not marked down.
    if (-not $running -and -not (Test-TkCredentialGuardEdition)) {

        return New-TkAuditFinding -Id 'CRED-001' -Name 'Credential Guard' -Category 'Credentials' `
            -Status 'Info' -Measured ('Not available on {0}' -f (Get-TkWindowsEditionId)) `
            -Detail 'Credential Guard requires Windows Enterprise or Education. On this edition, LSA protection (CRED-002) closes the most direct route to the same credentials.'
    }

    return New-TkAuditFinding -Id 'CRED-001' -Name 'Credential Guard' -Category 'Credentials' `
        -Status $(if ($running) { 'Pass' } else { 'Warning' }) -Measured $state `
        -Detail 'Credential Guard isolates derived credentials in virtualised memory, so a process running as SYSTEM cannot read them out of LSASS. Without it, one administrator on one machine yields hashes usable everywhere.' `
        -Recommendation $(if ($running) { '' } else { 'Enable it by policy: Computer Configuration, System, Device Guard, Turn On Virtualization Based Security, with Credential Guard set to enabled with UEFI lock.' })
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

    return New-TkAuditFinding -Id 'CRED-002' -Name 'LSA protection (RunAsPPL)' -Category 'Credentials' `
        -Status $(if ($enabled) { 'Pass' } else { 'Warning' }) `
        -Measured $(if ($enabled) { 'Enabled ({0})' -f $value } else { 'Disabled' }) `
        -Detail 'A protected LSASS cannot be opened by an ordinary administrator process, which blocks the most direct route to credential dumping.' `
        -Recommendation $(if ($enabled) { '' } else { 'Set RunAsPPL to 1, then restart. Verify no security product depends on injecting into LSASS first.' }) `
        -RemediationId $(if ($enabled) { '' } else { 'enable-lsa-protection' })
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

    return New-TkAuditFinding -Id 'CRED-003' -Name 'WDigest credential caching' -Category 'Credentials' `
        -Status $(if ($unsafe) { 'Fail' } else { 'Pass' }) `
        -Measured $(if ($unsafe) { 'Enabled: plain text passwords are held in memory' } else { 'Disabled' }) `
        -Detail 'With UseLogonCredential set to 1, Windows keeps the plain text password in LSASS. It is the first thing an attacker sets, because it turns a hash dump into a password dump.' `
        -Recommendation $(if ($unsafe) { 'Set UseLogonCredential to 0 and investigate why it was ever enabled: nothing modern requires it.' } else { '' }) `
        -RemediationId $(if ($unsafe) { 'disable-wdigest' } else { '' })
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

    $defender = Get-TkDefenderActiveState

    if (-not $defender.Active) {

        return New-TkAuditFinding -Id 'EDR-001' -Name 'Attack Surface Reduction rules' -Category 'Endpoint' `
            -Status 'Info' -Measured ('Defender: {0}' -f $defender.Mode) `
            -Detail 'ASR rules only apply while Microsoft Defender is the active antivirus. Another product owns protection here, and the equivalent behaviour rules belong to it.'
    }

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

        return New-TkAuditFinding -Id 'EDR-001' -Name 'Attack Surface Reduction rules' -Category 'Endpoint' `
            -Status $severity -Measured ('{0} configured, {1} in block mode' -f $ids.Count, $blocking) `
            -Detail 'ASR rules block the specific behaviours malware needs: Office spawning child processes, script interpreters launching downloaded content, credential theft from LSASS. They stop whole classes of attack without signatures.' `
            -Recommendation $(if ($blocking -ge 8) { '' } else { 'Deploy the standard rule set in audit mode first, review what it would have blocked, then move to block.' })
    }
    catch {
        return New-TkAuditFinding -Id 'EDR-001' -Name 'Attack Surface Reduction rules' -Category 'Endpoint' `
            -Status 'NotAssessed' -Measured 'Defender not available' `
            -Detail 'ASR is a Defender feature; a third party product may cover the same ground.'
    }
}

<#
.SYNOPSIS
    Checks whether Defender tamper protection is on.
#>
function Test-TkTamperProtection {
    [CmdletBinding()]
    param()

    $defender = Get-TkDefenderActiveState

    if (-not $defender.Active) {

        return New-TkAuditFinding -Id 'EDR-002' -Name 'Tamper protection' -Category 'Endpoint' `
            -Status 'Info' -Measured ('Defender: {0}' -f $defender.Mode) `
            -Detail 'Tamper protection guards the settings of Defender, which is not the active antivirus here. The product that owns protection has its own self protection setting.'
    }

    try {
        $status = Get-TkDefenderStatus

        if ($null -eq $status) {
            throw 'Defender status is unavailable.'
        }

        $enabled = [bool] $status.IsTamperProtected

        return New-TkAuditFinding -Id 'EDR-002' -Name 'Tamper protection' -Category 'Endpoint' `
            -Status $(if ($enabled) { 'Pass' } else { 'Warning' }) `
            -Measured $(if ($enabled) { 'On' } else { 'Off' }) `
            -Detail 'Tamper protection stops Defender being disabled from the registry or the command line, which is the first move of most commodity malware.' `
            -Recommendation $(if ($enabled) { '' } else { 'Turn it on from Windows Security, or through Intune on a managed estate.' })
    }
    catch {
        return New-TkAuditFinding -Id 'EDR-002' -Name 'Tamper protection' -Category 'Endpoint' `
            -Status 'NotAssessed' -Measured 'Not readable' -Detail 'Defender status is unavailable.'
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

    return New-TkAuditFinding -Id 'LOG-001' -Name 'PowerShell logging' -Category 'Logging' `
        -Status $(if ($enabled) { 'Pass' } else { 'Warning' }) -Measured $state `
        -Detail 'Script block logging records PowerShell after it has been de-obfuscated, which is the single most useful piece of telemetry on Windows during an investigation.' `
        -Recommendation $(if ($enabled) { '' } else { 'Enable it by policy. The Tweaks page has it under security hardening.' }) `
        -RemediationId $(if ($enabled) { '' } else { 'enable-script-block-logging' })
}

<#
.SYNOPSIS
    Returns the audit subcategories every workstation should record.

.DESCRIPTION
    Identified by GUID because auditpol prints and accepts names only in the
    language of the machine. Each GUID was checked against
    "auditpol /list /subcategory:* /r" on a French Windows.

.OUTPUTS
    PSCustomObject[] with Guid and Name.
#>
function Get-TkAuditPolicyBaseline {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'logon' }
        [pscustomobject] @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'special logon' }
        [pscustomobject] @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'credential validation' }
        [pscustomobject] @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'account lockout' }
        [pscustomobject] @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'user account management' }
        [pscustomobject] @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'security group management' }
        [pscustomobject] @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'audit policy change' }
        [pscustomobject] @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'process creation' }
    )
}

<#
.SYNOPSIS
    Reads the setting of each audit subcategory out of an auditpol backup.

.DESCRIPTION
    The backup is read rather than "auditpol /get", because /get words its
    settings in the language of the machine ("Succes et echec" on a French
    Windows). A backup row carries the subcategory GUID and ends in a number:
    1 records successes, 2 failures, 3 both, 0 nothing.

    A row without a GUID, such as an option, is skipped. Where a GUID appears
    more than once the highest setting is kept.

.PARAMETER Text
    The content of the file written by "auditpol /backup".

.OUTPUTS
    Hashtable of upper case GUID in braces to setting.
#>
function ConvertFrom-TkAuditPolicyBackup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $settings = @{}

    foreach ($row in ($Text -split "`r?`n")) {

        $guid = [regex]::Match($row, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')

        if (-not $guid.Success) {
            continue
        }

        $last = ($row.TrimEnd() -split ',')[-1].Trim()

        if ($last -notmatch '^[0-3]$') {
            continue
        }

        $key   = $guid.Value.ToUpperInvariant()
        $value = [int] $last

        if (-not $settings.ContainsKey($key) -or $settings[$key] -lt $value) {
            $settings[$key] = $value
        }
    }

    return $settings
}

<#
.SYNOPSIS
    Checks whether the audit policy records what an investigation needs.
#>
function Test-TkAuditPolicy {
    [CmdletBinding()]
    param()

    if (-not (Test-TkIsElevated)) {

        return New-TkAuditFinding -Id 'LOG-002' -Name 'Audit policy' -Category 'Logging' `
            -Status 'NotAssessed' -Measured 'Needs elevation' `
            -Detail 'The effective audit policy is only readable as an administrator.'
    }

    # Under the Windows temporary folder, whose path has no space in it to
    # quote, and which only an administrator can write to.
    $file = Join-Path (Join-Path $env:SystemRoot 'Temp') ('tk-auditpol-{0}.csv' -f [guid]::NewGuid())
    $text = ''

    try {
        $result = Invoke-TkProcess -FilePath 'auditpol.exe' -ArgumentList @('/backup', ('/file:{0}' -f $file)) -TimeoutSeconds 30

        if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) {
            $text = [string] (Get-Content -LiteralPath $file -Raw)
        }
    }
    finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }

    $settings = ConvertFrom-TkAuditPolicyBackup -Text $text

    if ($settings.Count -eq 0) {

        return New-TkAuditFinding -Id 'LOG-002' -Name 'Audit policy' -Category 'Logging' `
            -Status 'NotAssessed' -Measured 'Not readable' -Detail 'auditpol did not return a policy that could be read.'
    }

    $baseline = @(Get-TkAuditPolicyBaseline)

    $missing = @($baseline | Where-Object {
        -not ($settings.ContainsKey($_.Guid) -and ($settings[$_.Guid] -band 1))
    })

    $recorded = $baseline.Count - $missing.Count

    $status = if ($missing.Count -eq 0) { 'Pass' } elseif ($recorded -gt 0) { 'Warning' } else { 'Fail' }

    $detail = 'A default Windows installation audits very little, and none of these events can be recovered after the fact.'

    if ($missing.Count -gt 0) {
        $detail += ' Not recording successes: {0}.' -f ((@($missing | ForEach-Object { $_.Name })) -join ', ')
    }

    return New-TkAuditFinding -Id 'LOG-002' -Name 'Audit policy' -Category 'Logging' `
        -Status $status -Measured ('{0} of {1} baseline events recorded' -f $recorded, $baseline.Count) `
        -Detail $detail `
        -Recommendation $(if ($status -eq 'Pass') { '' } else { 'Record the baseline: logon, special logon, credential validation, account lockout, account and group management, audit policy changes and process creation.' })
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

        return New-TkAuditFinding -Id 'SMB-002' -Name 'SMB signing' -Category 'Network' `
            -Status 'NotAssessed' -Measured 'Not readable' -Detail 'The SMB configuration could not be read.'
    }

    $both = ($serverRequired -and $clientRequired)

    return New-TkAuditFinding -Id 'SMB-002' -Name 'SMB signing' -Category 'Network' `
        -Status $(if ($both) { 'Pass' } else { 'Warning' }) `
        -Measured ('server: {0}, client: {1}' -f $serverRequired, $clientRequired) `
        -Detail 'Without required signing, an attacker who can relay authentication can act as the user against any SMB service. This is what NTLM relay attacks depend on.' `
        -Recommendation $(if ($both) { '' } else { 'Require signing on both the client and the server by policy. Measure the performance impact first on file servers carrying heavy load.' })
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

    return New-TkAuditFinding -Id 'NET-002' -Name 'LAN Manager authentication level' -Category 'Network' `
        -Status $(if ($safe) { 'Pass' } elseif ($null -eq $level) { 'Warning' } else { 'Warning' }) `
        -Measured $(if ($null -eq $level) { 'Not configured, using the default' } else { 'Level {0}' -f $level }) `
        -Detail 'Anything below level 5 permits LM or NTLMv1 responses, which are trivially crackable when captured. Level 5 sends NTLMv2 only and refuses the rest.' `
        -Recommendation $(if ($safe) { '' } else { 'Set LmCompatibilityLevel to 5 by policy, after confirming no legacy appliance still needs NTLMv1.' }) `
        -RemediationId $(if ($safe) { '' } else { 'set-lm-level' })
}

# ---------------------------------------------------------------------------
# Administration
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

    return New-TkAuditFinding -Id 'ACC-003' -Name 'Local administrator password' -Category 'Accounts' `
        -Status $(if ($present) { 'Pass' } else { 'Warning' }) `
        -Measured $(if ($windowsLaps) { 'Windows LAPS policy present' }
                 elseif ($legacyLaps) { 'Legacy LAPS policy present' }
                 else { 'No LAPS policy' }) `
        -Detail 'A shared local administrator password is what turns one compromised workstation into all of them: the hash is the same everywhere, so it can be replayed against every machine. LAPS gives each machine its own, rotated, and escrowed in the directory.' `
        -Recommendation $(if ($present) { '' } else { 'Deploy Windows LAPS. It is built into current Windows and needs a schema extension plus a policy.' })
}
