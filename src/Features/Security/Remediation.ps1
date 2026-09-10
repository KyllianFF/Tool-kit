<#
    Toolkit - Features / Remediation

    A finding that says something is wrong and leaves you to go and fix it by
    hand is half a tool. This maps the findings that have a safe, single step
    correction to an action, and shows the operator exactly what will run
    before it runs.

    Two rules govern what is allowed in here.

    First, the same rule as the fixes catalog: a finding names a key in the
    table below, never a command. The table is declared in code, so no data
    file can cause anything to execute.

    Second, only corrections that are safe, reversible and single step are
    offered. Enabling BitLocker is not one of them, and neither is deploying
    LAPS: both need decisions the tool cannot make. Those findings stay
    advisory, which is honest, rather than being given a button that would do
    something approximate.
#>

<#
.SYNOPSIS
    Returns the allow list of corrections the toolkit can apply.

.DESCRIPTION
    Keyed by remediation identifier. Each entry carries what it does, the
    command shown to the operator before it runs, and the function that
    actually performs it.

.OUTPUTS
    System.Collections.Hashtable
#>
function Get-TkRemediationTable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{

        'disable-autorun' = @{
            Name        = 'Disable AutoRun on every drive type'
            Explanation = 'Sets NoDriveTypeAutoRun to 255, which stops anything starting on its own when removable media is inserted.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" NoDriveTypeAutoRun 255'
            Action      = 'Repair-TkAutoRun'
            Elevated    = $true
            Reversible  = 'Set the value back to 145, the Windows default.'
        }

        'disable-llmnr' = @{
            Name        = 'Disable LLMNR'
            Explanation = 'Sets EnableMulticast to 0 by policy. Nothing on a network with working DNS needs LLMNR, and it is what Responder abuses to capture NTLM hashes.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" EnableMulticast 0'
            Action      = 'Repair-TkLlmnr'
            Elevated    = $true
            Reversible  = 'Delete the value to return to the default.'
        }

        'disable-wdigest' = @{
            Name        = 'Stop WDigest caching plain text passwords'
            Explanation = 'Sets UseLogonCredential to 0, so Windows stops keeping the plain text password in LSASS.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential 0'
            Action      = 'Repair-TkWdigest'
            Elevated    = $true
            Reversible  = 'Nothing modern requires the old behaviour, so there is no reason to undo it.'
        }

        'enable-lsa-protection' = @{
            Name        = 'Run LSASS as a protected process'
            Explanation = 'Sets RunAsPPL to 1. A protected LSASS cannot be opened by an ordinary administrator process, which blocks the most direct route to credential dumping. Takes effect at the next restart.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL 1'
            Action      = 'Repair-TkLsaProtection'
            Elevated    = $true
            Reversible  = 'Set RunAsPPL to 0 and restart. Check first that no security product needs to inject into LSASS.'
        }

        'enable-script-block-logging' = @{
            Name        = 'Enable PowerShell script block logging'
            Explanation = 'Records PowerShell after it has been de-obfuscated, into the event log. The single most useful piece of telemetry on Windows during an investigation.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging 1'
            Action      = 'Repair-TkScriptBlockLogging'
            Elevated    = $true
            Reversible  = 'Delete the value. Expect a noticeable volume of events on a busy machine.'
        }

        'set-lm-level' = @{
            Name        = 'Send NTLMv2 only'
            Explanation = 'Sets LmCompatibilityLevel to 5, which refuses LM and NTLMv1 responses. Those are trivially crackable when captured.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" LmCompatibilityLevel 5'
            Action      = 'Repair-TkLmCompatibility'
            Elevated    = $true
            Reversible  = 'Delete the value. Confirm first that no legacy appliance still needs NTLMv1.'
        }

        'enable-firewall' = @{
            Name        = 'Enable every firewall profile'
            Explanation = 'Turns the Domain, Private and Public profiles back on. The public profile is the one that matters on hotel and client networks.'
            Command     = 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'
            Action      = 'Repair-TkFirewallProfiles'
            Elevated    = $true
            Reversible  = 'Disabling a profile again is one command, but there is rarely a reason.'
        }

        'disable-guest' = @{
            Name        = 'Disable the Guest account'
            Explanation = 'Disables the built in Guest account, which permits unauthenticated access to shared resources.'
            Command     = 'Disable-LocalUser -SID <the account ending in -501>'
            Action      = 'Repair-TkGuestAccount'
            Elevated    = $true
            Reversible  = 'Enable-LocalUser on the same account.'
        }

        'update-signatures' = @{
            Name        = 'Update the antivirus signatures'
            Explanation = 'Forces Defender to fetch current definitions now rather than waiting for its schedule.'
            Command     = 'Update-MpSignature'
            Action      = 'Repair-TkSignatures'
            Elevated    = $true
            Reversible  = 'Nothing to undo.'
        }

        'start-spooler' = @{
            Name        = 'Start the print spooler'
            Explanation = 'Starts the Spooler service and sets it to start automatically. Nothing prints until it is running.'
            Command     = 'Set-Service Spooler -StartupType Automatic; Start-Service Spooler'
            Action      = 'Repair-TkSpooler'
            Elevated    = $true
            Reversible  = 'Stop the service and set it to Disabled again.'
        }

        'clear-temp' = @{
            Name        = 'Delete temporary files'
            Explanation = 'Empties the user and system temporary folders and the prefetch cache. Files locked by a running process are skipped.'
            Command     = 'Clear-TkTemporaryFile'
            Action      = 'Clear-TkTemporaryFile'
            Elevated    = $false
            Reversible  = 'Deleted files are not recoverable, but nothing here is meant to persist.'
        }

        'disable-smbv1' = @{
            Name        = 'Remove SMBv1'
            Explanation = 'Disables the SMB1Protocol optional feature. SMBv1 is the protocol WannaCry and NotPetya spread over, and nothing modern needs it. Takes effect at the next restart.'
            Command     = 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
            Action      = 'Repair-TkSmbV1'
            Elevated    = $true
            Reversible  = 'Enable-WindowsOptionalFeature on the same feature, if a genuinely legacy device needs it.'
        }

        'disable-powershell-v2' = @{
            Name        = 'Remove the PowerShell 2.0 engine'
            Explanation = 'Disables the downgrade engine, which bypasses script block logging, AMSI and constrained language mode. Attackers ask for it by name.'
            Command     = 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
            Action      = 'Repair-TkPowerShellV2'
            Elevated    = $true
            Reversible  = 'Re-enable the feature. Almost nothing legitimately needs it.'
        }
    }
}

<#
.SYNOPSIS
    Applies one correction from the allow list.

.DESCRIPTION
    Resolves the identifier through the table and calls the registered
    function. An identifier that is not in the table is refused, which is what
    keeps a catalog file from becoming executable.

.PARAMETER Id
    Remediation identifier.

.OUTPUTS
    System.Boolean
#>
function Invoke-TkRemediation {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Id
    )

    $table = Get-TkRemediationTable

    if (-not $table.ContainsKey($Id)) {

        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'Refused: "{0}" is not a registered correction.' -f $Id
        )

        return $false
    }

    $entry = $table[$Id]

    if ($entry.Elevated -and -not (Assert-TkElevated -Operation ('Correction: {0}' -f $entry.Name))) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($entry.Name, 'Apply correction')) {
        return $false
    }

    $stopwatch = Start-TkOperation -Name ('Correction: {0}' -f $entry.Name) -Category 'Remediation'

    try {
        $result  = & $entry.Action -Confirm:$false
        $success = ($result -ne $false)
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            '{0} failed: {1}' -f $entry.Name, $_.Exception.Message
        )

        $success = $false
    }

    Stop-TkOperation -Name ('Correction: {0}' -f $entry.Name) -Stopwatch $stopwatch `
                     -Category 'Remediation' -Success $success

    return $success
}

# ---------------------------------------------------------------------------
# The corrections themselves
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Disables AutoRun on every drive type.

.OUTPUTS
    System.Boolean
#>
function Repair-TkAutoRun {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('AutoRun on every drive type', 'Apply the correction')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                                -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Disables LLMNR by policy.

.OUTPUTS
    System.Boolean
#>
function Repair-TkLlmnr {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('LLMNR', 'Apply the correction')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                                -Name 'EnableMulticast' -Value 0 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Stops WDigest keeping plain text credentials in memory.

.OUTPUTS
    System.Boolean
#>
function Repair-TkWdigest {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('WDigest credential caching', 'Apply the correction')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                                -Name 'UseLogonCredential' -Value 0 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Turns on LSA protection.

.OUTPUTS
    System.Boolean
#>
function Repair-TkLsaProtection {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('LSA protection', 'Apply the correction')) {
        return $false
    }

    $applied = Set-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                                   -Name 'RunAsPPL' -Value 1 -Type DWord -Confirm:$false

    if ($applied) {
        Write-TkLog -Level Warning -Category 'Remediation' -Message (
            'LSA protection takes effect at the next restart.'
        )
    }

    return $applied
}

<#
.SYNOPSIS
    Enables PowerShell script block logging.

.OUTPUTS
    System.Boolean
#>
function Repair-TkScriptBlockLogging {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('PowerShell script block logging', 'Apply the correction')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                                -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Sets the LAN Manager authentication level to NTLMv2 only.

.OUTPUTS
    System.Boolean
#>
function Repair-TkLmCompatibility {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('the LAN Manager authentication level', 'Apply the correction')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                                -Name 'LmCompatibilityLevel' -Value 5 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Enables every firewall profile.

.OUTPUTS
    System.Boolean
#>
function Repair-TkFirewallProfiles {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable every firewall profile')) {
        return $false
    }

    try {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Remediation' -Message 'Every firewall profile enabled.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'The firewall profiles could not be enabled: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Disables the built in Guest account.

.OUTPUTS
    System.Boolean
#>
function Repair-TkGuestAccount {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable the Guest account')) {
        return $false
    }

    try {
        # Matched on the well known RID suffix, because the name is localised
        # and can be changed.
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' }

        if (-not $guest) {
            Write-TkLog -Level Information -Category 'Remediation' -Message 'No Guest account on this machine.'
            return $true
        }

        Disable-LocalUser -SID $guest.SID -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Remediation' -Message (
            'Guest account "{0}" disabled.' -f $guest.Name
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'The Guest account could not be disabled: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Updates the Defender signatures now.

.OUTPUTS
    System.Boolean
#>
function Repair-TkSignatures {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Update the antivirus signatures')) {
        return $false
    }

    try {
        Update-MpSignature -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Remediation' -Message 'Signatures updated.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'The signatures could not be updated: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Starts the print spooler and sets it to start automatically.

.OUTPUTS
    System.Boolean
#>
function Repair-TkSpooler {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Start the print spooler')) {
        return $false
    }

    try {
        Set-Service -Name 'Spooler' -StartupType Automatic -ErrorAction Stop
        Start-Service -Name 'Spooler' -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Remediation' -Message 'Print spooler started.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'The spooler could not be started: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Removes the SMBv1 optional feature.

.OUTPUTS
    System.Boolean
#>
function Repair-TkSmbV1 {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    return (Disable-TkOptionalFeature -FeatureName 'SMB1Protocol')
}

<#
.SYNOPSIS
    Removes the PowerShell 2.0 engine.

.OUTPUTS
    System.Boolean
#>
function Repair-TkPowerShellV2 {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    return (Disable-TkOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2Root')
}

<#
.SYNOPSIS
    Disables an optional Windows feature without restarting.

.DESCRIPTION
    Shared by the two feature removals. A feature that is already disabled is
    reported as success, so re-running a correction is harmless.

.OUTPUTS
    System.Boolean
#>
function Disable-TkOptionalFeature {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $FeatureName
    )

    if (-not $PSCmdlet.ShouldProcess($FeatureName, 'Disable the optional feature')) {
        return $false
    }

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop

        if ($feature.State -ne 'Enabled') {

            Write-TkLog -Level Information -Category 'Remediation' -Message (
                '{0} is already disabled.' -f $FeatureName
            )

            return $true
        }

        Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop | Out-Null

        Write-TkLog -Level Warning -Category 'Remediation' -Message (
            '{0} disabled. A restart is needed to complete it.' -f $FeatureName
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            '{0} could not be disabled: {1}' -f $FeatureName, $_.Exception.Message
        )

        return $false
    }
}
