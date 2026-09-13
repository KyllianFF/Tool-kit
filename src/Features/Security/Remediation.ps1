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

        # --- Corrections that open the page where the change is made ---------
        #
        # An Open entry never changes the machine. Its target is checked by
        # Test-TkRemediationTarget against a closed list, for the same reason a
        # Fix names a function rather than a command line: the table is code
        # that gets reviewed, and nothing reaching it can widen what it runs.

        'open-windows-security' = @{
            Kind        = 'Open'
            Name        = 'Open Windows Security, virus and threat protection'
            Explanation = 'Shows which antivirus or EDR Windows considers active, and lets you start it, update it, or open the product that owns protection.'
            Target      = 'windowsdefender://threat'
            Elevated    = $false
        }

        'open-defender-settings' = @{
            Kind        = 'Open'
            Name        = 'Open the Microsoft Defender protection settings'
            Explanation = 'Tamper protection can only be turned on by a person, from this page, or by Intune on a managed estate. Windows refuses it from a script on purpose, so that malware cannot turn it off the same way.'
            Target      = 'windowsdefender://threatsettings'
            Elevated    = $false
        }

        'open-windows-update' = @{
            Kind        = 'Open'
            Name        = 'Open Windows Update'
            Explanation = 'Check for updates, resume a pause, and see what is waiting for a restart. Installing is left to Windows Update, which knows the order updates need.'
            Target      = 'ms-settings:windowsupdate'
            Elevated    = $false
        }

        'open-remote-desktop' = @{
            Kind        = 'Open'
            Name        = 'Open the Remote Desktop settings'
            Explanation = 'Turn Remote Desktop off if nobody manages this machine through it. It is not switched off from here, because that would cut off an administrator connected through it right now.'
            Target      = 'ms-settings:remotedesktop'
            Elevated    = $false
        }

        'open-bitlocker' = @{
            Kind        = 'Open'
            Name        = 'Open BitLocker Drive Encryption'
            Explanation = 'Turn BitLocker on for each drive, choose how it unlocks, and back up the recovery key. Encryption is not started from here, because the recovery key has to be saved somewhere you choose before it is safe to start.'
            Target      = 'control.exe /name Microsoft.BitLockerDriveEncryption'
            Fallback    = 'ms-settings:deviceencryption'
            Elevated    = $false
        }

        'open-local-users' = @{
            Kind        = 'Open'
            Name        = 'Open Local Users and Groups'
            Explanation = 'Review the accounts named in the finding: remove from Administrators the ones that do not need it, and disable or set an expiry on the ones nobody owns. Which account belongs here is a decision the toolkit cannot make.'
            Target      = 'lusrmgr.msc'
            Fallback    = 'ms-settings:otherusers'
            Elevated    = $false
        }

        'open-laps-guide' = @{
            Kind        = 'Open'
            Name        = 'Open the Windows LAPS deployment guide'
            Button      = 'Open guide'
            Explanation = 'LAPS is configured by a directory or Intune policy rather than on the machine, so there is no local setting to change. The guide covers the schema update and the policy.'
            Target      = 'https://learn.microsoft.com/windows-server/identity/laps/laps-overview'
            Elevated    = $false
        }

        # --- Corrections applied in one step ----------------------------------

        'set-account-lockout' = @{
            Kind        = 'Fix'
            Name        = 'Lock an account after ten bad passwords'
            Explanation = 'Sets the local lockout threshold to 10 attempts, with a 15 minute lockout and a 15 minute counting window, as CIS and the ANSSI ask. On a domain joined machine the domain policy still decides for domain accounts.'
            Command     = 'net accounts /lockoutthreshold:10 ; net accounts /lockoutduration:15 /lockoutwindow:15'
            Action      = 'Repair-TkAccountLockout'
            Elevated    = $true
            Reversible  = 'net accounts /lockoutthreshold:0 removes the lockout again.'
        }

        'set-password-length' = @{
            Kind        = 'Fix'
            Name        = 'Require passwords of at least 12 characters'
            Explanation = 'Sets the local minimum password length to 12. It applies the next time a local password is changed: nobody is locked out, and Microsoft or Entra accounts are not affected.'
            Command     = 'net accounts /minpwlen:12'
            Action      = 'Repair-TkPasswordLength'
            Elevated    = $true
            Reversible  = 'net accounts /minpwlen:0 removes the minimum.'
        }

        'set-inactivity-lock' = @{
            Kind        = 'Fix'
            Name        = 'Lock the session after 15 minutes idle'
            Explanation = 'Sets the machine inactivity limit to 900 seconds by policy, so the session locks by itself and asks for the password whatever the screen saver settings say. It cannot be turned off from the desktop.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" InactivityTimeoutSecs 900'
            Action      = 'Repair-TkInactivityLock'
            Elevated    = $true
            Reversible  = 'Delete the InactivityTimeoutSecs value.'
        }

        'disable-winrm' = @{
            Kind        = 'Fix'
            Name        = 'Stop and disable WinRM'
            Explanation = 'Stops the WinRM service and disables it, which closes remote PowerShell on this machine. Do not apply it to a machine managed over WinRM: the management tool would lose its way in.'
            Command     = 'Stop-Service WinRM ; Set-Service WinRM -StartupType Disabled'
            Action      = 'Repair-TkWinRm'
            Elevated    = $true
            Reversible  = 'Enable-PSRemoting turns it back on.'
        }

        'enable-uac' = @{
            Kind        = 'Fix'
            Name        = 'Turn User Account Control back on'
            Explanation = 'Sets EnableLUA to 1. With UAC off, every program an administrator starts runs with full rights. Takes effect at the next restart.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 1'
            Action      = 'Repair-TkUacEnabled'
            Elevated    = $true
            Reversible  = 'Set EnableLUA back to 0 and restart.'
        }

        'restart-to-firmware' = @{
            Kind        = 'Fix'
            Name        = 'Restart into the firmware settings'
            Button      = 'Restart to firmware'
            Explanation = 'Restarts the computer in 60 seconds straight into its UEFI settings, where Secure Boot and the TPM are switched on (the TPM is often called PTT on Intel boards and fTPM on AMD). Open programs are closed and unsaved work is lost: save it first.'
            Command     = 'shutdown.exe /r /fw /t 60'
            Action      = 'Restart-TkToFirmware'
            Elevated    = $true
            Reversible  = 'Run "shutdown /a /fw" within the 60 seconds to cancel.'
        }

        'enable-credential-guard' = @{
            Kind        = 'Fix'
            Name        = 'Turn on Credential Guard, without UEFI lock'
            Explanation = 'Turns on virtualisation based security and Credential Guard through the registry, as Microsoft documents it. Without the UEFI lock it can be turned off again later. Takes effect at the next restart; some old VPN clients and hypervisors do not work with it.'
            Command     = 'DeviceGuard: EnableVirtualizationBasedSecurity 1, RequirePlatformSecurityFeatures 1 ; Lsa: LsaCfgFlags 2'
            Action      = 'Repair-TkCredentialGuard'
            Elevated    = $true
            Reversible  = 'Set LsaCfgFlags to 0 and restart.'
        }

        'asr-audit-mode' = @{
            Kind        = 'Fix'
            Name        = 'Add the core ASR rules in audit mode'
            Explanation = 'Adds up to eight Attack Surface Reduction rules in audit mode: nothing is blocked, each rule only records what it would have stopped. Rules already configured are left exactly as they are. Review the events for a few weeks, then move the rules to block; this control keeps its warning until then, deliberately.'
            Command     = 'Add-MpPreference -AttackSurfaceReductionRules_Ids <rules not yet configured> -AttackSurfaceReductionRules_Actions AuditMode'
            Action      = 'Repair-TkAsrAuditMode'
            Elevated    = $true
            Reversible  = 'Remove-MpPreference -AttackSurfaceReductionRules_Ids with the same rules.'
        }

        'enable-baseline-audit-policy' = @{
            Kind        = 'Fix'
            Name        = 'Record the baseline security events'
            Explanation = 'Turns on success and failure auditing for logon, special logon, credential validation, account lockout, user and group management, audit policy changes and process creation. These are the events an investigation needs and cannot recover afterwards. A domain audit policy, where there is one, replaces this at its next refresh.'
            Command     = 'auditpol /set /subcategory:<8 subcategories by GUID> /success:enable /failure:enable'
            Action      = 'Repair-TkAuditPolicyBaseline'
            Elevated    = $true
            Reversible  = 'auditpol /set with the same subcategories and /success:disable /failure:disable.'
        }

        'require-smb-signing' = @{
            Kind        = 'Fix'
            Name        = 'Require SMB signing'
            Explanation = 'Requires signing on both the SMB client and the SMB server, which defeats NTLM relay against file shares. A very old NAS or printer that cannot sign stops being reachable: check first that nothing on the network depends on one.'
            Command     = 'Set-SmbClientConfiguration -RequireSecuritySignature $true ; Set-SmbServerConfiguration -RequireSecuritySignature $true'
            Action      = 'Repair-TkSmbSigning'
            Elevated    = $true
            Reversible  = 'Run the same two commands with $false.'
        }

        'resume-bitlocker' = @{
            Kind        = 'Fix'
            Name        = 'Resume BitLocker protection'
            Explanation = 'Resumes protection on every drive where BitLocker is suspended. While suspended the key sits unprotected on the drive: the data is encrypted, but anyone holding the drive can read it.'
            Command     = 'Resume-BitLocker -MountPoint <each suspended drive>'
            Action      = 'Resume-TkBitLockerProtection'
            Elevated    = $true
            Reversible  = 'Suspend-BitLocker, which Windows also does by itself before a firmware update.'
        }

        'enable-rdp-nla' = @{
            Kind        = 'Fix'
            Name        = 'Require Network Level Authentication for Remote Desktop'
            Explanation = 'Sets UserAuthentication to 1, so a client proves who it is before the server creates a session. Without it, anything that reaches the port gets a logon screen to attack.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" UserAuthentication 1'
            Action      = 'Repair-TkRdpNla'
            Elevated    = $true
            Reversible  = 'Set the value back to 0. Only needed for clients too old to support NLA, which should not be reaching this machine anyway.'
        }

        'restore-uac-prompt' = @{
            Kind        = 'Fix'
            Name        = 'Make UAC prompt again for administrators'
            Explanation = 'Sets ConsentPromptBehaviorAdmin to 2, the prompt on the secure desktop. Left at 0, an administrator elevates silently and so does anything running as that administrator.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin 2'
            Action      = 'Repair-TkUacPrompt'
            Elevated    = $true
            Reversible  = 'Set the value back to what it was. The Windows default is 5.'
        }

        'disable-autorun' = @{
            Kind        = 'Fix'
            Name        = 'Disable AutoRun on every drive type'
            Explanation = 'Sets NoDriveTypeAutoRun to 255, which stops anything starting on its own when removable media is inserted.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" NoDriveTypeAutoRun 255'
            Action      = 'Repair-TkAutoRun'
            Elevated    = $true
            Reversible  = 'Set the value back to 145, the Windows default.'
        }

        'disable-llmnr' = @{
            Kind        = 'Fix'
            Name        = 'Disable LLMNR'
            Explanation = 'Sets EnableMulticast to 0 by policy. Nothing on a network with working DNS needs LLMNR, and it is what Responder abuses to capture NTLM hashes.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" EnableMulticast 0'
            Action      = 'Repair-TkLlmnr'
            Elevated    = $true
            Reversible  = 'Delete the value to return to the default.'
        }

        'disable-wdigest' = @{
            Kind        = 'Fix'
            Name        = 'Stop WDigest caching plain text passwords'
            Explanation = 'Sets UseLogonCredential to 0, so Windows stops keeping the plain text password in LSASS.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential 0'
            Action      = 'Repair-TkWdigest'
            Elevated    = $true
            Reversible  = 'Nothing modern requires the old behaviour, so there is no reason to undo it.'
        }

        'enable-lsa-protection' = @{
            Kind        = 'Fix'
            Name        = 'Run LSASS as a protected process'
            Explanation = 'Sets RunAsPPL to 1. A protected LSASS cannot be opened by an ordinary administrator process, which blocks the most direct route to credential dumping. Takes effect at the next restart.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL 1'
            Action      = 'Repair-TkLsaProtection'
            Elevated    = $true
            Reversible  = 'Set RunAsPPL to 0 and restart. Check first that no security product needs to inject into LSASS.'
        }

        'enable-script-block-logging' = @{
            Kind        = 'Fix'
            Name        = 'Enable PowerShell script block logging'
            Explanation = 'Records PowerShell after it has been de-obfuscated, into the event log. The single most useful piece of telemetry on Windows during an investigation.'
            Command     = 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging 1'
            Action      = 'Repair-TkScriptBlockLogging'
            Elevated    = $true
            Reversible  = 'Delete the value. Expect a noticeable volume of events on a busy machine.'
        }

        'set-lm-level' = @{
            Kind        = 'Fix'
            Name        = 'Send NTLMv2 only'
            Explanation = 'Sets LmCompatibilityLevel to 5, which refuses LM and NTLMv1 responses. Those are trivially crackable when captured.'
            Command     = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" LmCompatibilityLevel 5'
            Action      = 'Repair-TkLmCompatibility'
            Elevated    = $true
            Reversible  = 'Delete the value. Confirm first that no legacy appliance still needs NTLMv1.'
        }

        'enable-firewall' = @{
            Kind        = 'Fix'
            Name        = 'Enable every firewall profile'
            Explanation = 'Turns the Domain, Private and Public profiles back on. The public profile is the one that matters on hotel and client networks.'
            Command     = 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'
            Action      = 'Repair-TkFirewallProfiles'
            Elevated    = $true
            Reversible  = 'Disabling a profile again is one command, but there is rarely a reason.'
        }

        'disable-guest' = @{
            Kind        = 'Fix'
            Name        = 'Disable the Guest account'
            Explanation = 'Disables the built in Guest account, which permits unauthenticated access to shared resources.'
            Command     = 'Disable-LocalUser -SID <the account ending in -501>'
            Action      = 'Repair-TkGuestAccount'
            Elevated    = $true
            Reversible  = 'Enable-LocalUser on the same account.'
        }

        'update-signatures' = @{
            Kind        = 'Fix'
            Name        = 'Update the antivirus signatures'
            Explanation = 'Forces Defender to fetch current definitions now rather than waiting for its schedule.'
            Command     = 'Update-MpSignature'
            Action      = 'Repair-TkSignatures'
            Elevated    = $true
            Reversible  = 'Nothing to undo.'
        }

        'start-spooler' = @{
            Kind        = 'Fix'
            Name        = 'Start the print spooler'
            Explanation = 'Starts the Spooler service and sets it to start automatically. Nothing prints until it is running.'
            Command     = 'Set-Service Spooler -StartupType Automatic; Start-Service Spooler'
            Action      = 'Repair-TkSpooler'
            Elevated    = $true
            Reversible  = 'Stop the service and set it to Disabled again.'
        }

        'clear-temp' = @{
            Kind        = 'Fix'
            Name        = 'Delete temporary files'
            Explanation = 'Empties the user and system temporary folders and the prefetch cache. Files locked by a running process are skipped.'
            Command     = 'Clear-TkTemporaryFile'
            Action      = 'Clear-TkTemporaryFile'
            Elevated    = $false
            Reversible  = 'Deleted files are not recoverable, but nothing here is meant to persist.'
        }

        'disable-smbv1' = @{
            Kind        = 'Fix'
            Name        = 'Remove SMBv1'
            Explanation = 'Disables the SMB1Protocol optional feature. SMBv1 is the protocol WannaCry and NotPetya spread over, and nothing modern needs it. Takes effect at the next restart.'
            Command     = 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
            Action      = 'Repair-TkSmbV1'
            Elevated    = $true
            Reversible  = 'Enable-WindowsOptionalFeature on the same feature, if a genuinely legacy device needs it.'
        }

        'disable-powershell-v2' = @{
            Kind        = 'Fix'
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

    # An Open entry has nothing to run. Refused by name rather than left to
    # fail on a missing Action, so the log says what actually happened.
    if ([string] $entry.Kind -eq 'Open') {

        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'Refused: "{0}" opens a page and changes nothing. Use Open-TkRemediationTarget.' -f $Id
        )

        return $false
    }

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
    Says whether a target may be opened by an Open correction.

.DESCRIPTION
    The closed list behind every "open settings" button.

    Open-TkUri refuses anything that is not a web address, on purpose. Opening
    a Windows page needs a different door, so this one is narrow in its own
    way: a Settings or Windows Security page by name, a page on Microsoft
    Learn, or one of two named Windows tools, matched exactly. No file paths,
    no other programs, nothing that could carry a second command.

.PARAMETER Target
    The target as written in the correction table.

.OUTPUTS
    System.Boolean
#>
function Test-TkRemediationTarget {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Target
    )

    if ($Target -cmatch '^ms-settings:[a-z-]+$') {
        return $true
    }

    if ($Target -cmatch '^windowsdefender://[a-z]+$') {
        return $true
    }

    if ($Target -cmatch '^https://learn\.microsoft\.com/[A-Za-z0-9/._-]+$') {
        return $true
    }

    $tools = @(
        'control.exe /name Microsoft.BitLockerDriveEncryption'
        'lusrmgr.msc'
    )

    return ($tools -ccontains $Target)
}

<#
.SYNOPSIS
    Opens the page an Open correction points at.

.DESCRIPTION
    Tries the target, then the fallback when there is one. The fallback exists
    for editions that lack the first tool: Home has no Local Users and Groups,
    so it gets the accounts page of Settings instead.

    Every target is checked again here rather than trusted because it came
    from the table, so a table edit that slipped past review still cannot
    launch anything the list does not allow.

.PARAMETER Id
    Key of an Open entry in the correction table.

.OUTPUTS
    System.Boolean, true when something was opened.
#>
function Open-TkRemediationTarget {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Id
    )

    $table = Get-TkRemediationTable

    if (-not $table.ContainsKey($Id) -or [string] $table[$Id].Kind -ne 'Open') {

        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'Refused: "{0}" is not a registered page to open.' -f $Id
        )

        return $false
    }

    $entry = $table[$Id]

    if (-not $PSCmdlet.ShouldProcess($entry.Name, 'Open')) {
        return $false
    }

    foreach ($target in @($entry.Target, $entry.Fallback)) {

        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }

        if (-not (Test-TkRemediationTarget -Target $target)) {

            Write-TkLog -Level Error -Category 'Remediation' -Message (
                'Refused to open "{0}": not on the list of pages a correction may open.' -f $target
            )

            continue
        }

        # A snap-in missing from this edition is looked for first, so Home
        # goes straight to the fallback.
        if ($target -like '*.msc' -and
            -not (Test-Path -LiteralPath (Join-Path $env:SystemRoot ('System32\{0}' -f $target)))) {
            continue
        }

        try {
            if ($target -like 'https://*') {

                if (Open-TkUri -Uri $target) {
                    return $true
                }

                continue
            }

            $parts = $target -split ' ', 2

            if ($parts.Count -eq 2) {
                Start-Process -FilePath $parts[0] -ArgumentList $parts[1] -ErrorAction Stop
            }
            else {
                Start-Process -FilePath $target -ErrorAction Stop
            }

            Write-TkLog -Level Information -Category 'Remediation' -Message ('Opened {0}' -f $target)

            return $true
        }
        catch {
            Write-TkLog -Level Warning -Category 'Remediation' -Message (
                'Could not open {0}: {1}' -f $target, $_.Exception.Message
            )
        }
    }

    return $false
}

<#
.SYNOPSIS
    Sets the local account lockout policy.
#>
function Repair-TkAccountLockout {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('Local account policy', 'Lock an account after ten bad passwords')) {
        return $false
    }

    # The threshold on its own first: the duration and the window only mean
    # something once there is a threshold for them to apply to.
    $threshold = Invoke-TkProcess -FilePath 'net.exe' -ArgumentList @('accounts', '/lockoutthreshold:10') -TimeoutSeconds 30

    if ($threshold.ExitCode -ne 0) {
        return $false
    }

    $timing = Invoke-TkProcess -FilePath 'net.exe' `
                               -ArgumentList @('accounts', '/lockoutduration:15', '/lockoutwindow:15') -TimeoutSeconds 30

    return ($timing.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Sets the local minimum password length to 12.
#>
function Repair-TkPasswordLength {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('Local password policy', 'Require at least 12 characters')) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'net.exe' -ArgumentList @('accounts', '/minpwlen:12') -TimeoutSeconds 30

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Locks the session after fifteen minutes idle, by machine policy.
#>
function Repair-TkInactivityLock {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('Interactive logon', 'Lock after 900 seconds idle')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                                -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Stops WinRM and disables it.
#>
function Repair-TkWinRm {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('WinRM service', 'Stop and disable')) {
        return $false
    }

    try {
        Stop-Service -Name 'WinRM' -Force -ErrorAction Stop
        Set-Service -Name 'WinRM' -StartupType Disabled -ErrorAction Stop

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'WinRM could not be disabled: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Turns User Account Control back on.
#>
function Repair-TkUacEnabled {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('User Account Control', 'Turn on')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                                -Name 'EnableLUA' -Value 1 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Schedules a restart into the firmware settings, sixty seconds out.

.DESCRIPTION
    Secure Boot and the TPM are switched on in the firmware and nowhere else,
    so the most a tool running in Windows can do is take the operator there.
    Sixty seconds rather than none, so the dialog that confirmed it is not the
    last thing on screen before unsaved work disappears.
#>
function Restart-TkToFirmware {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('This computer', 'Restart into the firmware settings in 60 seconds')) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'shutdown.exe' -ArgumentList @('/r', '/fw', '/t', '60') -TimeoutSeconds 30

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Turns on Credential Guard without UEFI lock, where the edition has it.
#>
function Repair-TkCredentialGuard {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Test-TkCredentialGuardEdition)) {

        Write-TkLog -Level Warning -Category 'Remediation' -Message (
            'Credential Guard needs Windows Enterprise or Education. Nothing was changed.'
        )

        return $false
    }

    if (-not $PSCmdlet.ShouldProcess('Credential Guard', 'Turn on without UEFI lock')) {
        return $false
    }

    $deviceGuard = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'

    # Values from Microsoft's "Configure Credential Guard" page: 2 is enabled
    # without lock, which keeps the change reversible.
    $applied = (Set-TkRegistryValue -Path $deviceGuard -Name 'EnableVirtualizationBasedSecurity' `
                                    -Value 1 -Type DWord -Confirm:$false) -and
               (Set-TkRegistryValue -Path $deviceGuard -Name 'RequirePlatformSecurityFeatures' `
                                    -Value 1 -Type DWord -Confirm:$false) -and
               (Set-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' `
                                    -Value 2 -Type DWord -Confirm:$false)

    return [bool] $applied
}

<#
.SYNOPSIS
    Returns the Attack Surface Reduction rules the audit mode correction adds.

.DESCRIPTION
    Every identifier here was checked against Microsoft's ASR rules reference.
    A rule is added by GUID alone, so a mistyped one would be a rule that
    protects against nothing, with no error to say so.

.OUTPUTS
    PSCustomObject[] with Id and Name.
#>
function Get-TkAsrBaselineRule {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Id = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Name = 'Block executable content from email client and webmail' }
        [pscustomobject] @{ Id = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; Name = 'Block all Office applications from creating child processes' }
        [pscustomobject] @{ Id = '3b576869-a4ec-4529-8536-b80a7769e899'; Name = 'Block Office applications from creating executable content' }
        [pscustomobject] @{ Id = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Name = 'Block Office applications from injecting code into other processes' }
        [pscustomobject] @{ Id = 'd3e037e1-3eb8-44c8-a917-57927947596d'; Name = 'Block JavaScript or VBScript from launching downloaded executable content' }
        [pscustomobject] @{ Id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Name = 'Block credential stealing from the Windows local security authority subsystem' }
        [pscustomobject] @{ Id = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; Name = 'Block persistence through WMI event subscription' }
        [pscustomobject] @{ Id = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; Name = 'Block process creations originating from PSExec and WMI commands' }
    )
}

<#
.SYNOPSIS
    Adds the baseline ASR rules in audit mode, leaving configured rules alone.

.DESCRIPTION
    Add-MpPreference replaces the action of a rule that is already there. Sent
    blindly, it would turn a rule someone had set to block back into audit,
    which is a correction that weakens the machine. Only rules not configured
    at all are added.
#>
function Repair-TkAsrAuditMode {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('Attack Surface Reduction', 'Add the baseline rules in audit mode')) {
        return $false
    }

    try {
        $configured = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids |
                        ForEach-Object { ([string] $_).ToLowerInvariant() })

        $missing = @(Get-TkAsrBaselineRule | Where-Object { $configured -notcontains $_.Id })

        if ($missing.Count -eq 0) {
            Write-TkLog -Level Information -Category 'Remediation' -Message 'Every baseline ASR rule is already configured.'
            return $true
        }

        Add-MpPreference -AttackSurfaceReductionRules_Ids @($missing | ForEach-Object { $_.Id }) `
                         -AttackSurfaceReductionRules_Actions @($missing | ForEach-Object { 'AuditMode' }) `
                         -ErrorAction Stop

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'The ASR rules could not be added: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Turns on success and failure auditing for the baseline subcategories.
#>
function Repair-TkAuditPolicyBaseline {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('Audit policy', 'Record the baseline security events')) {
        return $false
    }

    # By GUID, never by name: auditpol only accepts names in the language of
    # the machine.
    $subcategories = (@(Get-TkAuditPolicyBaseline) | ForEach-Object { $_.Guid }) -join ','

    $result = Invoke-TkProcess -FilePath 'auditpol.exe' `
                               -ArgumentList @('/set', ('/subcategory:{0}' -f $subcategories), '/success:enable', '/failure:enable') `
                               -TimeoutSeconds 30

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Requires SMB signing on the client and the server.
#>
function Repair-TkSmbSigning {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('SMB client and server', 'Require signing')) {
        return $false
    }

    try {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -Confirm:$false -ErrorAction Stop
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false -ErrorAction Stop

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'SMB signing could not be required: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Resumes BitLocker protection on every suspended drive.
#>
function Resume-TkBitLockerProtection {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('BitLocker', 'Resume protection on suspended drives')) {
        return $false
    }

    try {
        $suspended = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object {
            [string] $_.ProtectionStatus -eq 'Off' -and [string] $_.VolumeStatus -eq 'FullyEncrypted'
        })

        foreach ($volume in $suspended) {
            [void] (Resume-BitLocker -MountPoint $volume.MountPoint -ErrorAction Stop)
        }

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Remediation' -Message (
            'BitLocker protection could not be resumed: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Requires Network Level Authentication for Remote Desktop.
#>
function Repair-TkRdpNla {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('Remote Desktop', 'Require Network Level Authentication')) {
        return $false
    }

    return (Set-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                                -Name 'UserAuthentication' -Value 1 -Type DWord -Confirm:$false)
}

<#
.SYNOPSIS
    Makes UAC prompt on the secure desktop again.
#>
function Repair-TkUacPrompt {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess('User Account Control', 'Prompt administrators on the secure desktop')) {
        return $false
    }

    # 2 is "prompt for consent on the secure desktop": it asks, and nothing
    # running in the user's session can answer for them.
    return (Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                                -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord -Confirm:$false)
}

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
