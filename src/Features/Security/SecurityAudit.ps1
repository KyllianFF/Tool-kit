<#
    Toolkit - Features / Local security audit

    A read only posture check of the workstation in front of you. Every item
    is a control a technician can actually change, and every finding carries
    the reason it matters rather than only a red marker.

    This is a hygiene check, not a compliance audit. It does not replace a
    CIS benchmark run, and it says so in the report header.
#>

<#
.SYNOPSIS
    Runs every local security check and returns the findings.

.OUTPUTS
    PSCustomObject[] with Id, Name, Category, Status, Detail and Recommendation.
#>
function Invoke-TkSecurityAudit {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $stopwatch = Start-TkOperation -Name 'Local security audit' -Category 'Audit'

    $checks = @(
        'Test-TkAuditBitLocker',
        'Test-TkAuditSecureBoot',
        'Test-TkAuditTpm',
        'Test-TkAuditDefender',
        'Test-TkAuditFirewall',
        'Test-TkAuditSmbV1',
        'Test-TkAuditLlmnr',
        'Test-TkAuditPowerShellV2',
        'Test-TkAuditRemoteDesktop',
        'Test-TkAuditUac',
        'Test-TkAuditGuestAccount',
        'Test-TkAuditLocalAdministrators',
        'Test-TkAuditWindowsUpdate',
        'Test-TkAuditAutoPlay',
        'Test-TkAuditPasswordPolicy'
    )

    $findings = @()

    foreach ($check in $checks) {

        try {
            $findings += & $check
        }
        catch {
            Write-TkLog -Level Warning -Category 'Audit' -Message (
                '{0} could not run: {1}' -f $check, $_.Exception.Message
            )
        }
    }

    $failed = @($findings | Where-Object { $_.Status -eq 'Fail' }).Count

    Stop-TkOperation -Name 'Local security audit' -Stopwatch $stopwatch -Category 'Audit'

    Write-TkLog -Level Information -Category 'Audit' -Message (
        'Audit finished: {0} checks, {1} failing.' -f $findings.Count, $failed
    )

    return $findings
}

<#
.SYNOPSIS
    Builds a finding object.

.DESCRIPTION
    Single constructor so every check produces the same shape, which is what
    lets the interface bind them to one grid.

.OUTPUTS
    PSCustomObject
#>
function New-TkAuditFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Category,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info')]
        [string] $Status,

        [Parameter(Mandatory)] [string] $Detail,
        [Parameter()]          [string] $Recommendation = ''
    )

    return [pscustomobject]@{
        Id             = $Id
        Name           = $Name
        Category       = $Category
        Status         = $Status
        Detail         = $Detail
        Recommendation = $Recommendation
    }
}

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks whether the system drive is encrypted.
#>
function Test-TkAuditBitLocker {
    [CmdletBinding()]
    param()

    try {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

        if ($volume.ProtectionStatus -eq 'On') {

            return New-TkAuditFinding -Id 'ENC-001' -Name 'Disk encryption' -Category 'Data protection' `
                -Status 'Pass' -Detail ('BitLocker is on ({0}, {1}% encrypted).' -f $volume.EncryptionMethod, $volume.EncryptionPercentage)
        }

        return New-TkAuditFinding -Id 'ENC-001' -Name 'Disk encryption' -Category 'Data protection' `
            -Status 'Fail' -Detail 'The system drive is not encrypted.' `
            -Recommendation 'Enable BitLocker. A stolen laptop without it is a data breach, not a hardware loss.'
    }
    catch {
        return New-TkAuditFinding -Id 'ENC-001' -Name 'Disk encryption' -Category 'Data protection' `
            -Status 'Info' -Detail 'BitLocker state could not be read (needs elevation, or an edition without it).'
    }
}

<#
.SYNOPSIS
    Checks the Secure Boot state.
#>
function Test-TkAuditSecureBoot {
    [CmdletBinding()]
    param()

    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) {

            return New-TkAuditFinding -Id 'BOOT-001' -Name 'Secure Boot' -Category 'Platform' `
                -Status 'Pass' -Detail 'Secure Boot is enabled.'
        }

        return New-TkAuditFinding -Id 'BOOT-001' -Name 'Secure Boot' -Category 'Platform' `
            -Status 'Fail' -Detail 'Secure Boot is disabled.' `
            -Recommendation 'Enable Secure Boot in the firmware. Without it a bootkit can load before Windows does.'
    }
    catch {
        return New-TkAuditFinding -Id 'BOOT-001' -Name 'Secure Boot' -Category 'Platform' `
            -Status 'Info' -Detail 'Not readable: the machine is in legacy BIOS mode, or elevation is missing.'
    }
}

<#
.SYNOPSIS
    Checks for a usable TPM.
#>
function Test-TkAuditTpm {
    [CmdletBinding()]
    param()

    $tpm = Get-TkCimInstanceSafe -ClassName 'Win32_Tpm' -Namespace 'Root\CIMV2\Security\MicrosoftTpm'

    if (-not $tpm) {

        return New-TkAuditFinding -Id 'TPM-001' -Name 'TPM' -Category 'Platform' `
            -Status 'Warning' -Detail 'No TPM was detected.' `
            -Recommendation 'A TPM is required for BitLocker without a startup key and for Windows 11 support.'
    }

    if ($tpm.IsEnabled_InitialValue -and $tpm.IsActivated_InitialValue) {

        return New-TkAuditFinding -Id 'TPM-001' -Name 'TPM' -Category 'Platform' `
            -Status 'Pass' -Detail ('TPM {0} is enabled and activated.' -f $tpm.SpecVersion)
    }

    return New-TkAuditFinding -Id 'TPM-001' -Name 'TPM' -Category 'Platform' `
        -Status 'Fail' -Detail 'A TPM is present but not enabled or not activated.' `
        -Recommendation 'Enable the TPM in the firmware.'
}

<#
.SYNOPSIS
    Checks Microsoft Defender real time protection and signature age.
#>
function Test-TkAuditDefender {
    [CmdletBinding()]
    param()

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        if (-not $status.RealTimeProtectionEnabled) {

            return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus' -Category 'Endpoint' `
                -Status 'Fail' -Detail 'Defender real time protection is disabled.' `
                -Recommendation 'Re-enable it, or confirm a third party product owns protection on this machine.'
        }

        $age = (Get-Date) - $status.AntivirusSignatureLastUpdated

        if ($age.TotalDays -gt 7) {

            return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus' -Category 'Endpoint' `
                -Status 'Warning' -Detail ('Signatures are {0} days old.' -f [int] $age.TotalDays) `
                -Recommendation 'Run Update-MpSignature or check that the machine reaches the update service.'
        }

        return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus' -Category 'Endpoint' `
            -Status 'Pass' -Detail ('Real time protection on, signatures {0} days old.' -f [int] $age.TotalDays)
    }
    catch {
        return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus' -Category 'Endpoint' `
            -Status 'Info' -Detail 'Defender status is unavailable, which usually means a third party product is installed.'
    }
}

<#
.SYNOPSIS
    Checks that all three firewall profiles are enabled.
#>
function Test-TkAuditFirewall {
    [CmdletBinding()]
    param()

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $disabled = @($profiles | Where-Object { -not $_.Enabled })

        if ($disabled.Count -eq 0) {

            return New-TkAuditFinding -Id 'FW-001' -Name 'Windows Firewall' -Category 'Network' `
                -Status 'Pass' -Detail 'All three profiles are enabled.'
        }

        return New-TkAuditFinding -Id 'FW-001' -Name 'Windows Firewall' -Category 'Network' `
            -Status 'Fail' -Detail ('Disabled profile(s): {0}.' -f (($disabled.Name) -join ', ')) `
            -Recommendation 'Enable every profile. The public profile is the one that matters on hotel and client networks.'
    }
    catch {
        return New-TkAuditFinding -Id 'FW-001' -Name 'Windows Firewall' -Category 'Network' `
            -Status 'Info' -Detail 'Firewall state could not be read.'
    }
}

<#
.SYNOPSIS
    Checks whether the SMBv1 client or server is still installed.
#>
function Test-TkAuditSmbV1 {
    [CmdletBinding()]
    param()

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop

        if ($feature.State -eq 'Enabled') {

            return New-TkAuditFinding -Id 'SMB-001' -Name 'SMBv1' -Category 'Network' `
                -Status 'Fail' -Detail 'SMBv1 is enabled.' `
                -Recommendation 'Remove it. SMBv1 is the protocol WannaCry and NotPetya spread over, and nothing modern needs it.'
        }

        return New-TkAuditFinding -Id 'SMB-001' -Name 'SMBv1' -Category 'Network' `
            -Status 'Pass' -Detail 'SMBv1 is not enabled.'
    }
    catch {
        return New-TkAuditFinding -Id 'SMB-001' -Name 'SMBv1' -Category 'Network' `
            -Status 'Info' -Detail 'SMBv1 state could not be read (needs elevation).'
    }
}

<#
.SYNOPSIS
    Checks whether LLMNR is still allowed.
#>
function Test-TkAuditLlmnr {
    [CmdletBinding()]
    param()

    $value = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                                 -Name 'EnableMulticast'

    if ($value -eq 0) {

        return New-TkAuditFinding -Id 'NET-001' -Name 'LLMNR' -Category 'Network' `
            -Status 'Pass' -Detail 'LLMNR is disabled by policy.'
    }

    return New-TkAuditFinding -Id 'NET-001' -Name 'LLMNR' -Category 'Network' `
        -Status 'Warning' -Detail 'LLMNR is not disabled.' `
        -Recommendation 'Disable it by policy. LLMNR and NBT-NS name resolution is what Responder abuses to capture NTLM hashes on a flat network.'
}

<#
.SYNOPSIS
    Checks whether the PowerShell 2.0 engine is still present.
#>
function Test-TkAuditPowerShellV2 {
    [CmdletBinding()]
    param()

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction Stop

        if ($feature.State -eq 'Enabled') {

            return New-TkAuditFinding -Id 'PS-001' -Name 'PowerShell 2.0 engine' -Category 'Endpoint' `
                -Status 'Fail' -Detail 'The PowerShell 2.0 engine is installed.' `
                -Recommendation 'Remove it. It bypasses script block logging, AMSI and constrained language mode, which is why attackers ask for it by name.'
        }

        return New-TkAuditFinding -Id 'PS-001' -Name 'PowerShell 2.0 engine' -Category 'Endpoint' `
            -Status 'Pass' -Detail 'The downgrade engine is not installed.'
    }
    catch {
        return New-TkAuditFinding -Id 'PS-001' -Name 'PowerShell 2.0 engine' -Category 'Endpoint' `
            -Status 'Info' -Detail 'Feature state could not be read (needs elevation).'
    }
}

<#
.SYNOPSIS
    Checks Remote Desktop exposure and Network Level Authentication.
#>
function Test-TkAuditRemoteDesktop {
    [CmdletBinding()]
    param()

    $denied = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
                                  -Name 'fDenyTSConnections'

    if ($denied -ne 0) {

        return New-TkAuditFinding -Id 'RDP-001' -Name 'Remote Desktop' -Category 'Remote access' `
            -Status 'Pass' -Detail 'Remote Desktop is disabled.'
    }

    $nla = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                               -Name 'UserAuthentication'

    if ($nla -eq 1) {

        return New-TkAuditFinding -Id 'RDP-001' -Name 'Remote Desktop' -Category 'Remote access' `
            -Status 'Warning' -Detail 'Remote Desktop is enabled, with Network Level Authentication required.' `
            -Recommendation 'Acceptable when RDP is reachable only from a management network, never from the internet.'
    }

    return New-TkAuditFinding -Id 'RDP-001' -Name 'Remote Desktop' -Category 'Remote access' `
        -Status 'Fail' -Detail 'Remote Desktop is enabled without Network Level Authentication.' `
        -Recommendation 'Require NLA: without it the logon screen is rendered before authentication, which is a free pre-auth attack surface.'
}

<#
.SYNOPSIS
    Checks the User Account Control level.
#>
function Test-TkAuditUac {
    [CmdletBinding()]
    param()

    $path    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enabled = Get-TkRegistryValue -Path $path -Name 'EnableLUA'
    $prompt  = Get-TkRegistryValue -Path $path -Name 'ConsentPromptBehaviorAdmin'

    if ($enabled -ne 1) {

        return New-TkAuditFinding -Id 'UAC-001' -Name 'User Account Control' -Category 'Endpoint' `
            -Status 'Fail' -Detail 'UAC is turned off.' `
            -Recommendation 'Turn it back on. With EnableLUA at 0 every process of an administrator runs fully elevated.'
    }

    if ($prompt -eq 0) {

        return New-TkAuditFinding -Id 'UAC-001' -Name 'User Account Control' -Category 'Endpoint' `
            -Status 'Fail' -Detail 'UAC elevates without prompting.' `
            -Recommendation 'Set the consent prompt to at least "prompt for consent on the secure desktop".'
    }

    return New-TkAuditFinding -Id 'UAC-001' -Name 'User Account Control' -Category 'Endpoint' `
        -Status 'Pass' -Detail ('UAC is enabled (consent behaviour {0}).' -f $prompt)
}

<#
.SYNOPSIS
    Checks whether the built in Guest account is enabled.
#>
function Test-TkAuditGuestAccount {
    [CmdletBinding()]
    param()

    try {
        # Matched on the well known RID suffix rather than the name, which is
        # localised and can be renamed.
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' }

        if ($guest -and $guest.Enabled) {

            return New-TkAuditFinding -Id 'ACC-001' -Name 'Guest account' -Category 'Accounts' `
                -Status 'Fail' -Detail ('The Guest account ({0}) is enabled.' -f $guest.Name) `
                -Recommendation 'Disable it. It permits unauthenticated access to shared resources.'
        }

        return New-TkAuditFinding -Id 'ACC-001' -Name 'Guest account' -Category 'Accounts' `
            -Status 'Pass' -Detail 'The Guest account is disabled.'
    }
    catch {
        return New-TkAuditFinding -Id 'ACC-001' -Name 'Guest account' -Category 'Accounts' `
            -Status 'Info' -Detail 'Local accounts could not be enumerated.'
    }
}

<#
.SYNOPSIS
    Lists the members of the local Administrators group.
#>
function Test-TkAuditLocalAdministrators {
    [CmdletBinding()]
    param()

    try {
        # -544 is the well known RID of the Administrators group.
        $group   = Get-LocalGroup -ErrorAction Stop | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' }
        $members = Get-LocalGroupMember -Group $group -ErrorAction Stop

        $names  = @($members | ForEach-Object { $_.Name })
        $status = if ($names.Count -gt 3) { 'Warning' } else { 'Info' }

        return New-TkAuditFinding -Id 'ACC-002' -Name 'Local administrators' -Category 'Accounts' `
            -Status $status -Detail ('{0} member(s): {1}' -f $names.Count, ($names -join ', ')) `
            -Recommendation 'Every extra member is another account whose compromise gives full control of the machine.'
    }
    catch {
        return New-TkAuditFinding -Id 'ACC-002' -Name 'Local administrators' -Category 'Accounts' `
            -Status 'Info' -Detail 'The group could not be enumerated.'
    }
}

<#
.SYNOPSIS
    Checks how long ago the last update was installed.
#>
function Test-TkAuditWindowsUpdate {
    [CmdletBinding()]
    param()

    try {
        $lastUpdate = Get-HotFix -ErrorAction Stop |
                      Where-Object { $_.InstalledOn } |
                      Sort-Object -Property InstalledOn -Descending |
                      Select-Object -First 1

        if (-not $lastUpdate) {

            return New-TkAuditFinding -Id 'UPD-001' -Name 'Patch level' -Category 'Servicing' `
                -Status 'Info' -Detail 'No dated update was found in the hotfix list.'
        }

        $age = (Get-Date) - $lastUpdate.InstalledOn

        if ($age.TotalDays -gt 60) {

            return New-TkAuditFinding -Id 'UPD-001' -Name 'Patch level' -Category 'Servicing' `
                -Status 'Fail' -Detail ('The last update was installed {0} days ago ({1}).' -f [int] $age.TotalDays, $lastUpdate.HotFixID) `
                -Recommendation 'Run a Windows Update scan. Two missed patch cycles is where publicly exploited vulnerabilities live.'
        }

        if ($age.TotalDays -gt 35) {

            return New-TkAuditFinding -Id 'UPD-001' -Name 'Patch level' -Category 'Servicing' `
                -Status 'Warning' -Detail ('The last update was installed {0} days ago.' -f [int] $age.TotalDays) `
                -Recommendation 'One patch cycle has been missed.'
        }

        return New-TkAuditFinding -Id 'UPD-001' -Name 'Patch level' -Category 'Servicing' `
            -Status 'Pass' -Detail ('Last update {0} days ago ({1}).' -f [int] $age.TotalDays, $lastUpdate.HotFixID)
    }
    catch {
        return New-TkAuditFinding -Id 'UPD-001' -Name 'Patch level' -Category 'Servicing' `
            -Status 'Info' -Detail 'The update history could not be read.'
    }
}

<#
.SYNOPSIS
    Checks whether AutoPlay and AutoRun are disabled.
#>
function Test-TkAuditAutoPlay {
    [CmdletBinding()]
    param()

    $value = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                                 -Name 'NoDriveTypeAutoRun'

    # 0xFF disables AutoRun on every drive type.
    if ($value -eq 255) {

        return New-TkAuditFinding -Id 'USB-001' -Name 'AutoRun' -Category 'Endpoint' `
            -Status 'Pass' -Detail 'AutoRun is disabled for all drive types.'
    }

    return New-TkAuditFinding -Id 'USB-001' -Name 'AutoRun' -Category 'Endpoint' `
        -Status 'Warning' -Detail 'AutoRun is not fully disabled.' `
        -Recommendation 'Set NoDriveTypeAutoRun to 255. A dropped USB stick should not be able to start anything on insertion.'
}

<#
.SYNOPSIS
    Reads the local password policy.
#>
function Test-TkAuditPasswordPolicy {
    [CmdletBinding()]
    param()

    $result = Invoke-TkProcess -FilePath 'net' -ArgumentList @('accounts') -TimeoutSeconds 30

    if ($result.ExitCode -ne 0) {

        return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
            -Status 'Info' -Detail 'The local policy could not be read.'
    }

    $minimumLength = 0

    if ($result.StandardOutput -match 'Minimum password length[^\d]*(\d+)') {
        $minimumLength = [int] $Matches[1]
    }

    if ($minimumLength -eq 0) {

        return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
            -Status 'Fail' -Detail 'No minimum password length is enforced.' `
            -Recommendation 'Require at least 12 characters, or 14 for accounts with administrative rights.'
    }

    if ($minimumLength -lt 12) {

        return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
            -Status 'Warning' -Detail ('The minimum password length is {0}.' -f $minimumLength) `
            -Recommendation 'Length is what defeats offline cracking; 12 characters is the current floor.'
    }

    return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
        -Status 'Pass' -Detail ('The minimum password length is {0}.' -f $minimumLength)
}

<#
.SYNOPSIS
    Writes an audit report to disk.

.PARAMETER Path
    Destination file.

.OUTPUTS
    System.String
#>
function Export-TkSecurityAuditReport {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        $Findings
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write audit report')) {
        return $null
    }

    if (-not $Findings) {
        $Findings = Invoke-TkSecurityAudit
    }

    $report = [pscustomobject]@{
        Computer    = $env:COMPUTERNAME
        GeneratedAt = (Get-Date).ToString('s')
        Toolkit     = (Get-TkContext).Version
        Note        = 'Local hygiene check. It does not replace a CIS or ANSSI benchmark run.'
        Summary     = [pscustomobject]@{
            Pass    = @($Findings | Where-Object { $_.Status -eq 'Pass' }).Count
            Fail    = @($Findings | Where-Object { $_.Status -eq 'Fail' }).Count
            Warning = @($Findings | Where-Object { $_.Status -eq 'Warning' }).Count
            Info    = @($Findings | Where-Object { $_.Status -eq 'Info' }).Count
        }
        Findings    = $Findings
    }

    try {
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Audit' -Message ('Audit report written to {0}' -f $Path)

        return $Path
    }
    catch {
        Write-TkLog -Level Error -Category 'Audit' -Message (
            'Could not write the report: {0}' -f $_.Exception.Message
        )

        return $null
    }
}
