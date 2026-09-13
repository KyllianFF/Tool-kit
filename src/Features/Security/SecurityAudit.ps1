<#
    Toolkit - Features / Local security audit

    A read only posture check of the workstation in front of you. Every item
    is a control a technician can actually change, and every finding carries
    the reason it matters rather than only a red marker.

    This is a hygiene check, not a compliance audit. It does not replace a
    CIS benchmark run, and it says so in the report header.

    Three things decide the shape of this file.

    The control table below, not the checks, carries the risk weight and the
    level. A reviewer asking "is disk encryption really worth five times
    AutoRun" reads one table instead of forty call sites, and a check stays a
    function that answers one question about the machine.

    A check answers about the machine, never about our rights. When a value
    cannot be read for want of a privilege the finding is NotAssessed, which
    is a different thing from Info: Info is a real result that needs no
    action, NotAssessed is the absence of a result, and only one of the two
    may be left out of a score.
#>

<#
    The controls, in the order a report reads best.

    Weight is the risk carried by getting this one wrong, on a scale where 10
    is "this alone loses the data on a stolen machine" and 2 is "worth
    tidying". It is the whole of the score's opinion, so it is written where
    it can be argued with rather than buried in the checks.

    Level is what an Essential pass covers: the controls that go wrong often
    enough, and are cheap enough to fix, to be worth checking on every machine.
    Full adds the ones that need a decision, a licence or a domain behind them.

    Action is what the button on a warning or a failure does: a correction
    where one safe step exists, the page where the setting lives otherwise.
    Every control has one, because a warning with no way forward is a report
    that stops being read. A check can still choose a different action for one
    of its paths; the table only fills in what the check left empty.
#>
$script:TkAuditControl = @(

    # --- Data protection ---------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditBitLocker';           Weight = 10; Level = 'Essential'; Action = 'open-bitlocker' }

    # --- Endpoint protection -----------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditAntivirus';           Weight = 10; Level = 'Essential'; Action = 'open-windows-security' }
    [pscustomobject] @{ Function = 'Test-TkAuditDefenderSignature';   Weight =  4; Level = 'Essential'; Action = 'update-signatures' }
    [pscustomobject] @{ Function = 'Test-TkTamperProtection';         Weight =  6; Level = 'Full';      Action = 'open-defender-settings' }
    [pscustomobject] @{ Function = 'Test-TkAsrRules';                 Weight =  5; Level = 'Full';      Action = 'asr-audit-mode' }
    [pscustomobject] @{ Function = 'Test-TkAuditUac';                 Weight =  7; Level = 'Essential'; Action = 'enable-uac' }
    [pscustomobject] @{ Function = 'Test-TkAuditPowerShellV2';        Weight =  5; Level = 'Essential'; Action = 'disable-powershell-v2' }
    [pscustomobject] @{ Function = 'Test-TkAuditAutoPlay';            Weight =  3; Level = 'Essential'; Action = 'disable-autorun' }
    [pscustomobject] @{ Function = 'Test-TkAuditScreenLock';          Weight =  6; Level = 'Essential'; Action = 'set-inactivity-lock' }

    # --- Platform ----------------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditSecureBoot';          Weight =  6; Level = 'Essential'; Action = 'restart-to-firmware' }
    [pscustomobject] @{ Function = 'Test-TkAuditTpm';                 Weight =  4; Level = 'Essential'; Action = 'restart-to-firmware' }

    # --- Credential protection ---------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkWdigest';                  Weight =  8; Level = 'Essential'; Action = 'disable-wdigest' }
    [pscustomobject] @{ Function = 'Test-TkLsaProtection';            Weight =  6; Level = 'Full';      Action = 'enable-lsa-protection' }
    [pscustomobject] @{ Function = 'Test-TkCredentialGuard';          Weight =  5; Level = 'Full';      Action = 'enable-credential-guard' }

    # --- Network -----------------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditFirewall';            Weight =  9; Level = 'Essential'; Action = 'enable-firewall' }
    [pscustomobject] @{ Function = 'Test-TkAuditSmbV1';               Weight =  8; Level = 'Essential'; Action = 'disable-smbv1' }
    [pscustomobject] @{ Function = 'Test-TkSmbSigning';               Weight =  5; Level = 'Full';      Action = 'require-smb-signing' }
    [pscustomobject] @{ Function = 'Test-TkNtlmRestriction';          Weight =  6; Level = 'Full';      Action = 'set-lm-level' }
    [pscustomobject] @{ Function = 'Test-TkAuditLlmnr';               Weight =  4; Level = 'Essential'; Action = 'disable-llmnr' }

    # --- Remote access -----------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditRemoteDesktop';       Weight =  7; Level = 'Essential'; Action = 'open-remote-desktop' }
    [pscustomobject] @{ Function = 'Test-TkAuditRdpNla';              Weight =  8; Level = 'Essential'; Action = 'enable-rdp-nla' }
    [pscustomobject] @{ Function = 'Test-TkAuditWinRm';               Weight =  5; Level = 'Full';      Action = 'disable-winrm' }

    # --- Accounts ----------------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditGuestAccount';        Weight =  5; Level = 'Essential'; Action = 'disable-guest' }
    [pscustomobject] @{ Function = 'Test-TkAuditLocalAdministrators'; Weight =  7; Level = 'Essential'; Action = 'open-local-users' }
    [pscustomobject] @{ Function = 'Test-TkAuditPasswordPolicy';      Weight =  5; Level = 'Essential'; Action = 'set-password-length' }
    [pscustomobject] @{ Function = 'Test-TkAuditAccountLockout';      Weight =  6; Level = 'Essential'; Action = 'set-account-lockout' }
    [pscustomobject] @{ Function = 'Test-TkAuditStaleLocalAccount';   Weight =  4; Level = 'Full';      Action = 'open-local-users' }
    [pscustomobject] @{ Function = 'Test-TkLaps';                     Weight =  5; Level = 'Full';      Action = 'open-laps-guide' }

    # --- Servicing ---------------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkAuditWindowsUpdate';       Weight =  8; Level = 'Essential'; Action = 'open-windows-update' }
    [pscustomobject] @{ Function = 'Test-TkAuditUpdatePaused';        Weight =  5; Level = 'Essential'; Action = 'open-windows-update' }

    # --- Logging -----------------------------------------------------------
    [pscustomobject] @{ Function = 'Test-TkPowerShellLogging';        Weight =  4; Level = 'Full';      Action = 'enable-script-block-logging' }
    [pscustomobject] @{ Function = 'Test-TkAuditPolicy';              Weight =  4; Level = 'Full';      Action = 'enable-baseline-audit-policy' }
)

<#
.SYNOPSIS
    Returns the control table, narrowed to one level when asked.

.DESCRIPTION
    Read through a function so the engine, the interface and the tests all see
    the same table, and none of them reaches into script state to get it.

.PARAMETER Level
    Essential returns only the Essential controls. Full returns every one.
#>
function Get-TkAuditControl {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $Level = 'Full'
    )

    if ($Level -eq 'Essential') {
        return @($script:TkAuditControl | Where-Object { $_.Level -eq 'Essential' })
    }

    return @($script:TkAuditControl)
}

# Administrator accounts the operator has declared expected. Held for the span
# of one run rather than passed down, because only the account controls read
# it and threading it through every check would be noise.
$script:TkAuditExcludedAccount = @()

<#
.SYNOPSIS
    Runs the local security controls and returns the findings.

.DESCRIPTION
    One engine. The audit and the hardening check used to be two, which meant
    BitLocker was tested twice, Defender interrogated three times, and the two
    halves did not agree on the shape of a finding.

.PARAMETER Level
    Essential runs the controls worth checking on every machine. Full adds the
    ones that need a decision, a licence or a domain behind them.

.PARAMETER ExcludedAccount
    Administrator accounts the operator has decided are expected here, such as
    a domain group or a management agent. They are left out of the account
    controls and named in the report: an audit that hides its exclusions is
    not an audit.

.OUTPUTS
    PSCustomObject[] as built by New-TkAuditFinding.
#>
function Invoke-TkSecurityAudit {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $Level = 'Essential',

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ExcludedAccount = @()
    )

    $stopwatch = Start-TkOperation -Name 'Local security audit' -Category 'Audit'

    # Defender answers three of these controls and the call is not cheap. The
    # cache is cleared per run rather than kept, so an audit re-run after a fix
    # reports the machine as it is now.
    Clear-TkDefenderStatusCache

    $script:TkAuditExcludedAccount = @($ExcludedAccount)

    $findings = @()

    foreach ($control in (Get-TkAuditControl -Level $Level)) {

        try {
            foreach ($finding in @(& $control.Function)) {

                if ($null -eq $finding) {
                    continue
                }

                $findings += (Set-TkFindingControlDefault -Finding $finding -Control $control)
            }
        }
        catch {
            Write-TkLog -Level Warning -Category 'Audit' -Message (
                '{0} could not run: {1}' -f $control.Function, $_.Exception.Message
            )
        }
    }

    $script:TkAuditExcludedAccount = @()

    $failed = @($findings | Where-Object { $_.Status -eq 'Fail' }).Count

    Stop-TkOperation -Name 'Local security audit' -Stopwatch $stopwatch -Category 'Audit'

    Write-TkLog -Level Information -Category 'Audit' -Message (
        'Audit finished at level {0}: {1} controls, {2} failing.' -f $Level, $findings.Count, $failed
    )

    return $findings
}

<#
.SYNOPSIS
    Stamps a finding with what the control table says about its control.

.DESCRIPTION
    Weight and level always come from the table, so a check stays a question
    about the machine and the risk weighting stays in one reviewable place.

    The action comes from the table only for a warning or a failure the check
    left without one. A check still decides when one of its paths needs a
    different action: Remote Desktop without NLA gets the NLA correction
    rather than the settings page.

    A pass, an informational result and a control that could not be read get
    no button. There is nothing on them to act on.

.OUTPUTS
    PSCustomObject, the finding it was given.
#>
function Set-TkFindingControlDefault {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Finding,

        [Parameter(Mandatory)]
        [pscustomobject] $Control
    )

    $Finding.Weight = $Control.Weight
    $Finding.Level  = $Control.Level

    $actionable = ($Finding.Status -in @('Warning', 'Fail'))

    if ($actionable -and [string]::IsNullOrEmpty($Finding.RemediationId) -and $Control.PSObject.Properties['Action']) {
        $Finding.RemediationId = [string] $Control.Action
    }

    return $Finding
}

<#
.SYNOPSIS
    Scores a set of findings out of one hundred, weighted by risk.

.DESCRIPTION
    A plain count of passes would let eight easy controls hide an unencrypted
    disk. Each control contributes its weight instead: a pass earns all of it,
    a warning half, a failure none.

    NotAssessed leaves the denominator entirely. Counting an unreadable control
    as a failure invents a problem and counting it as a pass hides one; the
    only honest answer is to score what was measured and say how much was not.

.OUTPUTS
    PSCustomObject with Score, Passed, Failed, Warnings, NotAssessed, Assessed.
#>
function Get-TkAuditScore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding
    )

    $earned   = 0.0
    $possible = 0.0

    $passed      = 0
    $failed      = 0
    $warnings    = 0
    $notAssessed = 0

    foreach ($item in $Finding) {

        # Info is a real result that asks for nothing. There is no pass to be
        # earned, so it scores nothing and costs nothing.
        if ($item.Status -eq 'Info') {
            continue
        }

        if ($item.Status -eq 'NotAssessed') {
            $notAssessed++
            continue
        }

        $weight    = [double] $item.Weight
        $possible += $weight

        switch ($item.Status) {

            'Pass' {
                $earned += $weight
                $passed++
            }

            'Warning' {
                $earned += $weight / 2
                $warnings++
            }

            'Fail' {
                $failed++
            }
        }
    }

    $score = if ($possible -gt 0) { [int] [math]::Round(100 * $earned / $possible) } else { 0 }

    return [pscustomobject] @{
        Score       = $score
        Passed      = $passed
        Failed      = $failed
        Warnings    = $warnings
        NotAssessed = $notAssessed
        Assessed    = $passed + $failed + $warnings
    }
}

<#
.SYNOPSIS
    Builds a finding object.

.DESCRIPTION
    Single constructor so every control produces the same shape, which is what
    lets one renderer and one score read them all.

    Measured and Detail answer different questions and both are shown. Measured
    is the value read off the machine, short enough to sit next to the title
    ("2 of 5 rules in block mode"); Detail is the sentence explaining what that
    means. The card used to print the identifier where the measured value
    belongs, which told the reader nothing they could act on.

.PARAMETER Status
    Pass, Fail and Warning are judgements about the machine.

    Info is a real result that asks for nothing: three administrators on a
    workstation is a fact worth printing, not a problem.

    NotAssessed means the control could not be read at all. It is deliberately
    not a judgement, and it is the one status the score leaves out, because
    scoring an unread control either invents a problem or hides one.

.PARAMETER Weight
    Risk weighting. Set from the control table by Invoke-TkSecurityAudit, so
    the default here only matters to a check called on its own.

.PARAMETER Applicable
    False where the control cannot apply to this machine rather than failing
    on it, such as a TPM control on a virtual machine.

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
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'NotAssessed')]
        [string] $Status,

        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Detail,

        [Parameter()] [AllowEmptyString()] [string] $Measured       = '',
        [Parameter()] [AllowEmptyString()] [string] $Recommendation = '',

        # Key into the remediation allow list, when the finding has a safe
        # single step correction. Left empty when the fix needs a decision
        # the toolkit cannot make, which is more honest than a button that
        # does something approximate.
        [Parameter()] [AllowEmptyString()] [string] $RemediationId = '',

        [Parameter()] [int]  $Weight     = 5,
        [Parameter()] [ValidateSet('Essential', 'Full')] [string] $Level = 'Essential',
        [Parameter()] [bool] $Applicable = $true
    )

    return [pscustomobject]@{
        Id             = $Id
        Name           = $Name
        Category       = $Category
        Status         = $Status
        Measured       = $Measured
        Detail         = $Detail
        Recommendation = $Recommendation
        RemediationId  = $RemediationId
        Weight         = $Weight
        Level          = $Level
        Applicable     = $Applicable
    }
}

# ---------------------------------------------------------------------------
# Defender, read once per run
# ---------------------------------------------------------------------------

$script:TkDefenderStatus      = $null
$script:TkDefenderStatusRead  = $false

<#
.SYNOPSIS
    Forgets the cached Defender status.

.DESCRIPTION
    Called at the start of every audit. The cache exists to stop three
    controls making the same slow call, not to remember the machine between
    runs: an audit run again after a fix has to see the fix.
#>
function Clear-TkDefenderStatusCache {
    [CmdletBinding()]
    param()

    $script:TkDefenderStatus     = $null
    $script:TkDefenderStatusRead = $false
}

<#
.SYNOPSIS
    Reads Get-MpComputerStatus once, and returns null when it is unavailable.

.DESCRIPTION
    Unavailable is a normal answer, not an error: Defender is absent from some
    editions, and its module is not always present when another product owns
    protection. The null is the caller's cue to say so rather than to fail.
#>
function Get-TkDefenderStatus {
    [CmdletBinding()]
    param()

    if ($script:TkDefenderStatusRead) {
        return $script:TkDefenderStatus
    }

    $script:TkDefenderStatusRead = $true

    try {
        $script:TkDefenderStatus = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        $script:TkDefenderStatus = $null
    }

    return $script:TkDefenderStatus
}

<#
.SYNOPSIS
    Says whether Microsoft Defender is the antivirus protecting the machine.

.DESCRIPTION
    Attack Surface Reduction rules and tamper protection are Defender features.
    When another product owns protection, Defender is passive or stopped and
    the rules do not apply; marking them down would ask the operator to replace
    an antivirus that works. The mode comes back with the answer so a finding
    can name it.

.OUTPUTS
    PSCustomObject with Active and Mode.
#>
function Get-TkDefenderActiveState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $status = Get-TkDefenderStatus

    $mode = if ($status -and $status.PSObject.Properties['AMRunningMode']) { [string] $status.AMRunningMode } else { '' }

    # Older builds do not report a mode; real time protection answers for them.
    $active = ($mode -eq 'Normal') -or
              (-not $mode -and $null -ne $status -and [bool] $status.RealTimeProtectionEnabled)

    return [pscustomobject] @{
        Active = $active
        Mode   = $(if ($mode) { $mode } elseif ($null -eq $status) { 'Not available' } else { 'Unknown' })
    }
}

<#
.SYNOPSIS
    Decodes the productState bit field Security Center reports for a product.

.DESCRIPTION
    Undocumented, but stable for a decade and read the same way by every
    endpoint tool: as six hex digits, the second pair says whether real time
    protection is running, the third whether the signatures are current.

    A value outside the known patterns decodes to null rather than to a guess.
    The caller treats null as "unknown", which is the honest reading of a
    product that reports something new.

    Kept apart from the WMI query so the decoding can be tested against the
    values real products report, without a real product.

.PARAMETER State
    The productState integer.

.OUTPUTS
    PSCustomObject with RealTimeEnabled, SignaturesCurrent and Raw.
#>
function ConvertFrom-TkProductState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $State
    )

    $hex = '{0:x6}' -f $State

    # Second pair: 10 and 11 mean protection is running.
    $realTime = switch ($hex.Substring(2, 2)) {
        '10'    { $true }
        '11'    { $true }
        '00'    { $false }
        '01'    { $false }
        default { $null }
    }

    # Third pair: 00 means the signatures are current.
    $current = switch ($hex.Substring(4, 2)) {
        '00'    { $true }
        '10'    { $false }
        default { $null }
    }

    return [pscustomobject] @{
        RealTimeEnabled   = $realTime
        SignaturesCurrent = $current
        Raw               = $hex
    }
}

<#
.SYNOPSIS
    Lists the antivirus and EDR products Windows Security Center knows about.

.DESCRIPTION
    root\SecurityCenter2 is where every registered protection product declares
    itself, which is the only way to see a third party antivirus or an EDR
    agent at all. Asking Defender alone was the bug this replaces.

    productState is a bit field Microsoft has never documented, but its layout
    has been stable for a decade and every endpoint tool reads it the same way:
    as six hex digits, the second pair says whether real time protection is on,
    the third whether the signatures are current. Anything unexpected is
    reported as unknown rather than guessed at.

    The namespace does not exist on Server editions, where Security Center is
    not installed. That returns nothing, and the caller falls back to Defender.

.OUTPUTS
    PSCustomObject[] with Name, RealTimeEnabled, SignaturesCurrent, Raw.
#>
function Get-TkAntivirusProduct {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    # -All matters more here than anywhere else in the project: without it
    # the helper returns the first instance only, which on a machine running
    # a third party product next to Defender is whichever of the two the
    # provider happens to list first. That is exactly the wrong answer.
    $products = Get-TkCimInstanceSafe -ClassName 'AntiVirusProduct' -Namespace 'root\SecurityCenter2' -All

    if (-not $products) {
        return @()
    }

    $result = @()

    foreach ($product in $products) {

        $state = if ($null -ne $product.productState) { [int] $product.productState } else { 0 }

        $decoded = ConvertFrom-TkProductState -State $state

        $result += [pscustomobject] @{
            Name              = [string] $product.displayName
            RealTimeEnabled   = $decoded.RealTimeEnabled
            SignaturesCurrent = $decoded.SignaturesCurrent
            Raw               = $decoded.Raw
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Individual checks

# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks BitLocker on every drive, not only the system drive.

.DESCRIPTION
    One control where there used to be two. The audit and the hardening check
    each asked whether the system drive was encrypted, and neither looked at
    any other drive. A data drive lifted out of a desktop is readable in any
    other machine, which is the same breach as a stolen laptop.

    Reading happens here and judging in ConvertTo-TkBitLockerFinding, so the
    judgement can be tested without a BitLocker drive to test it on.
#>
function Test-TkAuditBitLocker {
    [CmdletBinding()]
    param()

    try {
        $volumes = @(Get-BitLockerVolume -ErrorAction Stop)
    }
    catch {
        return New-TkAuditFinding -Id 'ENC-001' -Name 'Drive encryption' -Category 'Data protection' `
            -Status 'NotAssessed' -Measured 'Not readable' `
            -Detail 'BitLocker could not be read: it needs elevation, and not every edition includes it.'
    }

    # Removable drives are listed but never judged: whether a USB stick has to
    # be encrypted is a policy of the estate, not a property of this machine.
    $removable = @(Get-TkCimInstanceSafe -ClassName 'Win32_LogicalDisk' -Filter 'DriveType = 2' -All |
                   ForEach-Object { [string] $_.DeviceID })

    return ConvertTo-TkBitLockerFinding -Volume $volumes -RemovableMountPoint $removable
}

<#
.SYNOPSIS
    Describes how a BitLocker drive unlocks, in the words a technician uses.

.DESCRIPTION
    The recovery password is left out: it is the way back in, not the way the
    drive opens every day, and the finding reports it on its own. So is the key
    behind automatic unlock, which is shown as automatic unlock rather than as
    the startup key it technically is.

.OUTPUTS
    System.String
#>
function Get-TkBitLockerUnlockMethod {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Volume
    )

    $names = @{
        'Tpm'              = 'TPM only'
        'TpmPin'           = 'TPM + PIN'
        'TpmStartupKey'    = 'TPM + startup key'
        'TpmPinStartupKey' = 'TPM + PIN + startup key'
        'TpmNetworkKey'    = 'network unlock'
        'ExternalKey'      = 'startup key on USB'
        'Password'         = 'password'
        'PublicKey'        = 'smart card'
        'AdAccountOrGroup' = 'domain account'
    }

    $methods = @()

    foreach ($protector in @($Volume.KeyProtector)) {

        if ($null -eq $protector -or $protector.AutoUnlockProtector -eq $true) {
            continue
        }

        $type = [string] $protector.KeyProtectorType

        if ($names.ContainsKey($type) -and $methods -notcontains $names[$type]) {
            $methods += $names[$type]
        }
    }

    if ($Volume.AutoUnlockEnabled -eq $true) {
        $methods += 'automatic unlock'
    }

    if ($methods.Count -eq 0) {
        return 'no unlock method'
    }

    return ($methods -join ', ')
}

<#
.SYNOPSIS
    Turns a BitLocker encryption method into the name of the cipher.
#>
function ConvertTo-TkBitLockerCipherName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Method
    )

    switch ($Method) {
        'XtsAes128'      { return 'XTS-AES 128' }
        'XtsAes256'      { return 'XTS-AES 256' }
        'Aes128'         { return 'AES-CBC 128' }
        'Aes256'         { return 'AES-CBC 256' }
        'Aes128Diffuser' { return 'AES-CBC 128 with diffuser' }
        'Aes256Diffuser' { return 'AES-CBC 256 with diffuser' }
        'Hardware'       { return 'drive hardware encryption' }
        default          { return $Method }
    }
}

<#
.SYNOPSIS
    Judges a set of BitLocker volumes and returns one finding.

.DESCRIPTION
    Fixed drives are judged. Removable drives are listed and never judged.
    Volumes without a letter, such as the recovery partition, are skipped:
    they hold no user data.

    Failure: a fixed drive that is not encrypted, or a system drive with no
    recovery password, which is one firmware update away from being lost for
    good.

    Warning: protection suspended, a data drive without a recovery password,
    the old AES-CBC ciphers, or encryption handed to the drive's own hardware,
    which Microsoft stopped trusting by default after several self-encrypting
    drives were found to protect nothing (advisory ADV180028).

    TPM only on the system drive is not marked down. It is the Windows default
    and it protects a drive taken out of the machine; the detail says that the
    ANSSI asks for TPM and PIN on a laptop, which is a policy for the estate.

.PARAMETER Volume
    Objects shaped like the output of Get-BitLockerVolume.

.PARAMETER RemovableMountPoint
    Drive letters, such as "E:", that belong to removable drives.

.OUTPUTS
    PSCustomObject, a finding.
#>
function ConvertTo-TkBitLockerFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Volume,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $RemovableMountPoint = @()
    )

    $encryptedStates = @(
        'FullyEncrypted', 'EncryptionInProgress', 'EncryptionSuspended',
        'FullyEncryptedWipeInProgress', 'FullyEncryptedWipeSuspended'
    )

    $removable = @($RemovableMountPoint | ForEach-Object { ([string] $_).TrimEnd('\').ToUpperInvariant() })

    $lines = @()
    $notes = @()

    $fixed     = 0
    $protected = 0

    $unencrypted      = @()
    $suspended        = @()
    $systemNoRecovery = @()
    $dataNoRecovery   = @()
    $legacyCipher     = @()
    $hardware         = @()
    $tpmOnly          = $false

    foreach ($item in ($Volume | Sort-Object -Property { [string] $_.MountPoint })) {

        $mount = ([string] $item.MountPoint).TrimEnd('\')

        if ($mount -notmatch '^[A-Za-z]:$') {
            continue
        }

        $mount = $mount.ToUpperInvariant()

        $isSystem    = ([string] $item.VolumeType -eq 'OperatingSystem')
        $isRemovable = ($removable -contains $mount)

        $role = if ($isSystem) { 'system' } elseif ($isRemovable) { 'removable' } else { 'data' }

        if (-not $isRemovable) {
            $fixed++
        }

        $status    = [string] $item.VolumeStatus
        $encrypted = ($encryptedStates -contains $status)

        if (-not $encrypted) {

            $lines += '{0} ({1}): not encrypted' -f $mount, $role

            if (-not $isRemovable) {
                $unencrypted += $mount
            }

            continue
        }

        $isOn        = ([string] $item.ProtectionStatus -eq 'On')
        $encrypting  = ($status -eq 'EncryptionInProgress')
        $hasRecovery = (@($item.KeyProtector | Where-Object {
                            $null -ne $_ -and [string] $_.KeyProtectorType -eq 'RecoveryPassword'
                        }).Count -gt 0)

        $state = if ($encrypting) { 'encrypting, {0}% done' -f [int] $item.EncryptionPercentage }
                 elseif ($isOn) { 'protected' }
                 else { 'encrypted but protection suspended' }

        $method = [string] $item.EncryptionMethod
        $unlock = Get-TkBitLockerUnlockMethod -Volume $item

        $lines += '{0} ({1}): {2}, {3}, {4}, {5}' -f $mount, $role, $state,
            (ConvertTo-TkBitLockerCipherName -Method $method), $unlock,
            $(if ($hasRecovery) { 'recovery password present' } else { 'no recovery password' })

        if ($isRemovable) {
            continue
        }

        if ($isOn) {
            $protected++
        }
        elseif (-not $encrypting) {
            $suspended += $mount
        }

        if (-not $hasRecovery) {
            if ($isSystem) { $systemNoRecovery += $mount } else { $dataNoRecovery += $mount }
        }

        if ($method -in @('Aes128', 'Aes256', 'Aes128Diffuser', 'Aes256Diffuser')) {
            $legacyCipher += $mount
        }

        if ($method -eq 'Hardware') {
            $hardware += $mount
        }

        if ($isSystem -and $unlock -eq 'TPM only') {
            $tpmOnly = $true
        }
    }

    if ($fixed -eq 0) {

        return New-TkAuditFinding -Id 'ENC-001' -Name 'Drive encryption' -Category 'Data protection' `
            -Status 'NotAssessed' -Measured 'No fixed drive found' `
            -Detail 'BitLocker reported no fixed drive with a letter.'
    }

    if ($tpmOnly) {
        $notes += 'The system drive unlocks with the TPM alone, the Windows default. That protects a drive taken out of the machine; on a laptop the ANSSI asks for TPM and PIN, so that a stolen machine does not start Windows by itself.'
    }

    if ($legacyCipher.Count -gt 0) {
        $notes += 'Legacy AES-CBC on {0}: XTS-AES has been the Windows default since Windows 10 1511, and changing it means decrypting and encrypting again.' -f ($legacyCipher -join ', ')
    }

    if ($hardware.Count -gt 0) {
        $notes += 'Encryption is left to the drive itself on {0}. Several self-encrypting drives were found to protect nothing (Microsoft advisory ADV180028), and Windows no longer trusts them by default.' -f ($hardware -join ', ')
    }

    $measured = '{0} of {1} fixed drive(s) protected' -f $protected, $fixed
    $detail   = (@($lines) + @($notes)) -join [Environment]::NewLine

    if ($unencrypted.Count -gt 0 -or $systemNoRecovery.Count -gt 0) {

        $advice = @()

        if ($unencrypted.Count -gt 0) {
            $advice += 'Encrypt {0}. Every fixed drive needs it, not only the system drive: a data drive taken out of the machine is readable anywhere.' -f ($unencrypted -join ', ')
        }

        if ($systemNoRecovery.Count -gt 0) {
            $advice += 'Add a recovery password to {0} and keep it somewhere you can reach: without one, a firmware update or a TPM reset locks the data away for good.' -f ($systemNoRecovery -join ', ')
        }

        return New-TkAuditFinding -Id 'ENC-001' -Name 'Drive encryption' -Category 'Data protection' `
            -Status 'Fail' -Measured $measured -Detail $detail -Recommendation ($advice -join ' ')
    }

    if ($suspended.Count -gt 0) {

        return New-TkAuditFinding -Id 'ENC-001' -Name 'Drive encryption' -Category 'Data protection' `
            -Status 'Warning' -Measured $measured -Detail $detail `
            -Recommendation ('Resume protection on {0}. While suspended, the key is stored in the clear on the drive.' -f ($suspended -join ', ')) `
            -RemediationId 'resume-bitlocker'
    }

    if ($dataNoRecovery.Count -gt 0 -or $legacyCipher.Count -gt 0 -or $hardware.Count -gt 0) {

        $advice = @()

        if ($dataNoRecovery.Count -gt 0) {
            $advice += 'Add a recovery password to {0}.' -f ($dataNoRecovery -join ', ')
        }

        if ($legacyCipher.Count -gt 0 -or $hardware.Count -gt 0) {
            $advice += 'Re-encrypt {0} with XTS-AES when the machine can spare the time.' -f ((@($legacyCipher) + @($hardware) | Select-Object -Unique) -join ', ')
        }

        return New-TkAuditFinding -Id 'ENC-001' -Name 'Drive encryption' -Category 'Data protection' `
            -Status 'Warning' -Measured $measured -Detail $detail -Recommendation ($advice -join ' ')
    }

    return New-TkAuditFinding -Id 'ENC-001' -Name 'Drive encryption' -Category 'Data protection' `
        -Status 'Pass' -Measured $measured -Detail $detail `
        -Recommendation 'Confirm the recovery keys are escrowed centrally, which cannot be seen from the machine itself.'
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
            -Status 'NotAssessed' -Detail 'Not readable: the machine is in legacy BIOS mode, or elevation is missing.'
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
    Checks that at least one antivirus or EDR is installed and running.

.DESCRIPTION
    The control this replaces asked Defender and nothing else, so a machine
    properly protected by a third party product failed it. Defender steps into
    passive mode when another product registers, and passive mode reports real
    time protection as off, which is correct and means nothing is wrong.

    What matters is the question the operator actually has: is something
    watching this machine, and what. So the control enumerates every registered
    product, names them, and passes when at least one is running.

    Passive Defender alongside a running product is worth a line in the detail
    but is not a finding. Passive Defender with nothing else running is a
    failure, and so is no product at all.
#>
function Test-TkAuditAntivirus {
    [CmdletBinding()]
    param()

    $products = @(Get-TkAntivirusProduct)
    $defender = Get-TkDefenderStatus

    # Defender's own mode, which Security Center reports less precisely.
    $defenderMode = if ($defender -and $defender.PSObject.Properties['AMRunningMode']) {
                        [string] $defender.AMRunningMode
                    }
                    else {
                        ''
                    }

    $running = @($products | Where-Object { $_.RealTimeEnabled -eq $true })

    # Server editions have no Security Center to ask, so an empty list there is
    # ignorance rather than an answer. Defender still speaks for itself.
    if ($products.Count -eq 0) {

        if ($null -eq $defender) {

            return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus or EDR' -Category 'Endpoint' `
                -Status 'NotAssessed' -Measured 'No product registered' `
                -Detail 'Neither Security Center nor Defender could be read, so what protects this machine is unknown.' `
                -Recommendation 'Check from the endpoint management console which agent owns this machine.'
        }

        if ($defender.RealTimeProtectionEnabled) {

            return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus or EDR' -Category 'Endpoint' `
                -Status 'Pass' -Measured 'Microsoft Defender' `
                -Detail 'Microsoft Defender is running with real time protection on.'
        }

        return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus or EDR' -Category 'Endpoint' `
            -Status 'Fail' -Measured ('Defender {0}' -f $(if ($defenderMode) { $defenderMode } else { 'inactive' })) `
            -Detail 'Defender is not protecting this machine and no other product is registered.' `
            -Recommendation 'Install an antivirus or EDR agent, or re-enable Defender. An unprotected endpoint is the cheapest way into an estate.'
    }

    $names = @($products | ForEach-Object { $_.Name })

    if ($running.Count -gt 0) {

        $detail = 'Running: {0}.' -f (@($running | ForEach-Object { $_.Name }) -join ', ')

        # Worth saying, because an operator seeing Defender "off" elsewhere
        # needs to know it is deliberate rather than a fault.
        if ($defenderMode -like '*Passive*') {
            $detail += ' Microsoft Defender is in passive mode alongside it, which is the expected arrangement.'
        }

        $stale = @($running | Where-Object { $_.SignaturesCurrent -eq $false })

        if ($stale.Count -gt 0) {

            return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus or EDR' -Category 'Endpoint' `
                -Status 'Warning' -Measured (($running | ForEach-Object { $_.Name }) -join ', ') `
                -Detail ('{0} Signatures are out of date on: {1}.' -f $detail, (@($stale | ForEach-Object { $_.Name }) -join ', ')) `
                -Recommendation 'Update the signatures, or check that the machine reaches its update service.' `
                -RemediationId $(if ($stale.Name -contains 'Windows Defender') { 'update-signatures' } else { '' })
        }

        return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus or EDR' -Category 'Endpoint' `
            -Status 'Pass' -Measured (($running | ForEach-Object { $_.Name }) -join ', ') -Detail $detail
    }

    return New-TkAuditFinding -Id 'AV-001' -Name 'Antivirus or EDR' -Category 'Endpoint' `
        -Status 'Fail' -Measured ('{0}, none running' -f ($names -join ', ')) `
        -Detail ('Registered but not protecting: {0}.' -f ($names -join ', ')) `
        -Recommendation 'Start the product or repair its installation. An agent that is installed but not running protects nothing.'
}

<#
.SYNOPSIS
    Checks how old the Defender signatures are, where Defender is the product.
#>
function Test-TkAuditDefenderSignature {
    [CmdletBinding()]
    param()

    $status = Get-TkDefenderStatus

    if ($null -eq $status) {

        return New-TkAuditFinding -Id 'AV-002' -Name 'Defender signature age' -Category 'Endpoint' `
            -Status 'NotAssessed' -Measured 'Defender not readable' `
            -Detail 'Defender is not installed, or its module did not answer.'
    }

    $mode = if ($status.PSObject.Properties['AMRunningMode']) { [string] $status.AMRunningMode } else { '' }

    # Signature age is not a judgement on a machine another product protects:
    # passive Defender does not scan, so stale definitions cost nothing.
    if ($mode -like '*Passive*') {

        return New-TkAuditFinding -Id 'AV-002' -Name 'Defender signature age' -Category 'Endpoint' `
            -Status 'Info' -Measured $mode `
            -Detail 'Defender is passive because another product owns protection, so its signature age does not matter.'
    }

    # Defender stopped entirely reports no signature date at all. Subtracting
    # from it threw, which is a crash where the honest answer is "not ours".
    if ($null -eq $status.AntivirusSignatureLastUpdated) {

        return New-TkAuditFinding -Id 'AV-002' -Name 'Defender signature age' -Category 'Endpoint' `
            -Status 'Info' -Measured $(if ($mode) { $mode } else { 'Not running' }) `
            -Detail 'Defender is not the product protecting this machine, so it reports no signature date.'
    }

    $age = (Get-Date) - $status.AntivirusSignatureLastUpdated

    if ($age.TotalDays -gt 7) {

        return New-TkAuditFinding -Id 'AV-002' -Name 'Defender signature age' -Category 'Endpoint' `
            -Status 'Warning' -Measured ('{0} days old' -f [int] $age.TotalDays) `
            -Detail 'Definitions this old miss most of what is circulating now.' `
            -Recommendation 'Run Update-MpSignature, or check that the machine reaches the update service.' `
            -RemediationId 'update-signatures'
    }

    return New-TkAuditFinding -Id 'AV-002' -Name 'Defender signature age' -Category 'Endpoint' `
        -Status 'Pass' -Measured ('{0} days old' -f [int] $age.TotalDays) `
        -Detail 'Definitions are current.'
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
            -Recommendation 'Enable every profile. The public profile is the one that matters on hotel and client networks.' -RemediationId 'enable-firewall'
    }
    catch {
        return New-TkAuditFinding -Id 'FW-001' -Name 'Windows Firewall' -Category 'Network' `
            -Status 'NotAssessed' -Detail 'Firewall state could not be read.'
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
                -Recommendation 'Remove it. SMBv1 is the protocol WannaCry and NotPetya spread over, and nothing modern needs it.' -RemediationId 'disable-smbv1'
        }

        return New-TkAuditFinding -Id 'SMB-001' -Name 'SMBv1' -Category 'Network' `
            -Status 'Pass' -Detail 'SMBv1 is not enabled.'
    }
    catch {
        return New-TkAuditFinding -Id 'SMB-001' -Name 'SMBv1' -Category 'Network' `
            -Status 'NotAssessed' -Detail 'SMBv1 state could not be read (needs elevation).'
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
        -Recommendation 'Disable it by policy. LLMNR and NBT-NS name resolution is what Responder abuses to capture NTLM hashes on a flat network.' -RemediationId 'disable-llmnr'
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
                -Recommendation 'Remove it. It bypasses script block logging, AMSI and constrained language mode, which is why attackers ask for it by name.' -RemediationId 'disable-powershell-v2'
        }

        return New-TkAuditFinding -Id 'PS-001' -Name 'PowerShell 2.0 engine' -Category 'Endpoint' `
            -Status 'Pass' -Detail 'The downgrade engine is not installed.'
    }
    catch {
        return New-TkAuditFinding -Id 'PS-001' -Name 'PowerShell 2.0 engine' -Category 'Endpoint' `
            -Status 'NotAssessed' -Detail 'Feature state could not be read (needs elevation).'
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
        -Recommendation 'Require NLA: without it the logon screen is rendered before authentication, which is a free pre-auth attack surface.' `
        -RemediationId 'enable-rdp-nla'
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
            -Status 'Fail' -Measured 'No prompt' -Detail 'UAC elevates without prompting.' `
            -Recommendation 'Set the consent prompt to at least "prompt for consent on the secure desktop".' `
            -RemediationId 'restore-uac-prompt'
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
                -Recommendation 'Disable it. It permits unauthenticated access to shared resources.' -RemediationId 'disable-guest'
        }

        return New-TkAuditFinding -Id 'ACC-001' -Name 'Guest account' -Category 'Accounts' `
            -Status 'Pass' -Detail 'The Guest account is disabled.'
    }
    catch {
        return New-TkAuditFinding -Id 'ACC-001' -Name 'Guest account' -Category 'Accounts' `
            -Status 'NotAssessed' -Detail 'Local accounts could not be enumerated.'
    }
}

<#
.SYNOPSIS
    Lists the members of the local Administrators group.

.DESCRIPTION
    Membership alone is not the finding. A domain group and a management agent
    both belong there and both look like extra administrators; a local account
    nobody can name does not. So the check returns what is needed to tell them
    apart, and honours the exclusions the operator has declared.

    Exclusions are named in the finding, never silently applied. An audit that
    hides what it was told to ignore is worse than one that never ran, because
    the reader has no way to know the question was narrowed.
#>
function Test-TkAuditLocalAdministrators {
    [CmdletBinding()]
    param(
        # Defaults to what the running audit was given. A parameter rather than
        # a bare read of script state, so the exclusion rule can be checked on
        # its own.
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ExcludedAccount = $script:TkAuditExcludedAccount,

        # The group's members. Read from the machine when not given.
        [Parameter()]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Member
    )

    $members = if ($PSBoundParameters.ContainsKey('Member')) { @($Member) }
               else { @(Get-TkLocalAdministrator) }

    if ($members.Count -eq 0) {

        return New-TkAuditFinding -Id 'ACC-002' -Name 'Local administrators' -Category 'Accounts' `
            -Status 'NotAssessed' -Measured 'Not enumerable' `
            -Detail 'The Administrators group could not be enumerated.'
    }

    $excluded = @($members | Where-Object { $ExcludedAccount -contains $_.Name })
    $counted  = @($members | Where-Object { $ExcludedAccount -notcontains $_.Name })

    $names = @($counted | ForEach-Object { $_.Name })

    $detail = '{0} member(s): {1}.' -f $names.Count, ($names -join ', ')

    if ($excluded.Count -gt 0) {
        $detail += ' Excluded by the operator, and not counted: {0}.' -f
            ((@($excluded | ForEach-Object { $_.Name })) -join ', ')
    }

    # Three is the point where a workstation stops looking like one account,
    # the built in administrator and a management agent.
    $status = if ($names.Count -gt 3) { 'Warning' } else { 'Info' }

    return New-TkAuditFinding -Id 'ACC-002' -Name 'Local administrators' -Category 'Accounts' `
        -Status $status -Measured ('{0} counted' -f $names.Count) -Detail $detail `
        -Recommendation 'Every extra member is another account whose compromise gives full control of the machine. Exclude the ones that belong here so the rest stand out.'
}

<#
.SYNOPSIS
    Lists the members of the local Administrators group with what identifies them.

.DESCRIPTION
    Kept apart from the control because the interface needs the same list to
    offer the exclusions, and because the name alone cannot tell a domain group
    from a local account: the object class, the source and the SID can.

.OUTPUTS
    PSCustomObject[] with Name, ObjectClass, Source and Sid.
#>
function Get-TkLocalAdministrator {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    try {
        # -544 is the well known RID of the Administrators group, which is what
        # to match on: the group is renamed on a localised Windows.
        $group = Get-LocalGroup -ErrorAction Stop | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' }

        if (-not $group) {
            return @()
        }

        $result = @()

        foreach ($member in (Get-LocalGroupMember -Group $group -ErrorAction Stop)) {

            $result += [pscustomobject] @{
                Name        = [string] $member.Name
                ObjectClass = [string] $member.ObjectClass
                Source      = [string] $member.PrincipalSource
                Sid         = [string] $member.SID
            }
        }

        return $result
    }
    catch {
        Write-TkLog -Level Warning -Category 'Audit' -Message (
            'The Administrators group could not be enumerated: {0}' -f $_.Exception.Message
        )

        return @()
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
                -Status 'NotAssessed' -Detail 'No dated update was found in the hotfix list.'
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
            -Status 'NotAssessed' -Detail 'The update history could not be read.'
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
        -Recommendation 'Set NoDriveTypeAutoRun to 255. A dropped USB stick should not be able to start anything on insertion.' -RemediationId 'disable-autorun'
}

<#
.SYNOPSIS
    Reads the password and lockout policy out of "net accounts" output.

.DESCRIPTION
    Every label in that output is translated, and so are the words for "never"
    and "none". Matching on "Minimum password length" meant a French Windows
    never found the row, read a length of zero, and failed the control whatever
    its real policy was.

    The order of the rows is not translated and has not changed since NT, so
    the values are taken by position: the fourth row is the minimum length, the
    sixth the lockout threshold. A number is a number in every language, and
    anything that is not a number on the threshold row means there is none.

.PARAMETER Text
    The standard output of "net accounts".

.OUTPUTS
    PSCustomObject with MinimumPasswordLength and LockoutThreshold, each null
    when its row could not be read.
#>
function ConvertFrom-TkNetAccountsOutput {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    # Policy rows carry a colon before their value; the closing "the command
    # completed successfully" line does not, whatever the language.
    $values = @()

    foreach ($row in ($Text -split "`r?`n")) {

        if ($row -match '^.*:\s*(\S.*?)\s*$') {
            $values += $Matches[1]
        }
    }

    $length    = $null
    $threshold = $null

    if ($values.Count -gt 3 -and $values[3] -match '^\d+$') {
        $length = [int] $values[3]
    }

    if ($values.Count -gt 5) {
        $threshold = if ($values[5] -match '^\d+$') { [int] $values[5] } else { 0 }
    }

    return [pscustomobject] @{
        MinimumPasswordLength = $length
        LockoutThreshold      = $threshold
    }
}

<#
.SYNOPSIS
    Runs "net accounts" and returns the parsed policy, or null.
#>
function Get-TkNetAccountsPolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $result = Invoke-TkProcess -FilePath 'net.exe' -ArgumentList @('accounts') -TimeoutSeconds 30

    if (-not $result -or $result.ExitCode -ne 0) {
        return $null
    }

    return ConvertFrom-TkNetAccountsOutput -Text $result.StandardOutput
}

<#
.SYNOPSIS
    Reads the local password policy.
#>
function Test-TkAuditPasswordPolicy {
    [CmdletBinding()]
    param()

    $policy = Get-TkNetAccountsPolicy

    if ($null -eq $policy -or $null -eq $policy.MinimumPasswordLength) {

        return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
            -Status 'NotAssessed' -Measured 'Not readable' `
            -Detail 'The local password policy could not be read.'
    }

    $minimumLength = $policy.MinimumPasswordLength

    if ($minimumLength -eq 0) {

        return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
            -Status 'Fail' -Measured 'No minimum' `
            -Detail 'No minimum password length is enforced.' `
            -Recommendation 'Require at least 12 characters, or 14 for accounts with administrative rights.'
    }

    if ($minimumLength -lt 12) {

        return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
            -Status 'Warning' -Measured ('{0} characters' -f $minimumLength) `
            -Detail ('The minimum password length is {0}.' -f $minimumLength) `
            -Recommendation 'Length is what defeats offline cracking; 12 characters is the current floor.'
    }

    return New-TkAuditFinding -Id 'PWD-001' -Name 'Password policy' -Category 'Accounts' `
        -Status 'Pass' -Measured ('{0} characters' -f $minimumLength) `
        -Detail ('The minimum password length is {0}.' -f $minimumLength)
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

    # The same score the screen shows, so an exported report and the page it
    # came from never disagree about the number.
    $score = Get-TkAuditScore -Finding @($Findings)

    $report = [pscustomobject]@{
        Computer    = $env:COMPUTERNAME
        GeneratedAt = (Get-Date).ToString('s')
        Toolkit     = (Get-TkContext).Version
        Note        = 'Local hygiene check. It does not replace a CIS or ANSSI benchmark run.'
        Summary     = [pscustomobject]@{
            Score       = $score.Score
            Pass        = $score.Passed
            Fail        = $score.Failed
            Warning     = $score.Warnings
            NotAssessed = $score.NotAssessed
            Info        = @($Findings | Where-Object { $_.Status -eq 'Info' }).Count
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

# ---------------------------------------------------------------------------
# Controls added from the CIS and ANSSI workstation baselines
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Checks that the screen locks itself, and asks for a password when it does.

.DESCRIPTION
    The control everybody skips and every auditor opens with, because an
    unlocked machine in an open office defeats every other control on this
    list. Both halves matter: a screen saver that does not ask for the password
    is decoration.
#>
function Test-TkAuditScreenLock {
    [CmdletBinding()]
    param()

    # The machine wide policy, which wins where it is set.
    $machine = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                                   -Name 'InactivityTimeoutSecs'

    if ($null -ne $machine -and [int] $machine -gt 0) {

        $minutes = [int] ([int] $machine / 60)

        if ([int] $machine -le 900) {

            return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
                -Status 'Pass' -Measured ('Locks after {0} minute(s)' -f $minutes) `
                -Detail 'The machine locks itself by policy.'
        }

        return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
            -Status 'Warning' -Measured ('Locks after {0} minute(s)' -f $minutes) `
            -Detail 'Longer than the fifteen minutes both CIS and the ANSSI ask for.' `
            -Recommendation 'Set the interactive logon inactivity limit to 900 seconds or less.'
    }

    # Falling back to the user's own screen saver settings.
    $active  = Get-TkRegistryValue -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive'
    $secure  = Get-TkRegistryValue -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaverIsSecure'
    $timeout = Get-TkRegistryValue -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveTimeOut'

    if ($null -eq $active) {

        return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
            -Status 'NotAssessed' -Measured 'No setting found' `
            -Detail 'Neither a machine policy nor a screen saver setting could be read.'
    }

    if ([string] $active -ne '1') {

        return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
            -Status 'Fail' -Measured 'Never locks' `
            -Detail 'Nothing locks this session when it is left alone.' `
            -Recommendation 'Set an inactivity limit by policy, which cannot be turned off from the desktop.'
    }

    if ([string] $secure -ne '1') {

        return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
            -Status 'Fail' -Measured 'Locks without asking for a password' `
            -Detail 'The screen saver starts but does not require the password to dismiss it, so it stops nobody.' `
            -Recommendation 'Require a password on resume, by policy rather than per user.'
    }

    $minutes = if ($timeout) { [int] ([int] $timeout / 60) } else { 0 }

    if ($minutes -gt 15 -or $minutes -eq 0) {

        return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
            -Status 'Warning' -Measured ('{0} minute(s), per user' -f $minutes) `
            -Detail 'Set per user rather than by policy, so anybody can turn it off.' `
            -Recommendation 'Set the interactive logon inactivity limit by policy, at 900 seconds or less.'
    }

    return New-TkAuditFinding -Id 'LOCK-001' -Name 'Screen lock' -Category 'Endpoint' `
        -Status 'Warning' -Measured ('{0} minute(s), per user' -f $minutes) `
        -Detail 'The session locks with a password, but from a per user setting anybody can turn off.' `
        -Recommendation 'Set the same limit by policy so it cannot be removed from the desktop.'
}

<#
.SYNOPSIS
    Checks that repeated bad passwords lock the account.

.DESCRIPTION
    Without a threshold, an account with a weak password falls to an online
    guessing attack given an afternoon. Windows 11 sets ten by default, but a
    machine upgraded from an older build often still has none.
#>
function Test-TkAuditAccountLockout {
    [CmdletBinding()]
    param()

    $policy = Get-TkNetAccountsPolicy

    if ($null -eq $policy -or $null -eq $policy.LockoutThreshold) {

        return New-TkAuditFinding -Id 'ACC-004' -Name 'Account lockout' -Category 'Accounts' `
            -Status 'NotAssessed' -Measured 'Not readable' `
            -Detail 'The local account policy could not be read.'
    }

    $threshold = $policy.LockoutThreshold

    if ($threshold -eq 0) {

        return New-TkAuditFinding -Id 'ACC-004' -Name 'Account lockout' -Category 'Accounts' `
            -Status 'Fail' -Measured 'No threshold' `
            -Detail 'Passwords can be guessed indefinitely: nothing stops an attacker trying.' `
            -Recommendation 'Set a lockout threshold of ten or fewer bad attempts, with a lockout of fifteen minutes.'
    }

    if ($threshold -gt 10) {

        return New-TkAuditFinding -Id 'ACC-004' -Name 'Account lockout' -Category 'Accounts' `
            -Status 'Warning' -Measured ('{0} attempts' -f $threshold) `
            -Detail 'Higher than the ten both CIS and the ANSSI ask for.' `
            -Recommendation 'Lower the threshold to ten or fewer.'
    }

    return New-TkAuditFinding -Id 'ACC-004' -Name 'Account lockout' -Category 'Accounts' `
        -Status 'Pass' -Measured ('{0} attempts' -f $threshold) `
        -Detail 'Repeated bad passwords lock the account.'
}

<#
.SYNOPSIS
    Checks that Remote Desktop requires authentication before drawing a desktop.

.DESCRIPTION
    Network Level Authentication makes the client prove who it is before the
    server allocates a session. Without it, anything that can reach the port
    gets a logon screen and a session to attack, which is how an exposed RDP
    host becomes a ransomware entry point.

    Not applicable when RDP is off, which is the better answer anyway.
#>
function Test-TkAuditRdpNla {
    [CmdletBinding()]
    param()

    $denied = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
                                  -Name 'fDenyTSConnections'

    if ($null -eq $denied) {

        return New-TkAuditFinding -Id 'RDP-002' -Name 'Remote Desktop authentication' -Category 'Remote access' `
            -Status 'NotAssessed' -Measured 'Not readable' `
            -Detail 'The Terminal Server configuration could not be read.'
    }

    if ([int] $denied -eq 1) {

        return New-TkAuditFinding -Id 'RDP-002' -Name 'Remote Desktop authentication' -Category 'Remote access' `
            -Status 'Pass' -Measured 'Remote Desktop is off' -Applicable $false `
            -Detail 'Nothing listens, so there is no session to authenticate to.'
    }

    $nla = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                               -Name 'UserAuthentication'

    if ([string] $nla -eq '1') {

        return New-TkAuditFinding -Id 'RDP-002' -Name 'Remote Desktop authentication' -Category 'Remote access' `
            -Status 'Pass' -Measured 'Network Level Authentication on' `
            -Detail 'A client proves who it is before a session is created.'
    }

    return New-TkAuditFinding -Id 'RDP-002' -Name 'Remote Desktop authentication' -Category 'Remote access' `
        -Status 'Fail' -Measured 'Network Level Authentication off' `
        -Detail 'Anything that reaches the port is handed a logon screen and a session to attack.' `
        -Recommendation 'Require Network Level Authentication. Only very old clients cannot use it.' `
        -RemediationId 'enable-rdp-nla'
}

<#
.SYNOPSIS
    Checks whether Windows Update has been paused.

.DESCRIPTION
    A pause is a deliberate act with an expiry date, and the date is routinely
    forgotten. A machine paused six months ago looks healthy in every other
    check while missing every patch since.
#>
function Test-TkAuditUpdatePaused {
    [CmdletBinding()]
    param()

    $until = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' `
                                 -Name 'PauseFeatureUpdatesEndTime'

    $quality = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' `
                                   -Name 'PauseQualityUpdatesEndTime'

    $dates = @()

    foreach ($value in @($until, $quality)) {

        if (-not $value) {
            continue
        }

        $parsed = [datetime]::MinValue

        if ([datetime]::TryParse([string] $value, [ref] $parsed)) {
            $dates += $parsed
        }
    }

    if ($dates.Count -eq 0) {

        return New-TkAuditFinding -Id 'UPD-002' -Name 'Windows Update pause' -Category 'Servicing' `
            -Status 'Pass' -Measured 'Not paused' -Detail 'Updates are not held back.'
    }

    $latest = ($dates | Sort-Object -Descending)[0]

    if ($latest -gt (Get-Date)) {

        return New-TkAuditFinding -Id 'UPD-002' -Name 'Windows Update pause' -Category 'Servicing' `
            -Status 'Warning' -Measured ('Paused until {0:yyyy-MM-dd}' -f $latest) `
            -Detail 'Updates are held back. A pause set and forgotten is how a machine falls a year behind.' `
            -Recommendation 'Resume updates, or note the date this pause is meant to end.'
    }

    return New-TkAuditFinding -Id 'UPD-002' -Name 'Windows Update pause' -Category 'Servicing' `
        -Status 'Pass' -Measured 'Pause expired' -Detail 'A pause was set but has lapsed.'
}

<#
.SYNOPSIS
    Checks whether WinRM is listening, and to whom.

.DESCRIPTION
    WinRM is remote code execution as an administrator, by design. On a server
    it is how the machine is managed; on a workstation it is usually something
    a script turned on and nobody turned off, and it is worth knowing about.
#>
function Test-TkAuditWinRm {
    [CmdletBinding()]
    param()

    $service = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue

    if ($null -eq $service) {

        return New-TkAuditFinding -Id 'NET-003' -Name 'WinRM remote management' -Category 'Remote access' `
            -Status 'NotAssessed' -Measured 'Service not found' `
            -Detail 'The WinRM service could not be read.'
    }

    if ($service.Status -ne 'Running') {

        return New-TkAuditFinding -Id 'NET-003' -Name 'WinRM remote management' -Category 'Remote access' `
            -Status 'Pass' -Measured 'Not running' `
            -Detail 'Nothing accepts remote PowerShell on this machine.'
    }

    # Listening is the question, not the service being up: the service runs for
    # local use on a machine with no listener at all.
    $listeners = @(Get-ChildItem -Path 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue)

    if ($listeners.Count -eq 0) {

        return New-TkAuditFinding -Id 'NET-003' -Name 'WinRM remote management' -Category 'Remote access' `
            -Status 'Pass' -Measured 'Running, no listener' `
            -Detail 'The service runs but accepts nothing from the network.'
    }

    return New-TkAuditFinding -Id 'NET-003' -Name 'WinRM remote management' -Category 'Remote access' `
        -Status 'Warning' -Measured ('{0} listener(s)' -f $listeners.Count) `
        -Detail 'WinRM grants remote code execution as an administrator. On a workstation it is rarely wanted.' `
        -Recommendation 'If this machine is not managed over WinRM, disable it with Disable-PSRemoting and stop the service.'
}

<#
.SYNOPSIS
    Checks for enabled local accounts whose password never expires.

.DESCRIPTION
    A local account with a password that never expires and a name nobody
    recognises is the classic quiet backdoor, and the classic leftover from a
    technician who needed an account once. Either way it deserves a name.
#>
function Test-TkAuditStaleLocalAccount {
    [CmdletBinding()]
    param()

    try {
        $accounts = @(Get-LocalUser -ErrorAction Stop |
                      Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
    }
    catch {
        return New-TkAuditFinding -Id 'ACC-005' -Name 'Local accounts that never expire' -Category 'Accounts' `
            -Status 'NotAssessed' -Measured 'Not enumerable' `
            -Detail 'Local accounts could not be enumerated.'
    }

    # The built in accounts are expected to be shaped this way, and disabling
    # their expiry is not the operator's decision to make.
    $builtIn  = @($accounts | Where-Object { $_.SID.Value -match '-(500|501|503|504)$' })
    $reported = @($accounts | Where-Object { $_.SID.Value -notmatch '-(500|501|503|504)$' })

    if ($reported.Count -eq 0) {

        return New-TkAuditFinding -Id 'ACC-005' -Name 'Local accounts that never expire' -Category 'Accounts' `
            -Status 'Pass' -Measured ('{0} built in only' -f $builtIn.Count) `
            -Detail 'No ordinary local account has a password set never to expire.'
    }

    return New-TkAuditFinding -Id 'ACC-005' -Name 'Local accounts that never expire' -Category 'Accounts' `
        -Status 'Warning' -Measured ('{0} account(s)' -f $reported.Count) `
        -Detail ('Enabled, with a password that never expires: {0}.' -f
            ((@($reported | ForEach-Object { $_.Name })) -join ', ')) `
        -Recommendation 'Confirm each one is still needed and still owned by somebody, then set an expiry or disable it.'
}
