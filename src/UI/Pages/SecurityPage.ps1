<#
    Toolkit - UI / Security page

    Five tabs: SSH keys, file integrity, credential tools, the local audit
    and the settings that hold the VirusTotal key.

    Secrets are read straight from the PasswordBox as a SecureString and
    passed on without ever becoming a plain string in this file.
#>

# Last generated secret, kept only so the copy button works. Cleared as soon
# as it is copied.
$script:TkLastGeneratedSecret = ''

# Last audit result, kept so the export button has something to write.
$script:TkLastAudit = $null

<#
.SYNOPSIS
    Wires the Security page.
#>
function Initialize-TkSecurityPage {
    [CmdletBinding()]
    param()

    # --- SSH --------------------------------------------------------------
    $keyType = Get-TkControl -Name 'SshKeyType'

    if ($keyType) {

        foreach ($type in @('ed25519', 'ecdsa', 'rsa')) {
            [void] $keyType.Items.Add($type)
        }

        $keyType.SelectedIndex = 0
    }

    $comment = Get-TkControl -Name 'SshKeyComment'

    if ($comment) {
        $comment.Text = '{0}@{1}' -f $env:USERNAME, $env:COMPUTERNAME
    }

    Register-TkClick -Name 'BtnGenerateSshKey' -Action { New-TkSshKeyFromUi }
    Register-TkClick -Name 'BtnListSshKeys'    -Action { Show-TkSshKeyList }

    Register-TkClick -Name 'BtnCopyPublicKey' -Action {

        $keys = Get-TkSshKey

        if ($keys.Count -eq 0) {
            Set-TkStatus -Text 'No key was found in the profile.'
            return
        }

        $latest = $keys | Sort-Object -Property Created -Descending | Select-Object -First 1

        if (Set-TkClipboard -Text $latest.PublicKey) {
            Set-TkStatus -Text ('Public key copied: {0}' -f $latest.Name)
        }
    }

    # --- File integrity ---------------------------------------------------
    Register-TkClick -Name 'BtnBrowseHashFile' -Action {

        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Title  = 'Select a file'
        $dialog.Filter = 'All files (*.*)|*.*'

        if ($dialog.ShowDialog()) {
            (Get-TkControl -Name 'HashFilePath').Text = $dialog.FileName
        }
    }

    Register-TkClick -Name 'BtnComputeHash' -Action { Invoke-TkHashComputation }
    Register-TkClick -Name 'BtnVerifyHash'  -Action { Invoke-TkHashVerification }
    Register-TkClick -Name 'BtnVirusTotal'  -Action { Invoke-TkVirusTotalCheck }

    # --- Credentials ------------------------------------------------------
    Register-TkClick -Name 'BtnGeneratePassword'   -Action { New-TkPasswordFromUi }
    Register-TkClick -Name 'BtnGeneratePassphrase' -Action { New-TkPassphraseFromUi }
    Register-TkClick -Name 'BtnCheckBreach'        -Action { Invoke-TkBreachCheck }

    Register-TkClick -Name 'BtnCopyPassword' -Action {

        if ([string]::IsNullOrEmpty($script:TkLastGeneratedSecret)) {
            Set-TkStatus -Text 'Generate something first.'
            return
        }

        if (Set-TkClipboard -Text $script:TkLastGeneratedSecret) {

            # Do not keep the secret in memory once it has been handed over.
            $script:TkLastGeneratedSecret = ''
            Set-TkStatus -Text 'Copied to the clipboard, and cleared from the toolkit.'
        }
    }

    # --- Audit ------------------------------------------------------------
    Register-TkClick -Name 'BtnRunAudit'        -Action { Invoke-TkAuditFromUi }
    Register-TkClick -Name 'BtnExportAudit'     -Action { Export-TkAuditFromUi }
    Register-TkClick -Name 'BtnAuditExclusions' -Action { Show-TkAuditExclusionDialog }

    $levelBox = Get-TkControl -Name 'AuditLevel'

    if ($levelBox) {

        # Filled and selected before anything is attached to the selection, the
        # house pattern: an Add_SelectionChanged in place first would fire while
        # the list is still being built.
        [void] $levelBox.Items.Add('Essential - the usual suspects')
        [void] $levelBox.Items.Add('Full - everything, including the hard ones')

        $levelBox.SelectedIndex = 0
    }

    # --- Settings ---------------------------------------------------------
    Register-TkClick -Name 'BtnSaveVtKey' -Action {

        $box = Get-TkControl -Name 'VtApiKey'

        if ($box.SecurePassword.Length -eq 0) {
            Set-TkStatus -Text 'Paste the API key first.'
            return
        }

        if (Set-TkVirusTotalApiKey -ApiKey $box.SecurePassword -Confirm:$false) {
            $box.Clear()
            Update-TkVirusTotalKeyStatus
        }
    }

    Register-TkClick -Name 'BtnRemoveVtKey' -Action {

        Remove-TkVirusTotalApiKey -Confirm:$false | Out-Null
        Update-TkVirusTotalKeyStatus
    }

    Register-TkClick -Name 'BtnOpenDataFolder' -Action {
        Start-Process -FilePath 'explorer.exe' -ArgumentList (Get-TkContext).DataRoot
    }

    Register-TkClick -Name 'BtnClearLogs' -Action { Clear-TkOldLog }

    $dataPath = Get-TkControl -Name 'DataPathText'

    if ($dataPath) {
        $dataPath.Text = (Get-TkContext).DataRoot
    }

    Update-TkVirusTotalKeyStatus
}

# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Generates a key pair from the values on the page.
#>
function New-TkSshKeyFromUi {
    [CmdletBinding()]
    param()

    $name          = (Get-TkControl -Name 'SshKeyName').Text.Trim()
    $type          = [string] (Get-TkControl -Name 'SshKeyType').SelectedItem
    $comment       = (Get-TkControl -Name 'SshKeyComment').Text.Trim()
    $passphraseBox = Get-TkControl -Name 'SshPassphrase'
    $noPassphrase  = (Get-TkControl -Name 'SshNoPassphrase').IsChecked

    if ([string]::IsNullOrWhiteSpace($name)) {
        Set-TkStatus -Text 'Give the key a file name.'
        return
    }

    if ($passphraseBox.SecurePassword.Length -eq 0 -and -not $noPassphrase) {

        Set-TkOutput -ControlName 'SshOutput' -Text (
            'A passphrase is required. A private key without one is usable by anything that can read the file: any process running as you, any backup, any sync client.' +
            [Environment]::NewLine + [Environment]::NewLine +
            'Tick the box to generate one anyway.'
        )

        return
    }

    $parameters = @{
        Name    = $name
        Type    = $type
        Comment = $comment
        Confirm = $false
    }

    if ($noPassphrase) {
        $parameters['AllowEmptyPassphrase'] = $true
    }
    else {
        $parameters['Passphrase'] = $passphraseBox.SecurePassword
    }

    $key = New-TkSshKey @parameters

    $passphraseBox.Clear()

    if (-not $key) {
        Set-TkOutput -ControlName 'SshOutput' -Text 'The key was not generated. See the output panel for the reason.'
        return
    }

    $lines = @(
        'Key generated.'
        ''
        'Private key   {0}' -f $key.PrivateKeyPath
        'Public key    {0}' -f $key.PublicKeyPath
        'Fingerprint   {0}' -f $key.Fingerprint
        ''
        'Public key, ready to paste into authorized_keys or a Git host:'
        ''
        $key.PublicKey
        ''
        'The private key permissions were restricted to your account. Never copy the'
        'private key to another machine: generate a new pair there instead.'
    )

    Set-TkOutput -ControlName 'SshOutput' -Text ($lines -join [Environment]::NewLine)
    Set-TkStatus -Text ('SSH key {0} generated.' -f $key.Name)
}

<#
.SYNOPSIS
    Lists the SSH keys in the user profile.
#>
function Show-TkSshKeyList {
    [CmdletBinding()]
    param()

    $status = Get-TkSshStatus
    $keys   = Get-TkSshKey

    $lines = @(
        'OpenSSH       {0}' -f $(if ($status.Available) { $status.Version } else { 'not installed' })
        'Directory     {0}' -f $status.SshDirectory
        'Agent         {0}' -f $(if ($status.AgentStatus) { $status.AgentStatus } else { 'not present' })
        ''
    )

    if ($keys.Count -eq 0) {
        $lines += 'No key pair was found.'
    }
    else {
        foreach ($key in $keys) {

            $lines += ('{0} ({1})' -f $key.Name, $key.Algorithm)
            $lines += ('    Comment      {0}' -f $key.Comment)
            $lines += ('    Fingerprint  {0}' -f $key.Fingerprint)
            $lines += ('    Private key  {0}' -f $(if ($key.HasPrivateKey) { 'present' } else { 'MISSING' }))
            $lines += ''
        }
    }

    Set-TkOutput -ControlName 'SshOutput' -Text ($lines -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# File integrity
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Hashes the selected file and reports its signature.
#>
function Invoke-TkHashComputation {
    [CmdletBinding()]
    param()

    $path = (Get-TkControl -Name 'HashFilePath').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($path)) {
        Set-TkStatus -Text 'Select a file first.'
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Hashing...' `
        -ArgumentList @($path) `
        -ScriptBlock {
            param($filePath)
            Get-TkFileHashReport -Path $filePath -Algorithm @('MD5', 'SHA1', 'SHA256')
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                Set-TkOutput -ControlName 'IntegrityOutput' -Text 'The file could not be read.'
                return
            }

            $lines = @(
                'File          {0}' -f $report.Name
                'Path          {0}' -f $report.Path
                'Size          {0}' -f $report.Size
                'Modified      {0}' -f $report.Modified
                ''
                'MD5           {0}' -f $report.Hashes['MD5']
                'SHA1          {0}' -f $report.Hashes['SHA1']
                'SHA256        {0}' -f $report.Hashes['SHA256']
                ''
                'Signature     {0}' -f $report.Signature.Status
                'Signer        {0}' -f $report.Signature.Signer
                'Note          {0}' -f $report.Signature.Message
                ''
                $report.WeakWarning
            )

            Set-TkOutput -ControlName 'IntegrityOutput' -Text ($lines -join [Environment]::NewLine)
        }
}

<#
.SYNOPSIS
    Compares the file against the expected hash.
#>
function Invoke-TkHashVerification {
    [CmdletBinding()]
    param()

    $path     = (Get-TkControl -Name 'HashFilePath').Text.Trim()
    $expected = (Get-TkControl -Name 'ExpectedHash').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($expected)) {
        Set-TkStatus -Text 'A file and an expected hash are both required.'
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Verifying...' `
        -ArgumentList @($path, $expected) `
        -ScriptBlock {
            param($filePath, $reference)
            Test-TkFileHash -Path $filePath -ExpectedHash $reference
        } `
        -OnComplete {
            param($result)

            $verification = @($result.Output) | Select-Object -First 1

            if (-not $verification) {
                return
            }

            $lines = @(
                'Result        {0}' -f $(if ($verification.Match) { 'MATCH' } else { 'NO MATCH' })
                'Algorithm     {0}' -f $verification.Algorithm
                'Expected      {0}' -f $verification.Expected
                'Computed      {0}' -f $verification.Actual
                ''
                $verification.Message
            )

            Set-TkOutput -ControlName 'IntegrityOutput' -Text ($lines -join [Environment]::NewLine)
        }
}

<#
.SYNOPSIS
    Looks the selected file up on VirusTotal by hash.
#>
function Invoke-TkVirusTotalCheck {
    [CmdletBinding()]
    param()

    $path = (Get-TkControl -Name 'HashFilePath').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($path)) {
        Set-TkStatus -Text 'Select a file first.'
        return
    }

    if (-not (Get-TkVirusTotalApiKey)) {

        Set-TkOutput -ControlName 'IntegrityOutput' -Text (
            'No VirusTotal API key is stored. Add one on the Settings tab. A free account provides 4 requests per minute and 500 per day.'
        )

        return
    }

    Invoke-TkBackgroundAction -StatusText 'Querying VirusTotal...' `
        -ArgumentList @($path) `
        -ScriptBlock {
            param($filePath)
            Get-TkVirusTotalFileReport -Path $filePath
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                Set-TkOutput -ControlName 'IntegrityOutput' -Text 'No answer from VirusTotal. See the output panel.'
                return
            }

            $lines = @(
                'File          {0}' -f $report.FileName
                'SHA256        {0}' -f $report.Sha256
                ''
                'Verdict       {0}' -f $report.Verdict
            )

            if ($report.Known) {

                $lines += 'Malicious     {0}' -f $report.Malicious
                $lines += 'Suspicious    {0}' -f $report.Suspicious
                $lines += 'Harmless      {0}' -f $report.Harmless
                $lines += 'Undetected    {0}' -f $report.Undetected
                $lines += 'First seen    {0}' -f $report.FirstSeen
                $lines += 'Last analysis {0}' -f $report.LastAnalysis
            }
            else {
                $lines += ''
                $lines += $report.Detail
            }

            $lines += ''
            $lines += 'Report        {0}' -f $report.Permalink
            $lines += ''
            $lines += 'Only the SHA256 was sent. The file itself was not uploaded.'

            Set-TkOutput -ControlName 'IntegrityOutput' -Text ($lines -join [Environment]::NewLine)
        }
}

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Generates a password from the options on the page.
#>
function New-TkPasswordFromUi {
    [CmdletBinding()]
    param()

    $length = 0

    if (-not [int]::TryParse((Get-TkControl -Name 'PasswordLength').Text.Trim(), [ref] $length)) {
        $length = 20
    }

    $length = [Math]::Max(8, [Math]::Min(128, $length))

    try {
        $result = New-TkPassword -Length $length `
            -IncludeUppercase ([bool] (Get-TkControl -Name 'PwdUpper').IsChecked) `
            -IncludeLowercase ([bool] (Get-TkControl -Name 'PwdLower').IsChecked) `
            -IncludeDigits    ([bool] (Get-TkControl -Name 'PwdDigits').IsChecked) `
            -IncludeSymbols   ([bool] (Get-TkControl -Name 'PwdSymbols').IsChecked)
    }
    catch {
        Set-TkOutput -ControlName 'CredentialOutput' -Text ('Error: {0}' -f $_.Exception.Message)
        return
    }

    $script:TkLastGeneratedSecret = $result.Password

    $lines = @(
        $result.Password
        ''
        'Length        {0}' -f $result.Length
        'Alphabet      {0} characters' -f $result.AlphabetSize
        'Entropy       {0} bits' -f $result.EntropyBits
        'Assessment    {0}' -f $result.Strength
        ''
        'Generated with the cryptographic random number generator, using rejection'
        'sampling so no character is more likely than another.'
    )

    Set-TkOutput -ControlName 'CredentialOutput' -Text ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Generates a passphrase.
#>
function New-TkPassphraseFromUi {
    [CmdletBinding()]
    param()

    $result = New-TkPassphrase -WordCount 5 -AppendNumber

    $script:TkLastGeneratedSecret = $result.Passphrase

    $lines = @(
        $result.Passphrase
        ''
        'Words         {0} from a list of {1}' -f $result.WordCount, $result.ListSize
        'Entropy       {0} bits' -f $result.EntropyBits
        'Assessment    {0}' -f $result.Strength
        ''
        'A passphrase is the better choice wherever the credential has to be typed'
        'by hand: a server console, a phone, or dictated over the telephone.'
    )

    Set-TkOutput -ControlName 'CredentialOutput' -Text ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Checks a password against the breach corpus.
#>
function Invoke-TkBreachCheck {
    [CmdletBinding()]
    param()

    $box = Get-TkControl -Name 'BreachPassword'

    if ($box.SecurePassword.Length -eq 0) {
        Set-TkStatus -Text 'Type the password to check.'
        return
    }

    # Runs on the UI thread: a SecureString cannot safely cross a runspace
    # boundary, and the request is a single fast lookup.
    $result = Test-TkPasswordBreached -Password $box.SecurePassword

    $box.Clear()

    $lines = @(
        'Result        {0}' -f $(if ($result.Found) { 'FOUND IN BREACHES' } else { 'Not found' })
        'Occurrences   {0}' -f $(if ($result.Count -ge 0) { $result.Count } else { 'unknown' })
        ''
        $result.Message
        ''
        'Only the first five characters of the SHA1 hash were sent. The service'
        'returned every matching suffix and the comparison happened locally, so'
        'the password itself never left this machine.'
    )

    Set-TkOutput -ControlName 'CredentialOutput' -Text ($lines -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# Audit and settings
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Runs the security audit and renders it.

.DESCRIPTION
    Rendered as cards rather than as a grid, because a finding is not a row of
    data: it needs its explanation next to it, and where a safe correction
    exists it needs the button that applies it.

    The audit refuses to run without elevation. Half of these controls read
    values a standard user cannot see, so what came back was a report two
    thirds of which said "not readable" while looking exactly like a real one.
    A refusal with a way to fix it is more use than a misleading pass.
#>
function Invoke-TkAuditFromUi {
    [CmdletBinding()]
    param()

    if (-not (Test-TkIsElevated)) {
        Show-TkAuditElevationNotice
        return
    }

    # Held in script scope rather than captured in a closure: the completion
    # runs long after this function has returned, and a closure here would also
    # give the block its own module scope, which is how $script: reads have
    # gone wrong in this project before.
    $script:TkAuditLevel     = Get-TkSelectedAuditLevel
    $script:TkAuditExclusion = @(Get-TkAuditExclusion)

    Invoke-TkBackgroundAction -StatusText ('Running the {0} security audit...' -f $script:TkAuditLevel.ToLowerInvariant()) `
        -ScriptBlock {
            param($Level, $ExcludedAccount)

            Invoke-TkSecurityAudit -Level $Level -ExcludedAccount $ExcludedAccount
        } `
        -ParameterList @{ Level = $script:TkAuditLevel; ExcludedAccount = $script:TkAuditExclusion } `
        -OnComplete {
            param($result)

            Show-TkAuditReport -Finding @($result.Output) `
                -Level $script:TkAuditLevel -ExcludedAccount $script:TkAuditExclusion
        }
}

<#
.SYNOPSIS
    Draws a finished audit: the score card, then the findings by category.

.DESCRIPTION
    Kept apart from the background action, so a report can be drawn from any
    set of findings: the one just run, one read back from an export, or one
    rendered off screen to check the layout without an elevated audit first.

.PARAMETER Finding
    Findings as returned by Invoke-TkSecurityAudit.

.PARAMETER Level
    The depth the findings were produced at, for the heading.

.PARAMETER ExcludedAccount
    The accounts the run left out, named in the report.
#>
function Show-TkAuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding,

        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $Level = 'Essential',

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ExcludedAccount = @()
    )

    $findings = @($Finding)
    $script:TkLastAudit = $findings

    Show-TkAuditScore -Finding $findings

    $document = New-TkFlowDocument

    Add-TkHeading -Document $document -Text (
        '{0} audit of {1}' -f $Level, $env:COMPUTERNAME) -Level 1

    Add-TkParagraph -Document $document -Muted -Text (
        'A hygiene check, not a compliance audit: it does not replace a CIS or ANSSI benchmark run. Controls that could not be read are marked "not assessed" and left out of the score rather than counted either way.'
    )

    if ($ExcludedAccount.Count -gt 0) {
        Add-TkParagraph -Document $document -Muted -Text (
            'Excluded from the account controls at your request: {0}.' -f
                ($ExcludedAccount -join ', ')
        )
    }

    # Failing first, then warnings, then the rest: the order someone
    # reads a report in.
    $order = @{ 'Fail' = 0; 'Warning' = 1; 'NotAssessed' = 2; 'Info' = 3; 'Pass' = 4 }

    foreach ($category in (@($findings | ForEach-Object { $_.Category }) | Select-Object -Unique)) {

        Add-TkHeading -Document $document -Text $category -Level 2

        $inCategory = $findings |
                      Where-Object { $_.Category -eq $category } |
                      Sort-Object -Property @{ Expression = { $order[$_.Status] } }, 'Name'

        foreach ($finding in $inCategory) {

            # Measured, not the identifier. The card used to print
            # "ENC-001" where the value read off the machine belongs,
            # which told the reader nothing they could act on.
            Add-TkFindingCard -Document $document -Severity $finding.Status -Tinted `
                -Title ('{0}  -  {1}' -f $finding.Id, $finding.Name) `
                -State $finding.Measured -Detail $finding.Detail `
                -Action $finding.Recommendation -RemediationId $finding.RemediationId
        }
    }

    Set-TkDocument -ControlName 'AuditOutput' -Document $document

    $score = Get-TkAuditScore -Finding $findings

    Set-TkStatus -Text ('Audit: {0} of 100, {1} failing, {2} warnings.' -f
        $score.Score, $score.Failed, $score.Warnings)
}

<#
.SYNOPSIS
    Reads the depth selector.
#>
function Get-TkSelectedAuditLevel {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $box = Get-TkControl -Name 'AuditLevel'

    if ($box -and $box.SelectedItem -and ([string] $box.SelectedItem) -like 'Full*') {
        return 'Full'
    }

    return 'Essential'
}

<#
.SYNOPSIS
    Fills the score card above the report.

.DESCRIPTION
    The number is the first thing read, so it is drawn before the findings and
    large enough to read across a desk. The bar is the same number again for
    anyone who takes in a proportion faster than a figure, and it is coloured
    by the same thresholds a technician would use out loud: good, needs work,
    bad.
#>
function Show-TkAuditScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding
    )

    $score = Get-TkAuditScore -Finding $Finding

    $card = Get-TkControl -Name 'AuditScoreCard'

    if ($card) {
        $card.Visibility = [System.Windows.Visibility]::Visible
    }

    $severity = if ($score.Score -ge 85) { 'Pass' }
                elseif ($score.Score -ge 60) { 'Warning' }
                else { 'Fail' }

    $value = Get-TkControl -Name 'AuditScoreValue'

    if ($value) {
        $value.Text = [string] $score.Score
        $value.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty,
            (Get-TkSeverityBrushKey -Severity $severity))
    }

    $headline = Get-TkControl -Name 'AuditScoreHeadline'

    if ($headline) {
        $headline.Text = '{0} of {1} controls passed.' -f $score.Passed, $score.Assessed
    }

    $summary = Get-TkControl -Name 'AuditSummary'

    if ($summary) {

        $text = '{0} failing, {1} worth attention.' -f $score.Failed, $score.Warnings

        if ($score.NotAssessed -gt 0) {
            $text += ' {0} could not be read and are outside the score.' -f $score.NotAssessed
        }

        $summary.Text = $text
    }

    # The same bar as the disk space bars, from the same helper.
    Set-TkUsageBar -BarName 'AuditScoreBar' -FillName 'AuditScoreFill' -Percent $score.Score -Severity $severity
}

<#
.SYNOPSIS
    Explains why the audit will not run, and offers the way out.
#>
function Show-TkAuditElevationNotice {
    [CmdletBinding()]
    param()

    $document = New-TkFlowDocument

    Add-TkHeading -Document $document -Text 'The audit needs administrator rights' -Level 1

    Add-TkParagraph -Document $document -Text (
        'Disk encryption, the firewall, SMBv1, the password policy and the credential protections are all read from places a standard user cannot see.'
    )

    Add-TkParagraph -Document $document -Text (
        'Run unelevated, most of this report would say "not readable" while still looking like a security report, and a machine with real problems would come back looking fine. That is worse than no report, so the audit does not produce one.'
    )

    Add-TkParagraph -Document $document -Muted -Text (
        'Use "Restart as administrator" in the header, then run the audit again.'
    )

    Set-TkDocument -ControlName 'AuditOutput' -Document $document

    $card = Get-TkControl -Name 'AuditScoreCard'

    if ($card) {
        $card.Visibility = [System.Windows.Visibility]::Collapsed
    }

    Set-TkStatus -Text 'The security audit needs administrator rights.'
}

<#
.SYNOPSIS
    Returns the administrator accounts the operator has excluded.

.DESCRIPTION
    Kept in the settings rather than asked for each run, because the answer is
    a property of the machine ("this management agent belongs here"), not of
    the moment.

.OUTPUTS
    String[], possibly empty.
#>
function Get-TkAuditExclusion {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $ctx = Get-TkContext

    if ($null -eq $ctx.Settings -or -not $ctx.Settings.ContainsKey('AuditExcludedAccounts')) {
        return @()
    }

    return @($ctx.Settings['AuditExcludedAccounts'] | Where-Object { $_ })
}

<#
.SYNOPSIS
    Stores the excluded accounts.
#>
function Set-TkAuditExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Name
    )

    $ctx = Get-TkContext

    $ctx.Settings['AuditExcludedAccounts'] = @($Name)

    [void] (Save-TkSettings)
}

<#
.SYNOPSIS
    Lets the operator say which administrator accounts belong on this machine.

.DESCRIPTION
    Every account is shown with its class and where it comes from, because the
    name alone cannot separate a domain group that belongs there from a local
    account that does not. Nothing is excluded by default: the tool has no way
    to know which of them is expected, and guessing would quietly answer the
    question the operator came to ask.

    Exclusions are reported in the audit, never applied silently.
#>
function Show-TkAuditExclusionDialog {
    [CmdletBinding()]
    param()

    $members = @(Get-TkLocalAdministrator)

    if ($members.Count -eq 0) {
        Set-TkStatus -Text 'The Administrators group could not be enumerated.'
        return
    }

    $excluded = @(Get-TkAuditExclusion)

    $ctx = Get-TkContext

    $window = New-Object System.Windows.Window
    $window.Title                 = 'Excluded administrator accounts'
    $window.Width                 = 560
    $window.SizeToContent         = [System.Windows.SizeToContent]::Height
    $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterOwner
    $window.ResizeMode            = [System.Windows.ResizeMode]::NoResize

    if ($ctx.Window) {
        $window.Owner = $ctx.Window
        $window.Resources = $ctx.Window.Resources
    }

    $window.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'Surface')

    $stack = New-Object System.Windows.Controls.StackPanel
    $stack.Margin = New-Object System.Windows.Thickness(18)

    $intro = New-Object System.Windows.Controls.TextBlock
    $intro.Text         = 'Tick the accounts that are expected on this machine. They are left out of the account controls and named in the report.'
    $intro.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $intro.Margin       = New-Object System.Windows.Thickness(0, 0, 0, 12)
    $intro.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

    [void] $stack.Children.Add($intro)

    $boxes = @()

    foreach ($member in $members) {

        $box = New-Object System.Windows.Controls.CheckBox
        $box.Content     = '{0}    ({1}, {2})' -f $member.Name, $member.ObjectClass, $member.Source
        $box.Tag         = $member.Name
        $box.IsChecked   = ($excluded -contains $member.Name)
        $box.Margin      = New-Object System.Windows.Thickness(0, 0, 0, 7)
        $box.SetResourceReference([System.Windows.Controls.CheckBox]::ForegroundProperty, 'TextPrimary')

        [void] $stack.Children.Add($box)

        $boxes += $box
    }

    $buttons = New-Object System.Windows.Controls.StackPanel
    $buttons.Orientation         = [System.Windows.Controls.Orientation]::Horizontal
    $buttons.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
    $buttons.Margin              = New-Object System.Windows.Thickness(0, 14, 0, 0)

    $save = New-Object System.Windows.Controls.Button
    $save.Content = 'Save'
    $save.Margin  = New-Object System.Windows.Thickness(0, 0, 8, 0)
    $save.Padding = New-Object System.Windows.Thickness(16, 6, 16, 6)

    $cancel = New-Object System.Windows.Controls.Button
    $cancel.Content = 'Cancel'
    $cancel.Padding = New-Object System.Windows.Thickness(16, 6, 16, 6)

    $save.Add_Click({
        $chosen = @($boxes | Where-Object { $_.IsChecked } | ForEach-Object { [string] $_.Tag })

        Set-TkAuditExclusion -Name $chosen

        Set-TkStatus -Text $(if ($chosen.Count -eq 0) {
                                 'No administrator account is excluded.'
                             }
                             else {
                                 '{0} administrator account(s) excluded. Run the audit again to apply it.' -f $chosen.Count
                             })

        $window.Close()
    }.GetNewClosure())

    $cancel.Add_Click({ $window.Close() }.GetNewClosure())

    [void] $buttons.Children.Add($save)
    [void] $buttons.Children.Add($cancel)
    [void] $stack.Children.Add($buttons)

    $window.Content = $stack

    [void] $window.ShowDialog()
}

<#
.SYNOPSIS
    Writes the audit report to a file chosen by the user.
#>
function Export-TkAuditFromUi {
    [CmdletBinding()]
    param()

    if (-not $script:TkLastAudit) {
        Set-TkStatus -Text 'Run the audit first.'
        return
    }

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title    = 'Export the audit report'
    $dialog.Filter   = 'JSON report (*.json)|*.json'
    $dialog.FileName = '{0}-audit-{1}.json' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd')

    if (-not $dialog.ShowDialog()) {
        return
    }

    $written = Export-TkSecurityAuditReport -Path $dialog.FileName -Findings $script:TkLastAudit -Confirm:$false

    if ($written) {
        Set-TkStatus -Text ('Audit report written to {0}' -f $written)
    }
}

<#
.SYNOPSIS
    Refreshes the VirusTotal key status label.
#>
function Update-TkVirusTotalKeyStatus {
    [CmdletBinding()]
    param()

    $label = Get-TkControl -Name 'VtKeyStatus'

    if (-not $label) {
        return
    }

    if (Get-TkVirusTotalApiKey) {
        $label.Text = 'A key is stored for this Windows account.'
    }
    else {
        $label.Text = 'No key is stored. File reputation lookups are unavailable until one is added.'
    }
}

<#
.SYNOPSIS
    Deletes log files older than 30 days.
#>
function Clear-TkOldLog {
    [CmdletBinding()]
    param()

    $ctx     = Get-TkContext
    $cutoff  = (Get-Date).AddDays(-30)
    $removed = 0

    foreach ($file in (Get-ChildItem -LiteralPath $ctx.LogRoot -Filter '*.log' -File -ErrorAction SilentlyContinue)) {

        if ($file.LastWriteTime -lt $cutoff -and $file.FullName -ne $ctx.LogFile) {

            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            $removed++
        }
    }

    Set-TkStatus -Text ('{0} log file(s) older than 30 days deleted.' -f $removed)
}
