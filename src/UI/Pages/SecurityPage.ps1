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
    Register-TkClick -Name 'BtnRunAudit'    -Action { Invoke-TkAuditFromUi }
    Register-TkClick -Name 'BtnExportAudit' -Action { Export-TkAuditFromUi }

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
    Runs the local security audit and renders it as findings.

.DESCRIPTION
    Rendered as cards rather than as a grid, because a finding is not a row of
    data: it needs its explanation next to it, and where a safe correction
    exists it needs the button that applies it. Genuinely tabular output, such
    as the adapter list, stays in a grid.
#>
function Invoke-TkAuditFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Running the security audit...' `
        -ScriptBlock { Invoke-TkSecurityAudit } `
        -OnComplete {
            param($result)

            $findings = @($result.Output)
            $script:TkLastAudit = $findings

            $document = New-TkFlowDocument

            Add-TkHeading -Document $document -Text ('Local audit of {0}' -f $env:COMPUTERNAME) -Level 1

            $counts = @{
                Fail    = @($findings | Where-Object { $_.Status -eq 'Fail' }).Count
                Warning = @($findings | Where-Object { $_.Status -eq 'Warning' }).Count
                Pass    = @($findings | Where-Object { $_.Status -eq 'Pass' }).Count
                Info    = @($findings | Where-Object { $_.Status -eq 'Info' }).Count
            }

            Add-TkParagraph -Document $document -Muted -Text (
                '{0} checks: {1} failing, {2} worth attention, {3} passing, {4} not readable. A hygiene check, not a compliance audit: it does not replace a CIS or ANSSI benchmark run.' -f
                    $findings.Count, $counts.Fail, $counts.Warning, $counts.Pass, $counts.Info
            )

            if (-not (Test-TkIsElevated)) {
                Add-TkParagraph -Document $document -Muted -Text (
                    'Running as a standard user, so several checks could not read what they needed and reported "Info" rather than a real result.'
                )
            }

            # Failing first, then warnings, then the rest: the order someone
            # reads a report in.
            $order = @{ 'Fail' = 0; 'Warning' = 1; 'Info' = 2; 'Pass' = 3 }

            foreach ($category in (@($findings | ForEach-Object { $_.Category }) | Select-Object -Unique)) {

                Add-TkHeading -Document $document -Text $category -Level 2

                $inCategory = $findings |
                              Where-Object { $_.Category -eq $category } |
                              Sort-Object -Property @{ Expression = { $order[$_.Status] } }, 'Name'

                foreach ($finding in $inCategory) {

                    Add-TkFindingCard -Document $document -Severity $finding.Status `
                        -Title $finding.Name -State $finding.Id -Detail $finding.Detail `
                        -Action $finding.Recommendation -RemediationId $finding.RemediationId
                }
            }

            Set-TkDocument -ControlName 'AuditOutput' -Document $document

            $summary = Get-TkControl -Name 'AuditSummary'

            if ($summary) {
                $summary.Text = '{0} checks: {1} pass, {2} fail, {3} warning, {4} informational.' -f
                    $findings.Count, $counts.Pass, $counts.Fail, $counts.Warning, $counts.Info
            }

            Set-TkStatus -Text ('Audit: {0} failing, {1} warnings.' -f $counts.Fail, $counts.Warning)
        }
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
