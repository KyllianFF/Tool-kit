<#
    Toolkit - UI / Tools page, calculators

    The Ports, chmod, Regex, Timestamps and Encoding tabs of the Tools page.
    Each one reads its controls, calls a function of Calculators.ps1 and
    writes plain text, so the result can be selected and copied.
#>

# Set while the chmod controls are written from code, so the handlers that
# follow them do not answer their own change.
$script:TkChmodUpdating = $false

# Set while HTML is loaded into the editor, so the editor does not rewrite
# the HTML box while it is being read from it.
$script:TkEditorLoading = $false

<#
.SYNOPSIS
    Wires the calculator tabs of the Tools page.
#>
function Initialize-TkToolsPage {
    [CmdletBinding()]
    param()

    # --- Chooser ----------------------------------------------------------
    # Found by title in Get-TkToolEntry, like the Diagnostics reports, so a
    # tool inserted in the list cannot shift the others onto the wrong panel.
    $choices = Get-TkControl -Name 'ToolChoices'

    if ($choices) {

        $choices.Add_SelectionChanged({
            $title = Get-TkItemTitle -Item (Get-TkControl -Name 'ToolChoices').SelectedItem

            if ($title) {
                Show-TkTool -Title $title
            }
        })

        [void] (Select-TkListChoice -ListName 'ToolChoices' -Title (@(Get-TkToolEntry)[0].Title))
    }

    # --- Ports ------------------------------------------------------------
    $range = Get-TkControl -Name 'PortRange'

    if ($range) {

        foreach ($name in @(Get-TkPortRangeChoice | ForEach-Object { $_.Label })) {
            [void] $range.Items.Add($name)
        }

        $range.SelectedIndex = 0

        # From and To only count for the custom range.
        $range.Add_SelectionChanged({ Update-TkPortRangeControl })
        Update-TkPortRangeControl
    }

    Register-TkClick -Name 'BtnGeneratePorts' -Action { Invoke-TkPortGeneratorFromUi }
    Register-TkClick -Name 'BtnCopyPorts'     -Action { Copy-TkToolOutput -ControlName 'PortOutput' }

    # --- chmod ------------------------------------------------------------
    foreach ($name in @((Get-TkChmodBitMap).Keys)) {

        $box = Get-TkControl -Name $name

        if ($box) {
            $box.Add_Click({ Update-TkChmodFromCheckBox })
        }
    }

    $octal = Get-TkControl -Name 'ChmodOctal'

    if ($octal) {
        $octal.Add_TextChanged({ Update-TkChmodFromText -Source 'ChmodOctal' })
    }

    $symbolic = Get-TkControl -Name 'ChmodSymbolic'

    if ($symbolic) {
        $symbolic.Add_TextChanged({ Update-TkChmodFromText -Source 'ChmodSymbolic' })
    }

    Register-TkClick -Name 'BtnCopyChmod' -Action { Copy-TkToolOutput -ControlName 'ChmodOutput' }

    Set-TkChmodControl -Bits 493

    # --- Regex ------------------------------------------------------------
    foreach ($name in @('RegexPattern', 'RegexText', 'RegexReplacement')) {

        $box = Get-TkControl -Name $name

        if ($box) {
            $box.Add_TextChanged({ Invoke-TkRegexFromUi })
        }
    }

    foreach ($name in @('RegexIgnoreCase', 'RegexMultiline', 'RegexSingleline')) {

        $box = Get-TkControl -Name $name

        if ($box) {
            $box.Add_Click({ Invoke-TkRegexFromUi })
        }
    }

    Initialize-TkRegexCheatSheet

    # --- Timestamps -------------------------------------------------------
    $timestamp = Get-TkControl -Name 'TimestampInput'

    if ($timestamp) {
        $timestamp.Add_TextChanged({ Update-TkTimestampFromUi })
    }

    Register-TkClick -Name 'BtnTimestampNow' -Action { (Get-TkControl -Name 'TimestampInput').Text = 'now' }

    Update-TkTimestampFromUi

    # --- Encoding ---------------------------------------------------------
    $operation = Get-TkControl -Name 'EncodingOperation'

    if ($operation) {

        foreach ($name in @(Get-TkTextOperationChoice | ForEach-Object { $_.Label })) {
            [void] $operation.Items.Add($name)
        }

        $operation.SelectedIndex = 0
    }

    Register-TkClick -Name 'BtnConvertText' -Action { Invoke-TkTextConversionFromUi }

    Register-TkClick -Name 'BtnSwapText' -Action {
        (Get-TkControl -Name 'EncodingInput').Text = (Get-TkControl -Name 'EncodingOutput').Text
    }

    # --- UUIDs ------------------------------------------------------------
    $uuidVersion = Get-TkControl -Name 'UuidVersion'

    if ($uuidVersion) {
        [void] $uuidVersion.Items.Add('4, random')
        [void] $uuidVersion.Items.Add('7, ordered by time')
        $uuidVersion.SelectedIndex = 0
    }

    $uuidFormat = Get-TkControl -Name 'UuidFormat'

    if ($uuidFormat) {

        foreach ($choice in @(Get-TkUuidFormatChoice)) {
            [void] $uuidFormat.Items.Add($choice.Label)
        }

        $uuidFormat.SelectedIndex = 0
    }

    Register-TkClick -Name 'BtnGenerateUuid' -Action { Invoke-TkUuidFromUi }
    Register-TkClick -Name 'BtnCopyUuid'     -Action { Copy-TkToolOutput -ControlName 'UuidOutput' }
    Register-TkClick -Name 'BtnDecodeUuid'   -Action { Invoke-TkUuidDecodeFromUi }

    # --- Safe Links, URL parser, NATO alphabet, phone numbers -------------
    # Worked out as the text changes: each is a few milliseconds.
    foreach ($binding in @(
        @{ Name = 'SafeLinkInput';    Update = { Update-TkSafeLinkFromUi } }
        @{ Name = 'UrlInput';         Update = { Update-TkUrlFromUi } }
        @{ Name = 'NatoInput';        Update = { Update-TkNatoFromUi } }
        @{ Name = 'PhoneInput';       Update = { Update-TkPhoneFromUi } }
        @{ Name = 'MailHeaderInput';  Update = { Update-TkMailHeaderFromUi } }
        @{ Name = 'CertificateInput'; Update = { Update-TkCertificateFromUi } }
    )) {
        $box = Get-TkControl -Name $binding.Name

        if ($box) {
            $box.Add_TextChanged($binding.Update)
        }
    }

    # --- Mail records and certificates ------------------------------------
    # The mail check goes out on the network, so it waits for the button, or
    # Enter in the domain box.
    Register-TkClick -Name 'BtnCheckMailDns'    -Action { Invoke-TkMailDnsFromUi }
    Register-TkClick -Name 'BtnOpenCertificate' -Action { Open-TkCertificateFileFromUi }

    $mailDomain = Get-TkControl -Name 'MailDnsDomain'

    if ($mailDomain) {
        $mailDomain.Add_KeyDown({
            param($eventSource, $routedArgs)

            if ($routedArgs.Key -eq [System.Windows.Input.Key]::Return) {
                Invoke-TkMailDnsFromUi
                $routedArgs.Handled = $true
            }
        })
    }

    $markCase = Get-TkControl -Name 'NatoMarkCase'

    if ($markCase) {
        $markCase.Add_Click({ Update-TkNatoFromUi })
    }

    Register-TkClick -Name 'BtnCopySafeLink' -Action {

        $destinations = @(ConvertFrom-TkSafeLink -Text ([string] (Get-TkControl -Name 'SafeLinkInput').Text) | ForEach-Object { $_.Destination })

        if ($destinations.Count -eq 0) {
            Set-TkStatus -Text 'No Safe Links URL to copy from.'
            return
        }

        if (Set-TkClipboard -Text ($destinations -join [Environment]::NewLine)) {
            Set-TkStatus -Text ('{0} destination(s) copied to the clipboard.' -f $destinations.Count)
        }
    }

    $phoneCountry = Get-TkControl -Name 'PhoneCountry'

    if ($phoneCountry) {

        foreach ($country in @(Get-TkPhoneCountry)) {
            [void] $phoneCountry.Items.Add(('{0} (+{1})' -f $country.Name, $country.Code))
        }

        $phoneCountry.SelectedIndex = 0
        $phoneCountry.Add_SelectionChanged({ Update-TkPhoneFromUi })
    }

    # --- Text diff --------------------------------------------------------
    Register-TkClick -Name 'BtnCompareText' -Action { Invoke-TkTextDiffFromUi }

    Register-TkClick -Name 'BtnSwapDiff' -Action {
        $before = Get-TkControl -Name 'DiffBefore'
        $after  = Get-TkControl -Name 'DiffAfter'
        $held         = $before.Text
        $before.Text  = $after.Text
        $after.Text   = $held
    }

    # --- Crontab ----------------------------------------------------------
    $cronPreset = Get-TkControl -Name 'CronPreset'

    if ($cronPreset) {

        foreach ($choice in @(Get-TkCronPreset)) {
            [void] $cronPreset.Items.Add($choice.Label)
        }

        $cronPreset.SelectedIndex = 0

        $cronPreset.Add_SelectionChanged({
            $chosen = @(Get-TkCronPreset) | Where-Object { $_.Label -eq [string] (Get-TkControl -Name 'CronPreset').SelectedItem } | Select-Object -First 1

            if ($chosen -and $chosen.Expression) {
                (Get-TkControl -Name 'CronExpression').Text = $chosen.Expression
            }
        })
    }

    foreach ($name in @('CronExpression', 'CronCommand')) {

        $box = Get-TkControl -Name $name

        if ($box) {
            $box.Add_TextChanged({ Update-TkCronFromUi })
        }
    }

    Register-TkClick -Name 'BtnCopyCron' -Action {
        if (Set-TkClipboard -Text (Get-TkCronLine)) {
            Set-TkStatus -Text 'Crontab line copied to the clipboard.'
        }
    }

    # --- docker run to Compose --------------------------------------------
    Register-TkClick -Name 'BtnConvertDocker' -Action { Invoke-TkDockerComposeFromUi }
    Register-TkClick -Name 'BtnCopyCompose'   -Action { Copy-TkToolOutput -ControlName 'DockerComposeOutput' }

    # --- HTML editor ------------------------------------------------------
    $editor = Get-TkControl -Name 'HtmlEditor'

    if ($editor) {
        $editor.Document = New-TkEditorDocument -Block @(ConvertFrom-TkHtmlDocument -Html '<h2>Title</h2><p>Write here, with <strong>bold</strong>, <em>italic</em> and <a href="https://learn.microsoft.com/">links</a>.</p><ul><li>A list</li><li>of points</li></ul>')
        $editor.Add_TextChanged({ Update-TkHtmlSourceFromUi })
    }

    Register-TkClick -Name 'BtnEditorBold'      -Action { Invoke-TkEditorCommand -Command 'ToggleBold' }
    Register-TkClick -Name 'BtnEditorItalic'    -Action { Invoke-TkEditorCommand -Command 'ToggleItalic' }
    Register-TkClick -Name 'BtnEditorUnderline' -Action { Invoke-TkEditorCommand -Command 'ToggleUnderline' }
    Register-TkClick -Name 'BtnEditorBullets'   -Action { Invoke-TkEditorCommand -Command 'ToggleBullets' }
    Register-TkClick -Name 'BtnEditorNumbering' -Action { Invoke-TkEditorCommand -Command 'ToggleNumbering' }
    Register-TkClick -Name 'BtnEditorHeading1'  -Action { Set-TkEditorParagraphStyle -Style 'Heading1' }
    Register-TkClick -Name 'BtnEditorHeading2'  -Action { Set-TkEditorParagraphStyle -Style 'Heading2' }
    Register-TkClick -Name 'BtnEditorBody'      -Action { Set-TkEditorParagraphStyle -Style 'Body' }
    Register-TkClick -Name 'BtnEditorLink'      -Action { Set-TkEditorLink }
    Register-TkClick -Name 'BtnHtmlCopy'        -Action { Copy-TkToolOutput -ControlName 'HtmlSource' }
    Register-TkClick -Name 'BtnHtmlLoad'        -Action { Import-TkHtmlIntoEditor }

    Register-TkClick -Name 'BtnEditorClear' -Action {
        (Get-TkControl -Name 'HtmlEditor').Selection.ClearAllProperties()
        Update-TkHtmlSourceFromUi
    }

    Update-TkSafeLinkFromUi
    Update-TkUrlFromUi
    Update-TkNatoFromUi
    Update-TkPhoneFromUi
    # --- QR codes ---------------------------------------------------------
    foreach ($listName in @('QrErrorCorrection')) {

        $levels = Get-TkControl -Name $listName

        if ($levels) {

            foreach ($choice in @(Get-TkQrErrorCorrectionChoice)) {
                [void] $levels.Items.Add($choice.Label)
            }

            $levels.SelectedIndex = 0
            $levels.Add_SelectionChanged({ Update-TkQrFromUi })
        }
    }

    $qrInput = Get-TkControl -Name 'QrInput'

    if ($qrInput) {
        $qrInput.Add_TextChanged({ Update-TkQrFromUi })
    }

    $security = Get-TkControl -Name 'WifiQrSecurity'

    if ($security) {

        foreach ($choice in @(Get-TkWifiQrSecurityChoice)) {
            [void] $security.Items.Add($choice.Label)
        }

        $security.SelectedIndex = 0
        $security.Add_SelectionChanged({ Update-TkWifiQrFromUi })
    }

    $ssid = Get-TkControl -Name 'WifiQrSsid'

    if ($ssid) {
        $ssid.Add_TextChanged({ Update-TkWifiQrFromUi })
    }

    $key = Get-TkControl -Name 'WifiQrPassword'

    if ($key) {
        $key.Add_PasswordChanged({ Update-TkWifiQrFromUi })
    }

    $hidden = Get-TkControl -Name 'WifiQrHidden'

    if ($hidden) {
        $hidden.Add_Click({ Update-TkWifiQrFromUi })
    }

    Register-TkClick -Name 'BtnSaveQr'        -Action { Save-TkQrPicture -ImageName 'QrImage' -FileName 'qr-code' }
    Register-TkClick -Name 'BtnCopyQr'        -Action { Copy-TkQrPicture -ImageName 'QrImage' }
    Register-TkClick -Name 'BtnSaveWifiQr'    -Action { Save-TkQrPicture -ImageName 'WifiQrImage' -FileName ('wifi-{0}' -f ([string] (Get-TkControl -Name 'WifiQrSsid').Text -replace '[^A-Za-z0-9_-]', '-')) }
    Register-TkClick -Name 'BtnCopyWifiQr'    -Action { Copy-TkQrPicture -ImageName 'WifiQrImage' }
    Register-TkClick -Name 'BtnWifiQrCurrent' -Action { Invoke-TkWifiQrCurrentNetwork }

    Update-TkCronFromUi
    Update-TkHtmlSourceFromUi
    Update-TkQrFromUi
    Update-TkWifiQrFromUi
}

# ---------------------------------------------------------------------------
# UUIDs
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Generates UUIDs from the choices on the page.
#>
function Invoke-TkUuidFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'UuidOutput'
    $count  = 0

    if (-not [int]::TryParse([string] (Get-TkControl -Name 'UuidCount').Text, [ref] $count) -or $count -lt 1 -or $count -gt 1000) {
        $output.Text = 'Type how many, from 1 to 1000.'
        return
    }

    $version = if ((Get-TkControl -Name 'UuidVersion').SelectedIndex -eq 1) { 7 } else { 4 }
    $choice  = @(Get-TkUuidFormatChoice) | Where-Object { $_.Label -eq [string] (Get-TkControl -Name 'UuidFormat').SelectedItem } | Select-Object -First 1
    $format  = if ($choice) { $choice.Format } else { 'Standard' }

    $output.Text = (@(New-TkUuid -Version $version -Count $count) | ForEach-Object { Format-TkUuid -Uuid $_ -Format $format }) -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Decodes the UUID typed on the page.
#>
function Invoke-TkUuidDecodeFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'UuidOutput'
    $info   = ConvertFrom-TkUuid -Text ([string] (Get-TkControl -Name 'UuidDecodeInput').Text)

    if (-not $info.Valid) {
        $output.Text = $info.Note
        return
    }

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('UUID      {0}' -f $info.Uuid))
    $lines.Add(('Kind      {0}' -f $info.VersionName))

    if ($info.Variant) {
        $lines.Add(('Variant   {0}' -f $info.Variant))
    }

    if ($info.Time) {
        $lines.Add(('Created   {0} UTC, {1}' -f $info.Time.ToString('yyyy-MM-dd HH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture), (Format-TkRelativeTime -Utc $info.Time)))
    }

    if ($info.Node) {
        $lines.Add(('Node      {0}, {1}' -f $info.Node, (Get-TkMacVendor -MacAddress $info.Node)))
    }

    $lines.Add('')
    $lines.Add($info.Note)

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# Safe Links and URLs
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Decodes the Safe Links pasted on the page, as they are pasted.
#>
function Update-TkSafeLinkFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'SafeLinkOutput'
    $box    = Get-TkControl -Name 'SafeLinkInput'

    if (-not $output -or -not $box) {
        return
    }

    $text = [string] $box.Text

    if (-not $text.Trim()) {
        $output.Text = 'Paste a link that starts with https://...safelinks.protection.outlook.com/, or a whole e-mail.'
        return
    }

    $rows = @(ConvertFrom-TkSafeLink -Text $text)

    if ($rows.Count -eq 0) {
        $output.Text = 'No Safe Links URL was found in what was pasted. A link that is not wrapped can be read with the URL parser.'
        return
    }

    $lines  = New-Object System.Collections.Generic.List[string]
    $number = 0

    foreach ($row in $rows) {

        $number++

        $lines.Add(('Link {0}' -f $number))
        $lines.Add(('  Goes to    {0}' -f $row.Destination))
        $lines.Add(('  Site       {0}' -f $row.Host))

        if ($row.Recipient) {
            $lines.Add(('  Sent to    {0}' -f $row.Recipient))
        }

        if ($row.Layers -gt 1) {
            $lines.Add(('  Wrapped    {0} times, as happens when a message is forwarded' -f $row.Layers))
        }

        foreach ($warning in @($row.Warnings)) {
            $lines.Add(('  Warning    {0}' -f $warning))
        }

        $lines.Add('')
    }

    $lines.Add('A Safe Links wrapper means the link is checked when it is clicked, not that the site is genuine: judge the site by its name above.')

    $output.Text = $lines -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Takes apart the link typed on the page, as it is typed.
#>
function Update-TkUrlFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'UrlOutput'
    $box    = Get-TkControl -Name 'UrlInput'

    if (-not $output -or -not $box) {
        return
    }

    $part = Get-TkUrlPart -Url ([string] $box.Text)

    if (-not $part.Valid) {
        $output.Text = $part.Note
        return
    }

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Scheme      {0}' -f $part.Scheme))

    if ($part.User) {
        $lines.Add(('User        {0}{1}' -f $part.User, $(if ($part.HasPassword) { ', with a password (not shown)' } else { '' })))
    }

    $lines.Add(('Host        {0}' -f $part.UnicodeHost))

    if ($part.AsciiHost -ne $part.UnicodeHost) {
        $lines.Add(('For DNS     {0}' -f $part.AsciiHost))
    }

    $lines.Add(('Host type   {0}' -f $part.HostType))

    if ($part.Port -ge 0) {
        $lines.Add(('Port        {0}{1}' -f $part.Port, $(if ($part.IsDefaultPort) { ', the default for ' + $part.Scheme } else { '' })))
    }

    $lines.Add(('Path        {0}' -f $part.Path))
    $lines.Add(('Origin      {0}' -f $part.Origin))

    if (@($part.Query).Count -gt 0) {

        $lines.Add('')
        $lines.Add(('Query, {0} parameter(s)' -f @($part.Query).Count))

        foreach ($parameter in $part.Query) {
            $lines.Add(('  {0} = {1}' -f $parameter.Name, $(if ($null -eq $parameter.Value) { '(no value)' } else { $parameter.Value })))
        }
    }

    if ($part.Fragment) {
        $lines.Add('')
        $lines.Add(('Fragment    {0}' -f $part.Fragment))
    }

    if (@($part.Warnings).Count -gt 0) {

        $lines.Add('')

        foreach ($warning in $part.Warnings) {
            $lines.Add(('Warning     {0}' -f $warning))
        }
    }

    if ($part.Note) {
        $lines.Add('')
        $lines.Add($part.Note)
    }

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# E-mail headers, mail records and certificates
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Analyses the e-mail headers pasted on the page, as they are pasted.
#>
function Update-TkMailHeaderFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'MailHeaderOutput'
    $box    = Get-TkControl -Name 'MailHeaderInput'

    if (-not $output -or -not $box) {
        return
    }

    $text = [string] $box.Text

    if (-not $text.Trim()) {
        $output.Text = 'Paste the headers of a message. In classic Outlook: File, Properties, Internet headers; in the new Outlook and Outlook on the web: View, View message details; in Gmail: Show original.'
        return
    }

    $report = Get-TkMailHeaderReport -Text $text

    if ($report.HeaderCount -eq 0) {
        $output.Text = 'No header was recognised. Headers are lines such as Received: from ... or From: ..., pasted as the mail client shows them.'
        return
    }

    $output.Text = (Format-TkMailHeaderReport -Report $report) -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Checks the mail DNS records of the domain typed on the page.

.DESCRIPTION
    Runs in the background: a domain with many SPF includes takes a few
    seconds of lookups, which must not freeze the window.
#>
function Invoke-TkMailDnsFromUi {
    [CmdletBinding()]
    param()

    $domain    = ([string] (Get-TkControl -Name 'MailDnsDomain').Text).Trim()
    $selectors = ([string] (Get-TkControl -Name 'MailDnsSelectors').Text).Trim()

    if (-not $domain) {
        Set-TkStatus -Text 'Type a domain to check, such as contoso.com.'
        return
    }

    Set-TkOutput -ControlName 'MailDnsOutput' -Text ('Querying the mail records of {0}...' -f $domain)

    Invoke-TkBackgroundAction -StatusText ('Checking the mail records of {0}...' -f $domain) `
        -ArgumentList @($domain, $selectors) `
        -ScriptBlock {
            param($name, $selectorText)

            $selectorNames = @($selectorText -split '[,;\s]+' | Where-Object { $_ })

            Get-TkMailDnsReport -Domain $name -Selector $selectorNames
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                Set-TkOutput -ControlName 'MailDnsOutput' -Text 'The check did not complete. See the output panel for the reason.'
                return
            }

            Set-TkOutput -ControlName 'MailDnsOutput' -Text ((Format-TkMailDnsReport -Report $report) -join [Environment]::NewLine)
            Set-TkStatus -Text ('Mail records of {0} checked.' -f $report.Domain)
        }
}

<#
.SYNOPSIS
    Decodes the certificates pasted on the page, as they are pasted.
#>
function Update-TkCertificateFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'CertificateOutput'
    $box    = Get-TkControl -Name 'CertificateInput'

    if (-not $output -or -not $box) {
        return
    }

    $text = [string] $box.Text

    if (-not $text.Trim()) {
        $output.Text = 'Paste a certificate, a chain or a certificate request with its -----BEGIN and -----END lines, or open a file.'
        return
    }

    $items = @(Get-TkCertificateItem -Text $text)

    if ($items.Count -eq 0) {
        $output.Text = 'Nothing was recognised. Paste the whole block, -----BEGIN and -----END lines included, or open the file.'
        return
    }

    $output.Text = (Format-TkCertificateItem -Item $items) -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Decodes a certificate, chain or request file chosen in a dialog.
#>
function Open-TkCertificateFileFromUi {
    [CmdletBinding()]
    param()

    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title  = 'Open a certificate or a certificate request'
    $dialog.Filter = 'Certificates and requests (*.cer;*.crt;*.pem;*.der;*.csr;*.req;*.p7b)|*.cer;*.crt;*.pem;*.der;*.csr;*.req;*.p7b|All files (*.*)|*.*'

    if (-not $dialog.ShowDialog()) {
        return
    }

    $file = Get-Item -LiteralPath $dialog.FileName

    # A certificate file is a few kilobytes; a large file is not one.
    if ($file.Length -gt 1MB) {
        Set-TkOutput -ControlName 'CertificateOutput' -Text ('{0} is {1}: too large to be a certificate or a request.' -f $file.Name, (Format-TkBytes -Bytes $file.Length))
        return
    }

    $items = @(Get-TkCertificateItem -Bytes ([System.IO.File]::ReadAllBytes($file.FullName)))
    $lines = @(('File         {0}' -f $file.FullName), '') + @(Format-TkCertificateItem -Item $items)

    Set-TkOutput -ControlName 'CertificateOutput' -Text ($lines -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# NATO alphabet and phone numbers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Spells out the text typed on the page, as it is typed.
#>
function Update-TkNatoFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'NatoOutput'
    $box    = Get-TkControl -Name 'NatoInput'

    if (-not $output -or -not $box) {
        return
    }

    $rows = @(ConvertTo-TkNatoAlphabet -Text ([string] $box.Text) -MarkCase:([bool] (Get-TkControl -Name 'NatoMarkCase').IsChecked))

    if ($rows.Count -eq 0) {
        $output.Text = 'Type the text to spell out.'
        return
    }

    $lines = foreach ($row in $rows) {
        '{0,-8} {1}' -f $(if ($row.Character -eq ' ') { '(space)' } else { $row.Character }), $row.Spoken
    }

    $output.Text = (@($lines) + @('', (($rows | ForEach-Object { $_.Spoken }) -join ' - '))) -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Writes the phone number typed on the page in its standard forms.
#>
function Update-TkPhoneFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'PhoneOutput'
    $box    = Get-TkControl -Name 'PhoneInput'
    $list   = Get-TkControl -Name 'PhoneCountry'

    if (-not $output -or -not $box -or -not $list) {
        return
    }

    $countries = @(Get-TkPhoneCountry)
    $default   = if ($list.SelectedIndex -ge 0) { $countries[$list.SelectedIndex].Iso } else { 'FR' }
    $number    = ConvertFrom-TkPhoneNumber -Text ([string] $box.Text) -DefaultCountry $default

    if (-not $number.Valid) {
        $output.Text = $number.Note
        return
    }

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Country         {0}' -f $(if ($number.Country) { '{0}, +{1}' -f $number.Country, $number.CountryCode } else { '+' + $number.CountryCode })))

    if ($number.Type) {
        $lines.Add(('Type            {0}' -f $number.Type))
    }

    $lines.Add('')
    $lines.Add(('E.164           {0}' -f $number.E164))
    $lines.Add(('International   {0}' -f $number.International))

    if ($number.National) {
        $lines.Add(('National        {0}' -f $number.National))
    }

    $lines.Add(('Link            {0}{1}' -f $number.Rfc3966, $(if ($number.Extension) { ';ext=' + $number.Extension } else { '' })))

    if ($number.Extension) {
        $lines.Add(('Extension       {0}' -f $number.Extension))
    }

    if ($number.Note) {
        $lines.Add('')
        $lines.Add($number.Note)
    }

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# Text diff
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Compares the two texts on the page and colours the changes.
#>
function Invoke-TkTextDiffFromUi {
    [CmdletBinding()]
    param()

    $document = New-TkFlowDocument

    try {
        $result = Compare-TkText -Before ([string] (Get-TkControl -Name 'DiffBefore').Text) -After ([string] (Get-TkControl -Name 'DiffAfter').Text) `
                                 -IgnoreCase:([bool] (Get-TkControl -Name 'DiffIgnoreCase').IsChecked) `
                                 -IgnoreWhitespace:([bool] (Get-TkControl -Name 'DiffIgnoreWhitespace').IsChecked)
    }
    catch {
        Add-TkParagraph -Document $document -Text ('Could not compare: {0}' -f $_.Exception.Message)
        Set-TkDocument -ControlName 'DiffOutput' -Document $document
        return
    }

    if ($result.Identical) {
        Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'The two texts are the same' `
            -Detail ('{0} line(s)' -f $result.Same)
        Set-TkDocument -ControlName 'DiffOutput' -Document $document
        return
    }

    Add-TkParagraph -Document $document -Muted -Text (
        '{0} line(s) removed, {1} added, {2} unchanged. Removed lines are marked -, added lines +, with their line numbers before and after.' -f $result.Removed, $result.Added, $result.Same
    )

    $mono      = New-Object System.Windows.Media.FontFamily('Cascadia Mono, Consolas, Courier New')
    $paragraph = $null
    $lastKind  = ''

    foreach ($row in (Get-TkDiffView -Rows $result.Rows -Context 3)) {

        if ($row.Kind -ne $lastKind) {

            $paragraph            = New-Object System.Windows.Documents.Paragraph
            $paragraph.FontFamily = $mono
            $paragraph.FontSize   = 12.5
            $paragraph.Margin     = New-Object System.Windows.Thickness(0)
            $paragraph.Padding    = New-Object System.Windows.Thickness(6, 1, 6, 1)

            switch ($row.Kind) {
                'Removed' { Set-TkResourceBrush -Element $paragraph -Property Background -Key (Get-TkSeverityTintKey -Severity 'Fail' -Alpha 60) }
                'Added'   { Set-TkResourceBrush -Element $paragraph -Property Background -Key (Get-TkSeverityTintKey -Severity 'Pass' -Alpha 60) }
                'Gap'     { $paragraph.SetResourceReference([System.Windows.Documents.TextElement]::ForegroundProperty, 'TextMuted') }
            }

            $document.Blocks.Add($paragraph)
            $lastKind = $row.Kind
        }
        else {
            $paragraph.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
        }

        $marker = switch ($row.Kind) { 'Added' { '+' } 'Removed' { '-' } default { ' ' } }

        $text = if ($row.Kind -eq 'Gap') {
                    '{0,11}   ... {1}' -f '', $row.Text
                }
                else {
                    '{0,5} {1,5} {2} {3}' -f $(if ($null -ne $row.Before) { [string] $row.Before } else { '' }), $(if ($null -ne $row.After) { [string] $row.After } else { '' }), $marker, $row.Text
                }

        $paragraph.Inlines.Add((New-Object System.Windows.Documents.Run($text)))
    }

    Set-TkDocument -ControlName 'DiffOutput' -Document $document
}

# ---------------------------------------------------------------------------
# Crontab and Docker Compose
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the crontab line made of the expression and the command on the page.
#>
function Get-TkCronLine {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $expression = ([string] (Get-TkControl -Name 'CronExpression').Text).Trim() -replace '\s+', ' '
    $command    = ([string] (Get-TkControl -Name 'CronCommand').Text).Trim()

    if (-not $command) {
        $command = '/path/to/command'
    }

    return ('{0} {1}' -f $expression, $command)
}

<#
.SYNOPSIS
    Describes the cron expression on the page, as it is typed.
#>
function Update-TkCronFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'CronOutput'
    $box    = Get-TkControl -Name 'CronExpression'

    if (-not $output -or -not $box) {
        return
    }

    $schedule = ConvertFrom-TkCronExpression -Expression ([string] $box.Text)

    if (-not $schedule.Valid) {
        $output.Text = $schedule.Error
        return
    }

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Runs       {0}' -f $schedule.Description))

    if ($schedule.Macro -and -not $schedule.Reboot) {
        $lines.Add(('Same as    {0}' -f $schedule.Expression))
    }

    if (-not $schedule.Reboot) {

        $runs = @(Get-TkCronNextRun -Schedule $schedule -Count 5)

        $lines.Add('')

        if ($runs.Count -eq 0) {
            $lines.Add('Never: no date in the next nine years matches, as with 31 February.')
        }
        else {
            $lines.Add('Next runs, in the time of the machine running cron')

            foreach ($run in $runs) {
                $lines.Add(('  {0}' -f $run.ToString('ddd yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)))
            }
        }
    }

    $lines.Add('')
    $lines.Add('Line for crontab -e')
    $lines.Add((Get-TkCronLine))

    $output.Text = $lines -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Converts the docker run command on the page.
#>
function Invoke-TkDockerComposeFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'DockerComposeOutput'

    try {
        $result = ConvertFrom-TkDockerRun -Command ([string] (Get-TkControl -Name 'DockerRunInput').Text)
    }
    catch {
        $output.Text = $_.Exception.Message
        return
    }

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add($result.Yaml)

    if (@($result.Notes).Count -gt 0) {

        $lines.Add('')

        foreach ($note in $result.Notes) {
            $lines.Add(('# {0}' -f $note))
        }
    }

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# HTML editor
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Adds the runs of a WPF inline collection to a list of model runs.

.PARAMETER Target
    The list to add to.

.PARAMETER Inlines
    The inlines of a paragraph, a span or a hyperlink.

.PARAMETER Underline
    Whether an enclosing span underlines, since text decorations are not
    inherited the way the font weight is.

.PARAMETER Link
    The link of an enclosing hyperlink.

.PARAMETER IgnoreBold
    For a heading, whose bold comes from the heading style.
#>
function Add-TkEditorInlineFromElement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] $Inlines,
        [Parameter()] [bool] $Underline = $false,
        [Parameter()] [AllowEmptyString()] [string] $Link = '',
        [Parameter()] [bool] $IgnoreBold = $false
    )

    foreach ($inline in $Inlines) {

        $underlined = $Underline -or ($null -ne $inline.TextDecorations -and
                      @($inline.TextDecorations | Where-Object { $_.Location -eq [System.Windows.TextDecorationLocation]::Underline }).Count -gt 0)

        if ($inline -is [System.Windows.Documents.Run]) {

            if ($inline.Text) {
                $Target.Add((New-TkEditorInline -Text $inline.Text `
                    -Bold (-not $IgnoreBold -and $inline.FontWeight.ToOpenTypeWeight() -ge 600) `
                    -Italic ($inline.FontStyle -eq [System.Windows.FontStyles]::Italic) `
                    -Underline $underlined -Link $Link))
            }
        }
        elseif ($inline -is [System.Windows.Documents.LineBreak]) {
            $Target.Add((New-TkEditorInline -LineBreak))
        }
        elseif ($inline -is [System.Windows.Documents.Hyperlink]) {
            # The underline of a hyperlink is its style, not the text's.
            Add-TkEditorInlineFromElement -Target $Target -Inlines $inline.Inlines -Underline $false `
                -Link ([string] $inline.NavigateUri) -IgnoreBold $IgnoreBold
        }
        elseif ($inline -is [System.Windows.Documents.Span]) {
            Add-TkEditorInlineFromElement -Target $Target -Inlines $inline.Inlines -Underline $underlined `
                -Link $Link -IgnoreBold $IgnoreBold
        }
    }
}

<#
.SYNOPSIS
    Reads the blocks of a WPF document into the document model.

.PARAMETER Blocks
    The block collection of a document or a section.

.OUTPUTS
    PSCustomObject[], as New-TkEditorBlock builds them.
#>
function Get-TkEditorBlock {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        $Blocks
    )

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($block in $Blocks) {

        if ($block -is [System.Windows.Documents.Paragraph]) {

            $type  = if ([string] $block.Tag -in @('Heading1', 'Heading2', 'Heading3')) { [string] $block.Tag } else { 'Paragraph' }
            $model = New-TkEditorBlock -Type $type

            Add-TkEditorInlineFromElement -Target $model.Inlines -Inlines $block.Inlines -IgnoreBold ($type -ne 'Paragraph')
            $result.Add($model)
        }
        elseif ($block -is [System.Windows.Documents.List]) {

            $model = New-TkEditorBlock -Type $(if ($block.MarkerStyle -eq [System.Windows.TextMarkerStyle]::Decimal) { 'NumberedList' } else { 'BulletList' })

            foreach ($listItem in $block.ListItems) {

                $runs  = New-Object System.Collections.Generic.List[object]
                $first = $true

                foreach ($paragraph in @($listItem.Blocks | Where-Object { $_ -is [System.Windows.Documents.Paragraph] })) {

                    if (-not $first) {
                        $runs.Add((New-TkEditorInline -LineBreak))
                    }

                    Add-TkEditorInlineFromElement -Target $runs -Inlines $paragraph.Inlines
                    $first = $false
                }

                $model.Items.Add($runs)
            }

            $result.Add($model)
        }
        elseif ($block -is [System.Windows.Documents.Section]) {

            foreach ($inner in @(Get-TkEditorBlock -Blocks $block.Blocks)) {
                $result.Add($inner)
            }
        }
    }

    return $result.ToArray()
}

<#
.SYNOPSIS
    Builds a WPF document from the document model.

.PARAMETER Block
    The blocks.

.OUTPUTS
    System.Windows.Documents.FlowDocument
#>
function New-TkEditorDocument {
    [CmdletBinding()]
    [OutputType([System.Windows.Documents.FlowDocument])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Block
    )

    $document          = New-TkFlowDocument
    $document.FontSize = 14

    $sizes = @{ Heading1 = 24; Heading2 = 19; Heading3 = 16 }

    $fill = {
        param($target, $runs)

        # Enumerated as it is: @() on a generic list held in an object property
        # fails inside PowerShell (see ConvertTo-TkHtmlDocument).
        foreach ($piece in $runs) {

            if ($piece.LineBreak) {
                $target.Add((New-Object System.Windows.Documents.LineBreak))
                continue
            }

            $run = New-Object System.Windows.Documents.Run($piece.Text)

            if ($piece.Bold)      { $run.FontWeight = [System.Windows.FontWeights]::Bold }
            if ($piece.Italic)    { $run.FontStyle = [System.Windows.FontStyles]::Italic }
            if ($piece.Underline) { $run.TextDecorations = [System.Windows.TextDecorations]::Underline }

            if ($piece.Link) {

                $hyperlink = New-Object System.Windows.Documents.Hyperlink($run)

                try {
                    $hyperlink.NavigateUri = [Uri] $piece.Link
                }
                catch {
                    $null = $_
                }

                $target.Add($hyperlink)
            }
            else {
                $target.Add($run)
            }
        }
    }

    foreach ($item in $Block) {

        if ($item.Type -in @('BulletList', 'NumberedList')) {

            $list             = New-Object System.Windows.Documents.List
            $list.MarkerStyle = if ($item.Type -eq 'BulletList') { [System.Windows.TextMarkerStyle]::Disc } else { [System.Windows.TextMarkerStyle]::Decimal }

            foreach ($entry in $item.Items) {
                $paragraph = New-Object System.Windows.Documents.Paragraph
                & $fill $paragraph.Inlines $entry
                $list.ListItems.Add((New-Object System.Windows.Documents.ListItem($paragraph)))
            }

            $document.Blocks.Add($list)
        }
        else {
            $paragraph = New-Object System.Windows.Documents.Paragraph

            if ($sizes.ContainsKey($item.Type)) {
                $paragraph.Tag        = $item.Type
                $paragraph.FontSize   = $sizes[$item.Type]
                $paragraph.FontWeight = [System.Windows.FontWeights]::Bold
            }

            & $fill $paragraph.Inlines $item.Inlines
            $document.Blocks.Add($paragraph)
        }
    }

    return $document
}

<#
.SYNOPSIS
    Runs a formatting command on the editor selection.

.PARAMETER Command
    The editing command.
#>
function Invoke-TkEditorCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ToggleBold', 'ToggleItalic', 'ToggleUnderline', 'ToggleBullets', 'ToggleNumbering')]
        [string] $Command
    )

    $editor = Get-TkControl -Name 'HtmlEditor'

    [System.Windows.Documents.EditingCommands]::$Command.Execute($null, $editor)
    [void] $editor.Focus()

    Update-TkHtmlSourceFromUi
}

<#
.SYNOPSIS
    Makes the selected paragraphs a heading or body text.

.PARAMETER Style
    Heading1, Heading2 or Body.
#>
function Set-TkEditorParagraphStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Heading1', 'Heading2', 'Body')]
        [string] $Style
    )

    $editor    = Get-TkControl -Name 'HtmlEditor'
    $paragraph = $editor.Selection.Start.Paragraph
    $last      = $editor.Selection.End.Paragraph

    while ($paragraph) {

        if ($Style -eq 'Body') {
            $paragraph.Tag = $null
            $paragraph.ClearValue([System.Windows.Documents.TextElement]::FontSizeProperty)
            $paragraph.ClearValue([System.Windows.Documents.TextElement]::FontWeightProperty)
        }
        else {
            $paragraph.Tag        = $Style
            $paragraph.FontSize   = $(if ($Style -eq 'Heading1') { 24 } else { 19 })
            $paragraph.FontWeight = [System.Windows.FontWeights]::Bold
        }

        if ($paragraph -eq $last) {
            break
        }

        $paragraph = $paragraph.NextBlock -as [System.Windows.Documents.Paragraph]
    }

    [void] $editor.Focus()
    Update-TkHtmlSourceFromUi
}

<#
.SYNOPSIS
    Turns the editor selection into a link to the address typed on the page.
#>
function Set-TkEditorLink {
    [CmdletBinding()]
    param()

    $editor = Get-TkControl -Name 'HtmlEditor'
    $url    = ([string] (Get-TkControl -Name 'EditorLinkUrl').Text).Trim()

    if ($editor.Selection.IsEmpty) {
        Set-TkStatus -Text 'Select the text to turn into a link first.'
        return
    }

    if ($url -notmatch '^(?i)(https?://|mailto:|tel:)\S+$') {
        Set-TkStatus -Text 'Type a link that starts with https://, http://, mailto: or tel:.'
        return
    }

    $link             = New-Object System.Windows.Documents.Hyperlink($editor.Selection.Start, $editor.Selection.End)
    $link.NavigateUri = [Uri] $url

    Update-TkHtmlSourceFromUi
}

<#
.SYNOPSIS
    Writes the editor content as HTML in the box beside it.
#>
function Update-TkHtmlSourceFromUi {
    [CmdletBinding()]
    param()

    if ($script:TkEditorLoading) {
        return
    }

    $editor = Get-TkControl -Name 'HtmlEditor'
    $source = Get-TkControl -Name 'HtmlSource'

    if (-not $editor -or -not $source) {
        return
    }

    $source.Text = ConvertTo-TkHtmlDocument -Block @(Get-TkEditorBlock -Blocks $editor.Document.Blocks)
}

<#
.SYNOPSIS
    Loads the HTML typed or pasted beside the editor into it.
#>
function Import-TkHtmlIntoEditor {
    [CmdletBinding()]
    param()

    $editor = Get-TkControl -Name 'HtmlEditor'
    $source = Get-TkControl -Name 'HtmlSource'

    $script:TkEditorLoading = $true

    try {
        $editor.Document = New-TkEditorDocument -Block @(ConvertFrom-TkHtmlDocument -Html ([string] $source.Text))
    }
    finally {
        $script:TkEditorLoading = $false
    }

    # Written back from the editor, so what is shown is the HTML kept.
    Update-TkHtmlSourceFromUi
    Set-TkStatus -Text 'HTML loaded into the editor, without what the editor does not keep.'
}

# ---------------------------------------------------------------------------
# QR codes
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Draws a QR code as a picture.

.PARAMETER Code
    What New-TkQrCode returns.

.PARAMETER Scale
    Pixels per module.

.OUTPUTS
    System.Windows.Media.Imaging.BitmapSource, frozen, with the four module
    quiet zone the standard asks for.
#>
function New-TkQrPicture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Code,
        [Parameter()] [ValidateRange(1, 40)] [int] $Scale = 8
    )

    $width  = 0
    $pixels = [TkQrCode]::ToGray8($Code.Modules, $Scale, 4, [ref] $width)

    $picture = [System.Windows.Media.Imaging.BitmapSource]::Create($width, $width, 96, 96,
        [System.Windows.Media.PixelFormats]::Gray8, $null, $pixels, $width)

    $picture.Freeze()

    return $picture
}

<#
.SYNOPSIS
    Shows a QR code, or why there is none, in an image and its caption.
#>
function Set-TkQrPicture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ImageName,
        [Parameter(Mandatory)] [string] $InfoName,
        [Parameter()] [AllowNull()] $Code,
        [Parameter()] [AllowEmptyString()] [string] $Message = ''
    )

    $image = Get-TkControl -Name $ImageName
    $info  = Get-TkControl -Name $InfoName

    if (-not $image -or -not $info) {
        return
    }

    if ($null -eq $Code) {
        $image.Source = $null
        $info.Text    = $Message
        return
    }

    $image.Source = New-TkQrPicture -Code $Code

    $levels = @{ L = 'low, 7%'; M = 'medium, 15%'; Q = 'quartile, 25%'; H = 'high, 30%' }

    $info.Text = (@(
        ('Version        {0}' -f $Code.Version)
        ('Size           {0} x {0} modules' -f $Code.Size)
        ('Correction     {0}' -f $levels[$Code.ErrorCorrection])
        ('Content        {0} bytes of UTF-8' -f $Code.Bytes)
        ('Mask           {0}' -f $Code.Mask)
        ''
        $Message
    ) | Where-Object { $null -ne $_ }) -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Encodes the text on the page, as it is typed.
#>
function Update-TkQrFromUi {
    [CmdletBinding()]
    param()

    $box = Get-TkControl -Name 'QrInput'

    if (-not $box) {
        return
    }

    $text = [string] $box.Text

    if (-not $text) {
        Set-TkQrPicture -ImageName 'QrImage' -InfoName 'QrInfo' -Code $null -Message 'Type the link or the text to encode.'
        return
    }

    $choice = @(Get-TkQrErrorCorrectionChoice) | Where-Object { $_.Label -eq [string] (Get-TkControl -Name 'QrErrorCorrection').SelectedItem } | Select-Object -First 1
    $level  = if ($choice) { $choice.Level } else { 'M' }

    try {
        $code = New-TkQrCode -Text $text -ErrorCorrection $level
        Set-TkQrPicture -ImageName 'QrImage' -InfoName 'QrInfo' -Code $code
    }
    catch {
        Set-TkQrPicture -ImageName 'QrImage' -InfoName 'QrInfo' -Code $null -Message $_.Exception.Message
    }
}

<#
.SYNOPSIS
    Encodes the Wi-Fi network described on the page, as it is typed.
#>
function Update-TkWifiQrFromUi {
    [CmdletBinding()]
    param()

    $ssid = Get-TkControl -Name 'WifiQrSsid'
    $key  = Get-TkControl -Name 'WifiQrPassword'

    if (-not $ssid -or -not $key) {
        return
    }

    if (-not $ssid.Text) {
        Set-TkQrPicture -ImageName 'WifiQrImage' -InfoName 'WifiQrInfo' -Code $null -Message 'Type the name of the network and its password, or use the connected network.'
        return
    }

    $choice   = @(Get-TkWifiQrSecurityChoice) | Where-Object { $_.Label -eq [string] (Get-TkControl -Name 'WifiQrSecurity').SelectedItem } | Select-Object -First 1
    $security = if ($choice) { $choice.Security } else { 'WPA' }

    try {
        # The key is read from the password box only to be written into the
        # code, which is its purpose, and is not kept anywhere else.
        $text = ConvertTo-TkWifiQrText -Ssid ([string] $ssid.Text) -Key $key.Password -Security $security `
                                       -Hidden:([bool] (Get-TkControl -Name 'WifiQrHidden').IsChecked)

        Set-TkQrPicture -ImageName 'WifiQrImage' -InfoName 'WifiQrInfo' -Code (New-TkQrCode -Text $text -ErrorCorrection 'M') `
            -Message ('Joins {0} ({1}).' -f $ssid.Text, $(if ($choice) { $choice.Label } else { $security }))
    }
    catch {
        Set-TkQrPicture -ImageName 'WifiQrImage' -InfoName 'WifiQrInfo' -Code $null -Message $_.Exception.Message
    }
}

<#
.SYNOPSIS
    Fills in the name and security of the network this machine is connected to.

.DESCRIPTION
    Read in the background from the Wi-Fi API. The saved password is not
    read: Windows gives it only to an administrator, and a code made from a
    guessed security type would not join anyway.
#>
function Invoke-TkWifiQrCurrentNetwork {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the connected Wi-Fi network...' `
        -ScriptBlock { Get-TkWifiStatus -Days 1 } `
        -OnComplete {
            param($result)

            $status     = @($result.Output) | Select-Object -First 1
            $connection = if ($status) { @($status.Interfaces | Where-Object { $_.Connection } | ForEach-Object { $_.Connection }) | Select-Object -First 1 }

            if (-not $connection -or -not $connection.Ssid) {
                Set-TkStatus -Text 'No Wi-Fi network is connected on this machine.'
                return
            }

            $authentication = [string] $connection.Authentication

            if ($authentication -match 'Enterprise|802\.1X|EAP') {
                Set-TkStatus -Text ('{0} signs in with an account ({1}): a Wi-Fi QR code cannot carry that.' -f $connection.Ssid, $authentication)
                return
            }

            $security = if ($authentication -match 'WPA3' -and $authentication -notmatch 'WPA2') { 'SAE' }
                        elseif ($authentication -match 'Open|None') { 'nopass' }
                        elseif ($authentication -match 'WEP|Shared') { 'WEP' }
                        else { 'WPA' }

            $choice = @(Get-TkWifiQrSecurityChoice) | Where-Object { $_.Security -eq $security } | Select-Object -First 1

            (Get-TkControl -Name 'WifiQrSsid').Text             = [string] $connection.Ssid
            (Get-TkControl -Name 'WifiQrSecurity').SelectedItem = $choice.Label

            Set-TkStatus -Text ('{0} filled in ({1}). Type its password: Windows gives saved passwords only to an administrator.' -f $connection.Ssid, $authentication)
        }
}

<#
.SYNOPSIS
    Saves the QR code shown in an image as a PNG file.

.PARAMETER ImageName
    The image control.

.PARAMETER FileName
    The suggested file name, without extension.
#>
function Save-TkQrPicture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ImageName,
        [Parameter(Mandatory)] [string] $FileName
    )

    $picture = (Get-TkControl -Name $ImageName).Source

    if (-not $picture) {
        Set-TkStatus -Text 'There is no QR code to save yet.'
        return
    }

    $dialog          = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title    = 'Save the QR code'
    $dialog.Filter   = 'PNG picture (*.png)|*.png'
    $dialog.FileName = '{0}.png' -f $FileName

    if (-not $dialog.ShowDialog()) {
        return
    }

    $stream = $null

    try {
        $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
        $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($picture))

        $stream = [System.IO.File]::Create($dialog.FileName)
        $encoder.Save($stream)

        Set-TkStatus -Text ('QR code saved to {0}.' -f $dialog.FileName)
    }
    catch {
        Set-TkStatus -Text ('The QR code could not be saved: {0}' -f $_.Exception.Message)
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

<#
.SYNOPSIS
    Copies the QR code shown in an image to the clipboard.

.PARAMETER ImageName
    The image control.
#>
function Copy-TkQrPicture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ImageName
    )

    $picture = (Get-TkControl -Name $ImageName).Source

    if (-not $picture) {
        Set-TkStatus -Text 'There is no QR code to copy yet.'
        return
    }

    try {
        [System.Windows.Clipboard]::SetImage($picture)
        Set-TkStatus -Text 'QR code copied to the clipboard as a picture.'
    }
    catch {
        Set-TkStatus -Text ('The clipboard is busy: {0}' -f $_.Exception.Message)
    }
}

<#
.SYNOPSIS
    Lists the tools of the Tools page, by category, in the order of the list.

.DESCRIPTION
    Title is the text of the entry in ToolChoices, Panel the name of the grid
    that holds the tool. The markup lists the same tools under the same
    categories in the same order, which a test checks.

.OUTPUTS
    PSCustomObject[] with Category, Title and Panel.
#>
function Get-TkToolEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $tool = {
        param($category, $title, $panel)
        [pscustomobject] @{ Category = $category; Title = $title; Panel = $panel }
    }

    return @(
        (& $tool 'Security'         'Passwords'      'ToolPasswords')
        (& $tool 'Security'         'SSH keys'       'ToolSshKeys')
        (& $tool 'Security'         'File integrity' 'ToolFileIntegrity')
        (& $tool 'Security'         'Safe Links'     'ToolSafeLinks')
        (& $tool 'Security'         'E-mail headers' 'ToolMailHeaders')
        (& $tool 'Security'         'Mail DNS records' 'ToolMailDns')
        (& $tool 'Security'         'Certificates'   'ToolCertificates')
        (& $tool 'Generators'       'Ports'          'ToolPorts')
        (& $tool 'Generators'       'UUIDs'          'ToolUuids')
        (& $tool 'Generators'       'QR code'        'ToolQrCode')
        (& $tool 'Generators'       'Wi-Fi QR code'  'ToolWifiQr')
        (& $tool 'Text and data'    'Encoding'       'ToolEncoding')
        (& $tool 'Text and data'    'Regex'          'ToolRegex')
        (& $tool 'Text and data'    'Timestamps'     'ToolTimestamps')
        (& $tool 'Text and data'    'Text diff'      'ToolTextDiff')
        (& $tool 'Text and data'    'URL parser'     'ToolUrlParser')
        (& $tool 'Text and data'    'NATO alphabet'  'ToolNato')
        (& $tool 'Text and data'    'Phone numbers'  'ToolPhone')
        (& $tool 'Text and data'    'HTML editor'    'ToolHtmlEditor')
        (& $tool 'Linux and DevOps' 'chmod'          'ToolChmod')
        (& $tool 'Linux and DevOps' 'Crontab'        'ToolCrontab')
        (& $tool 'Linux and DevOps' 'Docker Compose' 'ToolDockerCompose')
    )
}

<#
.SYNOPSIS
    Shows one tool and hides the others.

.PARAMETER Title
    The title of the tool in Get-TkToolEntry.
#>
function Show-TkTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title
    )

    $chosen = @(Get-TkToolEntry) | Where-Object { $_.Title -eq $Title } | Select-Object -First 1

    if (-not $chosen) {
        return
    }

    foreach ($entry in @(Get-TkToolEntry)) {

        $panel = Get-TkControl -Name $entry.Panel

        if ($panel) {
            $panel.Visibility = if ($entry.Panel -eq $chosen.Panel) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
}

<#
.SYNOPSIS
    Copies the text of an output box.

.PARAMETER ControlName
    The output box.
#>
function Copy-TkToolOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ControlName
    )

    $text = (Get-TkControl -Name $ControlName).Text

    if ([string]::IsNullOrWhiteSpace($text)) {
        Set-TkStatus -Text 'Nothing to copy yet.'
        return
    }

    if (Set-TkClipboard -Text $text) {
        Set-TkStatus -Text 'Copied to the clipboard.'
    }
}

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Lists the port ranges offered by the generator.

.OUTPUTS
    PSCustomObject[] with Label, Minimum and Maximum. Custom has no bounds.
#>
function Get-TkPortRangeChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Dynamic and private (49152-65535)'; Minimum = 49152; Maximum = 65535 }
        [pscustomobject] @{ Label = 'Registered (1024-49151)';           Minimum = 1024;  Maximum = 49151 }
        [pscustomobject] @{ Label = 'Any above 1023 (1024-65535)';       Minimum = 1024;  Maximum = 65535 }
        [pscustomobject] @{ Label = 'Custom, from and to below';          Minimum = 0;     Maximum = 0 }
    )
}

<#
.SYNOPSIS
    Enables From and To only when the custom range is chosen.
#>
function Update-TkPortRangeControl {
    [CmdletBinding()]
    param()

    $custom = ([string] (Get-TkControl -Name 'PortRange').SelectedItem) -eq (@(Get-TkPortRangeChoice) | Where-Object { $_.Minimum -eq 0 } | Select-Object -First 1).Label

    foreach ($name in @('PortFrom', 'PortTo')) {

        $box = Get-TkControl -Name $name

        if ($box) {
            # The text box style has no disabled look of its own.
            $box.IsEnabled = $custom
            $box.Opacity   = if ($custom) { 1 } else { 0.45 }
        }
    }
}

<#
.SYNOPSIS
    Draws ports from the choices on the page.
#>
function Invoke-TkPortGeneratorFromUi {
    [CmdletBinding()]
    param()

    $choice = @(Get-TkPortRangeChoice) | Where-Object { $_.Label -eq [string] (Get-TkControl -Name 'PortRange').SelectedItem } | Select-Object -First 1
    $output = Get-TkControl -Name 'PortOutput'

    $minimum = $choice.Minimum
    $maximum = $choice.Maximum

    if ($minimum -eq 0) {

        $from = 0
        $to   = 0

        if (-not [int]::TryParse((Get-TkControl -Name 'PortFrom').Text, [ref] $from) -or -not [int]::TryParse((Get-TkControl -Name 'PortTo').Text, [ref] $to) -or
            $from -lt 1 -or $to -gt 65535 -or $from -gt $to) {
            $output.Text = 'Type a range from 1 to 65535 in From and To, with From not above To.'
            return
        }

        $minimum = $from
        $maximum = $to
    }

    $count = 0

    if (-not [int]::TryParse((Get-TkControl -Name 'PortCount').Text, [ref] $count) -or $count -lt 1 -or $count -gt 100) {
        $output.Text = 'Type how many ports, from 1 to 100.'
        return
    }

    $exclude = @()

    if ((Get-TkControl -Name 'PortSkipInUse').IsChecked) {
        $exclude = @(Get-TkPortInUse)
    }

    $skipKnown = [bool] (Get-TkControl -Name 'PortSkipKnown').IsChecked

    $ports = @(Get-TkRandomPort -Minimum $minimum -Maximum $maximum -Count $count -Exclude $exclude -SkipKnownServices:$skipKnown)

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Range {0}-{1}. {2}' -f $minimum, $maximum, $(if ($exclude.Count -gt 0) { 'Ports in use or reserved by Windows on this machine are left out.' } else { 'Ports in use here were not checked.' })))

    if ($ports.Count -lt $count) {
        $lines.Add(('Only {0} port(s) of the range are free.' -f $ports.Count))
    }

    $lines.Add('')

    foreach ($port in $ports) {
        $lines.Add([string] $port)
    }

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# chmod
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Maps each permission check box to its bit.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
function Get-TkChmodBitMap {
    [CmdletBinding()]
    param()

    return [ordered] @{
        ChmodOwnerRead     = 256
        ChmodOwnerWrite    = 128
        ChmodOwnerExecute  = 64
        ChmodGroupRead     = 32
        ChmodGroupWrite    = 16
        ChmodGroupExecute  = 8
        ChmodOthersRead    = 4
        ChmodOthersWrite   = 2
        ChmodOthersExecute = 1
        ChmodSetUid        = 2048
        ChmodSetGid        = 1024
        ChmodSticky        = 512
    }
}

<#
.SYNOPSIS
    Writes a mode into every chmod control but the one being typed in.

.PARAMETER Bits
    The mode.

.PARAMETER Skip
    The text box the value came from, left as typed.
#>
function Set-TkChmodControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int] $Bits,
        [Parameter()] [AllowEmptyString()] [string] $Skip = ''
    )

    $mode = ConvertTo-TkUnixMode -Bits $Bits

    $script:TkChmodUpdating = $true

    try {
        $map = Get-TkChmodBitMap

        foreach ($name in @($map.Keys)) {

            $box = Get-TkControl -Name $name

            if ($box) {
                $box.IsChecked = [bool] ($Bits -band $map[$name])
            }
        }

        if ($Skip -ne 'ChmodOctal') {
            (Get-TkControl -Name 'ChmodOctal').Text = $mode.Octal
        }

        if ($Skip -ne 'ChmodSymbolic') {
            (Get-TkControl -Name 'ChmodSymbolic').Text = $mode.Symbolic
        }
    }
    finally {
        $script:TkChmodUpdating = $false
    }

    $describe = {
        param($who)
        $words = @($(if ($who.Read) { 'read' }), $(if ($who.Write) { 'write' }), $(if ($who.Execute) { 'execute' })) | Where-Object { $_ }
        if (@($words).Count -gt 0) { $words -join ', ' } else { 'nothing' }
    }

    $special = @($(if ($mode.SetUid) { 'setuid: runs as the owner of the file' }), $(if ($mode.SetGid) { 'setgid: runs as the group of the file, or new files inherit the group of the folder' }), $(if ($mode.Sticky) { 'sticky: in a folder, only the owner of a file may delete it' })) | Where-Object { $_ }

    (Get-TkControl -Name 'ChmodOutput').Text = @(
        ('{0,-9} {1}' -f 'Numeric', $mode.NumericCommand)
        ('{0,-9} {1}' -f 'Symbolic', $mode.SymbolicCommand)
        ('{0,-9} {1}' -f 'ls -l', $mode.Listing)
        ''
        ('{0,-9} {1}' -f 'Owner', (& $describe $mode.Owner))
        ('{0,-9} {1}' -f 'Group', (& $describe $mode.Group))
        ('{0,-9} {1}' -f 'Others', (& $describe $mode.Others))
        ('{0,-9} {1}' -f 'Special', $(if (@($special).Count -gt 0) { $special -join '; ' } else { 'none' }))
    ) -join [Environment]::NewLine
}

<#
.SYNOPSIS
    Follows a click on a permission check box.
#>
function Update-TkChmodFromCheckBox {
    [CmdletBinding()]
    param()

    if ($script:TkChmodUpdating) {
        return
    }

    $map  = Get-TkChmodBitMap
    $bits = 0

    foreach ($name in @($map.Keys)) {
        if ((Get-TkControl -Name $name).IsChecked) {
            $bits += $map[$name]
        }
    }

    Set-TkChmodControl -Bits $bits
}

<#
.SYNOPSIS
    Follows a mode typed in the octal or the symbolic box.

.PARAMETER Source
    The box typed in.
#>
function Update-TkChmodFromText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Source
    )

    if ($script:TkChmodUpdating) {
        return
    }

    $bits = ConvertFrom-TkUnixModeText -Text (Get-TkControl -Name $Source).Text

    if ($null -eq $bits) {
        (Get-TkControl -Name 'ChmodOutput').Text = 'Not a mode yet: type three or four octal digits such as 755, or nine characters such as rwxr-xr-x.'
        return
    }

    Set-TkChmodControl -Bits $bits -Skip $Source
}

# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Fills the cheat sheet beside the tester, one heading per section.
#>
function Initialize-TkRegexCheatSheet {
    [CmdletBinding()]
    param()

    $list = Get-TkControl -Name 'RegexCheatSheet'

    if (-not $list) {
        return
    }

    $list.Items.Clear()
    $section = ''

    foreach ($entry in @(Get-TkRegexCheatSheet)) {

        if ($entry.Section -ne $section) {

            $section = $entry.Section

            $title = New-Object System.Windows.Controls.TextBlock
            $title.Text = $section.ToUpperInvariant()
            $title.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'ChoiceGroupTitle')

            $heading = New-Object System.Windows.Controls.ListBoxItem
            $heading.Content = $title
            $heading.SetResourceReference([System.Windows.FrameworkElement]::StyleProperty, 'ChoiceGroup')

            [void] $list.Items.Add($heading)
        }

        $token = New-Object System.Windows.Controls.TextBlock
        $token.Text              = $entry.Token
        $token.Width             = 112
        $token.TextTrimming      = [System.Windows.TextTrimming]::CharacterEllipsis
        $token.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
        $token.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Accent')

        $description = New-Object System.Windows.Controls.TextBlock
        $description.Text         = $entry.Description
        $description.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $description.FontFamily   = New-Object System.Windows.Media.FontFamily('Segoe UI')
        $description.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

        $row = New-Object System.Windows.Controls.DockPanel
        [System.Windows.Controls.DockPanel]::SetDock($token, [System.Windows.Controls.Dock]::Left)
        [void] $row.Children.Add($token)
        [void] $row.Children.Add($description)

        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = $row
        $item.Tag     = $entry
        $item.ToolTip = 'Double-click to insert into the {0}: {1}' -f $entry.Target.ToLowerInvariant(), $entry.Insert

        [void] $list.Items.Add($item)
    }

    $list.Add_MouseDoubleClick({ Add-TkRegexCheatSheetToken })

    $list.Add_KeyDown({
        param($eventSource, $routedArgs)

        if ($routedArgs.Key -eq [System.Windows.Input.Key]::Return) {
            Add-TkRegexCheatSheetToken
            $routedArgs.Handled = $true
        }
    })
}

<#
.SYNOPSIS
    Inserts the chosen cheat sheet token at the caret of its box.

.DESCRIPTION
    Replaces the selection when there is one, as typing would, and leaves the
    caret after the insertion, inside the parentheses for a group so its
    content can be typed straight away.
#>
function Add-TkRegexCheatSheetToken {
    [CmdletBinding()]
    param()

    $list  = Get-TkControl -Name 'RegexCheatSheet'
    $entry = if ($list -and $list.SelectedItem) { $list.SelectedItem.Tag } else { $null }

    if (-not $entry) {
        return
    }

    $box = Get-TkControl -Name $(if ($entry.Target -eq 'Replacement') { 'RegexReplacement' } else { 'RegexPattern' })

    if (-not $box) {
        return
    }

    $start  = $box.SelectionStart
    $insert = [string] $entry.Insert
    $caret  = $start + $insert.Length

    # An empty group leaves the caret between its parentheses.
    if ($insert.Length -gt 1 -and $insert.StartsWith('(') -and $insert.EndsWith(')')) {
        $caret--
    }

    $box.Text       = $box.Text.Remove($start, $box.SelectionLength).Insert($start, $insert)
    $box.CaretIndex = $caret

    [void] $box.Focus()
}

<#
.SYNOPSIS
    Runs the pattern on the page against its text, as it is typed.
#>
function Invoke-TkRegexFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'RegexOutput'

    if (-not $output) {
        return
    }

    $replacement = [string] (Get-TkControl -Name 'RegexReplacement').Text

    $result = Test-TkRegularExpression -Pattern ([string] (Get-TkControl -Name 'RegexPattern').Text) `
                                       -Text ([string] (Get-TkControl -Name 'RegexText').Text) `
                                       -IgnoreCase:([bool] (Get-TkControl -Name 'RegexIgnoreCase').IsChecked) `
                                       -Multiline:([bool] (Get-TkControl -Name 'RegexMultiline').IsChecked) `
                                       -Singleline:([bool] (Get-TkControl -Name 'RegexSingleline').IsChecked) `
                                       -Replace:([bool] $replacement) -Replacement $replacement

    $lines = New-Object System.Collections.Generic.List[string]

    if (-not $result.Valid) {
        $lines.Add($(if ($result.Error -eq 'Type a pattern.') { 'Type a pattern and a text to test it on.' } else { 'The pattern is not valid: {0}' -f $result.Error }))
    }
    elseif ($result.TimedOut) {
        $lines.Add('Stopped after 2 seconds: the pattern backtracks too much on this text. Make its repeated parts more specific, for example [^,]+ rather than .+ between separators.')
    }
    else {

        $lines.Add(('{0} match(es){1}' -f @($result.Matches).Count, $(if ($result.Truncated) { ', the first 500 shown' } else { '' })))

        foreach ($match in $result.Matches) {

            $lines.Add('')
            $lines.Add(('Line {0}, index {1}, length {2}: {3}' -f $match.Line, $match.Index, $match.Length, $match.Value))

            foreach ($group in $match.Groups) {
                $lines.Add(('    {0}: {1}' -f $group.Name, $(if ($group.Success) { $group.Value } else { '(no match)' })))
            }
        }

        if ($null -ne $result.Replaced) {
            $lines.Add('')
            $lines.Add('After replacement')
            $lines.Add($result.Replaced)
        }

        if ($result.Error) {
            $lines.Add('')
            $lines.Add($result.Error)
        }
    }

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Converts the value typed, as it is typed.
#>
function Update-TkTimestampFromUi {
    [CmdletBinding()]
    param()

    $output = Get-TkControl -Name 'TimestampOutput'
    $value  = Get-TkControl -Name 'TimestampInput'

    if (-not $output -or -not $value) {
        return
    }

    $result = ConvertFrom-TkTimestamp -Text ([string] $value.Text)

    if (-not $result.Valid) {
        $output.Text = '{0} Examples: 1726300800, 1726300800000, 133709952000000000, 2026-09-14T08:00:00Z, now.' -f $result.Note
        return
    }

    $invariant = [Globalization.CultureInfo]::InvariantCulture
    $lines     = New-Object System.Collections.Generic.List[string]

    $lines.Add(('{0,-12} {1}' -f 'Read as', $result.Kind))

    if ($result.Utc) {

        $lines.Add(('{0,-12} {1}' -f 'UTC', $result.Utc.ToString('yyyy-MM-dd HH:mm:ss', $invariant)))
        $lines.Add(('{0,-12} {1} ({2})' -f 'Local', $result.Local.ToString('yyyy-MM-dd HH:mm:ss', $invariant), [TimeZoneInfo]::Local.Id))
        $lines.Add(('{0,-12} {1}' -f 'ISO 8601', $result.Iso))
        $lines.Add(('{0,-12} {1}' -f 'Relative', $result.Relative))
        $lines.Add('')
        $lines.Add(('{0,-12} {1}' -f 'Unix s', $result.UnixSeconds))
        $lines.Add(('{0,-12} {1}' -f 'Unix ms', $result.UnixMilliseconds))
        $lines.Add(('{0,-12} {1}' -f 'FILETIME', $(if ($null -ne $result.FileTime) { $result.FileTime } else { 'before 1601, not representable' })))
    }

    foreach ($other in @($result.Alternatives)) {
        $lines.Add(('Also possible as {0}: {1} UTC' -f $other.Kind, $other.Utc.ToString('yyyy-MM-dd HH:mm:ss', $invariant)))
    }

    if ($result.Note) {
        $lines.Add('')
        $lines.Add($result.Note)
    }

    $output.Text = $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Lists the text conversions offered.

.OUTPUTS
    PSCustomObject[] with Label and Operation.
#>
function Get-TkTextOperationChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Base64 encode'; Operation = 'Base64Encode' }
        [pscustomobject] @{ Label = 'Base64 decode'; Operation = 'Base64Decode' }
        [pscustomobject] @{ Label = 'URL encode';    Operation = 'UrlEncode' }
        [pscustomobject] @{ Label = 'URL decode';    Operation = 'UrlDecode' }
        [pscustomobject] @{ Label = 'HTML encode';   Operation = 'HtmlEncode' }
        [pscustomobject] @{ Label = 'HTML decode';   Operation = 'HtmlDecode' }
        [pscustomobject] @{ Label = 'Hex encode';    Operation = 'HexEncode' }
        [pscustomobject] @{ Label = 'Hex decode';    Operation = 'HexDecode' }
        [pscustomobject] @{ Label = 'Decode a JWT';  Operation = 'JwtDecode' }
    )
}

<#
.SYNOPSIS
    Converts the text on the page.
#>
function Invoke-TkTextConversionFromUi {
    [CmdletBinding()]
    param()

    $choice = @(Get-TkTextOperationChoice) | Where-Object { $_.Label -eq [string] (Get-TkControl -Name 'EncodingOperation').SelectedItem } | Select-Object -First 1
    $output = Get-TkControl -Name 'EncodingOutput'

    try {
        $output.Text = Convert-TkText -Text ([string] (Get-TkControl -Name 'EncodingInput').Text) -Operation $choice.Operation
    }
    catch {
        $output.Text = 'Could not convert: {0}' -f $_.Exception.Message
    }
}
