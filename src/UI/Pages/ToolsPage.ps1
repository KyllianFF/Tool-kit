<#
    Toolkit - UI / Tools page, calculators

    The Ports, chmod, Regex, Timestamps and Encoding tabs of the Tools page.
    Each one reads its controls, calls a function of Calculators.ps1 and
    writes plain text, so the result can be selected and copied.
#>

# Set while the chmod controls are written from code, so the handlers that
# follow them do not answer their own change.
$script:TkChmodUpdating = $false

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
        (& $tool 'Generators'       'Ports'          'ToolPorts')
        (& $tool 'Text and data'    'Encoding'       'ToolEncoding')
        (& $tool 'Text and data'    'Regex'          'ToolRegex')
        (& $tool 'Text and data'    'Timestamps'     'ToolTimestamps')
        (& $tool 'Linux and DevOps' 'chmod'          'ToolChmod')
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
