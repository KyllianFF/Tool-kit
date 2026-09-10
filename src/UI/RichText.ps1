<#
    Toolkit - UI / Rich text rendering

    Builds FlowDocuments for the knowledge base and the vendor command
    reference.

    Why not a text box. The reference content is structured: headings, prose,
    bullet lists and, for things like the port list, genuine tables. Flattened
    into one monospaced block it becomes unreadable exactly where it matters
    most, which is when you are looking for one row among fifty. A
    FlowDocument renders each of those as what it is, and it is also the only
    control here that can highlight a search term inside the text.

    Every colour is read from the window resources at build time, so a
    document follows the current theme. A document is rebuilt on a theme
    change rather than repainted, which is why Set-TkTheme re-renders the
    selected topic.
#>

<#
.SYNOPSIS
    Returns a theme brush by resource key.

.DESCRIPTION
    Falls back to a readable grey when the window is not up, so the rendering
    functions stay callable from a console session and from the tests.

.OUTPUTS
    System.Windows.Media.Brush
#>
function Get-TkBrush {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Key
    )

    $ctx = Get-TkContext

    if ($ctx.Window -and $ctx.Window.Resources[$Key]) {
        return $ctx.Window.Resources[$Key]
    }

    return [System.Windows.Media.Brushes]::Gray
}

<#
.SYNOPSIS
    Creates an empty document styled for the current theme.

.OUTPUTS
    System.Windows.Documents.FlowDocument
#>
function New-TkFlowDocument {
    [CmdletBinding()]
    [OutputType([System.Windows.Documents.FlowDocument])]
    param()

    $document = New-Object System.Windows.Documents.FlowDocument

    $document.FontFamily      = New-Object System.Windows.Media.FontFamily('Segoe UI')
    $document.FontSize        = 13
    $document.SetResourceReference([System.Windows.Documents.FlowDocument]::ForegroundProperty, 'TextPrimary')
    $document.Background      = [System.Windows.Media.Brushes]::Transparent
    $document.PagePadding     = New-Object System.Windows.Thickness(4)
    $document.TextAlignment   = [System.Windows.TextAlignment]::Left

    return $document
}

<#
.SYNOPSIS
    Builds the inline runs for a piece of text, highlighting a search term.

.DESCRIPTION
    Splits the text on every case insensitive occurrence of the term and
    returns alternating plain and highlighted runs. With no term, a single
    run. This is what makes a search result readable: finding the topic is
    only half of it, you still have to find the line.

.PARAMETER Text
    Text to render.

.PARAMETER Highlight
    Term to mark, or empty for none.

.OUTPUTS
    System.Windows.Documents.Run[]
#>
function New-TkTextRuns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = ''
    )

    if ([string]::IsNullOrWhiteSpace($Highlight) -or [string]::IsNullOrEmpty($Text)) {
        return @((New-Object System.Windows.Documents.Run($Text)))
    }

    $runs     = @()
    $position = 0

    while ($true) {

        $found = $Text.IndexOf($Highlight, $position, [System.StringComparison]::OrdinalIgnoreCase)

        if ($found -lt 0) {
            break
        }

        if ($found -gt $position) {
            $runs += New-Object System.Windows.Documents.Run($Text.Substring($position, $found - $position))
        }

        $match = New-Object System.Windows.Documents.Run($Text.Substring($found, $Highlight.Length))
        $match.Background = Get-TkBrush -Key 'Warning'
        $match.Foreground = [System.Windows.Media.Brushes]::Black
        $match.FontWeight = [System.Windows.FontWeights]::SemiBold

        $runs += $match

        $position = $found + $Highlight.Length
    }

    if ($position -lt $Text.Length) {
        $runs += New-Object System.Windows.Documents.Run($Text.Substring($position))
    }

    return $runs
}

<#
.SYNOPSIS
    Appends a heading to a document.

.PARAMETER Level
    1 for the topic title, 2 for a section.
#>
function Add-TkHeading {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter()]
        [ValidateRange(1, 3)]
        [int] $Level = 2,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = ''
    )

    $paragraph = New-Object System.Windows.Documents.Paragraph

    $paragraph.FontSize   = @(20, 15, 13)[$Level - 1]
    $paragraph.FontWeight = [System.Windows.FontWeights]::SemiBold
    $paragraph.Foreground = Get-TkBrush -Key $(if ($Level -eq 1) { 'TextPrimary' } else { 'Accent' })
    $paragraph.Margin     = New-Object System.Windows.Thickness(0, $(if ($Level -eq 1) { 0 } else { 18 }), 0, 6)

    foreach ($run in (New-TkTextRuns -Text $Text -Highlight $Highlight)) {
        $paragraph.Inlines.Add($run)
    }

    $Document.Blocks.Add($paragraph)
}

<#
.SYNOPSIS
    Appends a paragraph of prose to a document.
#>
function Add-TkParagraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = '',

        [Parameter()]
        [switch] $Muted
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return
    }

    $paragraph = New-Object System.Windows.Documents.Paragraph
    $paragraph.Margin     = New-Object System.Windows.Thickness(0, 0, 0, 10)
    $paragraph.LineHeight = 19

    if ($Muted) {
        $paragraph.Foreground = Get-TkBrush -Key 'TextMuted'
        $paragraph.FontSize   = 12
    }

    foreach ($run in (New-TkTextRuns -Text $Text -Highlight $Highlight)) {
        $paragraph.Inlines.Add($run)
    }

    $Document.Blocks.Add($paragraph)
}

<#
.SYNOPSIS
    Appends a bullet list to a document.
#>
function Add-TkBulletList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Item,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = ''
    )

    if ($Item.Count -eq 0) {
        return
    }

    $list = New-Object System.Windows.Documents.List
    $list.MarkerStyle = [System.Windows.TextMarkerStyle]::Disc
    $list.Margin      = New-Object System.Windows.Thickness(18, 0, 0, 10)
    $list.Padding     = New-Object System.Windows.Thickness(0)

    foreach ($text in $Item) {

        $paragraph = New-Object System.Windows.Documents.Paragraph
        $paragraph.Margin     = New-Object System.Windows.Thickness(0, 0, 0, 5)
        $paragraph.LineHeight = 19

        foreach ($run in (New-TkTextRuns -Text $text -Highlight $Highlight)) {
            $paragraph.Inlines.Add($run)
        }

        $listItem = New-Object System.Windows.Documents.ListItem($paragraph)
        $list.ListItems.Add($listItem)
    }

    $Document.Blocks.Add($list)
}

<#
.SYNOPSIS
    Appends a table to a document, with proportional and resizable columns.

.DESCRIPTION
    Built as a Grid hosted in a BlockUIContainer rather than as a FlowDocument
    Table, because the FlowDocument Table accepts star widths and then ignores
    them. A Grid honours star sizing, wraps its cell text instead of
    truncating it, and takes a GridSplitter between columns.

    Two decisions worth knowing about.

    Colours are attached with SetResourceReference rather than assigned. An
    assigned brush is a snapshot: the table kept the palette it was built with
    and stayed unreadable after a theme change until the page was rebuilt.
    A resource reference is the code equivalent of DynamicResource and follows
    the swap.

    Cells are read only TextBoxes rather than TextBlocks, because a TextBlock
    cannot be selected and a table nobody can copy out of is half a table.
    The cost is that a search term cannot be marked inside the text, so a
    matching cell is tinted whole instead.

.PARAMETER Column
    Column headings.

.PARAMETER Row
    Rows, each an array of cell values matching the columns. Build them with
    the comma operator inside a pipeline, otherwise PowerShell flattens the
    inner arrays and every row arrives with one cell.

.PARAMETER Weight
    Relative column widths. Defaults to a narrow first column for the key
    being looked up and progressively wider ones after it.

.PARAMETER Highlight
    Search term. A cell containing it is tinted.

.EXAMPLE
    Add-TkTable -Document $document -Column @('Port', 'Service') -Row @(
        , @('443', 'HTTPS')
        , @('22',  'SSH')
    )
#>
function Add-TkTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [string[]] $Column,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row,

        [Parameter()]
        [double[]] $Weight = @(),

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = ''
    )

    if ($Column.Count -eq 0) {
        return
    }

    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = New-Object System.Windows.Thickness(0, 2, 0, 16)
    $grid.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Stretch

    # --- Column widths ----------------------------------------------------
    for ($i = 0; $i -lt $Column.Count; $i++) {

        # Not named $weight: PowerShell variable names are case insensitive,
        # so that would assign to the $Weight parameter itself.
        $columnWeight = if ($i -lt $Weight.Count) { $Weight[$i] }
                        elseif ($i -eq 0) { 0.8 }
                        elseif ($i -eq ($Column.Count - 1)) { 2.6 }
                        else { 1.4 }

        $definition = New-Object System.Windows.Controls.ColumnDefinition
        $definition.Width    = [System.Windows.GridLength]::new([double] $columnWeight, [System.Windows.GridUnitType]::Star)
        $definition.MinWidth = 48

        $grid.ColumnDefinitions.Add($definition)
    }

    $grid.RowDefinitions.Add((New-TkAutoRow))

    foreach ($ignored in $Row) {
        $grid.RowDefinitions.Add((New-TkAutoRow))
    }

    # --- Header cells -----------------------------------------------------
    for ($i = 0; $i -lt $Column.Count; $i++) {

        $text = New-Object System.Windows.Controls.TextBlock
        $text.Text         = $Column[$i]
        $text.FontSize     = 12
        $text.FontWeight   = [System.Windows.FontWeights]::SemiBold
        $text.TextWrapping = [System.Windows.TextWrapping]::Wrap

        $text.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

        $cell = New-Object System.Windows.Controls.Border
        $cell.BorderThickness = New-Object System.Windows.Thickness(0, 0, 1, 1)
        $cell.Padding         = New-Object System.Windows.Thickness(8, 6, 8, 6)
        $cell.Child           = $text

        $cell.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SurfaceRaised')
        $cell.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')

        [System.Windows.Controls.Grid]::SetColumn($cell, $i)
        [System.Windows.Controls.Grid]::SetRow($cell, 0)

        [void] $grid.Children.Add($cell)
    }

    # --- Body cells -------------------------------------------------------
    $rowIndex = 1

    foreach ($values in $Row) {

        $cells = @($values)

        for ($i = 0; $i -lt $Column.Count; $i++) {

            $value = if ($i -lt $cells.Count) { [string] $cells[$i] } else { '' }

            $text = New-TkSelectableText -Value $value

            $text.FontSize = 12.5

            # The lookup key is monospaced so a column of ports lines up.
            if ($i -eq 0) {
                $text.FontFamily = New-Object System.Windows.Media.FontFamily('Cascadia Mono, Consolas')
                $text.FontWeight = [System.Windows.FontWeights]::SemiBold
            }

            $cell = New-Object System.Windows.Controls.Border
            $cell.BorderThickness = New-Object System.Windows.Thickness(0, 0, 1, 1)
            $cell.Padding         = New-Object System.Windows.Thickness(6, 4, 6, 4)
            $cell.Child           = $text

            $cell.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')

            # A matching cell is tinted whole. Marking the term inside the
            # text would mean giving up selection, which matters more.
            if ($Highlight -and $value -and
                $value.IndexOf($Highlight, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {

                $cell.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Selection')
            }

            [System.Windows.Controls.Grid]::SetColumn($cell, $i)
            [System.Windows.Controls.Grid]::SetRow($cell, $rowIndex)

            [void] $grid.Children.Add($cell)
        }

        $rowIndex++
    }

    # --- Resize handles ---------------------------------------------------
    # One splitter per boundary, spanning every row, so a column can be
    # widened by dragging its right edge when a value needs the room.
    for ($i = 0; $i -lt ($Column.Count - 1); $i++) {

        $splitter = New-Object System.Windows.Controls.GridSplitter
        $splitter.Width               = 6
        $splitter.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
        $splitter.VerticalAlignment   = [System.Windows.VerticalAlignment]::Stretch
        $splitter.Background          = [System.Windows.Media.Brushes]::Transparent
        $splitter.Cursor              = [System.Windows.Input.Cursors]::SizeWE
        $splitter.ResizeBehavior      = [System.Windows.Controls.GridResizeBehavior]::CurrentAndNext
        $splitter.ToolTip             = 'Drag to widen this column'

        [System.Windows.Controls.Grid]::SetColumn($splitter, $i)
        [System.Windows.Controls.Grid]::SetRow($splitter, 0)
        [System.Windows.Controls.Grid]::SetRowSpan($splitter, $grid.RowDefinitions.Count)

        [void] $grid.Children.Add($splitter)
    }

    $container = New-Object System.Windows.Documents.BlockUIContainer($grid)
    $container.Margin = New-Object System.Windows.Thickness(0)

    $Document.Blocks.Add($container)
}

<#
.SYNOPSIS
    Returns a Grid row definition sized to its content.

.OUTPUTS
    System.Windows.Controls.RowDefinition
#>
function New-TkAutoRow {
    [CmdletBinding()]
    [OutputType([System.Windows.Controls.RowDefinition])]
    param()

    $definition = New-Object System.Windows.Controls.RowDefinition
    $definition.Height = [System.Windows.GridLength]::Auto

    return $definition
}

<#
.SYNOPSIS
    Builds a read only text control whose content can be selected and copied.

.DESCRIPTION
    A TextBlock cannot be selected on .NET Framework, and a report nobody can
    copy a path or a thumbprint out of is half a report. A read only TextBox
    with no chrome looks identical and behaves the way people expect.

    Colours are attached by resource reference so the control follows a theme
    change instead of keeping the palette it was created with.

.OUTPUTS
    System.Windows.Controls.TextBox
#>
function New-TkSelectableText {
    [CmdletBinding()]
    [OutputType([System.Windows.Controls.TextBox])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $text = New-Object System.Windows.Controls.TextBox

    $text.Text            = $Value
    $text.IsReadOnly      = $true
    $text.BorderThickness = New-Object System.Windows.Thickness(0)
    $text.Background      = [System.Windows.Media.Brushes]::Transparent
    $text.Padding         = New-Object System.Windows.Thickness(0)
    $text.TextWrapping    = [System.Windows.TextWrapping]::Wrap
    $text.IsTabStop       = $false

    # The stock template would put the content in a centred, non scrolling
    # host and draw the hint the application style adds to every text box.
    $text.Template = $null
    $text.Style    = $null

    $text.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, 'TextPrimary')
    $text.SetResourceReference([System.Windows.Controls.TextBox]::SelectionBrushProperty, 'Accent')
    $text.SetResourceReference([System.Windows.Controls.TextBox]::CaretBrushProperty, 'TextPrimary')

    return $text
}

<#
.SYNOPSIS
    Appends a monospaced command block to a document.

.DESCRIPTION
    Used by the vendor reference, where the command has to be copied exactly
    and a proportional font hides trailing spaces and pipe characters.
#>
function Add-TkCodeBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = ''
    )

    $paragraph = New-Object System.Windows.Documents.Paragraph

    $paragraph.FontFamily      = New-Object System.Windows.Media.FontFamily('Cascadia Mono, Consolas, Courier New')
    $paragraph.FontSize        = 12.5
    $paragraph.Background      = Get-TkBrush -Key 'InputBackground'
    $paragraph.Padding         = New-Object System.Windows.Thickness(10, 8, 10, 8)
    $paragraph.Margin          = New-Object System.Windows.Thickness(0, 0, 0, 4)
    $paragraph.BorderBrush     = Get-TkBrush -Key 'BorderSubtle'
    $paragraph.BorderThickness = New-Object System.Windows.Thickness(1)
    $paragraph.LineHeight      = 17

    foreach ($run in (New-TkTextRuns -Text $Text -Highlight $Highlight)) {
        $paragraph.Inlines.Add($run)
    }

    $Document.Blocks.Add($paragraph)
}

<#
.SYNOPSIS
    Returns the resource key a severity should be drawn in.

.DESCRIPTION
    Lives here rather than on a page, because the cards, the chips and every
    report renderer share it.

.OUTPUTS
    System.String
#>
function Get-TkSeverityBrushKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Severity
    )

    switch ($Severity) {
        'Fail'    { return 'Danger' }
        'Warning' { return 'Warning' }
        'Pass'    { return 'Success' }
        default   { return 'TextMuted' }
    }
}

<#
.SYNOPSIS
    Appends a finding as a self contained card.

.DESCRIPTION
    Replaces the flat run of coloured words the reports used to be. A page of
    those reads as one undifferentiated block, which is exactly the complaint:
    nothing separates one finding from the next, and the eye has nowhere to
    rest.

    A card gives each finding a boundary, a severity chip that carries the
    verdict at a glance, a title line, and the explanation set apart
    underneath. Where a safe single step correction exists, the card carries
    the button for it.

    Colours are attached by resource reference so a card follows a theme
    change, and every piece of text is selectable.

.PARAMETER Severity
    Pass, Info, Warning or Fail.

.PARAMETER Title
    What the finding is about.

.PARAMETER State
    The measured value, shown to the right of the title.

.PARAMETER Detail
    The explanation. Set in muted text under the title.

.PARAMETER Action
    What to change, shown in its own band under the detail.

.PARAMETER RemediationId
    Key into the remediation allow list. When given and the correction is
    available, the card carries a button that applies it.
#>
function Add-TkFindingCard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Severity,

        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter()]
        [AllowEmptyString()]
        [string] $State = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Detail = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Action = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $RemediationId = ''
    )

    $card = New-Object System.Windows.Controls.Border
    $card.BorderThickness = New-Object System.Windows.Thickness(1)
    $card.CornerRadius    = New-Object System.Windows.CornerRadius(7)
    $card.Padding         = New-Object System.Windows.Thickness(14, 11, 14, 11)
    $card.Margin          = New-Object System.Windows.Thickness(0, 0, 0, 9)

    $card.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Surface')
    $card.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')

    $stack = New-Object System.Windows.Controls.StackPanel
    $card.Child = $stack

    # --- Title line: chip, title, state -----------------------------------
    $header = New-Object System.Windows.Controls.Grid

    foreach ($width in @('Auto', 'Star', 'Auto')) {

        $definition = New-Object System.Windows.Controls.ColumnDefinition

        $definition.Width = if ($width -eq 'Auto') { [System.Windows.GridLength]::Auto }
                            else { [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }

        $header.ColumnDefinitions.Add($definition)
    }

    $chip = New-TkSeverityChip -Severity $Severity
    [System.Windows.Controls.Grid]::SetColumn($chip, 0)
    [void] $header.Children.Add($chip)

    $titleText = New-TkSelectableText -Value $Title
    $titleText.FontWeight        = [System.Windows.FontWeights]::SemiBold
    $titleText.FontSize          = 13.5
    $titleText.Margin            = New-Object System.Windows.Thickness(10, 0, 10, 0)
    $titleText.VerticalAlignment = [System.Windows.VerticalAlignment]::Center

    [System.Windows.Controls.Grid]::SetColumn($titleText, 1)
    [void] $header.Children.Add($titleText)

    if ($State) {

        $stateText = New-TkSelectableText -Value $State
        $stateText.FontSize          = 12
        $stateText.TextWrapping      = [System.Windows.TextWrapping]::NoWrap
        $stateText.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $stateText.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, 'TextMuted')

        [System.Windows.Controls.Grid]::SetColumn($stateText, 2)
        [void] $header.Children.Add($stateText)
    }

    [void] $stack.Children.Add($header)

    # --- Explanation ------------------------------------------------------
    if ($Detail) {

        $detailText = New-TkSelectableText -Value $Detail
        $detailText.FontSize = 12
        $detailText.Margin   = New-Object System.Windows.Thickness(0, 7, 0, 0)
        $detailText.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, 'TextMuted')

        [void] $stack.Children.Add($detailText)
    }

    # --- What to change, and the button that does it ----------------------
    if ($Action -or $RemediationId) {

        $band = New-Object System.Windows.Controls.Border
        $band.BorderThickness = New-Object System.Windows.Thickness(0, 1, 0, 0)
        $band.Padding         = New-Object System.Windows.Thickness(0, 9, 0, 0)
        $band.Margin          = New-Object System.Windows.Thickness(0, 9, 0, 0)
        $band.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')

        $bandGrid = New-Object System.Windows.Controls.Grid

        foreach ($width in @('Star', 'Auto')) {

            $definition = New-Object System.Windows.Controls.ColumnDefinition

            $definition.Width = if ($width -eq 'Auto') { [System.Windows.GridLength]::Auto }
                                else { [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }

            $bandGrid.ColumnDefinitions.Add($definition)
        }

        if ($Action) {

            $actionText = New-TkSelectableText -Value $Action
            $actionText.FontSize          = 12
            $actionText.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            $actionText.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, 'TextPrimary')

            [System.Windows.Controls.Grid]::SetColumn($actionText, 0)
            [void] $bandGrid.Children.Add($actionText)
        }

        $button = New-TkRemediationButton -RemediationId $RemediationId

        if ($button) {
            [System.Windows.Controls.Grid]::SetColumn($button, 1)
            [void] $bandGrid.Children.Add($button)
        }

        $band.Child = $bandGrid
        [void] $stack.Children.Add($band)
    }

    $container = New-Object System.Windows.Documents.BlockUIContainer($card)
    $container.Margin = New-Object System.Windows.Thickness(0)

    $Document.Blocks.Add($container)
}

<#
.SYNOPSIS
    Builds the coloured severity chip shown on a finding card.

.OUTPUTS
    System.Windows.Controls.Border
#>
function New-TkSeverityChip {
    [CmdletBinding()]
    [OutputType([System.Windows.Controls.Border])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Severity
    )

    $label = if ($Severity) { $Severity.ToUpperInvariant() } else { 'INFO' }

    $text = New-Object System.Windows.Controls.TextBlock
    $text.Text       = $label
    $text.FontSize   = 10
    $text.FontWeight = [System.Windows.FontWeights]::Bold
    $text.FontFamily = New-Object System.Windows.Media.FontFamily('Cascadia Mono, Consolas')
    $text.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center

    $text.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty,
                               (Get-TkSeverityBrushKey -Severity $Severity))

    $chip = New-Object System.Windows.Controls.Border
    $chip.CornerRadius      = New-Object System.Windows.CornerRadius(4)
    $chip.BorderThickness   = New-Object System.Windows.Thickness(1)
    $chip.Padding           = New-Object System.Windows.Thickness(7, 3, 7, 3)
    $chip.MinWidth          = 66
    $chip.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $chip.Child             = $text

    $chip.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty,
                               (Get-TkSeverityBrushKey -Severity $Severity))
    $chip.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SurfaceRaised')

    return $chip
}

<#
.SYNOPSIS
    Builds the button that applies a correction, or nothing when there is none.

.DESCRIPTION
    Returns $null when the identifier is empty or is not in the allow list, so
    a finding with no safe single step fix simply has no button rather than a
    button that does something approximate.

    The button is disabled, with the reason in its tooltip, when the
    correction needs rights this instance does not have.

.OUTPUTS
    System.Windows.Controls.Button, or $null.
#>
function New-TkRemediationButton {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $RemediationId
    )

    if ([string]::IsNullOrWhiteSpace($RemediationId)) {
        return $null
    }

    $table = Get-TkRemediationTable

    if (-not $table.ContainsKey($RemediationId)) {
        return $null
    }

    $entry = $table[$RemediationId]

    $button = New-Object System.Windows.Controls.Button
    $button.Content    = 'Fix this'
    $button.Tag        = $RemediationId
    $button.Margin     = New-Object System.Windows.Thickness(12, 0, 0, 0)
    $button.MinWidth   = 90
    $button.Cursor     = [System.Windows.Input.Cursors]::Hand
    $button.VerticalAlignment = [System.Windows.VerticalAlignment]::Center

    $button.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'PrimaryButton')

    if ($entry.Elevated -and -not (Test-TkIsElevated)) {

        $button.IsEnabled = $false
        $button.ToolTip   = 'Needs administrator rights. Use "Restart as administrator" in the header.'
    }
    else {
        $button.ToolTip = $entry.Explanation
    }

    $button.Add_Click({
        # Not named $sender or $eventArgs: both are automatic variables.
        param($clicked, $clickArgs)

        $id = [string] $clicked.Tag

        if ($id) {
            Invoke-TkRemediationFromUi -RemediationId $id
        }
    })

    return $button
}

<#
.SYNOPSIS
    Puts a document into a rich text control.

.DESCRIPTION
    Tolerates a missing control so a page that lost its box degrades instead
    of throwing.
#>
function Set-TkDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ControlName,

        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document
    )

    $control = Get-TkControl -Name $ControlName

    if ($null -eq $control) {
        return
    }

    $control.Document = $Document
    $control.ScrollToHome()
}
