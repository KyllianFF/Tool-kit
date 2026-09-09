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
    $document.Foreground      = Get-TkBrush -Key 'TextPrimary'
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
    Table. The FlowDocument Table accepts star widths and then ignores them:
    the port reference came out with one wide column and the rest squeezed to
    nothing, which is worse than no table at all.

    A Grid honours star sizing, wraps its cell text instead of truncating it,
    and takes a GridSplitter between columns, so a column can be widened by
    dragging its edge when a value is long.

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
    Search term to mark inside the cells.

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
    # The first column holds the value being looked up, a port or a prefix,
    # and stays narrow. The last takes the remaining width because it holds
    # the explanation.
    for ($i = 0; $i -lt $Column.Count; $i++) {

        # Not named $weight: PowerShell variable names are case insensitive,
        # so that would assign to the $Weight parameter itself and the second
        # column would size from whatever the first one wrote there.
        $columnWeight = if ($i -lt $Weight.Count) { $Weight[$i] }
                        elseif ($i -eq 0) { 0.8 }
                        elseif ($i -eq ($Column.Count - 1)) { 2.6 }
                        else { 1.4 }

        # The constructor is called directly rather than through New-Object.
        # New-Object resolves the overload from the runtime types of the
        # arguments, and a weight that arrived as an untyped object makes it
        # fail to find the two argument form.
        $definition = New-Object System.Windows.Controls.ColumnDefinition
        $definition.Width    = [System.Windows.GridLength]::new([double] $columnWeight, [System.Windows.GridUnitType]::Star)
        $definition.MinWidth = 48

        $grid.ColumnDefinitions.Add($definition)
    }

    # --- Rows -------------------------------------------------------------
    $headerRow = New-Object System.Windows.Controls.RowDefinition
    $headerRow.Height = [System.Windows.GridLength]::Auto
    $grid.RowDefinitions.Add($headerRow)

    foreach ($ignored in $Row) {

        $definition = New-Object System.Windows.Controls.RowDefinition
        $definition.Height = [System.Windows.GridLength]::Auto
        $grid.RowDefinitions.Add($definition)
    }

    $border     = Get-TkBrush -Key 'BorderSubtle'
    $headerFill = Get-TkBrush -Key 'SurfaceRaised'
    $muted      = Get-TkBrush -Key 'TextMuted'
    $primary    = Get-TkBrush -Key 'TextPrimary'

    # --- Header cells -----------------------------------------------------
    for ($i = 0; $i -lt $Column.Count; $i++) {

        $text = New-Object System.Windows.Controls.TextBlock
        $text.Text         = $Column[$i]
        $text.Foreground   = $muted
        $text.FontSize     = 12
        $text.FontWeight   = [System.Windows.FontWeights]::SemiBold
        $text.TextWrapping = [System.Windows.TextWrapping]::Wrap

        $cell = New-Object System.Windows.Controls.Border
        $cell.Background      = $headerFill
        $cell.BorderBrush     = $border
        $cell.BorderThickness = New-Object System.Windows.Thickness(0, 0, 1, 1)
        $cell.Padding         = New-Object System.Windows.Thickness(8, 6, 8, 6)
        $cell.Child           = $text

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

            $text = New-Object System.Windows.Controls.TextBlock
            $text.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $text.Foreground   = $primary
            $text.FontSize     = 12.5

            # The lookup key is monospaced so a column of ports lines up.
            if ($i -eq 0) {
                $text.FontFamily = New-Object System.Windows.Media.FontFamily('Cascadia Mono, Consolas')
                $text.FontWeight = [System.Windows.FontWeights]::SemiBold
            }

            foreach ($run in (New-TkTextRuns -Text $value -Highlight $Highlight)) {
                [void] $text.Inlines.Add($run)
            }

            $cell = New-Object System.Windows.Controls.Border
            $cell.BorderBrush     = $border
            $cell.BorderThickness = New-Object System.Windows.Thickness(0, 0, 1, 1)
            $cell.Padding         = New-Object System.Windows.Thickness(8, 5, 8, 5)
            $cell.Child           = $text

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
        $splitter.Width               = 5
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
