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
    Appends a real table to a document.

.DESCRIPTION
    A table, not aligned text. The port list is the reason this exists: as a
    run of prose, finding which service owns port 3268 means reading the whole
    thing.

.PARAMETER Column
    Column headings.

.PARAMETER Row
    Rows, each an array of cell values matching the columns.
#>
function Add-TkTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [string[]] $Column,

        [Parameter(Mandatory)]
        [object[]] $Row,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Highlight = ''
    )

    $table = New-Object System.Windows.Documents.Table
    $table.CellSpacing = 0
    $table.Margin      = New-Object System.Windows.Thickness(0, 0, 0, 14)

    # The first column is narrow because it holds the key being looked up, a
    # port or a prefix; the last takes the remaining width for the note.
    for ($i = 0; $i -lt $Column.Count; $i++) {

        $definition = New-Object System.Windows.Documents.TableColumn

        if ($i -eq 0) {
            $definition.Width = New-Object System.Windows.GridLength(90)
        }
        elseif ($i -lt ($Column.Count - 1)) {
            $definition.Width = New-Object System.Windows.GridLength(1.2, [System.Windows.GridUnitType]::Star)
        }
        else {
            $definition.Width = New-Object System.Windows.GridLength(2.4, [System.Windows.GridUnitType]::Star)
        }

        $table.Columns.Add($definition)
    }

    $border     = Get-TkBrush -Key 'BorderSubtle'
    $headerFill = Get-TkBrush -Key 'SurfaceRaised'

    # --- Header ----------------------------------------------------------
    $headerGroup = New-Object System.Windows.Documents.TableRowGroup
    $headerRow   = New-Object System.Windows.Documents.TableRow

    foreach ($heading in $Column) {

        $paragraph = New-Object System.Windows.Documents.Paragraph(
            (New-Object System.Windows.Documents.Run($heading))
        )

        $cell = New-Object System.Windows.Documents.TableCell($paragraph)
        $cell.Background      = $headerFill
        $cell.BorderBrush     = $border
        $cell.BorderThickness = New-Object System.Windows.Thickness(0, 0, 0, 1)
        $cell.Padding         = New-Object System.Windows.Thickness(8, 6, 8, 6)
        $cell.Foreground      = Get-TkBrush -Key 'TextMuted'
        $cell.FontWeight      = [System.Windows.FontWeights]::SemiBold
        $cell.FontSize        = 12

        $headerRow.Cells.Add($cell)
    }

    $headerGroup.Rows.Add($headerRow)
    $table.RowGroups.Add($headerGroup)

    # --- Body -------------------------------------------------------------
    $bodyGroup = New-Object System.Windows.Documents.TableRowGroup

    foreach ($values in $Row) {

        $tableRow = New-Object System.Windows.Documents.TableRow
        $index    = 0

        foreach ($value in @($values)) {

            $paragraph = New-Object System.Windows.Documents.Paragraph
            $paragraph.LineHeight = 17

            foreach ($run in (New-TkTextRuns -Text ([string] $value) -Highlight $Highlight)) {
                $paragraph.Inlines.Add($run)
            }

            $cell = New-Object System.Windows.Documents.TableCell($paragraph)
            $cell.BorderBrush     = $border
            $cell.BorderThickness = New-Object System.Windows.Thickness(0, 0, 0, 1)
            $cell.Padding         = New-Object System.Windows.Thickness(8, 5, 8, 5)

            # The lookup key is monospaced so a column of ports lines up.
            if ($index -eq 0) {
                $cell.FontFamily = New-Object System.Windows.Media.FontFamily('Cascadia Mono, Consolas')
                $cell.FontWeight = [System.Windows.FontWeights]::SemiBold
            }

            $tableRow.Cells.Add($cell)
            $index++
        }

        $bodyGroup.Rows.Add($tableRow)
    }

    $table.RowGroups.Add($bodyGroup)
    $Document.Blocks.Add($table)
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
