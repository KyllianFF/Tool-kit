<#
    Toolkit - Features / HTML documents for the editor

    The HTML editor works on a small model of a document, blocks holding runs
    of text, so that the conversion both ways can be tested without a window:

      - a block is a Paragraph, a Heading1 to Heading3, or a BulletList or
        NumberedList whose items are lists of runs;
      - a run is text with Bold, Italic, Underline and a Link, or a line break.

    The page turns a WPF document into this model and back; this file turns
    the model into HTML and HTML into the model. Reading HTML keeps only what
    the model can hold, which is also what makes it safe to paste: scripts,
    styles, event attributes and javascript: links do not survive.
#>

<#
.SYNOPSIS
    Creates a run of text, or a line break.
#>
function New-TkEditorInline {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Text = '',
        [Parameter()] [bool] $Bold = $false,
        [Parameter()] [bool] $Italic = $false,
        [Parameter()] [bool] $Underline = $false,
        [Parameter()] [AllowEmptyString()] [string] $Link = '',
        [Parameter()] [switch] $LineBreak
    )

    return [pscustomobject] @{
        Text      = $Text
        Bold      = $Bold
        Italic    = $Italic
        Underline = $Underline
        Link      = $Link
        LineBreak = [bool] $LineBreak
    }
}

<#
.SYNOPSIS
    Creates an empty block.
#>
function New-TkEditorBlock {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Paragraph', 'Heading1', 'Heading2', 'Heading3', 'BulletList', 'NumberedList')]
        [string] $Type
    )

    return [pscustomobject] @{
        Type    = $Type
        Inlines = New-Object System.Collections.Generic.List[object]
        Items   = New-Object System.Collections.Generic.List[object]
    }
}

<#
.SYNOPSIS
    Writes runs as HTML.

.DESCRIPTION
    Consecutive runs with the same link share one anchor, and the formatting
    tags of neighbouring runs are merged, so bold text split in two runs by
    the editor still comes out as one strong element.

.PARAMETER Inline
    The runs.

.OUTPUTS
    System.String
#>
function ConvertTo-TkHtmlInline {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Inline
    )

    $builder = New-Object System.Text.StringBuilder
    $index   = 0

    while ($index -lt $Inline.Count) {

        $link = [string] $Inline[$index].Link
        $end  = $index

        while ($end + 1 -lt $Inline.Count -and [string] $Inline[$end + 1].Link -eq $link) {
            $end++
        }

        $inner = New-Object System.Text.StringBuilder

        foreach ($piece in $Inline[$index..$end]) {

            if ($piece.LineBreak) {
                [void] $inner.Append('<br>')
                continue
            }

            $text = [System.Net.WebUtility]::HtmlEncode([string] $piece.Text)

            if ($piece.Underline) { $text = '<u>{0}</u>' -f $text }
            if ($piece.Italic)    { $text = '<em>{0}</em>' -f $text }
            if ($piece.Bold)      { $text = '<strong>{0}</strong>' -f $text }

            [void] $inner.Append($text)
        }

        $html = ((($inner.ToString() -replace '</strong><strong>', '') -replace '</em><em>', '') -replace '</u><u>', '')

        if ($link) {
            $html = '<a href="{0}">{1}</a>' -f [System.Net.WebUtility]::HtmlEncode($link), $html
        }

        [void] $builder.Append($html)
        $index = $end + 1
    }

    return $builder.ToString()
}

<#
.SYNOPSIS
    Writes a document model as HTML, one block per line.

.PARAMETER Block
    The blocks.

.OUTPUTS
    System.String
#>
function ConvertTo-TkHtmlDocument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Block
    )

    $tags = @{ Paragraph = 'p'; Heading1 = 'h1'; Heading2 = 'h2'; Heading3 = 'h3' }

    $lines = foreach ($item in $Block) {

        if ($item.Type -in @('BulletList', 'NumberedList')) {

            $tag = if ($item.Type -eq 'BulletList') { 'ul' } else { 'ol' }

            '<{0}>' -f $tag

            # ToArray rather than @(): wrapping a generic list held in an object
            # property with @() fails inside PowerShell with "Argument types do
            # not match", in Windows PowerShell 5.1 and PowerShell 7 alike.
            foreach ($entry in $item.Items) {
                '  <li>{0}</li>' -f (ConvertTo-TkHtmlInline -Inline $entry.ToArray())
            }

            '</{0}>' -f $tag
        }
        else {
            $content = ConvertTo-TkHtmlInline -Inline $item.Inlines.ToArray()

            if ($content) {
                '<{0}>{1}</{0}>' -f $tags[$item.Type], $content
            }
        }
    }

    return (@($lines) -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Reads HTML into a document model, keeping only what the model holds.

.PARAMETER Html
    The HTML, a whole page or a fragment.

.OUTPUTS
    PSCustomObject[], the blocks.
#>
function ConvertFrom-TkHtmlDocument {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Html
    )

    $options = [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

    $clean = [regex]::Replace($Html, '<!--.*?-->', '', $options)
    $clean = [regex]::Replace($clean, '<(script|style|head|title|template)\b[^>]*>.*?</\1\s*>', '', $options)

    $blocks = New-Object System.Collections.Generic.List[object]
    $state  = @{ Block = $null; List = $null; Item = $null; Bold = 0; Italic = 0; Underline = 0; Links = New-Object 'System.Collections.Generic.Stack[string]' }

    # Where text goes: the open list item, else the open block, else a new
    # paragraph.
    $target = {
        # Compared with null: an empty list is false, and a list item is
        # empty until its first text arrives.
        if ($null -ne $state.Item) { return , $state.Item }

        if (-not $state.Block) {
            $state.Block = New-TkEditorBlock -Type Paragraph
            $blocks.Add($state.Block)
        }

        return , $state.Block.Inlines
    }

    $tokens = [regex]::Matches($clean, '<(?<close>/?)(?<tag>[A-Za-z][A-Za-z0-9]*)\b(?<attributes>[^>]*)>|(?<text>[^<]+)')

    foreach ($token in $tokens) {

        if ($token.Groups['text'].Success) {

            $text = [System.Net.WebUtility]::HtmlDecode($token.Groups['text'].Value) -replace '\s+', ' '

            # Whitespace between blocks and between list items is layout, not text.
            if (-not $text.Trim() -and ((-not $state.Block -and $null -eq $state.Item) -or ($state.List -and $null -eq $state.Item))) {
                continue
            }

            $into = & $target
            $link = if ($state.Links.Count -gt 0) { $state.Links.Peek() } else { '' }

            $into.Add((New-TkEditorInline -Text $text -Bold ($state.Bold -gt 0) -Italic ($state.Italic -gt 0) -Underline ($state.Underline -gt 0) -Link $link))
            continue
        }

        $tag     = $token.Groups['tag'].Value.ToLowerInvariant()
        $closing = $token.Groups['close'].Value -eq '/'
        $change  = if ($closing) { -1 } else { 1 }

        switch -Regex ($tag) {

            '^(p|div|section|article|header|footer|main|aside|blockquote|pre|table|tr|td|th)$' {
                $state.Block = $null
            }

            '^h(?<level>[1-6])$' {
                $state.Block = $null

                if (-not $closing -and -not $state.List) {
                    $state.Block = New-TkEditorBlock -Type ('Heading{0}' -f [math]::Min(3, [int] $Matches['level']))
                    $blocks.Add($state.Block)
                }
            }

            '^(ul|ol)$' {
                $state.Block = $null
                $state.Item  = $null

                if ($closing) {
                    $state.List = $null
                }
                else {
                    $state.List = New-TkEditorBlock -Type $(if ($tag -eq 'ul') { 'BulletList' } else { 'NumberedList' })
                    $blocks.Add($state.List)
                }
            }

            '^li$' {
                if ($closing) {
                    $state.Item = $null
                }
                elseif ($state.List) {
                    $state.Item = New-Object System.Collections.Generic.List[object]
                    $state.List.Items.Add($state.Item)
                }
                else {
                    $state.Block = $null
                }
            }

            '^br$' {
                $into = & $target
                $into.Add((New-TkEditorInline -LineBreak))
            }

            '^(b|strong)$' { $state.Bold      = [math]::Max(0, $state.Bold + $change) }
            '^(i|em)$'     { $state.Italic    = [math]::Max(0, $state.Italic + $change) }
            '^u$'          { $state.Underline = [math]::Max(0, $state.Underline + $change) }

            '^a$' {
                if ($closing) {
                    if ($state.Links.Count -gt 0) { [void] $state.Links.Pop() }
                }
                else {
                    $href  = [regex]::Match($token.Groups['attributes'].Value, 'href\s*=\s*(?:"(?<v>[^"]*)"|''(?<v>[^'']*)''|(?<v>[^\s>]+))', 'IgnoreCase')
                    $value = [System.Net.WebUtility]::HtmlDecode($href.Groups['v'].Value).Trim()

                    # Only links that go somewhere: javascript: and data: do not.
                    if ($value -notmatch '^(?i)(https?:|mailto:|tel:|#|/)') {
                        $value = ''
                    }

                    $state.Links.Push($value)
                }
            }
        }
    }

    # Spaces at the edges of a block are layout; empty paragraphs are nothing.
    $trim = {
        param($runs)

        $texts = @($runs | Where-Object { -not $_.LineBreak })

        if ($texts.Count -gt 0) {
            $texts[0].Text  = $texts[0].Text.TrimStart()
            $texts[-1].Text = $texts[-1].Text.TrimEnd()
        }

        for ($position = $runs.Count - 1; $position -ge 0; $position--) {
            if (-not $runs[$position].LineBreak -and -not $runs[$position].Text) {
                $runs.RemoveAt($position)
            }
        }
    }

    foreach ($block in $blocks) {
        & $trim $block.Inlines
        foreach ($entry in $block.Items) { & $trim $entry }
    }

    return @($blocks | Where-Object { $_.Type -in @('BulletList', 'NumberedList') -or $_.Inlines.Count -gt 0 })
}
