<#
    Toolkit - UI / Translating the window

    The markup is written in English. Once it is loaded, every text the
    dictionary knows is replaced by its translation, and the English is kept
    in the element's Uid: tabs are selected, choosers switch on their entry
    and the search finds a page by that English key, so the logic of the
    window reads the same in every language.

    The window is translated once, when it is built. A language chosen in
    Settings applies at the next start: the texts the pages write afterwards
    cannot be told from the markup's, and turning them back would mean
    guessing.
#>

<#
.SYNOPSIS
    Translates the texts of a window, or of any part of one, in place.

.DESCRIPTION
    Walks the logical tree: a TextBlock's text, a button's, a check box's or
    a list entry's content when it is text, a tab's or a group's header, a
    tooltip, the placeholder a text box holds in its Tag, and the window's
    title. Only exact texts of the dictionary are replaced, so a name, a
    value or a glyph is never touched.

.OUTPUTS
    System.Int32: how many texts were translated.
#>
function Set-TkWindowLanguage {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [System.Windows.DependencyObject] $Root,
        [Parameter()] [string] $Language = (Get-TkLanguage)
    )

    if ($null -eq $Root -or $Language -eq 'en' -or -not $PSCmdlet.ShouldProcess('the window', ('Show it in {0}' -f $Language))) {
        return 0
    }

    $count = 0
    $stack = New-Object 'System.Collections.Generic.Stack[System.Windows.DependencyObject]'
    $stack.Push($Root)

    $local = {
        param([string] $text)
        if ([string]::IsNullOrEmpty($text)) { return $null }
        $translated = ConvertTo-TkLocalText -Text $text -Exact -Language $Language
        if ($translated -ne $text) { return $translated }
        return $null
    }

    while ($stack.Count -gt 0) {

        $element = $stack.Pop()

        if ($element -is [System.Windows.Controls.TextBlock]) {
            $value = & $local ([string] $element.Text)
            if ($value) { if (-not $element.Uid) { $element.Uid = $element.Text }; $element.Text = $value; $count++ }
        }
        elseif ($element -is [System.Windows.Controls.HeaderedContentControl] -and $element.Header -is [string]) {
            $value = & $local $element.Header
            if ($value) { if (-not $element.Uid) { $element.Uid = $element.Header }; $element.Header = $value; $count++ }
        }
        elseif ($element -is [System.Windows.Controls.HeaderedItemsControl] -and $element.Header -is [string]) {
            $value = & $local $element.Header
            if ($value) { if (-not $element.Uid) { $element.Uid = $element.Header }; $element.Header = $value; $count++ }
        }
        elseif ($element -is [System.Windows.Controls.ContentControl] -and $element.Content -is [string] -and $element -isnot [System.Windows.Window]) {
            $value = & $local $element.Content
            if ($value) { if (-not $element.Uid) { $element.Uid = $element.Content }; $element.Content = $value; $count++ }
        }

        if ($element -is [System.Windows.Window]) {
            $value = & $local ([string] $element.Title)
            if ($value) { $element.Title = $value; $count++ }
        }

        if ($element -is [System.Windows.FrameworkElement]) {
            if ($element.ToolTip -is [string]) {
                $value = & $local $element.ToolTip
                if ($value) { $element.ToolTip = $value; $count++ }
            }
            if ($element -is [System.Windows.Controls.TextBox] -and $element.Tag -is [string]) {
                $value = & $local $element.Tag
                if ($value) { $element.Tag = $value; $count++ }
            }
        }

        foreach ($child in [System.Windows.LogicalTreeHelper]::GetChildren($element)) {
            if ($child -is [System.Windows.DependencyObject]) { $stack.Push($child) }
        }
    }

    return $count
}

<#
.SYNOPSIS
    The English text of an element, whatever language it is shown in.

.DESCRIPTION
    What the logic of the window compares: a tab's header, a list entry's
    title. The English kept in Uid when the element was translated, and the
    text shown otherwise.

.OUTPUTS
    System.String
#>
function Get-TkElementKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] $Element,
        [Parameter()] [AllowNull()] $Shown = $null
    )

    if ($Element -is [System.Windows.UIElement] -and $Element.Uid) {
        return [string] $Element.Uid
    }

    if ($null -ne $Shown) {
        return [string] $Shown
    }

    if ($Element -is [System.Windows.Controls.HeaderedContentControl]) { return [string] $Element.Header }
    if ($Element -is [System.Windows.Controls.ContentControl])         { return [string] $Element.Content }
    if ($Element -is [System.Windows.Controls.TextBlock])              { return [string] $Element.Text }

    return [string] $Element
}
