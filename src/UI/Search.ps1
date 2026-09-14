<#
    Toolkit - UI / Search

    One search box for the whole toolkit, opened with Ctrl+K or the button in
    the header. Twelve pages, their tabs and reports, 12 fixes, 35 tweaks,
    142 applications, 26 topics and 272 vendor commands are too many to find by
    walking the menu.

    The index is data: pages, tabs and list entries are read from the window
    markup, everything else from the catalogs and the quick action table, so a
    page, a report or a catalog entry added later is searchable without
    touching this file. Building the index and ranking the results need no
    window, which is what lets the tests assert them.
#>

$script:TkSearchIndex = $null

# What each chooser list holds, for the kind shown beside a result.
$script:TkSearchListKind = @{
    DiagnosticChoices = 'Report'
    HardwareChoices   = 'Hardware test'
    HuntChoices       = 'Investigation'
}

<#
.SYNOPSIS
    Builds one search entry.

.DESCRIPTION
    An entry says what to show and where it leads. Page, then TabControl and
    Tab, then SearchBox and SearchText, then List and Choice are applied in
    that order when it is opened. Action names a quick action instead.
#>
function New-TkSearchEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter()] [AllowEmptyString()] [string] $Detail = '',
        [Parameter()] [AllowEmptyString()] [string] $Page = '',
        [Parameter()] [AllowEmptyString()] [string] $TabControl = '',
        [Parameter()] [AllowEmptyString()] [string] $Tab = '',
        [Parameter()] [AllowEmptyString()] [string] $SearchBox = '',
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $SearchText = $null,
        [Parameter()] [AllowEmptyString()] [string] $List = '',
        [Parameter()] [AllowEmptyString()] [string] $Choice = '',
        [Parameter()] [AllowEmptyString()] [string] $Action = ''
    )

    return [pscustomobject] @{
        Title      = $Title
        Kind       = $Kind
        Detail     = $Detail
        Page       = $Page
        TabControl = $TabControl
        Tab        = $Tab
        SearchBox  = $SearchBox
        SearchText = $SearchText
        List       = $List
        Choice     = $Choice
        Action     = $Action
    }
}

<#
.SYNOPSIS
    Reads pages, tabs and chooser entries from the window markup.

.PARAMETER Markup
    The window XAML.

.OUTPUTS
    PSCustomObject[], as built by New-TkSearchEntry.
#>
function Get-TkMarkupSearchEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Markup
    )

    $xml       = [xml] $Markup
    $xamlSpace = 'http://schemas.microsoft.com/winfx/2006/xaml'

    $names = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $names.AddNamespace('p', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
    $names.AddNamespace('x', $xamlSpace)

    $entries = @()

    foreach ($page in @(Get-TkPageName)) {

        $button = $xml.SelectSingleNode(("//p:Button[@x:Name='Nav{0}']" -f $page), $names)
        $label  = if ($button -and $button.GetAttribute('Content')) { $button.GetAttribute('Content') } else { $page }

        $entries += New-TkSearchEntry -Title $label -Kind 'Page' -Page $page

        $panel = $xml.SelectSingleNode(("//*[@x:Name='Page{0}']" -f $page), $names)

        if ($null -eq $panel) {
            continue
        }

        foreach ($tab in $panel.SelectNodes('.//p:TabItem', $names)) {

            $control = $tab.ParentNode.GetAttribute('Name', $xamlSpace)

            $entries += New-TkSearchEntry -Title $tab.GetAttribute('Header') -Kind 'Tab' -Detail $label `
                                          -Page $page -TabControl $control -Tab $tab.GetAttribute('Header')
        }

        foreach ($list in $panel.SelectNodes('.//p:ListBox[p:ListBoxItem]', $names)) {

            $listName = $list.GetAttribute('Name', $xamlSpace)
            $kind     = if ($script:TkSearchListKind.ContainsKey($listName)) { $script:TkSearchListKind[$listName] } else { 'Entry' }

            $owner      = $list.SelectSingleNode('ancestor::p:TabItem[1]', $names)
            $tabHeader  = if ($owner) { $owner.GetAttribute('Header') } else { '' }
            $tabControl = if ($owner) { $owner.ParentNode.GetAttribute('Name', $xamlSpace) } else { '' }

            foreach ($item in $list.SelectNodes('p:ListBoxItem', $names)) {

                $text = $item.SelectSingleNode('.//p:TextBlock/@Text', $names)

                if ($null -eq $text) {
                    continue
                }

                $entries += New-TkSearchEntry -Title $text.Value -Kind $kind -Detail $item.GetAttribute('ToolTip') `
                                              -Page $page -TabControl $tabControl -Tab $tabHeader `
                                              -List $listName -Choice $text.Value
            }
        }
    }

    return $entries
}

<#
.SYNOPSIS
    Reads fixes, tweaks, applications, topics and vendor commands from the
    catalogs.

.OUTPUTS
    PSCustomObject[], as built by New-TkSearchEntry.
#>
function Get-TkCatalogSearchEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $entries = @()

    $fixes = Import-TkCatalog -Name 'fixes'

    foreach ($fix in @($fixes.fixes)) {
        $entries += New-TkSearchEntry -Title $fix.name -Kind 'Fix' -Detail ([string] $fix.whenToUse) -Page 'Fixes'
    }

    $tweaks = Import-TkCatalog -Name 'tweaks'

    foreach ($tweak in @($tweaks.tweaks)) {
        $entries += New-TkSearchEntry -Title $tweak.name -Kind 'Tweak' -Detail ([string] $tweak.description) `
                                      -Page 'Tweaks' -SearchBox 'TweakSearch' -SearchText $tweak.name
    }

    $applications = Import-TkCatalog -Name 'applications'

    foreach ($application in @($applications.applications)) {
        $entries += New-TkSearchEntry -Title $application.name -Kind 'Application' -Detail ([string] $application.description) `
                                      -Page 'Software' -SearchBox 'SoftwareSearch' -SearchText $application.name
    }

    # The topic list is filtered by its own search box, so it is cleared
    # before the topic is chosen.
    $knowledge = Import-TkCatalog -Name 'network-knowledge'

    foreach ($topic in @($knowledge.topics)) {
        $entries += New-TkSearchEntry -Title $topic.title -Kind 'Topic' -Detail ([string] $topic.summary) `
                                      -Page 'Knowledge' -TabControl 'KnowledgeTabs' -Tab 'Topics' `
                                      -SearchBox 'KnowledgeSearch' -SearchText '' `
                                      -List 'KnowledgeList' -Choice $topic.title
    }

    # A code or an event opens the Windows codes tab searched on it, on the row
    # of the list that names it.
    $errorCodes = Import-TkCatalog -Name 'windows-errors'

    foreach ($code in @($errorCodes.codes)) {
        $entries += New-TkSearchEntry -Title ([string] $code.code) -Kind 'Error code' `
                                      -Detail ((@([string] $code.name, [string] $code.meaning) | Where-Object { $_ }) -join ': ') `
                                      -Page 'Knowledge' -TabControl 'KnowledgeTabs' -Tab 'Windows codes' `
                                      -SearchBox 'ReferenceSearch' -SearchText ([string] $code.code) `
                                      -List 'ReferenceList' -Choice (Get-TkErrorCodeTitle -Hex ([string] $code.code) -Name ([string] $code.name) -Meaning ([string] $code.meaning))
    }

    $windowsEvents = Import-TkCatalog -Name 'windows-events'

    # Not $event: that name is an automatic variable of PowerShell.
    foreach ($windowsEvent in @($windowsEvents.events)) {
        $entries += New-TkSearchEntry -Title ('Event {0}, {1}' -f $windowsEvent.id, $windowsEvent.source) -Kind 'Event' `
                                      -Detail ('{0}: {1}' -f $windowsEvent.name, $windowsEvent.meaning) `
                                      -Page 'Knowledge' -TabControl 'KnowledgeTabs' -Tab 'Windows codes' `
                                      -SearchBox 'ReferenceSearch' -SearchText ([string] $windowsEvent.id) `
                                      -List 'ReferenceList' -Choice (Get-TkEventTitle -Entry $windowsEvent)
    }

    $vendors = Import-TkCatalog -Name 'vendor-commands'

    foreach ($vendor in @($vendors.vendors)) {
        foreach ($section in @($vendor.sections)) {
            foreach ($command in @($section.commands)) {

                $entries += New-TkSearchEntry -Title $command.command -Kind 'Command' `
                                              -Detail ('{0}, {1}: {2}' -f $vendor.name, $section.name, $command.description) `
                                              -Page 'VendorCommands' -SearchBox 'VendorSearch' -SearchText $command.command
            }
        }
    }

    return $entries
}

<#
.SYNOPSIS
    Returns the search index, built once and then reused.

.PARAMETER Markup
    The window XAML. Read from the build when omitted.

.PARAMETER Force
    Builds it again.
#>
function Get-TkSearchIndex {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [string] $Markup = '',

        [Parameter()]
        [switch] $Force
    )

    if ($script:TkSearchIndex -and -not $Force) {
        return $script:TkSearchIndex
    }

    if (-not $Markup) {
        $Markup = Get-TkMainWindowXaml
    }

    $entries = @(Get-TkMarkupSearchEntry -Markup $Markup) + @(Get-TkCatalogSearchEntry)

    if (Get-Command -Name 'Get-TkQuickAction' -ErrorAction SilentlyContinue) {

        foreach ($action in @(Get-TkQuickAction)) {
            $entries += New-TkSearchEntry -Title $action.Name -Kind 'Action' -Detail $action.Hint -Action $action.Id
        }
    }

    $script:TkSearchIndex = $entries

    return $entries
}

<#
.SYNOPSIS
    Finds and ranks the entries matching a query.

.DESCRIPTION
    Every word of the query has to appear in the title, the kind or the
    detail, in any order. A title that is the query, starts with it or has a
    word starting with it ranks first; then pages and tabs before reports,
    actions, fixes and tweaks, and those before the long lists of applications
    and commands, which would otherwise bury everything else.

.PARAMETER Index
    Output of Get-TkSearchIndex.

.PARAMETER Query
    What was typed.

.PARAMETER Limit
    How many results at most.

.OUTPUTS
    PSCustomObject[]
#>
function Find-TkSearchEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Index,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Query = '',

        [Parameter()]
        [ValidateRange(1, 500)]
        [int] $Limit = 40
    )

    $phrase = $Query.Trim().ToLowerInvariant()

    if (-not $phrase) {
        return @()
    }

    $words = @($phrase -split '\s+' | Where-Object { $_ })

    $boost = @{
        Page = 40; Tab = 30; Report = 25; 'Hardware test' = 25; Investigation = 25; Action = 20
        Fix = 15; Tweak = 10; Topic = 10; Entry = 10; Application = 5; Command = 0
    }

    $scored = foreach ($entry in $Index) {

        $title    = ([string] $entry.Title).ToLowerInvariant()
        $haystack = '{0} {1} {2}' -f $title, ([string] $entry.Kind).ToLowerInvariant(), ([string] $entry.Detail).ToLowerInvariant()

        if (@($words | Where-Object { -not $haystack.Contains($_) }).Count -gt 0) {
            continue
        }

        $score = if ($title -eq $phrase) { 1000 }
                 elseif ($title.StartsWith($phrase)) { 500 }
                 elseif ((' ' + $title).Contains(' ' + $phrase)) { 300 }
                 elseif ($title.Contains($phrase)) { 200 }
                 else { 0 }

        foreach ($word in $words) {
            $score += if ($title.Contains($word)) { 50 } else { 5 }
        }

        $score += [int] $boost[[string] $entry.Kind]

        [pscustomobject] @{ Entry = $entry; Score = $score }
    }

    return @($scored |
             Sort-Object -Property @{ Expression = 'Score'; Descending = $true },
                                   @{ Expression = { ([string] $_.Entry.Title).Length } },
                                   @{ Expression = { [string] $_.Entry.Title } } |
             Select-Object -First $Limit |
             ForEach-Object { $_.Entry })
}

<#
.SYNOPSIS
    Goes where a search result leads.

.PARAMETER Entry
    A search entry.
#>
function Open-TkSearchEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Entry
    )

    Hide-TkSearch

    if ($Entry.Action) {
        Invoke-TkQuickAction -Id $Entry.Action
        return
    }

    if ($Entry.Page) {
        Show-TkPage -Name $Entry.Page
    }

    if ($Entry.TabControl) {
        [void] (Select-TkTab -TabControlName $Entry.TabControl -Header $Entry.Tab)
    }

    # Null means leave the page search box alone; empty clears it.
    if ($Entry.SearchBox -and $null -ne $Entry.SearchText) {

        $box = Get-TkControl -Name $Entry.SearchBox

        if ($box) {
            $box.Text = $Entry.SearchText
        }
    }

    if ($Entry.List) {
        [void] (Select-TkListChoice -ListName $Entry.List -Title $Entry.Choice)
    }

    Set-TkStatus -Text ('{0}: {1}' -f $Entry.Kind, $Entry.Title)
}

<#
.SYNOPSIS
    Draws one result: its title, and its kind with the detail underneath.
#>
function New-TkSearchResultItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Entry
    )

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text       = $Entry.Title
    $title.FontSize   = 13
    $title.FontWeight = [System.Windows.FontWeights]::SemiBold
    $title.TextTrimming = [System.Windows.TextTrimming]::CharacterEllipsis
    $title.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextPrimary')

    $detail = New-Object System.Windows.Controls.TextBlock
    $detail.Text         = if ($Entry.Detail) { '{0}  -  {1}' -f $Entry.Kind, $Entry.Detail } else { $Entry.Kind }
    $detail.FontSize     = 11
    $detail.TextTrimming = [System.Windows.TextTrimming]::CharacterEllipsis
    $detail.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

    $stack = New-Object System.Windows.Controls.StackPanel
    [void] $stack.Children.Add($title)
    [void] $stack.Children.Add($detail)

    $item = New-Object System.Windows.Controls.ListBoxItem
    $item.Content = $stack
    $item.Tag     = $Entry

    return $item
}

<#
.SYNOPSIS
    Fills the result list for what is typed.

.DESCRIPTION
    With nothing typed, the pages are listed, so the palette is also a way to
    move around without the mouse.
#>
function Update-TkSearchResult {
    [CmdletBinding()]
    param()

    $searchBox   = Get-TkControl -Name 'SearchInput'
    $results = Get-TkControl -Name 'SearchResults'
    $hint    = Get-TkControl -Name 'SearchHint'

    if (-not $searchBox -or -not $results) {
        return
    }

    $index = @(Get-TkSearchIndex)
    $query = [string] $searchBox.Text

    $hits = if ($query.Trim()) { @(Find-TkSearchEntry -Index $index -Query $query) }
            else { @($index | Where-Object { $_.Kind -eq 'Page' }) }

    $results.Items.Clear()

    foreach ($hit in $hits) {
        [void] $results.Items.Add((New-TkSearchResultItem -Entry $hit))
    }

    if ($results.Items.Count -gt 0) {
        $results.SelectedIndex = 0
    }

    if ($hint) {
        $hint.Text = if (-not $query.Trim()) { 'Type to search. Up and down to choose, Enter to open, Escape to close.' }
                     elseif ($hits.Count -eq 0) { 'Nothing matches.' }
                     else { '{0} result(s). Enter opens the highlighted one.' -f $hits.Count }
    }
}

<#
.SYNOPSIS
    Opens the search palette.
#>
function Show-TkSearch {
    [CmdletBinding()]
    param()

    $overlay = Get-TkControl -Name 'SearchOverlay'
    $searchBox   = Get-TkControl -Name 'SearchInput'

    if (-not $overlay -or -not $searchBox) {
        return
    }

    $overlay.Visibility = [System.Windows.Visibility]::Visible
    $searchBox.Text = ''

    Update-TkSearchResult

    # Focus once the overlay has been laid out; a control that is still
    # collapsed when Focus is called does not take it.
    [void] $searchBox.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Input, [action] {
        $box = Get-TkControl -Name 'SearchInput'
        if ($box) { [void] $box.Focus() }
    })
}

<#
.SYNOPSIS
    Closes the search palette.
#>
function Hide-TkSearch {
    [CmdletBinding()]
    param()

    $overlay = Get-TkControl -Name 'SearchOverlay'

    if ($overlay) {
        $overlay.Visibility = [System.Windows.Visibility]::Collapsed
    }
}

<#
.SYNOPSIS
    Says whether the search palette is open.
#>
function Test-TkSearchOpen {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $overlay = Get-TkControl -Name 'SearchOverlay'

    return [bool] ($overlay -and $overlay.Visibility -eq [System.Windows.Visibility]::Visible)
}

<#
.SYNOPSIS
    Wires the search palette: the header button, Ctrl+K and the keys inside.
#>
function Initialize-TkSearch {
    [CmdletBinding()]
    param()

    $ctx = Get-TkContext

    Register-TkClick -Name 'BtnSearch' -Action { Show-TkSearch }

    $searchBox = Get-TkControl -Name 'SearchInput'

    if ($searchBox) {
        $searchBox.Add_TextChanged({ Update-TkSearchResult })
    }

    $results = Get-TkControl -Name 'SearchResults'

    if ($results) {
        $results.Add_MouseLeftButtonUp({
            $list = Get-TkControl -Name 'SearchResults'
            if ($list.SelectedItem -and $list.SelectedItem.Tag) {
                Open-TkSearchEntry -Entry $list.SelectedItem.Tag
            }
        })
    }

    $backdrop = Get-TkControl -Name 'SearchBackdrop'

    if ($backdrop) {
        $backdrop.Add_MouseLeftButtonDown({ Hide-TkSearch })
    }

    if ($null -eq $ctx.Window) {
        return
    }

    $ctx.Window.Add_PreviewKeyDown({
        param($window, $keyArgs)

        $control = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -ne 0

        # The keyboard test owns every key while it runs, Ctrl+K included.
        if ($control -and $keyArgs.Key -eq [System.Windows.Input.Key]::K -and -not $script:TkKeyboardRunning) {
            Show-TkSearch
            $keyArgs.Handled = $true
            return
        }

        if (-not (Test-TkSearchOpen)) {
            return
        }

        $list = Get-TkControl -Name 'SearchResults'

        switch ($keyArgs.Key) {

            ([System.Windows.Input.Key]::Escape) {
                Hide-TkSearch
                $keyArgs.Handled = $true
            }

            ([System.Windows.Input.Key]::Down) {
                if ($list.Items.Count -gt 0) {
                    $list.SelectedIndex = [math]::Min($list.SelectedIndex + 1, $list.Items.Count - 1)
                    $list.ScrollIntoView($list.SelectedItem)
                }
                $keyArgs.Handled = $true
            }

            ([System.Windows.Input.Key]::Up) {
                if ($list.Items.Count -gt 0) {
                    $list.SelectedIndex = [math]::Max($list.SelectedIndex - 1, 0)
                    $list.ScrollIntoView($list.SelectedItem)
                }
                $keyArgs.Handled = $true
            }

            ([System.Windows.Input.Key]::Enter) {
                if ($list.SelectedItem -and $list.SelectedItem.Tag) {
                    Open-TkSearchEntry -Entry $list.SelectedItem.Tag
                }
                $keyArgs.Handled = $true
            }
        }
    })
}
