<#
    Toolkit - UI / Main window

    Builds the window from XAML, registers every named control in the shared
    context and wires the navigation. Feature pages are initialised by their
    own files so this one stays about the shell only.
#>

# Set by the build script for the single file release. Empty during
# development, where the XAML is read from disk instead.
$script:TkEmbeddedXaml = ''

# Work a page wants done the first time it is opened, and the record of which
# pages have already been opened. Kept here rather than as a flag on each
# page so that adding one to a new page is a single Register call.
$script:TkFirstShowAction = @{}
$script:TkPageOpened      = @{}

<#
.SYNOPSIS
    Returns the main window XAML.

.DESCRIPTION
    Prefers the copy embedded at build time so a release has no external
    dependency, and falls back to the file next to the sources during
    development.

.OUTPUTS
    System.String
#>
function Get-TkMainWindowXaml {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not [string]::IsNullOrWhiteSpace($script:TkEmbeddedXaml)) {
        return $script:TkEmbeddedXaml
    }

    $candidates = @()

    if ($PSScriptRoot) {
        $candidates += (Join-Path -Path $PSScriptRoot -ChildPath 'MainWindow.xaml')
        $candidates += (Join-Path -Path $PSScriptRoot -ChildPath 'UI\MainWindow.xaml')
    }

    $candidates += (Join-Path -Path (Get-Location).Path -ChildPath 'src\UI\MainWindow.xaml')

    foreach ($candidate in $candidates) {

        if (Test-Path -LiteralPath $candidate) {
            return (Get-Content -LiteralPath $candidate -Raw -Encoding UTF8)
        }
    }

    throw 'MainWindow.xaml was not found and no XAML is embedded in this build.'
}

<#
.SYNOPSIS
    Creates the window and returns it.

.DESCRIPTION
    Parses the XAML, then walks every x:Name in the markup and stores the
    matching control in the context. Doing this once means page code can say
    $ctx.Controls['BtnRefresh'] instead of calling FindName everywhere.

.OUTPUTS
    System.Windows.Window
#>
function New-TkMainWindow {
    [CmdletBinding()]
    [OutputType([System.Windows.Window])]
    param()

    $ctx  = Get-TkContext
    $xaml = Get-TkMainWindowXaml

    try {
        $reader = New-Object System.Xml.XmlNodeReader ([xml] $xaml)
        $window = [Windows.Markup.XamlReader]::Load($reader)
    }
    catch {
        throw ('The interface could not be built from XAML: {0}' -f $_.Exception.Message)
    }

    $ctx.Window   = $window
    $ctx.Controls = @{}

    foreach ($match in [regex]::Matches($xaml, 'x:Name="(?<name>[^"]+)"')) {

        $name    = $match.Groups['name'].Value
        $control = $window.FindName($name)

        if ($null -ne $control) {
            $ctx.Controls[$name] = $control
        }
    }

    Write-TkLog -Level Debug -Category 'UI' -Message (
        '{0} named controls registered.' -f $ctx.Controls.Count
    )

    return $window
}

<#
.SYNOPSIS
    Returns a registered control by name.

.DESCRIPTION
    Returns $null rather than throwing when a control is missing, so a page
    that references a control removed from the XAML degrades instead of
    taking the whole window down.

.OUTPUTS
    System.Windows.DependencyObject
#>
function Get-TkControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    $ctx = Get-TkContext

    if ($ctx.Controls.ContainsKey($Name)) {
        return $ctx.Controls[$Name]
    }

    Write-TkLog -Level Debug -Category 'UI' -Message ('Unknown control "{0}".' -f $Name)

    return $null
}

<#
.SYNOPSIS
    Attaches a click handler to a button.

.DESCRIPTION
    Convenience wrapper that tolerates a missing control, which keeps page
    initialisation free of repeated null checks.
#>
function Register-TkClick {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [scriptblock] $Action
    )

    $control = Get-TkControl -Name $Name

    if ($null -eq $control) {
        return
    }

    $control.Add_Click($Action)
}

<#
.SYNOPSIS
    Finds the first descendant of a given type in a control's visual tree.

.DESCRIPTION
    For reaching an element that lives inside a template, where FindName
    cannot see it: the items panel of an ItemsControl is declared in an
    ItemsPanelTemplate and is not a named part of the window.

    Breadth first, so the nearest match wins rather than whichever branch is
    deepest. Returns nothing when there is no match, and when the control has
    not been laid out yet, which is the usual reason to find nothing.

.PARAMETER Parent
    Where to start.

.PARAMETER TypeName
    Short type name, for example UniformGrid.

.OUTPUTS
    System.Windows.DependencyObject, or $null.
#>
function Find-TkVisualChild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Windows.DependencyObject] $Parent,

        [Parameter(Mandatory)]
        [string] $TypeName
    )

    if ($null -eq $Parent) {
        return $null
    }

    $queue = New-Object 'System.Collections.Generic.Queue[System.Windows.DependencyObject]'
    $queue.Enqueue($Parent)

    while ($queue.Count -gt 0) {

        $current = $queue.Dequeue()
        $count   = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($current)

        for ($i = 0; $i -lt $count; $i++) {

            $child = [System.Windows.Media.VisualTreeHelper]::GetChild($current, $i)

            if ($child.GetType().Name -eq $TypeName) {
                return $child
            }

            $queue.Enqueue($child)
        }
    }

    return $null
}

<#
.SYNOPSIS
    Registers work to run the first time a page is opened.

.DESCRIPTION
    Some pages are only truthful once they have read the machine. The Software
    list is the clear case: until the installed packages have been read, every
    entry looks available, including the twenty already on the disk. Making
    the operator press Refresh to find that out puts the burden the wrong way
    round.

    The work runs on first open rather than at start up, because it costs a
    winget call and a page nobody visits should not pay for it.

.PARAMETER PageName
    Page key, as passed to Show-TkPage.

.PARAMETER Action
    Script block to run once.
#>
function Register-TkFirstShow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PageName,

        [Parameter(Mandatory)]
        [scriptblock] $Action
    )

    $script:TkFirstShowAction[$PageName] = $Action
}

<#
.SYNOPSIS
    Shows one feature page and hides the others.

.PARAMETER Name
    Page key: System, Software, Tweaks, Fixes, Network or Security.
#>
function Show-TkPage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Diagnostics', 'Security')]
        [string] $Name
    )

    $ctx = Get-TkContext

    foreach ($page in @('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Diagnostics', 'Security')) {

        $control = Get-TkControl -Name ('Page{0}' -f $page)

        if ($null -eq $control) {
            continue
        }

        if ($page -eq $Name) {
            $control.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $control.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }

    # Highlight the active navigation entry.
    foreach ($page in @('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Diagnostics', 'Security')) {

        $button = Get-TkControl -Name ('Nav{0}' -f $page)

        if ($null -eq $button) {
            continue
        }

        if ($page -eq $Name) {
            # Looked up on every call: a frozen brush captured once would keep
            # the palette that was active when the page was first shown.
            $button.Background = $ctx.Window.Resources['Selection']
            $button.FontWeight = [System.Windows.FontWeights]::SemiBold
        }
        else {
            $button.Background = [System.Windows.Media.Brushes]::Transparent
            $button.FontWeight = [System.Windows.FontWeights]::Normal
        }
    }

    $ctx.Settings['LastPage'] = $Name

    # First open only. The flag is set before the action runs, so an action
    # that throws does not queue itself again on the next visit.
    if (-not $script:TkPageOpened.ContainsKey($Name)) {

        $script:TkPageOpened[$Name] = $true

        if ($script:TkFirstShowAction.ContainsKey($Name)) {

            try {
                & $script:TkFirstShowAction[$Name]
            }
            catch {
                Write-TkLog -Level Warning -Category 'Interface' -Message (
                    'The {0} page could not finish its first load: {1}' -f $Name, $_.Exception.Message
                )
            }
        }
    }
}

<#
.SYNOPSIS
    Updates the status bar.

.PARAMETER Text
    Message to show.

.PARAMETER Busy
    Shows the indeterminate progress bar while an operation runs.
#>
function Set-TkStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [bool] $Busy = $false
    )

    $status = Get-TkControl -Name 'StatusText'
    $bar    = Get-TkControl -Name 'BusyBar'

    if ($status) {
        $status.Text = $Text
    }

    if ($bar) {
        $bar.Visibility = if ($Busy) { [System.Windows.Visibility]::Visible }
                          else       { [System.Windows.Visibility]::Hidden }
    }
}

<#
.SYNOPSIS
    Runs work off the UI thread and re-enables the interface when it returns.

.DESCRIPTION
    The single entry point every page uses for anything slow. It sets the
    busy state, queues the work, and restores the interface from the
    completion callback, which the task pump runs on the UI thread.

.PARAMETER ScriptBlock
    Work to run in the background runspace. Receives $ArgumentList.

.PARAMETER ArgumentList
    Positional values, scalars only. WPF objects must not cross the thread
    boundary.

.PARAMETER ParameterList
    Named parameters as a hashtable. The only safe way to pass a collection:
    a positional array is flattened by PowerShell before the call is made.

.PARAMETER OnComplete
    Runs on the UI thread with the task result.

.PARAMETER StatusText
    Message shown while the work runs.
#>
function Invoke-TkBackgroundAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [Parameter()]
        [object[]] $ArgumentList = @(),

        [Parameter()]
        [hashtable] $ParameterList,

        [Parameter()]
        [scriptblock] $OnComplete,

        [Parameter()]
        [string] $StatusText = 'Working...'
    )

    Set-TkStatus -Text $StatusText -Busy $true

    $wrapper = {
        param($result)

        Set-TkStatus -Text 'Ready.' -Busy $false

        if ($OnComplete) {
            & $OnComplete $result
        }
    }.GetNewClosure()

    $taskParameters = @{
        ScriptBlock  = $ScriptBlock
        ArgumentList = $ArgumentList
        OnComplete   = $wrapper
        Name         = $StatusText
    }

    if ($ParameterList) {
        $taskParameters['ParameterList'] = $ParameterList
    }

    Start-TkTask @taskParameters | Out-Null
}

<#
.SYNOPSIS
    Writes text into one of the page output boxes.

.PARAMETER ControlName
    Name of the target TextBox.

.PARAMETER Text
    Content to write.

.PARAMETER Append
    Adds to the existing content instead of replacing it.
#>
function Set-TkOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ControlName,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [switch] $Append
    )

    $control = Get-TkControl -Name $ControlName

    if ($null -eq $control) {
        return
    }

    if ($Append) {
        $control.AppendText($Text + [Environment]::NewLine)
        $control.ScrollToEnd()
    }
    else {
        $control.Text = $Text
    }
}

<#
.SYNOPSIS
    Renders objects as an aligned text table.

.DESCRIPTION
    Format-Table through Out-String, with a width wide enough that columns
    are not truncated the way they are at the default console width.

.OUTPUTS
    System.String
#>
function Format-TkTableText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return '(no result)'
    }

    $items = @($InputObject)

    if ($items.Count -eq 0) {
        return '(no result)'
    }

    return ($items | Format-Table -AutoSize | Out-String -Width 400).Trim()
}

<#
.SYNOPSIS
    Copies text to the clipboard.

.OUTPUTS
    System.Boolean
#>
function Set-TkClipboard {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $false
    }

    try {
        [System.Windows.Clipboard]::SetText($Text)
        return $true
    }
    catch {
        # The clipboard can be locked by another process for a moment.
        Write-TkLog -Level Warning -Category 'UI' -Message (
            'Clipboard unavailable: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Shows a confirmation dialog for an operation that changes the system.

.OUTPUTS
    System.Boolean
#>
function Confirm-TkAction {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [Parameter()]
        [string] $Title = 'Confirm'
    )

    return (Show-TkDialog -Title $Title -Message $Message -Kind 'Warning' `
                          -AcceptText 'Yes, do it' -RejectText 'Cancel')
}

<#
.SYNOPSIS
    Returns the icon character for a dialog of a given kind.

.OUTPUTS
    System.String
#>
function Get-TkDialogGlyph {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Kind
    )

    $glyphs = @{
        'Question'    = 0xE9CE  # question in a circle
        'Warning'     = 0xE7BA  # warning triangle
        'Information' = 0xE946  # information
        'Danger'      = 0xE783  # error
    }

    $point = if ($glyphs.ContainsKey($Kind)) { $glyphs[$Kind] } else { $glyphs['Information'] }

    return [string] [char] $point
}

<#
.SYNOPSIS
    Shows a modal dialog drawn in the application's own palette.

.DESCRIPTION
    Replaces the system message box. Three reasons it was worth replacing.

    It ignored the theme: a white box with black text in front of the dark
    window, every time. It could not be read from, because its text cannot be
    selected, and these dialogs list the exact tweaks or the exact adapter
    about to be changed. And its buttons said Yes and No, which say nothing
    about what is about to happen.

    Built in code rather than in MainWindow.xaml because it is a separate
    window: it borrows the main window's resource dictionary rather than
    copying it, which is what makes a theme change repaint it as well.

    Falls back to the system message box when there is no main window, so the
    function stays callable from a console session and from the tests.

.PARAMETER Title
    Shown in the title bar and as the heading.

.PARAMETER Message
    The body. Line breaks are kept, and the text can be selected and copied.

.PARAMETER Kind
    Question, Warning, Information or Danger. Sets the icon and its colour.

.PARAMETER AcceptText
    The affirmative button. Name the action rather than saying Yes.

.PARAMETER RejectText
    The dismissive button. Omitted entirely for a notice.

.PARAMETER NoticeOnly
    One button that dismisses. Always returns true.

.OUTPUTS
    System.Boolean. True when the accept button was pressed.
#>
function Show-TkDialog {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Message,

        [Parameter()]
        [ValidateSet('Question', 'Warning', 'Information', 'Danger')]
        [string] $Kind = 'Question',

        [Parameter()]
        [string] $AcceptText = 'Continue',

        [Parameter()]
        [string] $RejectText = 'Cancel',

        [Parameter()]
        [switch] $NoticeOnly
    )

    $ctx = Get-TkContext

    if ($null -eq $ctx.Window) {

        # No window to borrow a palette from, and nothing to own the dialog.
        $buttons = if ($NoticeOnly) { [System.Windows.MessageBoxButton]::OK }
                   else { [System.Windows.MessageBoxButton]::YesNo }

        $answer = [System.Windows.MessageBox]::Show($Message, $Title, $buttons)

        return ($answer -in @([System.Windows.MessageBoxResult]::Yes,
                              [System.Windows.MessageBoxResult]::OK))
    }

    $accepted = $false

    # --- Shell -----------------------------------------------------------
    $window = New-Object System.Windows.Window

    $window.Title  = $Title
    $window.Width  = 560
    $window.Owner  = $ctx.Window
    $window.SizeToContent         = [System.Windows.SizeToContent]::Height
    $window.ResizeMode            = [System.Windows.ResizeMode]::NoResize
    $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterOwner
    $window.ShowInTaskbar         = $false

    # The same dictionary instance, so a theme change reaches this too.
    $window.Resources = $ctx.Window.Resources
    $window.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'AppBackground')

    $layout = New-Object System.Windows.Controls.Grid
    $layout.Margin = New-Object System.Windows.Thickness(22, 20, 22, 18)

    foreach ($height in @('Auto', 'Auto')) {

        $row = New-Object System.Windows.Controls.RowDefinition
        $row.Height = [System.Windows.GridLength]::Auto

        $layout.RowDefinitions.Add($row)
    }

    # --- Icon and text ----------------------------------------------------
    $body = New-Object System.Windows.Controls.Grid

    foreach ($width in @('Auto', 'Star')) {

        $column = New-Object System.Windows.Controls.ColumnDefinition

        $column.Width = if ($width -eq 'Auto') { [System.Windows.GridLength]::Auto }
                        else { [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }

        $body.ColumnDefinitions.Add($column)
    }

    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.Text              = Get-TkDialogGlyph -Kind $Kind
    $icon.FontSize          = 26
    $icon.Margin            = New-Object System.Windows.Thickness(0, 1, 16, 0)
    $icon.VerticalAlignment = [System.Windows.VerticalAlignment]::Top

    $icon.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'IconFont')

    $iconKey = switch ($Kind) {
        'Warning'     { 'Warning' }
        'Danger'      { 'Danger' }
        'Question'    { 'Accent' }
        default       { 'Accent' }
    }

    $icon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $iconKey)

    [System.Windows.Controls.Grid]::SetColumn($icon, 0)
    [void] $body.Children.Add($icon)

    $stack = New-Object System.Windows.Controls.StackPanel
    [System.Windows.Controls.Grid]::SetColumn($stack, 1)

    $heading = New-Object System.Windows.Controls.TextBlock
    $heading.Text         = $Title
    $heading.FontSize     = 15
    $heading.FontWeight   = [System.Windows.FontWeights]::SemiBold
    $heading.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $heading.Margin       = New-Object System.Windows.Thickness(0, 0, 0, 8)

    $heading.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextPrimary')

    [void] $stack.Children.Add($heading)

    # Selectable, because these dialogs list the exact names about to change
    # and an operator writing a change record has to be able to copy them.
    $text = New-TkSelectableText -Value $Message
    $text.FontSize       = 13
    $text.AcceptsReturn  = $true
    $text.MaxHeight      = 320
    $text.VerticalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto

    [void] $stack.Children.Add($text)
    [void] $body.Children.Add($stack)

    [System.Windows.Controls.Grid]::SetRow($body, 0)
    [void] $layout.Children.Add($body)

    # --- Buttons ----------------------------------------------------------
    $bar = New-Object System.Windows.Controls.StackPanel
    $bar.Orientation         = [System.Windows.Controls.Orientation]::Horizontal
    $bar.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
    $bar.Margin              = New-Object System.Windows.Thickness(0, 20, 0, 0)

    if (-not $NoticeOnly) {

        $reject = New-Object System.Windows.Controls.Button
        $reject.Content   = $RejectText
        $reject.MinWidth  = 104
        $reject.IsCancel  = $true
        $reject.Margin    = New-Object System.Windows.Thickness(0, 0, 10, 0)

        $reject.Add_Click({
            param($clicked, $clickArgs)
            $clicked.Tag.DialogResult = $false
        })

        $reject.Tag = $window

        [void] $bar.Children.Add($reject)
    }

    $accept = New-Object System.Windows.Controls.Button
    $accept.Content   = if ($NoticeOnly) { 'Close' } else { $AcceptText }
    $accept.MinWidth  = 104
    $accept.IsDefault = $true
    $accept.Margin    = New-Object System.Windows.Thickness(0)
    $accept.Tag       = $window

    $accept.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'PrimaryButton')

    $accept.Add_Click({
        param($clicked, $clickArgs)
        $clicked.Tag.DialogResult = $true
    })

    [void] $bar.Children.Add($accept)

    [System.Windows.Controls.Grid]::SetRow($bar, 1)
    [void] $layout.Children.Add($bar)

    $window.Content = $layout

    # Focus the safe choice: Enter on a confirmation should not be the way a
    # destructive action gets run by someone who was typing.
    $window.Add_ContentRendered({
        param($shown, $renderArgs)
        $shown.MoveFocus((New-Object System.Windows.Input.TraversalRequest(
            [System.Windows.Input.FocusNavigationDirection]::First))) | Out-Null
    })

    $result = $window.ShowDialog()

    $accepted = ($result -eq $true)

    Write-TkLog -Level Debug -Category 'UI' -Message (
        'Dialog "{0}" answered {1}.' -f $Title, $(if ($accepted) { 'yes' } else { 'no' })
    )

    return $accepted
}

<#
.SYNOPSIS
    Shows a set of objects as a table in a window of its own.

.DESCRIPTION
    For answers that are a list rather than a value: the listening sockets,
    the routing table, the forwarding rules. Three things were wrong with
    where those used to go.

    Writing them to the console at the foot of the window hides them, because
    the console is collapsed by default. Writing them into another tab's
    output box moves the operator away from what they were doing, which is
    what the listening ports button did: it jumped to Diagnostics and left
    Adapters behind. And neither can be kept open beside the thing it
    explains.

    A window can. It is modeless on purpose, so several can be compared side
    by side, and it borrows the main window's resource dictionary rather than
    copying it, which is what makes a theme change repaint it too.

.PARAMETER Title
    Window title and heading.

.PARAMETER InputObject
    Rows. Any object with properties.

.PARAMETER Column
    Property names to show, in order. Taken from the first row when omitted.

.PARAMETER Description
    One line under the heading explaining what is being shown.

.PARAMETER EmptyText
    Shown instead of the table when there is nothing to list.
#>
function Show-TkTableWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $InputObject,

        [Parameter()]
        [string[]] $Column = @(),

        [Parameter()]
        [AllowEmptyString()]
        [string] $Description = '',

        [Parameter()]
        [string] $EmptyText = 'Nothing to show.'
    )

    $ctx = Get-TkContext

    if ($null -eq $ctx.Window) {
        return
    }

    $rows = ConvertTo-TkArray $InputObject

    # Take the shape from the data when the caller did not state it.
    if ($Column.Count -eq 0 -and $rows.Count -gt 0) {

        $Column = @(
            $rows[0].PSObject.Properties |
            Where-Object { $_.MemberType -eq 'NoteProperty' -or $_.MemberType -eq 'Property' } |
            Select-Object -ExpandProperty Name
        )
    }

    $document = New-TkFlowDocument

    Add-TkHeading -Document $document -Text $Title -Level 1

    if ($Description) {
        Add-TkParagraph -Document $document -Text $Description -Muted
    }

    if ($rows.Count -eq 0 -or $Column.Count -eq 0) {
        Add-TkParagraph -Document $document -Text $EmptyText -Muted
    }
    else {
        Add-TkTable -Document $document -Column $Column -Row (ConvertTo-TkTableRow $rows $Column)
    }

    $viewer = New-Object System.Windows.Controls.RichTextBox
    $viewer.Document        = $document
    $viewer.IsReadOnly      = $true
    $viewer.BorderThickness = New-Object System.Windows.Thickness(0)
    $viewer.Padding         = New-Object System.Windows.Thickness(18, 14, 18, 14)
    $viewer.VerticalScrollBarVisibility   = [System.Windows.Controls.ScrollBarVisibility]::Auto
    $viewer.HorizontalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Disabled

    $viewer.SetResourceReference([System.Windows.Controls.RichTextBox]::BackgroundProperty, 'AppBackground')
    $viewer.SetResourceReference([System.Windows.Controls.RichTextBox]::ForegroundProperty, 'TextPrimary')
    $viewer.SetResourceReference([System.Windows.Controls.Primitives.TextBoxBase]::SelectionBrushProperty, 'Accent')

    $window = New-Object System.Windows.Window

    $window.Title  = '{0} - {1}' -f $ctx.AppName, $Title
    $window.Width  = 940
    $window.Height = 620
    $window.Owner  = $ctx.Window
    $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterOwner
    $window.Content = $viewer

    # The same dictionary instance, not a copy: Set-TkTheme replaces the brush
    # objects inside it, so sharing it is what makes this window follow.
    $window.Resources = $ctx.Window.Resources

    $window.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'AppBackground')

    # Modeless, so two of these can be compared and the main window stays
    # usable behind them.
    $window.Show()

    Write-TkLog -Level Debug -Category 'Interface' -Message (
        'Opened the "{0}" table window with {1} row(s).' -f $Title, $rows.Count
    )
}

<#
.SYNOPSIS
    Wires the shell: header, navigation and window lifetime.
#>
function Initialize-TkShell {
    [CmdletBinding()]
    param()

    $ctx = Get-TkContext

    # --- Header -----------------------------------------------------------
    $version = Get-TkControl -Name 'HeaderVersion'

    if ($version) {
        $version.Text = 'v{0} ({1})' -f $ctx.Version, $ctx.Commit
    }

    $hostLabel = Get-TkControl -Name 'HeaderHost'

    if ($hostLabel) {
        $hostLabel.Text = '{0} - {1} - PowerShell {2}' -f $env:COMPUTERNAME, $ctx.OSCaption, $ctx.PSVersion
    }

    Initialize-TkThemeSelector
    Update-TkElevationBadge

    # --- Navigation -------------------------------------------------------
    foreach ($page in @('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Diagnostics', 'Security')) {

        $name = 'Nav{0}' -f $page

        # Capture the page name in a closure; without GetNewClosure every
        # handler would see the last value of the loop variable.
        $handler = {
            Show-TkPage -Name $page
        }.GetNewClosure()

        Register-TkClick -Name $name -Action $handler
    }

    # --- Shell buttons ----------------------------------------------------
    Register-TkClick -Name 'BtnElevate' -Action {

        if (Test-TkIsElevated) {
            Set-TkStatus -Text 'Already running as administrator.'
            return
        }

        $context = Get-TkContext

        if (Invoke-TkElevation -SourceUri $context.SourceUri -Confirm:$false) {
            $context.Window.Close()
        }
    }

    Register-TkClick -Name 'BtnOpenLogs' -Action {
        Start-Process -FilePath 'explorer.exe' -ArgumentList (Get-TkContext).LogRoot
    }

    Register-TkClick -Name 'BtnAbout' -Action {

        $ctx = Get-TkContext

        $message = @(
            '{0} {1} ({2})' -f $ctx.AppName, $ctx.Version, $ctx.Commit,
            '',
            'A toolkit for daily system, network and security work on Windows.',
            '',
            'Repository: {0}' -f $ctx.Repository,
            'Data folder: {0}' -f $ctx.DataRoot,
            '',
            'Read only features work as a standard user. Anything that changes',
            'the machine requires an elevated instance and is written to the log.'
        ) -join [Environment]::NewLine

        Show-TkDialog -Title 'About' -Message $message -Kind 'Information' -NoticeOnly | Out-Null
    }

    # --- Window lifetime --------------------------------------------------
    $ctx.Window.Add_Closing({

        Write-TkLog -Level Information -Category 'UI' -Message 'Closing.'

        Save-TkSettings -Confirm:$false
        Stop-TkThreading
    })
}

<#
.SYNOPSIS
    Disables the controls whose action cannot work without administrator
    rights, and says why.

.DESCRIPTION
    A button that looks available and then reports a refusal is worse than one
    that is plainly unavailable. Everything named here is disabled when the
    instance is not elevated, with the reason in its tooltip and the way out
    named: the restart button sits in the header.

    Only actions that strictly need elevation are listed. Applying tweaks is
    not, because several of them write to the current user hive and work
    perfectly well without it.
#>
function Update-TkPrivilegedControls {
    [CmdletBinding()]
    param()

    $elevated = Test-TkIsElevated

    # Software installation is deliberately absent from this list.
    #
    # winget is designed to run as the signed in user: Windows prompts for
    # rights per installer that needs them, and a package that installs into
    # the user profile needs none at all. Running winget from an elevated
    # toolkit is worse, not better. It suppresses those prompts, and when the
    # elevation used a different administrator account winget reads its
    # sources from that other profile, finds none, and reports every package
    # as not found. That is what "nothing installs at all" turned out to be.
    $controls = @{
        'BtnVendorTool'        = 'Installing the vendor firmware utility'
        'BtnRestorePoint'      = 'Creating a system restore point'
        'BtnAutoLogon'         = 'Configuring automatic logon'
        'BtnApplyProfile'      = 'Changing an adapter configuration'
        'BtnAddRoute'          = 'Adding a persistent route'
        'BtnRemoveRoute'       = 'Removing a route'
        'BtnAddProxy'          = 'Publishing a port'
        'BtnRemoveProxy'       = 'Removing a port proxy rule'
    }

    foreach ($name in $controls.Keys) {

        $control = Get-TkControl -Name $name

        if ($null -eq $control) {
            continue
        }

        $control.IsEnabled = $elevated

        $control.ToolTip = if ($elevated) { $controls[$name] }
                           else {
                               '{0} needs administrator rights. Use "Restart as administrator" at the top right.' -f $controls[$name]
                           }
    }

    Write-TkLog -Level Debug -Category 'UI' -Message (
        'Privileged controls {0}.' -f $(if ($elevated) { 'enabled' } else { 'disabled' })
    )
}

<#
.SYNOPSIS
    Updates the elevation badge in the header.

.DESCRIPTION
    The badge is the honest answer to "why is that button doing nothing":
    privileged features are disabled, not hidden, and the badge says why.
#>
function Update-TkElevationBadge {
    [CmdletBinding()]
    param()

    $ctx    = Get-TkContext
    $badge  = Get-TkControl -Name 'ElevationBadge'
    $text   = Get-TkControl -Name 'ElevationText'
    $button = Get-TkControl -Name 'BtnElevate'

    if (-not $text) {
        return
    }

    if ($ctx.IsElevated) {

        $text.Text = 'Administrator'

        if ($badge) {
            $badge.BorderBrush = $ctx.Window.Resources['Success']
        }

        if ($button) {
            $button.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }
    else {
        $text.Text = 'Standard user - system changes disabled'

        if ($badge) {
            $badge.BorderBrush = $ctx.Window.Resources['Warning']
        }
    }
}
