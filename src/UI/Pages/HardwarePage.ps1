<#
    Toolkit - UI / Hardware page

    The interactive checks. Everything on the Diagnostics page reads the
    machine and reports; these ask the operator to look, listen and press,
    because that is the only way to answer "is this key dead".

    The keyboard test is the reason this page exists in the shape it does. It
    needs to see keys that Windows treats as commands, and it needs Windows
    not to act on them while it runs, which means a low level hook and a
    polling loop rather than the ordinary key events. See KeyboardHook.ps1.
#>

# Which keys have been seen, keyed by physical identity, and the blocks drawn
# for them. Held here rather than on the controls so the test survives a
# redraw: changing the layout rebuilds the board but keeps the results.
$script:TkKeyboardSeen    = @{}
$script:TkKeyboardButtons = @{}
$script:TkKeyboardPressed = @{}
$script:TkKeyboardRunning = $false
$script:TkKeyboardHandler = $null
$script:TkKeyboardHook    = $null
$script:TkKeyboardSource  = $null
$script:TkKeyboardLayout  = 'FR AZERTY (French)'
$script:TkLastEscape      = [datetime]::MinValue

<#
.SYNOPSIS
    Wires the Hardware page.
#>
function Initialize-TkHardwarePage {
    [CmdletBinding()]
    param()

    $chooser = Get-TkControl -Name 'HardwareChoices'

    if ($chooser) {

        $chooser.SelectedIndex = 0

        $chooser.Add_SelectionChanged({

            $list = Get-TkControl -Name 'HardwareChoices'

            if ($list) {
                Show-TkHardwarePanel -Index $list.SelectedIndex
            }
        })
    }

    # --- Keyboard ---------------------------------------------------------
    # No start button: the test runs as soon as its panel is open. Pressing a
    # key is the only thing it ever needed the operator to do.
    Register-TkClick -Name 'BtnKeyboardReset' -Action { Reset-TkKeyboardTest }

    $layoutBox = Get-TkControl -Name 'KeyboardLayout'

    if ($layoutBox) {

        foreach ($name in (Get-TkKeyboardLayoutName)) {
            [void] $layoutBox.Items.Add($name)
        }

        # Selected before the handler is attached, so filling the list does not
        # fire a redraw of a board that does not exist yet.
        $layoutBox.SelectedItem = $script:TkKeyboardLayout

        $layoutBox.Add_SelectionChanged({

            $box = Get-TkControl -Name 'KeyboardLayout'

            if ($box -and $box.SelectedItem) {

                $script:TkKeyboardLayout = [string] $box.SelectedItem

                # The board is redrawn, the results are not thrown away: the
                # identity of a key is its physical position, which does not
                # move when the legend changes.
                Build-TkKeyboardSurface
            }
        })
    }

    # --- Display ----------------------------------------------------------
    Register-TkClick -Name 'BtnDisplayColours'  -Action { Show-TkDisplayTest -Mode 'Colours' }
    Register-TkClick -Name 'BtnDisplayGradient' -Action { Show-TkDisplayTest -Mode 'Gradient' }
    Register-TkClick -Name 'BtnDisplayGrid'     -Action { Show-TkDisplayTest -Mode 'Grid' }

    # --- Sound ------------------------------------------------------------
    Register-TkClick -Name 'BtnToneLeft'  -Action { Invoke-TkToneFromUi -Channel 'Left' }
    Register-TkClick -Name 'BtnToneRight' -Action { Invoke-TkToneFromUi -Channel 'Right' }
    Register-TkClick -Name 'BtnToneBoth'  -Action { Invoke-TkToneFromUi -Channel 'Both' }
    Register-TkClick -Name 'BtnToneSweep' -Action { Invoke-TkToneSweepFromUi }

    # --- Battery ----------------------------------------------------------
    Register-TkClick -Name 'BtnBatteryRefresh' -Action { Update-TkBatteryPanel }
    Register-TkClick -Name 'BtnBatteryReport'  -Action { Invoke-TkBatteryReportFromUi }

    # --- Memory -----------------------------------------------------------
    Register-TkClick -Name 'BtnMemoryRefresh' -Action { Update-TkMemoryPanel }

    Register-TkClick -Name 'BtnMemoryDiagnostic' -Action {

        # mdsched asks its own question about when to restart, so the toolkit
        # does not need to and must not answer it on the operator's behalf.
        try {
            Start-Process -FilePath 'mdsched.exe' -ErrorAction Stop
            Set-TkStatus -Text 'The Windows memory tool is open. It will ask when to restart.'
        }
        catch {
            Set-TkStatus -Text ('The Windows memory tool could not be started: {0}' -f $_.Exception.Message)
        }
    }

    Build-TkKeyboardSurface

    # Reading modules and panels costs a WMI call each, so it waits until
    # somebody opens the page.
    Register-TkFirstShow -PageName 'Hardware' -Action {
        Update-TkMemoryPanel
        Update-TkBatteryPanel
        Update-TkAudioPanel
    }

    # The keyboard test follows the page, not the chooser. Hanging it off the
    # chooser's SelectionChanged meant it never started: the default panel is
    # selected before the handler is attached, so the event does not fire for
    # it, and coming back to the page does not change the selection either.
    Register-TkPageVisibility -PageName 'Hardware' -Action {
        param([bool] $Visible)

        if ($Visible) {

            $list  = Get-TkControl -Name 'HardwareChoices'
            $index = if ($list -and $list.SelectedIndex -ge 0) { $list.SelectedIndex } else { 0 }

            Show-TkHardwarePanel -Index $index
        }
        elseif ($script:TkKeyboardRunning) {
            Stop-TkKeyboardTest
        }
    }
}

<#
.SYNOPSIS
    Shows one hardware panel and hides the others.

.PARAMETER Index
    Position in the chooser list.
#>
function Show-TkHardwarePanel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int] $Index
    )

    $panels = @('Keyboard', 'Display', 'Sound', 'Battery', 'Memory')

    for ($i = 0; $i -lt $panels.Count; $i++) {

        $panel = Get-TkControl -Name ('Panel{0}' -f $panels[$i])

        if ($null -eq $panel) {
            continue
        }

        $panel.Visibility = if ($i -eq $Index) { [System.Windows.Visibility]::Visible }
                            else { [System.Windows.Visibility]::Collapsed }
    }

    # The keyboard test follows its panel. Leaving it while the handler is
    # attached would swallow every keystroke with nothing on screen saying why,
    # and asking the operator to press Start to begin a test they just opened
    # was a step that earned nothing.
    if ($Index -eq 0) {
        Start-TkKeyboardTest
    }
    elseif ($script:TkKeyboardRunning) {
        Stop-TkKeyboardTest
    }
}

<#
.SYNOPSIS
    Draws the virtual keyboard.

.DESCRIPTION
    Three blocks side by side, as on a real board: the main block, the
    navigation cluster and the numeric keypad. The earlier version stacked all
    three as plain rows, which read as a heap of keys rather than a keyboard.

    Each key is a bordered block with a thicker bottom edge, which is what
    gives it the look of a keycap seen slightly from above; pressing it
    collapses that edge and drops the block two pixels.

    Blocks are indexed by physical identity, not by label, so redrawing for
    another layout keeps every result: the same piece of plastic stays the same
    key whatever is printed on it.
#>
function Build-TkKeyboardSurface {
    [CmdletBinding()]
    param()

    $surface = Get-TkControl -Name 'KeyboardSurface'

    if ($null -eq $surface) {
        return
    }

    $surface.Children.Clear()
    $script:TkKeyboardButtons = @{}
    $script:TkKeyboardPressed = @{}

    $map = Get-TkKeyboardMap -Layout $script:TkKeyboardLayout

    $board = New-Object System.Windows.Controls.Grid

    foreach ($width in @(0, 1, 2)) {

        $column = New-Object System.Windows.Controls.ColumnDefinition
        $column.Width = [System.Windows.GridLength]::Auto

        $board.ColumnDefinitions.Add($column)
    }

    $blocks = @(
        @{ Rows = $map.Main;       Column = 0; Margin = 0 },
        @{ Rows = $map.Navigation; Column = 1; Margin = 18 },
        @{ Rows = $map.Numpad;     Column = 2; Margin = 12 }
    )

    foreach ($block in $blocks) {

        $stack = New-Object System.Windows.Controls.StackPanel
        $stack.Margin            = New-Object System.Windows.Thickness($block.Margin, 0, 0, 0)
        $stack.VerticalAlignment = [System.Windows.VerticalAlignment]::Top

        foreach ($row in $block.Rows) {
            [void] $stack.Children.Add((New-TkKeyboardRow -Row $row))
        }

        [System.Windows.Controls.Grid]::SetColumn($stack, $block.Column)
        [void] $board.Children.Add($stack)
    }

    [void] $surface.Children.Add($board)

    # Re-light whatever was already pressed. Rebuilding made fresh grey blocks,
    # and Set-TkKeySeen refuses a key it has already recorded, so without this
    # a layout change would grey out results that can never come back.
    foreach ($identity in $script:TkKeyboardSeen.Keys) {

        if ($script:TkKeyboardButtons.ContainsKey($identity)) {
            Set-TkKeyBlockSeen -Block $script:TkKeyboardButtons[$identity] -Animate $false
        }
    }

    Update-TkKeyboardProgress
}

<#
.SYNOPSIS
    Builds one row of keys.

.DESCRIPTION
    An empty row still produces a spacer of the usual height, which is what
    puts the gap above the arrow keys where a real board has one.

.OUTPUTS
    System.Windows.Controls.StackPanel
#>
function New-TkKeyboardRow {
    [CmdletBinding()]
    [OutputType([System.Windows.Controls.StackPanel])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row
    )

    $unit = 38

    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $panel.Margin      = New-Object System.Windows.Thickness(0, 0, 0, 4)
    $panel.Height      = $unit - 4

    foreach ($key in $Row) {

        $block = New-Object System.Windows.Controls.Border
        $block.Width        = ($unit * $key.Width) - 4
        $block.Height       = $unit - 4
        $block.CornerRadius = New-Object System.Windows.CornerRadius(4)
        $block.Margin       = New-Object System.Windows.Thickness(0, 0, 4, 0)

        # A thicker bottom edge reads as the side of a keycap. Collapsing it on
        # press is cheaper than a drop shadow on a hundred and five elements.
        $block.BorderThickness = New-Object System.Windows.Thickness(1, 1, 1, 3)

        Set-TkKeyBlockRest -Block $block

        # Held so the press animation has something to move.
        $block.RenderTransform = New-Object System.Windows.Media.TranslateTransform

        $text = New-Object System.Windows.Controls.TextBlock
        $text.Text                = $key.Label
        $text.FontSize            = if ($key.Label.Length -gt 3) { 9.5 } else { 12 }
        $text.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
        $text.VerticalAlignment   = [System.Windows.VerticalAlignment]::Center
        $text.TextTrimming        = [System.Windows.TextTrimming]::CharacterEllipsis

        $text.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextPrimary')

        $block.Child = $text

        [void] $panel.Children.Add($block)

        $script:TkKeyboardButtons[$key.Key] = $block
    }

    return $panel
}

<#
.SYNOPSIS
    Starts the keyboard test.

.DESCRIPTION
    Two attachments, each doing one job.

    A window message hook reads WM_KEYDOWN and WM_KEYUP for this window, which
    carry the scan code and the extended flag in lParam. That pair is the
    physical key: it does not move when the Windows layout changes, and it is
    the only thing that tells the keypad Enter from the main Enter, which the
    WPF Key enumeration reports as the same value.

    This is NOT a system wide hook. HwndSource.AddHook filters the window
    procedure of our own window: it sees only messages Windows has already
    delivered here, and nothing at all from any other application. That is a
    different mechanism from SetWindowsHookEx(WH_KEYBOARD_LL), which was
    removed in f472df9 for being indistinguishable from a keylogger.

    A PreviewKeyDown handler then marks each key handled, which keeps Tab from
    moving the focus and Space from pressing whatever button has it.
#>
function Start-TkKeyboardTest {
    [CmdletBinding()]
    param()

    if ($script:TkKeyboardRunning) {
        return
    }

    $ctx = Get-TkContext

    if ($null -eq $ctx.Window) {
        return
    }

    $script:TkKeyboardRunning = $true
    $script:TkLastEscape      = [datetime]::MinValue

    # --- The message hook, for physical identity --------------------------
    try {
        $handle = (New-Object System.Windows.Interop.WindowInteropHelper($ctx.Window)).Handle

        if ($handle -ne [IntPtr]::Zero) {

            $source = [System.Windows.Interop.HwndSource]::FromHwnd($handle)

            if ($source) {

                $hook = [System.Windows.Interop.HwndSourceHook] {
                    param($windowHandle, $message, $wordParam, $longParam, $alreadyHandled)

                    Update-TkKeyboardFromMessage -Message $message -WordParam $wordParam -LongParam $longParam

                    return [IntPtr]::Zero
                }

                $source.AddHook($hook)

                $script:TkKeyboardHook   = $hook
                $script:TkKeyboardSource = $source
            }
        }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Hardware' -Message (
            'The window message hook could not be attached, so the keypad Enter cannot be told from the main Enter: {0}' -f
                $_.Exception.Message
        )
    }

    # --- The WPF handler, only to keep keys inside the window -------------
    $handler = [System.Windows.Input.KeyEventHandler] {
        param($sourceControl, $keyArgs)

        $keyArgs.Handled = $true
    }

    $ctx.Window.AddHandler([System.Windows.UIElement]::PreviewKeyDownEvent, $handler, $true)

    $script:TkKeyboardHandler = $handler

    # The verdict belongs to the run that produced it.
    Set-TkOutput -ControlName 'KeyboardResult' -Text ''

    Update-TkKeyboardProgress

    Set-TkStatus -Text 'Keyboard test running. Press every key. Escape twice to stop.'
}

<#
.SYNOPSIS
    Stops the keyboard test and hands the keyboard back.
#>
function Stop-TkKeyboardTest {
    [CmdletBinding()]
    param()

    if (-not $script:TkKeyboardRunning) {
        return
    }

    $ctx = Get-TkContext

    if ($ctx.Window -and $script:TkKeyboardHandler) {

        $ctx.Window.RemoveHandler(
            [System.Windows.UIElement]::PreviewKeyDownEvent,
            $script:TkKeyboardHandler)
    }

    if ($script:TkKeyboardSource -and $script:TkKeyboardHook) {

        try {
            $script:TkKeyboardSource.RemoveHook($script:TkKeyboardHook)
        }
        catch {
            $null = $_
        }
    }

    # Any key still held when the test stops would stay visually depressed.
    foreach ($identity in @($script:TkKeyboardPressed.Keys)) {
        Set-TkKeyPressed -Identity $identity -Down $false
    }

    $script:TkKeyboardHandler = $null
    $script:TkKeyboardHook    = $null
    $script:TkKeyboardSource  = $null
    $script:TkKeyboardRunning = $false

    Update-TkKeyboardProgress

    Set-TkStatus -Text 'Keyboard test stopped.'
}

<#
.SYNOPSIS
    Forgets which keys have been pressed.
#>
function Reset-TkKeyboardTest {
    [CmdletBinding()]
    param()

    $script:TkKeyboardSeen    = @{}
    $script:TkKeyboardPressed = @{}

    foreach ($identity in $script:TkKeyboardButtons.Keys) {

        $block = $script:TkKeyboardButtons[$identity]

        Set-TkKeyBlockRest -Block $block

        # A key held across the reset would otherwise stay sunk for good.
        $block.RenderTransform.Y = 0
        $block.BorderThickness   = New-Object System.Windows.Thickness(1, 1, 1, 3)
    }

    Update-TkKeyboardProgress

    Set-TkOutput -ControlName 'KeyboardResult' -Text ''
}

<#
.SYNOPSIS
    Handles one keyboard window message.

.DESCRIPTION
    The scan code is in bits 16 to 23 of lParam and the extended flag in bit
    24. Together they name the physical key. Pause and Num Lock are the one
    pair that shares a scan code without either being extended, so the virtual
    key from wParam is tried first as a third part of the identity.

.PARAMETER Message
    The window message number.

.PARAMETER WordParam
    wParam, the virtual key.

.PARAMETER LongParam
    lParam, carrying the scan code and the extended flag.
#>
function Update-TkKeyboardFromMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int] $Message,

        [Parameter(Mandatory)]
        [AllowNull()]
        $WordParam,

        [Parameter(Mandatory)]
        [AllowNull()]
        $LongParam
    )

    $isDown = ($Message -eq 0x0100 -or $Message -eq 0x0104)   # WM_KEYDOWN, WM_SYSKEYDOWN
    $isUp   = ($Message -eq 0x0101 -or $Message -eq 0x0105)   # WM_KEYUP,   WM_SYSKEYUP

    if (-not ($isDown -or $isUp)) {
        return
    }

    # The test follows its panel. If the operator navigated away by any route,
    # stop rather than keep swallowing their keyboard.
    $panel = Get-TkControl -Name 'PanelKeyboard'

    if ($panel -and -not $panel.IsVisible) {
        Stop-TkKeyboardTest
        return
    }

    $bits       = [int64] $LongParam
    $scanCode   = [int] (($bits -shr 16) -band 0xFF)
    $extended   = [int] (($bits -shr 24) -band 0x01)
    $virtualKey = [int] $WordParam

    # An injected key, and some remote desktop and software keyboards, report
    # no physical position at all. Asking Windows which key produces this
    # virtual key recovers it; the extended flag is correct either way.
    if ($scanCode -eq 0) {
        $scanCode = Get-TkScanCodeForVirtualKey -VirtualKey $virtualKey
    }

    if ($scanCode -eq 0) {
        return
    }

    $identity = '{0}:{1}:{2}' -f $scanCode, $extended, $virtualKey

    if (-not $script:TkKeyboardButtons.ContainsKey($identity)) {
        $identity = '{0}:{1}' -f $scanCode, $extended
    }

    if ($isUp) {
        Set-TkKeyPressed -Identity $identity -Down $false
        return
    }

    Set-TkKeyPressed -Identity $identity -Down $true

    # Escape twice in quick succession is the way out. One press cannot be,
    # because Escape is a key the test has to cover.
    if ($virtualKey -eq 0x1B) {

        $now = Get-Date

        if (($now - $script:TkLastEscape).TotalMilliseconds -lt 1000) {

            Set-TkKeySeen -Identity $identity
            Stop-TkKeyboardTest
            return
        }

        $script:TkLastEscape = $now
    }

    Set-TkKeySeen -Identity $identity
}

<#
.SYNOPSIS
    Shows a key as held down, or lets it back up.

.DESCRIPTION
    A held key is filled orange and drops two pixels with its bottom edge
    collapsing, which is what a keycap does. The orange applies whether or not
    the key has already been validated: it answers "the board is reading the
    key under my finger", which is a different question from "has this key been
    covered", and a key that were already green would answer nothing.

    Letting go settles the key: green if it has been validated, back to the
    resting colour otherwise. That is why the fade to green happens here rather
    than in Set-TkKeySeen, which would be overpainted by the press.
#>
function Set-TkKeyPressed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Identity,

        [Parameter(Mandatory)]
        [bool] $Down
    )

    if (-not $script:TkKeyboardButtons.ContainsKey($Identity)) {
        return
    }

    $block = $script:TkKeyboardButtons[$Identity]

    if ($Down) {

        if ($script:TkKeyboardPressed.ContainsKey($Identity)) {
            return
        }

        $script:TkKeyboardPressed[$Identity] = $true

        $block.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Warning')
        $block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'Warning')

        $block.RenderTransform.Y = 2
        $block.BorderThickness   = New-Object System.Windows.Thickness(1, 1, 1, 1)

        return
    }

    $script:TkKeyboardPressed.Remove($Identity)

    $block.RenderTransform.Y = 0
    $block.BorderThickness   = New-Object System.Windows.Thickness(1, 1, 1, 3)

    if ($script:TkKeyboardSeen.ContainsKey($Identity)) {
        Set-TkKeyBlockSeen -Block $block -Animate $true
    }
    else {
        Set-TkKeyBlockRest -Block $block
    }
}

<#
.SYNOPSIS
    Paints one block as untested.

.DESCRIPTION
    Resource references rather than brushes, so a resting key follows a theme
    change. Only a validated or a held key is painted explicitly.
#>
function Set-TkKeyBlockRest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Controls.Border] $Block
    )

    $Block.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SurfaceRaised')
    $Block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')
}

<#
.SYNOPSIS
    Records a key as tested and colours it.
#>
function Set-TkKeySeen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Identity
    )

    if ($script:TkKeyboardSeen.ContainsKey($Identity)) {
        return
    }

    # A key the board does not draw: a media key, a vendor button, or a board
    # with more keys than a standard one. Worth recording rather than dropping,
    # because "this key sends something" is the answer.
    $script:TkKeyboardSeen[$Identity] = $true

    if (-not $script:TkKeyboardButtons.ContainsKey($Identity)) {
        return
    }

    # While the key is held it stays orange. Releasing it paints the green,
    # which is also what makes the fade visible instead of instantaneous.
    if (-not $script:TkKeyboardPressed.ContainsKey($Identity)) {
        Set-TkKeyBlockSeen -Block $script:TkKeyboardButtons[$Identity] -Animate $true
    }

    Update-TkKeyboardProgress
}

<#
.SYNOPSIS
    Paints one block as tested.

.DESCRIPTION
    Fades to the success colour over two hundred milliseconds when the key was
    just pressed, and switches straight to it when the board is being redrawn
    for another layout, where a hundred simultaneous fades would only look like
    a fault.

    A validated block gets a brush of its own rather than a resource reference,
    which is what makes the animation possible and what stops it following a
    later theme change. Redrawing the board repaints them from the current
    palette.
#>
function Set-TkKeyBlockSeen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Controls.Border] $Block,

        [Parameter()]
        [bool] $Animate = $true
    )

    $ctx = Get-TkContext

    $target = if ($ctx.Window) { $ctx.Window.Resources['Success'] } else { $null }

    if ($null -eq $target) {
        $Block.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Success')
        $Block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'Success')
        return
    }

    $Block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'Success')

    if (-not $Animate) {
        $Block.Background = $target
        return
    }

    # Read from the block rather than assumed, because the fade now starts
    # from the orange of a key being released, not only from the resting
    # colour. A new brush every time: animating the palette's own brush would
    # turn every surface in the window green.
    $from = if ($Block.Background -is [System.Windows.Media.SolidColorBrush]) {
                $Block.Background.Color
            }
            else {
                $target.Color
            }

    $brush = New-Object System.Windows.Media.SolidColorBrush($from)
    $Block.Background = $brush

    $fade = New-Object System.Windows.Media.Animation.ColorAnimation
    $fade.To       = $target.Color
    $fade.Duration = New-Object System.Windows.Duration ([TimeSpan]::FromMilliseconds(200))

    $brush.BeginAnimation([System.Windows.Media.SolidColorBrush]::ColorProperty, $fade)
}

<#
.SYNOPSIS
    Updates the counter and, when the test is over, the list of missing keys.
#>
function Update-TkKeyboardProgress {
    [CmdletBinding()]
    param()

    $total = $script:TkKeyboardButtons.Count

    if ($total -eq 0) {
        return
    }

    $missing = @()

    foreach ($identity in $script:TkKeyboardButtons.Keys) {

        if (-not $script:TkKeyboardSeen.ContainsKey($identity)) {
            $missing += $script:TkKeyboardButtons[$identity].Child.Text
        }
    }

    $seen = $total - $missing.Count

    Set-TkOutput -ControlName 'KeyboardProgress' -Text ('{0} of {1} keys' -f $seen, $total)

    if ($script:TkKeyboardRunning -or $seen -eq 0) {
        return
    }

    if ($missing.Count -eq 0) {

        Set-TkOutput -ControlName 'KeyboardResult' -Text (
            'Every key on the board registered. ' + ((Get-TkUntestableKeyNote)[0])
        )

        return
    }

    $names = @($missing | Sort-Object -Unique)

    # Stopping after two keys would otherwise list the hundred you had not got
    # to yet, which buries the two that matter.
    $shown = if ($names.Count -gt 24) {
                 '{0} and {1} more' -f (($names | Select-Object -First 24) -join ', '), ($names.Count - 24)
             }
             else {
                 $names -join ', '
             }

    Set-TkOutput -ControlName 'KeyboardResult' -Text (
        ('Not seen ({0}): {1}.' -f $names.Count, $shown) +
        ' A key that never registers is either faulty, remapped in the keyboard, or not present on this board. ' +
        ((Get-TkUntestableKeyNote)[0])
    )
}

<#
.SYNOPSIS
    Enables or disables a named control, tolerating a missing one.
#>
function Set-TkControlEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [bool] $Enabled
    )

    $control = Get-TkControl -Name $Name

    if ($control) {
        $control.IsEnabled = $Enabled
    }
}

<#
.SYNOPSIS
    Shows a full screen display test.

.DESCRIPTION
    A borderless window on top of everything, because a dead pixel under the
    task bar is still a dead pixel. Any key or click moves on, Escape leaves.

.PARAMETER Mode
    Colours, Gradient or Grid.
#>
function Show-TkDisplayTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Colours', 'Gradient', 'Grid')]
        [string] $Mode
    )

    $ctx = Get-TkContext

    $window = New-Object System.Windows.Window
    $window.WindowStyle           = [System.Windows.WindowStyle]::None
    $window.WindowState           = [System.Windows.WindowState]::Maximized
    $window.ResizeMode            = [System.Windows.ResizeMode]::NoResize
    $window.Topmost               = $true
    $window.ShowInTaskbar         = $false
    $window.Owner                 = $ctx.Window
    $window.Cursor                = [System.Windows.Input.Cursors]::None
    $window.Background            = [System.Windows.Media.Brushes]::Black

    $surface = New-Object System.Windows.Controls.Grid
    $window.Content = $surface

    $hint = New-Object System.Windows.Controls.TextBlock
    $hint.FontSize            = 13
    $hint.Margin              = New-Object System.Windows.Thickness(18)
    $hint.VerticalAlignment   = [System.Windows.VerticalAlignment]::Bottom
    $hint.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $hint.Foreground          = New-Object System.Windows.Media.SolidColorBrush(
                                    [System.Windows.Media.Color]::FromArgb(150, 128, 128, 128))

    $state = @{ Step = 0 }

    switch ($Mode) {

        'Colours' {

            $colours = @(
                @('White',   [System.Windows.Media.Colors]::White),
                @('Black',   [System.Windows.Media.Colors]::Black),
                @('Red',     [System.Windows.Media.Colors]::Red),
                @('Green',   [System.Windows.Media.Colors]::Lime),
                @('Blue',    [System.Windows.Media.Colors]::Blue),
                @('Grey 50', ([System.Windows.Media.Color]::FromRgb(128, 128, 128)))
            )

            $state.Colours = $colours

            $window.Background = New-Object System.Windows.Media.SolidColorBrush($colours[0][1])

            $hint.Text = '{0}. Any key or click for the next, Escape to leave.' -f $colours[0][0]
        }

        'Gradient' {

            $brush = New-Object System.Windows.Media.LinearGradientBrush
            $brush.StartPoint = New-Object System.Windows.Point(0, 0)
            $brush.EndPoint   = New-Object System.Windows.Point(1, 0)

            $brush.GradientStops.Add((New-Object System.Windows.Media.GradientStop(
                [System.Windows.Media.Colors]::Black, 0.0)))
            $brush.GradientStops.Add((New-Object System.Windows.Media.GradientStop(
                [System.Windows.Media.Colors]::White, 1.0)))

            $window.Background = $brush

            $hint.Text = 'Look for steps rather than a smooth ramp. Escape to leave.'
        }

        'Grid' {

            $window.Background = [System.Windows.Media.Brushes]::Black

            $drawing = New-Object System.Windows.Controls.Canvas
            [void] $surface.Children.Add($drawing)

            # Drawn on load, when the real size is known.
            $window.Add_ContentRendered({

                $drawing.Children.Clear()

                for ($x = 0; $x -lt $drawing.ActualWidth; $x += 32) {

                    $line = New-Object System.Windows.Shapes.Line
                    $line.X1 = $x; $line.X2 = $x
                    $line.Y1 = 0;  $line.Y2 = $drawing.ActualHeight
                    $line.Stroke = [System.Windows.Media.Brushes]::White
                    $line.StrokeThickness = 1

                    [void] $drawing.Children.Add($line)
                }

                for ($y = 0; $y -lt $drawing.ActualHeight; $y += 32) {

                    $line = New-Object System.Windows.Shapes.Line
                    $line.X1 = 0;  $line.X2 = $drawing.ActualWidth
                    $line.Y1 = $y; $line.Y2 = $y
                    $line.Stroke = [System.Windows.Media.Brushes]::White
                    $line.StrokeThickness = 1

                    [void] $drawing.Children.Add($line)
                }
            }.GetNewClosure())

            $hint.Text = 'Lines should be crisp and evenly spaced. Escape to leave.'
        }
    }

    [void] $surface.Children.Add($hint)

    $advance = {
        param($shown, $advanceArgs)

        if ($Mode -ne 'Colours') {
            $window.Close()
            return
        }

        $state.Step++

        if ($state.Step -ge $state.Colours.Count) {
            $window.Close()
            return
        }

        $entry = $state.Colours[$state.Step]

        $window.Background = New-Object System.Windows.Media.SolidColorBrush($entry[1])
        $hint.Text = '{0}. Any key or click for the next, Escape to leave.' -f $entry[0]

        # The caption has to stay legible on both ends of the range.
        $hint.Foreground = if ($entry[0] -eq 'White') {
                               New-Object System.Windows.Media.SolidColorBrush(
                                   [System.Windows.Media.Color]::FromArgb(150, 60, 60, 60))
                           }
                           else {
                               New-Object System.Windows.Media.SolidColorBrush(
                                   [System.Windows.Media.Color]::FromArgb(150, 128, 128, 128))
                           }
    }.GetNewClosure()

    $window.Add_KeyDown({
        param($shown, $keyArgs)

        if ($keyArgs.Key -eq [System.Windows.Input.Key]::Escape) {
            $window.Close()
            return
        }

        & $advance $shown $keyArgs
    }.GetNewClosure())

    $window.Add_MouseLeftButtonDown($advance)

    Write-TkLog -Level Information -Category 'Hardware' -Message ('Display test: {0}.' -f $Mode)

    $window.ShowDialog() | Out-Null
}

<#
.SYNOPSIS
    Plays one test tone and reports what to listen for.
#>
function Invoke-TkToneFromUi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Left', 'Right', 'Both')]
        [string] $Channel
    )

    Set-TkOutput -ControlName 'SoundStatus' -Text ('Playing the {0} channel...' -f $Channel.ToLowerInvariant())

    Invoke-TkBackgroundAction -StatusText ('Playing a tone: {0}...' -f $Channel) `
        -ParameterList @{ channel = $Channel } `
        -ScriptBlock {
            param($channel)

            return (Invoke-TkTonePlayback -Channel $channel)
        } `
        -OnComplete {
            param($result)

            $played = (@($result.Output) -contains $true)

            Set-TkOutput -ControlName 'SoundStatus' -Text $(
                if ($played) {
                    'Tone finished. If one channel is quieter or silent, that side is the problem: check the balance in Windows before blaming the speaker.'
                }
                else {
                    'The tone could not be played. Check that an output device is selected in Windows.'
                }
            )
        }
}

<#
.SYNOPSIS
    Plays a rising sweep.

.DESCRIPTION
    Steps through the range rather than gliding, because a stepped sweep makes
    it obvious which pitch a rattle starts at.
#>
function Invoke-TkToneSweepFromUi {
    [CmdletBinding()]
    param()

    Set-TkOutput -ControlName 'SoundStatus' -Text 'Sweeping from low to high...'

    Invoke-TkBackgroundAction -StatusText 'Playing a frequency sweep...' `
        -ScriptBlock {

            foreach ($frequency in @(120, 250, 500, 1000, 2000, 4000, 8000)) {
                $null = Invoke-TkTonePlayback -Channel 'Both' -Frequency $frequency
            }

            return $true
        } `
        -OnComplete {
            param($result)

            Set-TkOutput -ControlName 'SoundStatus' -Text (
                'Sweep finished: 120 Hz to 8 kHz in seven steps. A buzz at one step and not the others is ' +
                'usually a loose driver or a panel resonating, not the amplifier.'
            )
        }
}

<#
.SYNOPSIS
    Reads the battery and fills the panel.
#>
function Update-TkBatteryPanel {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the battery...' `
        -ScriptBlock { Get-TkBatteryState } `
        -OnComplete {
            param($result)

            $batteries = ConvertTo-TkArray $result.Output

            Set-TkObjectTable -ControlName 'DocBattery' -InputObject $batteries `
                -Property @('Name', 'Charge', 'Health', 'FullCapacity', 'DesignCapacity') `
                -Column   @('Battery', 'Charge', 'Health', 'Holds now', 'Built to hold') `
                -Weight   @(2.0, 0.8, 0.8, 1.2, 1.2) `
                -EmptyText 'No battery is present. This is a desktop, or the pack is not reporting.'

            Set-TkStatus -Text ('{0} batter(y/ies) reported.' -f $batteries.Count)
        }
}

<#
.SYNOPSIS
    Builds the Windows battery report and opens it.
#>
function Invoke-TkBatteryReportFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Building the battery report...' `
        -ScriptBlock { New-TkBatteryReport } `
        -OnComplete {
            param($result)

            $path = @($result.Output) | Where-Object { $_ } | Select-Object -Last 1

            if (-not $path) {
                Set-TkStatus -Text 'No battery report was produced. This machine has no battery.'
                return
            }

            Set-TkStatus -Text ('Battery report written to {0}' -f $path)

            try {
                Start-Process -FilePath $path -ErrorAction Stop
            }
            catch {
                Write-TkLog -Level Warning -Category 'Hardware' -Message (
                    'The report was written but could not be opened: {0}' -f $_.Exception.Message
                )
            }
        }
}

<#
.SYNOPSIS
    Reads the memory modules and the attached panels.
#>
function Update-TkMemoryPanel {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the memory modules...' `
        -ScriptBlock { Get-TkMemoryModule } `
        -OnComplete {
            param($result)

            $modules = ConvertTo-TkArray $result.Output

            Set-TkObjectTable -ControlName 'DocMemory' -InputObject $modules `
                -Property @('Slot', 'Capacity', 'Speed', 'Manufacturer', 'PartNumber') `
                -Column   @('Slot', 'Capacity', 'Speed', 'Maker', 'Part number') `
                -Weight   @(1.2, 0.9, 0.9, 1.2, 1.8) `
                -EmptyText 'The memory modules could not be read.'

            Set-TkStatus -Text ('{0} memory module(s).' -f $modules.Count)
        }

    Invoke-TkBackgroundAction -StatusText 'Reading the displays...' `
        -ScriptBlock { Get-TkDisplayPanel } `
        -OnComplete {
            param($result)

            Set-TkObjectTable -ControlName 'DocDisplays' -InputObject $result.Output `
                -Property @('Name', 'Manufacturer', 'Serial', 'Year') `
                -Column   @('Panel', 'Maker', 'Detail', 'Year') `
                -Weight   @(2.0, 1.2, 2.0, 0.6) `
                -EmptyText 'No display information was returned.'
        }
}

<#
.SYNOPSIS
    Lists the audio devices.
#>
function Update-TkAudioPanel {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the audio devices...' `
        -ScriptBlock { Get-TkAudioDevice } `
        -OnComplete {
            param($result)

            Set-TkObjectTable -ControlName 'DocAudio' -InputObject $result.Output `
                -Property @('Name', 'Manufacturer', 'Status') `
                -Column   @('Device', 'Maker', 'State') `
                -Weight   @(2.4, 1.4, 0.8) `
                -EmptyText 'No audio device was reported.'
        }
}
