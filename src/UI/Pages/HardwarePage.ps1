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

# Which physical keys have been seen, keyed by "scanCode:extended", and the
# buttons drawn for them. Held here rather than on the controls so the test
# can be reset without rebuilding the keyboard.
$script:TkKeyboardSeen    = @{}
$script:TkKeyboardButtons = @{}
$script:TkKeyboardTimer   = $null
$script:TkKeyboardRunning = $false
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
    Register-TkClick -Name 'BtnKeyboardStart' -Action { Start-TkKeyboardTest }
    Register-TkClick -Name 'BtnKeyboardStop'  -Action { Stop-TkKeyboardTest }
    Register-TkClick -Name 'BtnKeyboardReset' -Action { Reset-TkKeyboardTest }

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

    # The keyboard must stop swallowing the moment this window is not the one
    # in front, whatever put it there. Without this, switching away by any
    # route that still works would take the keyboard with it.
    $ctx = Get-TkContext

    if ($ctx.Window) {

        $ctx.Window.Add_Deactivated({

            if ($script:TkKeyboardRunning) {

                Set-TkKeyboardSwallow -Enabled $false

                Set-TkStatus -Text 'Keyboard test paused: this window is no longer in front.'
            }
        })

        $ctx.Window.Add_Activated({

            if ($script:TkKeyboardRunning) {
                Set-TkKeyboardSwallow -Enabled $true
            }
        })
    }

    Build-TkKeyboardSurface

    # Reading modules and panels costs a WMI call each, so it waits until
    # somebody opens the page.
    Register-TkFirstShow -PageName 'Hardware' -Action {
        Update-TkMemoryPanel
        Update-TkBatteryPanel
        Update-TkAudioPanel
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

    # Leaving the keyboard panel while the hook is installed would leave the
    # keyboard swallowed with nothing on screen explaining why.
    if ($Index -ne 0 -and $script:TkKeyboardRunning) {
        Stop-TkKeyboardTest
    }
}

<#
.SYNOPSIS
    Draws the virtual keyboard.

.DESCRIPTION
    Built from the physical map, so the rows match the board rather than the
    layout. Each key is a bordered block indexed by its scan code and extended
    flag, which is the pair that identifies a physical key.
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

    $unit = 38

    foreach ($row in (Get-TkKeyboardMap)) {

        $panel = New-Object System.Windows.Controls.StackPanel
        $panel.Orientation = [System.Windows.Controls.Orientation]::Horizontal
        $panel.Margin      = New-Object System.Windows.Thickness(0, 0, 0, 4)

        foreach ($key in $row) {

            $block = New-Object System.Windows.Controls.Border
            $block.Width           = ($unit * $key.Width) - 4
            $block.Height          = $unit - 4
            $block.CornerRadius    = New-Object System.Windows.CornerRadius(4)
            $block.BorderThickness = New-Object System.Windows.Thickness(1)
            $block.Margin          = New-Object System.Windows.Thickness(0, 0, 4, 0)

            $block.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SurfaceRaised')
            $block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')

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

        [void] $surface.Children.Add($panel)
    }

    Update-TkKeyboardProgress
}

<#
.SYNOPSIS
    Starts the keyboard test.

.DESCRIPTION
    Installs the hook with suppression on, then polls it from a timer. Polling
    rather than an event keeps every interface change on the interface thread,
    which is the same rule the background task pump follows.
#>
function Start-TkKeyboardTest {
    [CmdletBinding()]
    param()

    if ($script:TkKeyboardRunning) {
        return
    }

    if (-not (Start-TkKeyboardCapture -Swallow)) {

        Set-TkStatus -Text 'The keyboard hook could not be installed. The test cannot run.'
        return
    }

    $script:TkKeyboardRunning = $true
    $script:TkLastEscape      = [datetime]::MinValue

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(40)
    $timer.Add_Tick({ Update-TkKeyboardFromHook })
    $timer.Start()

    $script:TkKeyboardTimer = $timer

    Set-TkControlEnabled -Name 'BtnKeyboardStart' -Enabled $false
    Set-TkControlEnabled -Name 'BtnKeyboardStop'  -Enabled $true

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

    if ($script:TkKeyboardTimer) {
        $script:TkKeyboardTimer.Stop()
        $script:TkKeyboardTimer = $null
    }

    Stop-TkKeyboardCapture

    $script:TkKeyboardRunning = $false

    Set-TkControlEnabled -Name 'BtnKeyboardStart' -Enabled $true
    Set-TkControlEnabled -Name 'BtnKeyboardStop'  -Enabled $false

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

    $script:TkKeyboardSeen = @{}

    foreach ($key in $script:TkKeyboardButtons.Keys) {

        $block = $script:TkKeyboardButtons[$key]

        $block.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SurfaceRaised')
        $block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderSubtle')
    }

    Update-TkKeyboardProgress

    Set-TkOutput -ControlName 'KeyboardResult' -Text ''
}

<#
.SYNOPSIS
    Drains the hook and marks the keys that were pressed.
#>
function Update-TkKeyboardFromHook {
    [CmdletBinding()]
    param()

    foreach ($keyEvent in (Receive-TkKeyboardEvent)) {

        if (-not $keyEvent.IsDown) {
            continue
        }

        # Escape twice in quick succession is the way out. One press cannot
        # be, because Escape is a key the test has to cover.
        if ($keyEvent.VirtualKey -eq 0x1B) {

            $now = Get-Date

            if (($now - $script:TkLastEscape).TotalMilliseconds -lt 1000) {

                Set-TkKeySeen -KeyEvent $keyEvent
                Stop-TkKeyboardTest
                return
            }

            $script:TkLastEscape = $now
        }

        Set-TkKeySeen -KeyEvent $keyEvent
    }
}

<#
.SYNOPSIS
    Colours one key as seen.
#>
function Set-TkKeySeen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $KeyEvent
    )

    $key = '{0}:{1}' -f $KeyEvent.ScanCode, [int] $KeyEvent.IsExtended

    if (-not $script:TkKeyboardButtons.ContainsKey($key)) {

        # A key the map does not draw: a media key, a vendor button, or a
        # board with more keys than a standard one. Worth recording rather
        # than dropping, because "this key sends something" is the answer.
        $script:TkKeyboardSeen[$key] = $true
        return
    }

    if ($script:TkKeyboardSeen.ContainsKey($key)) {
        return
    }

    $script:TkKeyboardSeen[$key] = $true

    $block = $script:TkKeyboardButtons[$key]

    $block.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Success')
    $block.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'Success')

    Update-TkKeyboardProgress
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

    foreach ($key in $script:TkKeyboardButtons.Keys) {

        if (-not $script:TkKeyboardSeen.ContainsKey($key)) {
            $missing += $script:TkKeyboardButtons[$key].Child.Text
        }
    }

    $seen = $total - $missing.Count

    Set-TkOutput -ControlName 'KeyboardProgress' -Text (
        '{0} of {1} keys seen.' -f $seen, $total
    )

    if ($script:TkKeyboardRunning) {
        return
    }

    if ($seen -eq 0) {
        Set-TkOutput -ControlName 'KeyboardResult' -Text ''
        return
    }

    if ($missing.Count -eq 0) {

        Set-TkOutput -ControlName 'KeyboardResult' -Text (
            'Every key on the map registered. ' + ((Get-TkUntestableKeyNote)[0])
        )

        return
    }

    Set-TkOutput -ControlName 'KeyboardResult' -Text (
        ('Not seen: {0}.' -f (($missing | Sort-Object -Unique) -join ', ')) +
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
