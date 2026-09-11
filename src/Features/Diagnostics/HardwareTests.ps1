<#
    Toolkit - Features / Hardware tests

    The checks a technician does with their hands rather than with a report:
    is every key alive, does the panel have a dead pixel, does sound come out
    of both sides, does the battery still hold a charge.

    Everything here is read only or produces a file in the log folder. None of
    it changes the machine.
#>

<#
.SYNOPSIS
    Returns a French AZERTY (ISO) keyboard as rows of keys.

.DESCRIPTION
    A fixed French AZERTY layout: the AZERTY letter rows, the accented number
    row, the extra key between the left Shift and W that marks an ISO board,
    and the tall Enter. Drawn as this one layout rather than read from the
    machine, because the operators work on French keyboards and a board that
    matches the keycaps in front of them is the point.

    Each key carries its WPF Key name, which is what the key events hand the
    test to match against, and which is unique per physical key: the numeric
    keypad has keys of its own, distinct from the navigation cluster.

    Widths are in key units, where a normal key is 1.

.PARAMETER Compact
    Leaves out the numeric keypad, for the keyboards that have none.

.OUTPUTS
    An array of row objects, each holding an array of key objects.
#>
function Get-TkKeyboardMap {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [switch] $Compact
    )

    # A French AZERTY (ISO) keyboard, position for position: the AZERTY letter
    # rows, the number row that carries the accented characters, the extra
    # key between the left Shift and W that is the mark of an ISO board, and
    # the tall Enter. It is drawn as this one fixed layout rather than read
    # from the machine, because the tool's operators work on French keyboards
    # and a board that matches the keycaps in front of them is the point.
    #
    # Each cell is @(WPF key name, label, width in key units). Identity is the
    # WPF Key value, which is what the key events hand the test to match
    # against and which already tells the numeric keypad apart from the
    # navigation cluster: NumPad7 is not Home, Divide is not Oem2.
    #
    # The accented labels are built from character codes rather than written
    # as literals, so the file stays plain ASCII and reads the same under
    # Windows PowerShell and PowerShell 7 whatever the encoding.
    $super2 = [string][char]0x00B2   # superscript two, the top left key
    $eAcute = [string][char]0x00E9   # e acute
    $eGrave = [string][char]0x00E8   # e grave
    $cCedil = [string][char]0x00E7   # c cedilla
    $aGrave = [string][char]0x00E0   # a grave
    $uGrave = [string][char]0x00F9   # u grave

    # Each row is appended with the comma operator. Written as bare @(...)
    # literals one per line they are separate statements, so PowerShell
    # enumerates them into the outer array and the rows collapse into one
    # long list of key definitions.
    $rows = @()

    $rows += , @(
        @('Escape', 'Esc', 1.0), @('F1', 'F1', 1.0), @('F2', 'F2', 1.0),
        @('F3', 'F3', 1.0),  @('F4', 'F4', 1.0), @('F5', 'F5', 1.0),
        @('F6', 'F6', 1.0),  @('F7', 'F7', 1.0), @('F8', 'F8', 1.0),
        @('F9', 'F9', 1.0),  @('F10', 'F10', 1.0), @('F11', 'F11', 1.0),
        @('F12', 'F12', 1.0)
    )

    # Number row: the AZERTY top row, digits reached with Shift.
    $rows += , @(
        @('Oem7', $super2, 1.0), @('D1', '&', 1.0), @('D2', $eAcute, 1.0),
        @('D3', '"', 1.0), @('D4', "'", 1.0), @('D5', '(', 1.0),
        @('D6', '-', 1.0), @('D7', $eGrave, 1.0), @('D8', '_', 1.0),
        @('D9', $cCedil, 1.0), @('D0', $aGrave, 1.0), @('Oem4', ')', 1.0),
        @('OemPlus', '=', 1.0), @('Back', 'Backspace', 2.0)
    )

    # A Z E R T Y, then the circumflex dead key and the currency key.
    $rows += , @(
        @('Tab', 'Tab', 1.5), @('A', 'A', 1.0), @('Z', 'Z', 1.0),
        @('E', 'E', 1.0), @('R', 'R', 1.0), @('T', 'T', 1.0),
        @('Y', 'Y', 1.0), @('U', 'U', 1.0), @('I', 'I', 1.0),
        @('O', 'O', 1.0), @('P', 'P', 1.0), @('Oem6', '^', 1.0),
        @('Oem1', '$', 1.0)
    )

    # Q S D F G H J K L M, then u grave and the star key, then Enter.
    $rows += , @(
        @('CapsLock', 'Caps', 1.75), @('Q', 'Q', 1.0), @('S', 'S', 1.0),
        @('D', 'D', 1.0), @('F', 'F', 1.0), @('G', 'G', 1.0),
        @('H', 'H', 1.0), @('J', 'J', 1.0), @('K', 'K', 1.0),
        @('L', 'L', 1.0), @('M', 'M', 1.0), @('Oem3', $uGrave, 1.0),
        @('Oem5', '*', 1.0), @('Return', 'Enter', 1.75)
    )

    # The ISO row: a shorter left Shift, the extra < > key, then W X C V B N.
    $rows += , @(
        @('LeftShift', 'Shift', 1.25), @('Oem102', '<', 1.0), @('W', 'W', 1.0),
        @('X', 'X', 1.0), @('C', 'C', 1.0), @('V', 'V', 1.0),
        @('B', 'B', 1.0), @('N', 'N', 1.0), @('OemComma', ',', 1.0),
        @('OemPeriod', ';', 1.0), @('Oem2', ':', 1.0), @('Oem8', '!', 1.0),
        @('RightShift', 'Shift', 2.75)
    )

    $rows += , @(
        @('LeftCtrl', 'Ctrl', 1.25), @('LWin', 'Win', 1.25), @('LeftAlt', 'Alt', 1.25),
        @('Space', 'Space', 6.25), @('RightAlt', 'AltGr', 1.25), @('RWin', 'Win', 1.25),
        @('Apps', 'Menu', 1.25), @('RightCtrl', 'Ctrl', 1.25)
    )

    if (-not $Compact) {

        # The navigation cluster and the arrows, on their own rows so they sit
        # under the main block rather than beside it.
        $rows += , @(
            @('Insert', 'Ins', 1.0), @('Home', 'Home', 1.0), @('PageUp', 'PgUp', 1.0),
            @('Delete', 'Del', 1.0), @('End', 'End', 1.0), @('Next', 'PgDn', 1.0),
            @('Up', 'Up', 1.0), @('Left', 'Left', 1.0), @('Down', 'Down', 1.0),
            @('Right', 'Right', 1.0)
        )

        # The keypad. WPF gives these keys of their own, so they no longer
        # collide with the navigation cluster the way raw scan codes did.
        $rows += , @(
            @('NumLock', 'NumLk', 1.0), @('Divide', 'N /', 1.0), @('Multiply', 'N *', 1.0),
            @('Subtract', 'N -', 1.0), @('NumPad7', 'N 7', 1.0), @('NumPad8', 'N 8', 1.0),
            @('NumPad9', 'N 9', 1.0), @('Add', 'N +', 1.0), @('NumPad4', 'N 4', 1.0),
            @('NumPad5', 'N 5', 1.0), @('NumPad6', 'N 6', 1.0), @('NumPad1', 'N 1', 1.0),
            @('NumPad2', 'N 2', 1.0), @('NumPad3', 'N 3', 1.0), @('NumPad0', 'N 0', 1.0),
            @('Decimal', 'N .', 1.0)
        )
    }

    $result = @()

    foreach ($row in $rows) {

        $keys = @()

        foreach ($definition in $row) {

            $keys += [pscustomobject] @{
                KeyName = [string] $definition[0]
                Key     = [string] $definition[0]
                Label   = [string] $definition[1]
                Width   = [double] $definition[2]
            }
        }

        $result += , $keys
    }

    return , $result
}

<#
.SYNOPSIS
    Returns the keys a keyboard test can never observe.

.DESCRIPTION
    Ctrl+Alt+Delete is the secure attention sequence: Winlogon handles it on a
    separate desktop and no hook can see or block it. Saying so is better than
    letting those keys sit unticked and look broken.

.OUTPUTS
    System.String[]
#>
function Get-TkUntestableKeyNote {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'The Windows key, Alt+Tab and Ctrl+Alt+Delete are claimed by the Windows shell before any application sees them, so they open the Start menu or switch windows rather than registering here. This test reads keys only while its own window has focus, on purpose: capturing them system wide is what a keylogger does, and antivirus software blocks it.',
        'A Fn key is usually wired in the keyboard rather than sent to Windows, so it will not light up. The keys it modifies still will.',
        'Keys the keyboard remaps in its own firmware, such as a media layer, report as whatever they are remapped to.'
    )
}

<#
.SYNOPSIS
    Returns the display panels attached to this machine.

.OUTPUTS
    An array of objects describing each panel.
#>
function Get-TkDisplayPanel {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $panels = @()

    try {
        $monitors = @(Get-CimInstance -ClassName 'WmiMonitorID' -Namespace 'root\wmi' -ErrorAction Stop)
    }
    catch {
        $monitors = @()
    }

    foreach ($monitor in $monitors) {

        # These come back as arrays of character codes padded with zeros.
        $name         = ConvertTo-TkWmiString -Code $monitor.UserFriendlyName
        $manufacturer = ConvertTo-TkWmiString -Code $monitor.ManufacturerName
        $serial       = ConvertTo-TkWmiString -Code $monitor.SerialNumberID

        $panels += [pscustomobject] @{
            Name         = if ($name) { $name } else { 'Display' }
            Manufacturer = $manufacturer
            Serial       = $serial
            Year         = $monitor.YearOfManufacture
        }
    }

    # The resolution and refresh rate come from a different class.
    try {
        $modes = @(Get-CimInstance -ClassName 'Win32_VideoController' -ErrorAction Stop)
    }
    catch {
        $modes = @()
    }

    foreach ($mode in $modes) {

        if (-not $mode.CurrentHorizontalResolution) {
            continue
        }

        $panels += [pscustomobject] @{
            Name         = $mode.Name
            Manufacturer = $mode.AdapterCompatibility
            Serial       = '{0} x {1} at {2} Hz' -f
                             $mode.CurrentHorizontalResolution,
                             $mode.CurrentVerticalResolution,
                             $mode.CurrentRefreshRate
            Year         = ''
        }
    }

    return , $panels
}

<#
.SYNOPSIS
    Turns the zero padded character array WMI returns into a string.

.OUTPUTS
    System.String
#>
function ConvertTo-TkWmiString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Code
    )

    if ($null -eq $Code) {
        return ''
    }

    $characters = @($Code | Where-Object { $_ -gt 0 } | ForEach-Object { [char] $_ })

    return (-join $characters).Trim()
}

<#
.SYNOPSIS
    Returns the audio endpoints Windows can play through.

.OUTPUTS
    An array of device objects.
#>
function Get-TkAudioDevice {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $devices = @()

    try {
        $found = @(Get-CimInstance -ClassName 'Win32_SoundDevice' -ErrorAction Stop)
    }
    catch {
        $found = @()
    }

    foreach ($device in $found) {

        $devices += [pscustomobject] @{
            Name         = $device.Name
            Manufacturer = $device.Manufacturer
            Status       = $device.Status
            Working      = ($device.StatusInfo -eq 3 -or $device.Status -eq 'OK')
        }
    }

    return , $devices
}

<#
.SYNOPSIS
    Builds a WAV tone in memory and returns it as a stream.

.DESCRIPTION
    Written by hand rather than reached for through a library, because the
    point is to put sound in one channel at a time: a machine with a dead
    right speaker passes any test that plays the same thing on both.

    Sixteen bit stereo at 44100, which every Windows audio stack accepts.

.PARAMETER Channel
    Left, Right or Both.

.PARAMETER Frequency
    Hertz. 440 is a comfortable reference.

.PARAMETER Seconds
    How long to play.

.OUTPUTS
    System.IO.MemoryStream, positioned at the start.
#>
function New-TkToneStream {
    [CmdletBinding()]
    [OutputType([System.IO.MemoryStream])]
    param(
        [Parameter()]
        [ValidateSet('Left', 'Right', 'Both')]
        [string] $Channel = 'Both',

        [Parameter()]
        [ValidateRange(50, 15000)]
        [int] $Frequency = 440,

        [Parameter()]
        [ValidateRange(1, 10)]
        [double] $Seconds = 1.5
    )

    $sampleRate = 44100
    $channels   = 2
    $bits       = 16

    $frames    = [int] ($sampleRate * $Seconds)
    $dataBytes = $frames * $channels * ($bits / 8)

    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)

    # --- RIFF header ------------------------------------------------------
    $writer.Write([char[]] 'RIFF')
    $writer.Write([int] (36 + $dataBytes))
    $writer.Write([char[]] 'WAVE')

    $writer.Write([char[]] 'fmt ')
    $writer.Write([int] 16)
    $writer.Write([int16] 1)                                        # PCM
    $writer.Write([int16] $channels)
    $writer.Write([int] $sampleRate)
    $writer.Write([int] ($sampleRate * $channels * ($bits / 8)))    # byte rate
    $writer.Write([int16] ($channels * ($bits / 8)))                # block align
    $writer.Write([int16] $bits)

    $writer.Write([char[]] 'data')
    $writer.Write([int] $dataBytes)

    # --- Samples ----------------------------------------------------------
    $amplitude = 9000
    $step      = 2 * [Math]::PI * $Frequency / $sampleRate

    # A short fade at each end. A tone that starts at full amplitude clicks,
    # and a click is exactly the kind of artefact this test is looking for.
    $fade = [int] ($sampleRate * 0.02)

    for ($i = 0; $i -lt $frames; $i++) {

        $envelope = 1.0

        if ($i -lt $fade) {
            $envelope = $i / $fade
        }
        elseif ($i -gt ($frames - $fade)) {
            $envelope = ($frames - $i) / $fade
        }

        $value = [int16] ($amplitude * $envelope * [Math]::Sin($step * $i))

        $left  = if ($Channel -eq 'Right') { [int16] 0 } else { $value }
        $right = if ($Channel -eq 'Left')  { [int16] 0 } else { $value }

        $writer.Write($left)
        $writer.Write($right)
    }

    $writer.Flush()
    $stream.Position = 0

    return $stream
}

<#
.SYNOPSIS
    Plays a test tone through the default output.

.PARAMETER Channel
    Left, Right or Both.

.OUTPUTS
    System.Boolean
#>
function Invoke-TkTonePlayback {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [ValidateSet('Left', 'Right', 'Both')]
        [string] $Channel = 'Both',

        [Parameter()]
        [ValidateRange(50, 15000)]
        [int] $Frequency = 440
    )

    try {
        $stream = New-TkToneStream -Channel $Channel -Frequency $Frequency

        $player = New-Object System.Media.SoundPlayer($stream)

        # Synchronous, so the caller knows when it finished and the operator
        # is not asked about a sound that is still playing.
        $player.PlaySync()
        $player.Dispose()
        $stream.Dispose()

        Write-TkLog -Level Information -Category 'Hardware' -Message (
            'Played a {0} Hz tone on the {1} channel.' -f $Frequency, $Channel.ToLowerInvariant()
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Hardware' -Message (
            'The test tone could not be played: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Produces the Windows battery report and returns where it was written.

.DESCRIPTION
    powercfg builds the report itself, and it is the one worth having: design
    capacity against what the pack now holds, the charge cycles, and the
    recent drain history. Nothing else on the machine has that.

    Returns nothing on a desktop, which is the correct answer rather than an
    error.

.OUTPUTS
    System.String, the path to the report, or $null.
#>
function New-TkBatteryReport {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $batteries = @()

    try {
        $batteries = @(Get-CimInstance -ClassName 'Win32_Battery' -ErrorAction Stop)
    }
    catch {
        $batteries = @()
    }

    if ($batteries.Count -eq 0) {

        Write-TkLog -Level Information -Category 'Hardware' -Message (
            'No battery is present, so there is no battery report to produce.'
        )

        return $null
    }

    $ctx    = Get-TkContext
    $folder = Join-Path -Path $ctx.LogRoot -ChildPath 'reports'

    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $path = Join-Path -Path $folder -ChildPath (
        'battery-{0}.html' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    )

    $result = Invoke-TkProcess -FilePath 'powercfg' `
                               -ArgumentList @('/batteryreport', '/output', $path) `
                               -TimeoutSeconds 120

    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $path)) {

        Write-TkLog -Level Error -Category 'Hardware' -Message (
            'powercfg could not write the battery report: {0}' -f
                (Get-TkFirstLine -Text ($result.StandardError + $result.StandardOutput))
        )

        return $null
    }

    Write-TkLog -Level Information -Category 'Hardware' -Message ('Battery report written to {0}' -f $path)

    return $path
}

<#
.SYNOPSIS
    Returns what the battery currently reports.

.OUTPUTS
    An array of battery objects, empty on a desktop.
#>
function Get-TkBatteryState {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $result = @()

    try {
        $batteries = @(Get-CimInstance -ClassName 'Win32_Battery' -ErrorAction Stop)
    }
    catch {
        return , $result
    }

    # Design and full charge capacity live in a different namespace, and it is
    # the ratio between them that says whether a pack is worn out.
    $static = @{}

    try {
        foreach ($entry in @(Get-CimInstance -ClassName 'BatteryStaticData' -Namespace 'root\wmi' -ErrorAction Stop)) {
            $static[$entry.InstanceName] = $entry
        }
    }
    catch {
        $static = @{}
    }

    $fullCharge = @{}

    try {
        foreach ($entry in @(Get-CimInstance -ClassName 'BatteryFullChargedCapacity' -Namespace 'root\wmi' -ErrorAction Stop)) {
            $fullCharge[$entry.InstanceName] = $entry.FullChargedCapacity
        }
    }
    catch {
        $fullCharge = @{}
    }

    foreach ($battery in $batteries) {

        $design  = $null
        $current = $null

        foreach ($key in $static.Keys) {
            $design = $static[$key].DesignedCapacity
            break
        }

        foreach ($key in $fullCharge.Keys) {
            $current = $fullCharge[$key]
            break
        }

        $health = ''

        if ($design -and $current -and $design -gt 0) {
            $health = '{0} %' -f [math]::Round(($current / $design) * 100, 0)
        }

        $result += [pscustomobject] @{
            Name           = $battery.Name
            Charge         = if ($null -ne $battery.EstimatedChargeRemaining) {
                                 '{0} %' -f $battery.EstimatedChargeRemaining
                             } else { '' }
            DesignCapacity = if ($design)  { '{0} mWh' -f $design }  else { '' }
            FullCapacity   = if ($current) { '{0} mWh' -f $current } else { '' }
            Health         = $health
        }
    }

    return , $result
}

<#
.SYNOPSIS
    Returns the installed memory modules.

.DESCRIPTION
    The slot by slot view, which is what a technician needs: a machine that
    reports less memory than it has usually has one module seated badly, and
    a machine running slowly sometimes has two modules of different speeds.

.OUTPUTS
    An array of module objects.
#>
function Get-TkMemoryModule {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $modules = @()

    try {
        $found = @(Get-CimInstance -ClassName 'Win32_PhysicalMemory' -ErrorAction Stop)
    }
    catch {
        return , $modules
    }

    foreach ($module in $found) {

        $modules += [pscustomobject] @{
            Slot         = $module.DeviceLocator
            Capacity     = Format-TkBytes -Bytes ([double] $module.Capacity)
            Speed        = if ($module.ConfiguredClockSpeed) { '{0} MT/s' -f $module.ConfiguredClockSpeed }
                           elseif ($module.Speed) { '{0} MT/s' -f $module.Speed }
                           else { '' }
            Manufacturer = $module.Manufacturer
            PartNumber   = if ($module.PartNumber) { $module.PartNumber.Trim() } else { '' }
        }
    }

    return , $modules
}
