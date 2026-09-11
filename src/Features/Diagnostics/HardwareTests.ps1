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
    Returns the physical keyboard as rows of keys.

.DESCRIPTION
    Described by scan code, which is the position of the key on the board and
    is the same on every layout, rather than by virtual key, which moves with
    the layout. Labels are asked of Windows per key, so an AZERTY board draws
    as AZERTY without this table knowing anything about it.

    A scan code alone is not unique: the navigation cluster and the numeric
    keypad share theirs and are told apart by the extended flag, which is why
    each key carries one and why identity is the pair.

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

    # Scan code, fallback label, width, extended flag.
    # The fallback is used for keys that produce no character of their own.
    #
    # Each row is appended with the comma operator. Written as bare @(...)
    # literals one per line they are separate statements, so PowerShell
    # enumerates them into the outer array and the rows collapse into one
    # long list of key definitions.
    $rows = @()

    $rows += , @(
        @(0x01, 'Esc', 1.0, $false), @(0x3B, 'F1', 1.0, $false), @(0x3C, 'F2', 1.0, $false),
        @(0x3D, 'F3', 1.0, $false),  @(0x3E, 'F4', 1.0, $false), @(0x3F, 'F5', 1.0, $false),
        @(0x40, 'F6', 1.0, $false),  @(0x41, 'F7', 1.0, $false), @(0x42, 'F8', 1.0, $false),
        @(0x43, 'F9', 1.0, $false),  @(0x44, 'F10', 1.0, $false), @(0x57, 'F11', 1.0, $false),
        @(0x58, 'F12', 1.0, $false)
    )

    $rows += , @(
        @(0x29, '`', 1.0, $false), @(0x02, '1', 1.0, $false), @(0x03, '2', 1.0, $false),
        @(0x04, '3', 1.0, $false), @(0x05, '4', 1.0, $false), @(0x06, '5', 1.0, $false),
        @(0x07, '6', 1.0, $false), @(0x08, '7', 1.0, $false), @(0x09, '8', 1.0, $false),
        @(0x0A, '9', 1.0, $false), @(0x0B, '0', 1.0, $false), @(0x0C, '-', 1.0, $false),
        @(0x0D, '=', 1.0, $false), @(0x0E, 'Backspace', 2.0, $false)
    )

    $rows += , @(
        @(0x0F, 'Tab', 1.5, $false), @(0x10, 'Q', 1.0, $false), @(0x11, 'W', 1.0, $false),
        @(0x12, 'E', 1.0, $false), @(0x13, 'R', 1.0, $false), @(0x14, 'T', 1.0, $false),
        @(0x15, 'Y', 1.0, $false), @(0x16, 'U', 1.0, $false), @(0x17, 'I', 1.0, $false),
        @(0x18, 'O', 1.0, $false), @(0x19, 'P', 1.0, $false), @(0x1A, '[', 1.0, $false),
        @(0x1B, ']', 1.0, $false), @(0x2B, '\', 1.5, $false)
    )

    $rows += , @(
        @(0x3A, 'Caps', 1.75, $false), @(0x1E, 'A', 1.0, $false), @(0x1F, 'S', 1.0, $false),
        @(0x20, 'D', 1.0, $false), @(0x21, 'F', 1.0, $false), @(0x22, 'G', 1.0, $false),
        @(0x23, 'H', 1.0, $false), @(0x24, 'J', 1.0, $false), @(0x25, 'K', 1.0, $false),
        @(0x26, 'L', 1.0, $false), @(0x27, ';', 1.0, $false), @(0x28, "'", 1.0, $false),
        @(0x1C, 'Enter', 2.25, $false)
    )

    $rows += , @(
        @(0x2A, 'Shift', 2.25, $false), @(0x2C, 'Z', 1.0, $false), @(0x2D, 'X', 1.0, $false),
        @(0x2E, 'C', 1.0, $false), @(0x2F, 'V', 1.0, $false), @(0x30, 'B', 1.0, $false),
        @(0x31, 'N', 1.0, $false), @(0x32, 'M', 1.0, $false), @(0x33, ',', 1.0, $false),
        @(0x34, '.', 1.0, $false), @(0x35, '/', 1.0, $false), @(0x36, 'Shift', 2.75, $false)
    )

    $rows += , @(
        @(0x1D, 'Ctrl', 1.25, $false), @(0x5B, 'Win', 1.25, $true), @(0x38, 'Alt', 1.25, $false),
        @(0x39, 'Space', 6.25, $false), @(0x38, 'AltGr', 1.25, $true), @(0x5C, 'Win', 1.25, $true),
        @(0x5D, 'Menu', 1.25, $true), @(0x1D, 'Ctrl', 1.25, $true)
    )

    if (-not $Compact) {

        # The navigation cluster and the arrows, on their own rows so they sit
        # under the main block rather than beside it. Every one is extended.
        $rows += , @(
            @(0x52, 'Ins', 1.0, $true), @(0x47, 'Home', 1.0, $true), @(0x49, 'PgUp', 1.0, $true),
            @(0x53, 'Del', 1.0, $true), @(0x4F, 'End', 1.0, $true), @(0x51, 'PgDn', 1.0, $true),
            @(0x48, 'Up', 1.0, $true), @(0x4B, 'Left', 1.0, $true), @(0x50, 'Down', 1.0, $true),
            @(0x4D, 'Right', 1.0, $true)
        )

        # The keypad. These repeat the scan codes above without the extended
        # flag, which is exactly how Windows tells the two apart.
        $rows += , @(
            @(0x45, 'NumLk', 1.0, $false), @(0x35, 'N /', 1.0, $true), @(0x37, 'N *', 1.0, $false),
            @(0x4A, 'N -', 1.0, $false), @(0x47, 'N 7', 1.0, $false), @(0x48, 'N 8', 1.0, $false),
            @(0x49, 'N 9', 1.0, $false), @(0x4E, 'N +', 1.0, $false), @(0x4B, 'N 4', 1.0, $false),
            @(0x4C, 'N 5', 1.0, $false), @(0x4D, 'N 6', 1.0, $false), @(0x4F, 'N 1', 1.0, $false),
            @(0x50, 'N 2', 1.0, $false), @(0x51, 'N 3', 1.0, $false), @(0x52, 'N 0', 1.0, $false),
            @(0x53, 'N .', 1.0, $false), @(0x1C, 'N Ent', 1.0, $true)
        )
    }

    $hookReady = Initialize-TkKeyboardHook

    $result = @()

    foreach ($row in $rows) {

        $keys = @()

        foreach ($definition in $row) {

            $scanCode = [int] $definition[0]
            $fallback = [string] $definition[1]
            $width    = [double] $definition[2]
            $extended = [bool] $definition[3]

            $label = $fallback

            # Ask Windows what this physical key produces here. Only for the
            # character keys: a label of "Backspace" is more use than nothing,
            # and more use than the control character it maps to.
            if ($hookReady -and $fallback.Length -eq 1) {

                $actual = [TkKeyboardHook]::GetKeyLabel($scanCode, $extended)

                if ($actual) {
                    $label = $actual.ToUpperInvariant()
                }
            }

            $keys += [pscustomobject] @{
                ScanCode = $scanCode
                Extended = $extended
                Key      = '{0}:{1}' -f $scanCode, [int] $extended
                Label    = $label
                Width    = $width
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
        'Ctrl+Alt+Delete is handled by Windows itself, on a desktop no application can reach. Pressing it ends the test rather than registering.',
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
