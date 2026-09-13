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
    Returns the keyboard layouts the test can draw.

.OUTPUTS
    System.String[]
#>
function Get-TkKeyboardLayoutName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'FR AZERTY (French)',
        'US QWERTY (US/International)',
        'GB QWERTY (United Kingdom)',
        'DE QWERTZ (German)'
    )
}

<#
.SYNOPSIS
    Returns the character printed on each key position for one layout.

.DESCRIPTION
    Keyed by scan code, which is the physical position of the key and does not
    change between layouts. Only the positions that carry a character are
    listed; Tab, Shift and the rest are named by the map itself.

    This is what makes the layout selector honest. Asking Windows what a key
    produces would only ever describe the layout Windows is currently set to,
    so a French machine could never draw a German board. The scan code is the
    key; the table below is the legend.

    Accented characters are built from code points rather than written as
    literals, so the file stays plain ASCII and reads the same under Windows
    PowerShell and PowerShell 7 whatever the encoding.

.OUTPUTS
    System.Collections.Hashtable
#>
function Get-TkKeyboardLegend {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Layout
    )

    $super2 = [string][char]0x00B2   # superscript two
    $eAcute = [string][char]0x00E9
    $eGrave = [string][char]0x00E8
    $cCedil = [string][char]0x00E7
    $aGrave = [string][char]0x00E0
    $uGrave = [string][char]0x00F9
    $uUmlaut = [string][char]0x00DC
    $oUmlaut = [string][char]0x00D6
    $aUmlaut = [string][char]0x00C4
    $sharpS  = [string][char]0x00DF
    $acute   = [string][char]0x00B4

    if ($Layout -like 'FR*') {

        return @{
            0x29 = $super2; 0x02 = '&'; 0x03 = $eAcute; 0x04 = '"'; 0x05 = "'"
            0x06 = '('; 0x07 = '-'; 0x08 = $eGrave; 0x09 = '_'; 0x0A = $cCedil
            0x0B = $aGrave; 0x0C = ')'; 0x0D = '='

            0x10 = 'A'; 0x11 = 'Z'; 0x12 = 'E'; 0x13 = 'R'; 0x14 = 'T'; 0x15 = 'Y'
            0x16 = 'U'; 0x17 = 'I'; 0x18 = 'O'; 0x19 = 'P'; 0x1A = '^'; 0x1B = '$'

            0x1E = 'Q'; 0x1F = 'S'; 0x20 = 'D'; 0x21 = 'F'; 0x22 = 'G'; 0x23 = 'H'
            0x24 = 'J'; 0x25 = 'K'; 0x26 = 'L'; 0x27 = 'M'; 0x28 = $uGrave; 0x2B = '*'

            0x56 = '<'; 0x2C = 'W'; 0x2D = 'X'; 0x2E = 'C'; 0x2F = 'V'; 0x30 = 'B'
            0x31 = 'N'; 0x32 = ','; 0x33 = ';'; 0x34 = ':'; 0x35 = '!'
        }
    }

    if ($Layout -like 'DE*') {

        return @{
            0x29 = '^'; 0x02 = '1'; 0x03 = '2'; 0x04 = '3'; 0x05 = '4'
            0x06 = '5'; 0x07 = '6'; 0x08 = '7'; 0x09 = '8'; 0x0A = '9'
            0x0B = '0'; 0x0C = $sharpS; 0x0D = $acute

            0x10 = 'Q'; 0x11 = 'W'; 0x12 = 'E'; 0x13 = 'R'; 0x14 = 'T'; 0x15 = 'Z'
            0x16 = 'U'; 0x17 = 'I'; 0x18 = 'O'; 0x19 = 'P'; 0x1A = $uUmlaut; 0x1B = '+'

            0x1E = 'A'; 0x1F = 'S'; 0x20 = 'D'; 0x21 = 'F'; 0x22 = 'G'; 0x23 = 'H'
            0x24 = 'J'; 0x25 = 'K'; 0x26 = 'L'; 0x27 = $oUmlaut; 0x28 = $aUmlaut; 0x2B = '#'

            0x56 = '<'; 0x2C = 'Y'; 0x2D = 'X'; 0x2E = 'C'; 0x2F = 'V'; 0x30 = 'B'
            0x31 = 'N'; 0x32 = 'M'; 0x33 = ','; 0x34 = '.'; 0x35 = '-'
        }
    }

    # US and GB share QWERTY; only four positions differ, patched below.
    $legend = @{
        0x29 = '`'; 0x02 = '1'; 0x03 = '2'; 0x04 = '3'; 0x05 = '4'
        0x06 = '5'; 0x07 = '6'; 0x08 = '7'; 0x09 = '8'; 0x0A = '9'
        0x0B = '0'; 0x0C = '-'; 0x0D = '='

        0x10 = 'Q'; 0x11 = 'W'; 0x12 = 'E'; 0x13 = 'R'; 0x14 = 'T'; 0x15 = 'Y'
        0x16 = 'U'; 0x17 = 'I'; 0x18 = 'O'; 0x19 = 'P'; 0x1A = '['; 0x1B = ']'

        0x1E = 'A'; 0x1F = 'S'; 0x20 = 'D'; 0x21 = 'F'; 0x22 = 'G'; 0x23 = 'H'
        0x24 = 'J'; 0x25 = 'K'; 0x26 = 'L'; 0x27 = ';'; 0x28 = "'"; 0x2B = '\'

        0x56 = '\'; 0x2C = 'Z'; 0x2D = 'X'; 0x2E = 'C'; 0x2F = 'V'; 0x30 = 'B'
        0x31 = 'N'; 0x32 = 'M'; 0x33 = ','; 0x34 = '.'; 0x35 = '/'
    }

    if ($Layout -like 'GB*') {

        # A British board keeps QWERTY but moves the quote and hash keys and
        # puts the backslash next to the left Shift.
        $legend[0x28] = "'"
        $legend[0x2B] = '#'
        $legend[0x56] = '\'
    }

    return $legend
}

<#
.SYNOPSIS
    Builds one key of the map.

.DESCRIPTION
    Identity is the pair of scan code and extended flag, which is the physical
    key and is the same whatever layout is drawn or active. Two positions share
    scan code 0x45 and neither is extended, Pause and Num Lock, so those two
    carry their virtual key as a third part of the identity.

.OUTPUTS
    System.Management.Automation.PSCustomObject
#>
function New-TkKeyEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $ScanCode,

        [Parameter()]
        [bool] $Extended = $false,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Label,

        [Parameter()]
        [double] $Width = 1.0,

        [Parameter()]
        [int] $VirtualKey = 0
    )

    $key = if ($VirtualKey -gt 0) {
               '{0}:{1}:{2}' -f $ScanCode, [int] $Extended, $VirtualKey
           }
           else {
               '{0}:{1}' -f $ScanCode, [int] $Extended
           }

    return [pscustomobject] @{
        ScanCode   = $ScanCode
        Extended   = $Extended
        VirtualKey = $VirtualKey
        Key        = $key
        Label      = $Label
        Width      = $Width
    }
}

<#
.SYNOPSIS
    Returns a 105 key ISO keyboard as three blocks.

.DESCRIPTION
    Three blocks rather than one list of rows: the main block, the navigation
    cluster and the numeric keypad sit side by side on a real board, and the
    earlier version stacked them underneath each other, which read as a heap of
    keys rather than a keyboard.

    The geometry is the same for every layout, because it is the geometry of an
    ISO board: the short left Shift with the extra key beside it, the tall
    Enter, 105 keys. Only the legend changes.

    Widths are in key units, where a normal key is 1.

.PARAMETER Layout
    One of Get-TkKeyboardLayoutName. Defaults to French.

.OUTPUTS
    A PSCustomObject with Main, Navigation and Numpad, each an array of rows,
    each row an array of key objects.
#>
function Get-TkKeyboardMap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string] $Layout = 'FR AZERTY (French)'
    )

    $legend = Get-TkKeyboardLegend -Layout $Layout

    # The character positions of each row, in order. Their labels come from the
    # legend; everything else is named here.
    $numberRow = @(0x29, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D)
    $topRow    = @(0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B)
    $homeRow   = @(0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2B)
    $shiftRow  = @(0x56, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35)

    $main = @()

    # Function row.
    $row = @(New-TkKeyEntry -ScanCode 0x01 -Label 'Esc')

    foreach ($pair in @(@(0x3B, 'F1'), @(0x3C, 'F2'), @(0x3D, 'F3'), @(0x3E, 'F4'),
                        @(0x3F, 'F5'), @(0x40, 'F6'), @(0x41, 'F7'), @(0x42, 'F8'),
                        @(0x43, 'F9'), @(0x44, 'F10'), @(0x57, 'F11'), @(0x58, 'F12'))) {

        $row += New-TkKeyEntry -ScanCode $pair[0] -Label $pair[1]
    }

    $main += , $row

    # Number row.
    $row = @()

    foreach ($scan in $numberRow) {
        $row += New-TkKeyEntry -ScanCode $scan -Label $legend[$scan]
    }

    $row += New-TkKeyEntry -ScanCode 0x0E -Label 'Backspace' -Width 2.0
    $main += , $row

    # Tab row.
    $row = @(New-TkKeyEntry -ScanCode 0x0F -Label 'Tab' -Width 1.5)

    foreach ($scan in $topRow) {
        $row += New-TkKeyEntry -ScanCode $scan -Label $legend[$scan]
    }

    $main += , $row

    # Home row, ending in the Enter key.
    $row = @(New-TkKeyEntry -ScanCode 0x3A -Label 'Caps' -Width 1.75)

    foreach ($scan in $homeRow) {
        $row += New-TkKeyEntry -ScanCode $scan -Label $legend[$scan]
    }

    $row += New-TkKeyEntry -ScanCode 0x1C -Label 'Enter' -Width 1.75
    $main += , $row

    # The ISO row: a short left Shift, then the extra key that ANSI boards do
    # not have, then the bottom letter run.
    $row = @(New-TkKeyEntry -ScanCode 0x2A -Label 'Shift' -Width 1.25)

    foreach ($scan in $shiftRow) {
        $row += New-TkKeyEntry -ScanCode $scan -Label $legend[$scan]
    }

    $row += New-TkKeyEntry -ScanCode 0x36 -Label 'Shift' -Width 2.75
    $main += , $row

    # Modifier row. Left and right Ctrl share a scan code and are told apart by
    # the extended flag, as do Alt and AltGr.
    $main += , @(
        (New-TkKeyEntry -ScanCode 0x1D -Label 'Ctrl' -Width 1.25),
        (New-TkKeyEntry -ScanCode 0x5B -Extended $true -Label 'Win' -Width 1.25),
        (New-TkKeyEntry -ScanCode 0x38 -Label 'Alt' -Width 1.25),
        (New-TkKeyEntry -ScanCode 0x39 -Label 'Space' -Width 6.25),
        (New-TkKeyEntry -ScanCode 0x38 -Extended $true -Label 'AltGr' -Width 1.25),
        (New-TkKeyEntry -ScanCode 0x5C -Extended $true -Label 'Win' -Width 1.25),
        (New-TkKeyEntry -ScanCode 0x5D -Extended $true -Label 'Menu' -Width 1.25),
        (New-TkKeyEntry -ScanCode 0x1D -Extended $true -Label 'Ctrl' -Width 1.25)
    )

    # --- Navigation cluster ------------------------------------------------
    $up    = [string][char]0x2191
    $down  = [string][char]0x2193
    $left  = [string][char]0x2190
    $right = [string][char]0x2192

    $navigation = @()

    # Pause carries its virtual key because Num Lock has the same scan code and
    # neither is flagged extended.
    $navigation += , @(
        (New-TkKeyEntry -ScanCode 0x37 -Extended $true -Label 'PrtSc'),
        (New-TkKeyEntry -ScanCode 0x46 -Label 'ScrLk'),
        (New-TkKeyEntry -ScanCode 0x45 -Label 'Pause' -VirtualKey 0x13)
    )

    $navigation += , @(
        (New-TkKeyEntry -ScanCode 0x52 -Extended $true -Label 'Ins'),
        (New-TkKeyEntry -ScanCode 0x47 -Extended $true -Label 'Home'),
        (New-TkKeyEntry -ScanCode 0x49 -Extended $true -Label 'PgUp')
    )

    $navigation += , @(
        (New-TkKeyEntry -ScanCode 0x53 -Extended $true -Label 'Del'),
        (New-TkKeyEntry -ScanCode 0x4F -Extended $true -Label 'End'),
        (New-TkKeyEntry -ScanCode 0x51 -Extended $true -Label 'PgDn')
    )

    # An empty row, so the arrows sit below a gap the way they do on a board.
    $navigation += , @()

    $navigation += , @(
        (New-TkKeyEntry -ScanCode 0x48 -Extended $true -Label $up)
    )

    $navigation += , @(
        (New-TkKeyEntry -ScanCode 0x4B -Extended $true -Label $left),
        (New-TkKeyEntry -ScanCode 0x50 -Extended $true -Label $down),
        (New-TkKeyEntry -ScanCode 0x4D -Extended $true -Label $right)
    )

    # --- Numeric keypad ----------------------------------------------------
    # Every one of these shares its scan code with the navigation cluster and
    # is told apart by the extended flag being absent.
    $numpad = @()

    $numpad += , @(
        (New-TkKeyEntry -ScanCode 0x45 -Label 'NumLk' -VirtualKey 0x90),
        (New-TkKeyEntry -ScanCode 0x35 -Extended $true -Label '/'),
        (New-TkKeyEntry -ScanCode 0x37 -Label '*'),
        (New-TkKeyEntry -ScanCode 0x4A -Label '-')
    )

    $numpad += , @(
        (New-TkKeyEntry -ScanCode 0x47 -Label '7'),
        (New-TkKeyEntry -ScanCode 0x48 -Label '8'),
        (New-TkKeyEntry -ScanCode 0x49 -Label '9'),
        (New-TkKeyEntry -ScanCode 0x4E -Label '+')
    )

    $numpad += , @(
        (New-TkKeyEntry -ScanCode 0x4B -Label '4'),
        (New-TkKeyEntry -ScanCode 0x4C -Label '5'),
        (New-TkKeyEntry -ScanCode 0x4D -Label '6')
    )

    $numpad += , @(
        (New-TkKeyEntry -ScanCode 0x4F -Label '1'),
        (New-TkKeyEntry -ScanCode 0x50 -Label '2'),
        (New-TkKeyEntry -ScanCode 0x51 -Label '3'),
        (New-TkKeyEntry -ScanCode 0x1C -Extended $true -Label 'Enter')
    )

    $numpad += , @(
        (New-TkKeyEntry -ScanCode 0x52 -Label '0' -Width 2.0),
        (New-TkKeyEntry -ScanCode 0x53 -Label '.')
    )

    return [pscustomobject] @{
        Layout     = $Layout
        Main       = $main
        Navigation = $navigation
        Numpad     = $numpad
    }
}

<#
.SYNOPSIS
    Returns the scan code Windows assigns to a virtual key.

.DESCRIPTION
    A fallback for the rare input that arrives with no scan code at all. A key
    message normally carries the physical position in lParam, but an injected
    key, some remote desktop configurations and a few software keyboards send
    zero there. Without this the keyboard test would simply ignore them.

    MapVirtualKey is a stateless lookup, the same one every on screen keyboard
    uses to paint its labels. It observes nothing and records nothing; it
    answers "which key on the board produces this".

.OUTPUTS
    System.Int32, or 0 when the lookup fails.
#>
function Get-TkScanCodeForVirtualKey {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [int] $VirtualKey
    )

    if (-not ('TkKeyboardLookup' -as [type])) {

        $source = @'
using System;
using System.Runtime.InteropServices;

/// <summary>
/// Virtual key to physical position. No hook, no capture: one stateless call.
/// </summary>
public static class TkKeyboardLookup
{
    [DllImport("user32.dll")]
    private static extern uint MapVirtualKey(uint code, uint mapType);

    private const uint MAPVK_VK_TO_VSC = 0x00;

    public static int ScanCode(int virtualKey)
    {
        if (virtualKey <= 0) return 0;

        return (int)MapVirtualKey((uint)virtualKey, MAPVK_VK_TO_VSC);
    }
}
'@

        try {
            Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
        }
        catch {
            return 0
        }
    }

    return [TkKeyboardLookup]::ScanCode($VirtualKey)
}

<#
.SYNOPSIS
    Returns every key of a map as one flat list.

.DESCRIPTION
    The map is shaped for drawing, in three blocks of rows. Counting keys,
    checking that no identity repeats and reporting which ones never registered
    all want a flat list instead.

    Returned without the comma operator, on purpose. Wrapping the result would
    keep it one array through an assignment but hand the pipeline a single
    object, so "Get-TkKeyboardKey | Where-Object" would filter one array rather
    than a hundred and five keys. This result exists to be filtered.

.OUTPUTS
    An array of key objects.
#>
function Get-TkKeyboardKey {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        $Map
    )

    $keys = @()

    foreach ($block in @($Map.Main, $Map.Navigation, $Map.Numpad)) {
        foreach ($row in $block) {
            foreach ($key in $row) {
                $keys += $key
            }
        }
    }

    return $keys
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
