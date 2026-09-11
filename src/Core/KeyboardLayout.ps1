<#
    Toolkit - Core / Keyboard layout labels

    Turns a key into the character it produces under the layout in use, so the
    keyboard test can draw an AZERTY board as AZERTY without knowing anything
    about layouts itself.

    This deliberately does NOT install a keyboard hook. An earlier version of
    the keyboard test used a low level WH_KEYBOARD_LL hook that recorded and
    swallowed every key system wide. That is, at the level of the Windows API,
    exactly what a keylogger does, and antivirus software is right to treat it
    as one: ESET and Defender behavioural monitoring both flag it. The test
    was rebuilt to read keys only while its own window has focus, through the
    ordinary WPF key events, which is what a local key tester should do and
    what nothing mistakes for malware.

    All that remains here is MapVirtualKey, a plain user32 lookup that on
    screen keyboards have always used. It sees nothing, records nothing and
    captures nothing; it only answers "what letter is on this key".
#>

$script:TkKeyboardLayoutReady = $false

<#
.SYNOPSIS
    Compiles the layout lookup helper.

.OUTPUTS
    System.Boolean
#>
function Initialize-TkKeyboardLayout {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:TkKeyboardLayoutReady) {
        return $true
    }

    if ('TkKeyboardLayout' -as [type]) {
        $script:TkKeyboardLayoutReady = $true
        return $true
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

/// <summary>
/// The character a physical key produces under the current layout. No hook,
/// no capture: a single stateless lookup, the same one an on screen keyboard
/// uses to paint its labels.
/// </summary>
public static class TkKeyboardLayout
{
    [DllImport("user32.dll")]
    private static extern uint MapVirtualKey(uint code, uint mapType);

    private const uint MAPVK_VK_TO_CHAR = 0x02;

    /// <summary>
    /// The printable character for a virtual key, or an empty string when the
    /// key produces no character of its own (Tab, Shift, the function keys).
    /// </summary>
    public static string LabelForVirtualKey(int virtualKey)
    {
        if (virtualKey <= 0) return "";

        uint character = MapVirtualKey((uint)virtualKey, MAPVK_VK_TO_CHAR) & 0x7FFF;

        if (character == 0) return "";

        char value = (char)character;

        return char.IsControl(value) ? "" : value.ToString();
    }
}
'@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop

        $script:TkKeyboardLayoutReady = $true

        return $true
    }
    catch {
        Write-TkLog -Level Warning -Category 'Hardware' -Message (
            'The keyboard layout helper could not be compiled, so keys will carry their default labels: {0}' -f
                $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Returns the layout specific label for a WPF key, or an empty string.

.DESCRIPTION
    Asked for by the key rather than by scan code, because the keyboard test
    now matches physical keys through the WPF key events and the WPF Key value
    is what it has in hand. WindowsBase provides the key to virtual key
    mapping; user32 provides the virtual key to character mapping.

.PARAMETER Key
    A System.Windows.Input.Key value.

.OUTPUTS
    System.String
#>
function Get-TkKeyLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Input.Key] $Key
    )

    if (-not (Initialize-TkKeyboardLayout)) {
        return ''
    }

    $virtualKey = [System.Windows.Input.KeyInterop]::VirtualKeyFromKey($Key)

    return [TkKeyboardLayout]::LabelForVirtualKey($virtualKey)
}
