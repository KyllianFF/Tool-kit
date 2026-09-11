<#
    Toolkit - Core / Low level keyboard hook

    Lets the keyboard test see every key and, while it runs, stop Windows
    acting on them.

    Why a hook rather than the ordinary WPF key events. A keyboard test has to
    observe keys that Windows treats as commands rather than input. Press the
    Windows key over a normal window and the Start menu opens and takes the
    focus; Alt moves to the menu bar, Alt+Tab switches away, Alt+F4 closes the
    thing you were testing. None of those ever reach the application, so none
    of them can be ticked off a list, and each one interrupts the test.

    A WH_KEYBOARD_LL hook runs before the shell sees the key. Returning a non
    zero value from the callback consumes it: the key is recorded and Windows
    never acts on it.

    What this cannot do, and it matters: Ctrl+Alt+Delete is the secure
    attention sequence. It is handled by Winlogon on a separate desktop and no
    hook of any kind can see or block it. That is a deliberate part of the
    Windows security model, it is not a limitation worth working around, and
    the keyboard test says so rather than appearing to miss those keys.

    Safety. A hook belongs to the process that installs it, so it dies with
    the process: a crash cannot leave a machine unable to type. Suppression is
    additionally tied to the test window being active, so switching away by
    any means that still works hands the keyboard straight back.
#>

# Compiled once per session. Add-Type throws if the type is already defined.
$script:TkKeyboardHookReady = $false

<#
.SYNOPSIS
    Compiles the keyboard hook helper.

.DESCRIPTION
    The callback has to be reachable from native code for as long as the hook
    lives, which rules out a PowerShell script block: the delegate would be
    collected and the process would fault on the next key press. Holding it in
    a static field of a compiled type is the supported way.

.OUTPUTS
    System.Boolean
#>
function Initialize-TkKeyboardHook {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:TkKeyboardHookReady) {
        return $true
    }

    if ('TkKeyboardHook' -as [type]) {

        $script:TkKeyboardHookReady = $true
        return $true
    }

    $source = @'
using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;

/// <summary>
/// A low level keyboard hook that records key events and can stop them
/// reaching the rest of Windows.
/// </summary>
public static class TkKeyboardHook
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN     = 0x0100;
    private const int WM_KEYUP       = 0x0101;
    private const int WM_SYSKEYDOWN  = 0x0104;
    private const int WM_SYSKEYUP    = 0x0105;

    private delegate IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr extraInfo;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, HookProc proc, IntPtr module, uint threadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(IntPtr hook);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string name);

    // Kept in a field on purpose. Windows holds a raw pointer to this
    // delegate; if the only reference were a local, the collector would take
    // it and the process would fault on the next key press.
    private static HookProc _proc;
    private static IntPtr   _hook = IntPtr.Zero;

    // The hook runs on the thread that installed it, but callers read from
    // the interface thread, so the queue has to be safe for both.
    private static readonly ConcurrentQueue<long> _events = new ConcurrentQueue<long>();

    /// <summary>
    /// While true, keys are recorded and then dropped. The caller clears it
    /// whenever its window stops being the active one, so switching away by
    /// any means that still works returns the keyboard immediately.
    /// </summary>
    public static volatile bool Swallow;

    public static bool IsRunning { get { return _hook != IntPtr.Zero; } }

    public static void Start()
    {
        if (_hook != IntPtr.Zero) return;

        _proc = Callback;
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(null), 0);

        if (_hook == IntPtr.Zero)
            throw new InvalidOperationException(
                "SetWindowsHookEx failed with error " + Marshal.GetLastWin32Error());
    }

    public static void Stop()
    {
        Swallow = false;

        if (_hook == IntPtr.Zero) return;

        UnhookWindowsHookEx(_hook);
        _hook = IntPtr.Zero;
        _proc = null;

        long ignored;
        while (_events.TryDequeue(out ignored)) { }
    }

    /// <summary>
    /// Takes the next key event. Scan code in the low sixteen bits, virtual
    /// key in the next sixteen, and the press flag above those.
    /// </summary>
    public static bool TryDequeue(out int scanCode, out int virtualKey, out bool isDown, out bool isExtended)
    {
        scanCode = 0; virtualKey = 0; isDown = false; isExtended = false;

        long packed;
        if (!_events.TryDequeue(out packed)) return false;

        scanCode   = (int)(packed & 0xFFFF);
        virtualKey = (int)((packed >> 16) & 0xFFFF);
        isDown     = ((packed >> 32) & 1) == 1;
        isExtended = ((packed >> 33) & 1) == 1;

        return true;
    }

    [DllImport("user32.dll")]
    private static extern uint MapVirtualKey(uint code, uint mapType);

    private const uint MAPVK_VSC_TO_VK_EX = 0x03;
    private const uint MAPVK_VK_TO_CHAR   = 0x02;

    /// <summary>
    /// The character a physical key produces under the layout in use.
    /// </summary>
    /// <remarks>
    /// Asked for by scan code, which is the physical position and does not
    /// change between layouts, rather than by virtual key, which does. Draw a
    /// keyboard from virtual keys and a French operator sees A where their A
    /// is not: on AZERTY the key that sends VK_A sits where QWERTY has Q.
    /// Going scan code to virtual key to character puts the right label on
    /// the right key for AZERTY, QWERTZ and QWERTY alike.
    /// </remarks>
    public static string GetKeyLabel(int scanCode, bool extended)
    {
        uint code = (uint)scanCode;

        if (extended) code |= 0xE000;

        uint virtualKey = MapVirtualKey(code, MAPVK_VSC_TO_VK_EX);

        if (virtualKey == 0) return "";

        uint character = MapVirtualKey(virtualKey, MAPVK_VK_TO_CHAR) & 0x7FFF;

        if (character == 0) return "";

        char value = (char)character;

        return char.IsControl(value) ? "" : value.ToString();
    }

    private static IntPtr Callback(int code, IntPtr wParam, IntPtr lParam)
    {
        if (code >= 0)
        {
            int message = wParam.ToInt32();

            bool down = (message == WM_KEYDOWN || message == WM_SYSKEYDOWN);
            bool up   = (message == WM_KEYUP   || message == WM_SYSKEYUP);

            if (down || up)
            {
                KBDLLHOOKSTRUCT data =
                    (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

                // LLKHF_EXTENDED. Right Ctrl, right Alt, the arrow cluster and
                // the numeric keypad Enter share scan codes with other keys
                // and are told apart only by this flag.
                bool extended = (data.flags & 0x01) != 0;

                long packed = (long)(data.scanCode & 0xFFFF)
                            | ((long)(data.vkCode & 0xFFFF) << 16)
                            | (down ? (1L << 32) : 0L)
                            | (extended ? (1L << 33) : 0L);

                _events.Enqueue(packed);

                // The whole point. A non zero return consumes the key, so the
                // Start menu stays shut and the test is not interrupted.
                if (Swallow) return new IntPtr(1);
            }
        }

        return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
    }
}
'@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop

        $script:TkKeyboardHookReady = $true

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Hardware' -Message (
            'The keyboard hook could not be compiled: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Starts recording key events.

.PARAMETER Swallow
    Also stop the keys reaching Windows, which is what keeps the Start menu
    shut and the test uninterrupted.

.OUTPUTS
    System.Boolean
#>
function Start-TkKeyboardCapture {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [switch] $Swallow
    )

    if (-not (Initialize-TkKeyboardHook)) {
        return $false
    }

    try {
        [TkKeyboardHook]::Start()
        [TkKeyboardHook]::Swallow = [bool] $Swallow

        Write-TkLog -Level Information -Category 'Hardware' -Message (
            'Keyboard capture started{0}.' -f $(if ($Swallow) { ', with system keys held back' } else { '' })
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Hardware' -Message (
            'The keyboard hook could not be installed: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Stops recording and hands the keyboard back.
#>
function Stop-TkKeyboardCapture {
    [CmdletBinding()]
    param()

    if (-not ('TkKeyboardHook' -as [type])) {
        return
    }

    if (-not [TkKeyboardHook]::IsRunning) {
        return
    }

    [TkKeyboardHook]::Stop()

    Write-TkLog -Level Information -Category 'Hardware' -Message 'Keyboard capture stopped.'
}

<#
.SYNOPSIS
    Turns suppression on or off without stopping the capture.

.DESCRIPTION
    Called when the test window gains or loses focus. Holding keys back while
    another window is in front would take the keyboard away from whatever the
    operator switched to.
#>
function Set-TkKeyboardSwallow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool] $Enabled
    )

    if (-not ('TkKeyboardHook' -as [type])) {
        return
    }

    if ([TkKeyboardHook]::IsRunning) {
        [TkKeyboardHook]::Swallow = $Enabled
    }
}

<#
.SYNOPSIS
    Returns the key events recorded since the last call.

.DESCRIPTION
    Drained rather than subscribed to, so the interface stays in charge of
    when it does work: the page polls this from a timer in the same way the
    background task pump works.

.OUTPUTS
    An array of objects with ScanCode, VirtualKey, IsDown and IsExtended.
#>
function Receive-TkKeyboardEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $events = @()

    if (-not ('TkKeyboardHook' -as [type])) {
        return , $events
    }

    if (-not [TkKeyboardHook]::IsRunning) {
        return , $events
    }

    $scanCode   = 0
    $virtualKey = 0
    $isDown     = $false
    $isExtended = $false

    while ([TkKeyboardHook]::TryDequeue([ref] $scanCode, [ref] $virtualKey,
                                        [ref] $isDown,   [ref] $isExtended)) {

        $events += [pscustomobject] @{
            ScanCode   = $scanCode
            VirtualKey = $virtualKey
            IsDown     = $isDown
            IsExtended = $isExtended
        }
    }

    return , $events
}
