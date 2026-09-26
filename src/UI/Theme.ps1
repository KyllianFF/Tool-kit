<#
    Toolkit - UI / Theme

    Two palettes, swapped at run time.

    How it works: every colour in MainWindow.xaml is referenced through
    DynamicResource against a named brush. Replacing the brush object behind
    a key repaints every control bound to it, with no window rebuild and no
    loss of state. The XAML ships the dark values as its defaults, so a
    window is readable even before this file runs.

    The rule that keeps it working: no control ever declares a literal
    colour. The first version broke that for combo boxes and list views and
    left black text on a dark background across half the interface.
#>

<#
.SYNOPSIS
    Returns the colour table for a theme.

.DESCRIPTION
    Keys match the brush keys declared in MainWindow.xaml. Both palettes
    define exactly the same keys, which is what makes a swap total: a key
    present in one and missing from the other would keep its previous value
    and produce an unreadable mix.

.PARAMETER Name
    Dark or Light.

.OUTPUTS
    System.Collections.Hashtable
#>
function Get-TkThemePalette {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Dark', 'Light')]
        [string] $Name
    )

    # The soft style: a violet accent, surfaces with a faint violet cast, and
    # the page background shared by the header and the navigation so the
    # cards carry the structure.
    #
    # AccentText is the label on an accent fill, the primary buttons. It is a
    # colour of its own because the accent is light in the dark theme and dark
    # in the light one, so no single text colour is legible on both.
    if ($Name -eq 'Dark') {

        return @{
            AppBackground   = '#15131C'
            Surface         = '#1E1B27'
            SurfaceRaised   = '#282433'
            InputBackground = '#1A1723'
            BorderSubtle    = '#302B3D'
            TextPrimary     = '#EDEAF4'
            TextMuted       = '#A39DB3'
            Accent          = '#A78BFA'
            AccentText      = '#1B1030'
            AccentMuted     = '#3B2F63'
            Selection       = '#2C2640'
            RowAlternate    = '#221F2C'
            Success         = '#4ADE80'
            Warning         = '#FBBF24'
            Danger          = '#F87171'
        }
    }

    # Light values are chosen for contrast rather than as inverted dark ones.
    # The accent is deepened so it carries white text on a primary button and
    # reads as text on white, and Success and Warning are deepened because the
    # dark theme values are unreadable on white.
    #
    # RowAlternate is the banding on every other table row. It is a colour per
    # theme rather than a transparency, because a transparency that reads as a
    # faint lift on the dark surface reads as dirt on the light one.
    return @{
        AppBackground   = '#F5F4FA'
        Surface         = '#FFFFFF'
        SurfaceRaised   = '#F0EEF7'
        InputBackground = '#FBFAFE'
        BorderSubtle    = '#E6E3F0'
        TextPrimary     = '#1E1B2E'
        TextMuted       = '#6B6680'
        Accent          = '#6D28D9'
        AccentText      = '#FFFFFF'
        AccentMuted     = '#EDE9FE'
        Selection       = '#EEE9FF'
        RowAlternate    = '#F7F5FC'
        Success         = '#15803D'
        Warning         = '#A16207'
        Danger          = '#DC2626'
    }
}

<#
.SYNOPSIS
    Derives the faint severity fills from a palette.

.DESCRIPTION
    Finding cards, dashboard tiles and diff lines are filled with a severity
    colour at low alpha. The fills are window resources like the palette
    colours and are recomputed with them, so what was drawn before a theme
    change follows it. Get-TkSeverityTintKey names them.

.PARAMETER Palette
    The table from Get-TkThemePalette.

.OUTPUTS
    System.Collections.Hashtable of resource key to #AARRGGBB colour.
#>
function Get-TkThemeTint {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Palette
    )

    $tints = @{}

    foreach ($key in @('Danger', 'Warning', 'Success', 'TextMuted')) {
        foreach ($alpha in @(38, 60)) {
            $tints[('{0}Tint{1}' -f $key, $alpha)] = '#{0:X2}{1}' -f $alpha, $Palette[$key].TrimStart('#')
        }
    }

    return $tints
}

<#
.SYNOPSIS
    Returns the theme in use: the stored choice, or Dark when there is none.

.OUTPUTS
    System.String: Dark or Light.
#>
function Get-TkThemeName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = Get-TkContext

    if ($ctx.Settings.ContainsKey('Theme') -and $ctx.Settings['Theme'] -in @('Dark', 'Light')) {
        return $ctx.Settings['Theme']
    }

    return 'Dark'
}

<#
.SYNOPSIS
    Paints a window's native title bar dark or light, to match the theme.

.DESCRIPTION
    WPF draws everything inside a window, but the title bar belongs to Windows,
    which paints it light whatever the palette underneath. The Desktop Window
    Manager paints it dark when asked through the immersive dark mode
    attribute: 20 from Windows 10 2004, 19 on the 1809 to 1909 builds that had
    it before it was documented. On a build with neither, or when the call
    fails, the light title bar stays and the window works as before.

    The call needs a small interop type, compiled on first use like the other
    Windows API calls in the toolkit. A light theme needs nothing until a dark
    one has been applied, because the title bar starts light: a session that
    stays light never compiles it.

.PARAMETER Window
    The window whose title bar to paint.

.PARAMETER Name
    Dark or Light.

.OUTPUTS
    System.Boolean: whether the title bar now matches.
#>
function Set-TkTitleBarTheme {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Window] $Window,

        [Parameter(Mandatory)]
        [ValidateSet('Dark', 'Light')]
        [string] $Name
    )

    $loaded = [bool] ('TkTitleBar' -as [type])

    if ($Name -eq 'Light' -and -not $loaded) {
        return $true
    }

    if (-not $loaded) {

        $source = @'
using System;
using System.Runtime.InteropServices;

/// <summary>
/// The dark title bar of a window. One stateless call to the Desktop Window
/// Manager, and one to redraw the frame so a change shows at once.
/// </summary>
public static class TkTitleBar
{
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("dwmapi.dll")]
    private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out int value, int size);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);

    private const int DarkMode       = 20;
    private const int DarkModeBefore = 19;

    private const uint SWP_NOSIZE       = 0x0001;
    private const uint SWP_NOMOVE       = 0x0002;
    private const uint SWP_NOZORDER     = 0x0004;
    private const uint SWP_NOACTIVATE   = 0x0010;
    private const uint SWP_FRAMECHANGED = 0x0020;

    public static bool SetDark(IntPtr hwnd, bool dark)
    {
        if (hwnd == IntPtr.Zero) return false;

        int value  = dark ? 1 : 0;
        int result = DwmSetWindowAttribute(hwnd, DarkMode, ref value, sizeof(int));

        if (result != 0)
        {
            result = DwmSetWindowAttribute(hwnd, DarkModeBefore, ref value, sizeof(int));
        }

        // The frame is otherwise repainted only on the next activation.
        SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0,
                     SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);

        return result == 0;
    }

    /// <summary>1 dark, 0 light, -1 when the attribute cannot be read.</summary>
    public static int Read(IntPtr hwnd)
    {
        int value;

        if (DwmGetWindowAttribute(hwnd, DarkMode, out value, sizeof(int)) == 0) return value;
        if (DwmGetWindowAttribute(hwnd, DarkModeBefore, out value, sizeof(int)) == 0) return value;

        return -1;
    }
}
'@

        try {
            Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
        }
        catch {
            Write-TkLog -Level Debug -Category 'UI' -Message ('The title bar colour is not available: {0}' -f $_.Exception.Message)
            return $false
        }
    }

    # A window not shown yet has no handle; EnsureHandle creates it, so the
    # title bar is right from the first frame instead of flashing light.
    $handle = (New-Object System.Windows.Interop.WindowInteropHelper($Window)).EnsureHandle()

    return [TkTitleBar]::SetDark($handle, ($Name -eq 'Dark'))
}

<#
.SYNOPSIS
    Applies a theme to the open window.

.DESCRIPTION
    Replaces the brush behind every palette key and every tint derived from
    it. The primary buttons need nothing more: their label is the AccentText
    key, set per theme. Nor does the navigation highlight: Show-TkPage gives
    it the Selection and Accent brushes by resource reference.

    Only what refers to a key follows: an element given the brush object
    itself keeps the old colour. Documents and generated controls use
    Set-TkResourceBrush for that reason.

.PARAMETER Name
    Dark or Light.

.PARAMETER Persist
    Saves the choice to the user settings so the next start matches.

.OUTPUTS
    System.Boolean
#>
function Set-TkTheme {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Dark', 'Light')]
        [string] $Name,

        [Parameter()]
        [switch] $Persist
    )

    $ctx = Get-TkContext

    if ($null -eq $ctx.Window) {
        return $false
    }

    $palette   = Get-TkThemePalette -Name $Name
    $colours   = $palette.Clone()
    $converter = New-Object System.Windows.Media.BrushConverter

    foreach ($tint in (Get-TkThemeTint -Palette $palette).GetEnumerator()) {
        $colours[$tint.Key] = $tint.Value
    }

    foreach ($key in $colours.Keys) {

        try {
            $brush = $converter.ConvertFromString($colours[$key])
            $brush.Freeze()

            $ctx.Window.Resources[$key] = $brush
        }
        catch {
            Write-TkLog -Level Warning -Category 'UI' -Message (
                'Could not apply the {0} colour: {1}' -f $key, $_.Exception.Message
            )
        }
    }

    $ctx.Settings['Theme'] = $Name

    # The native title bars: this window and every window it owns that is
    # still open, such as a document viewer left beside it.
    foreach ($target in @($ctx.Window) + @($ctx.Window.OwnedWindows)) {
        Set-TkTitleBarTheme -Window $target -Name $Name | Out-Null
    }

    # Nothing to repaint in the navigation: its active entry takes the
    # Selection brush by resource reference and follows the new palette by
    # itself. It used to be repainted by showing the last page again, which at
    # start up opened that page before its own code had registered what to load.

    Update-TkElevationBadge

    if ($Persist) {
        Save-TkSettings -Confirm:$false
    }

    Write-TkLog -Level Debug -Category 'UI' -Message ('{0} theme applied.' -f $Name)

    return $true
}

<#
.SYNOPSIS
    Wires the theme switch under Settings and applies the stored choice.

.DESCRIPTION
    Called once during shell initialisation. The stored theme is applied
    before the window is shown, so there is no flash of the wrong palette.

    The switch is on for the dark theme. It reacts to Click, which a mouse
    and the Space key raise, and not to Checked: setting IsChecked here to
    show the stored choice must not count as the user choosing it again.
#>
function Initialize-TkThemeToggle {
    [CmdletBinding()]
    param()

    $toggle  = Get-TkControl -Name 'ThemeToggle'
    $current = Get-TkThemeName

    if ($toggle) {

        $toggle.IsChecked = ($current -eq 'Dark')

        $toggle.Add_Click({

            $choice = if ((Get-TkControl -Name 'ThemeToggle').IsChecked) { 'Dark' } else { 'Light' }

            Set-TkTheme -Name $choice -Persist | Out-Null
            Set-TkStatus -Text ('{0} theme applied.' -f $choice)
        })
    }

    Set-TkTheme -Name $current | Out-Null
}
