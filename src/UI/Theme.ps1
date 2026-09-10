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

    if ($Name -eq 'Dark') {

        return @{
            AppBackground   = '#16181D'
            Surface         = '#1E2128'
            SurfaceRaised   = '#262A33'
            InputBackground = '#12141A'
            BorderSubtle    = '#333845'
            TextPrimary     = '#E7EAF0'
            TextMuted       = '#98A1B2'
            Accent          = '#4C8DFF'
            AccentMuted     = '#2A4C8A'
            Selection       = '#2F3A4F'
            RowAlternate    = '#252932'
            Success         = '#3FB950'
            Warning         = '#D29922'
            Danger          = '#F85149'
        }
    }

    # Light values are chosen for contrast rather than as inverted dark ones.
    # Accent and AccentMuted are darkened so white text on the primary button
    # still clears the 4.5:1 contrast ratio, and Success and Warning are
    # deepened because the dark theme values are unreadable on white.
    #
    # RowAlternate is the banding on every other table row. It is a colour per
    # theme rather than a transparency, because a transparency that reads as a
    # faint lift on the dark surface reads as dirt on the light one.
    return @{
        AppBackground   = '#F4F5F7'
        Surface         = '#FFFFFF'
        SurfaceRaised   = '#EDEFF3'
        InputBackground = '#FFFFFF'
        BorderSubtle    = '#D0D5DD'
        TextPrimary     = '#1B1F27'
        TextMuted       = '#5C6675'
        Accent          = '#1F63D6'
        AccentMuted     = '#DCE7FB'
        Selection       = '#E3EBF9'
        RowAlternate    = '#EFF1F5'
        Success         = '#1A7F37'
        Warning         = '#9A6700'
        Danger          = '#C0342B'
    }
}

<#
.SYNOPSIS
    Applies a theme to the open window.

.DESCRIPTION
    Replaces the brush behind every palette key. Also fixes up the two places
    a brush cannot be reached by DynamicResource: the primary button style,
    whose foreground has to stay legible on the accent fill in both themes,
    and the navigation highlight, which Show-TkPage sets in code.

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
    $converter = New-Object System.Windows.Media.BrushConverter

    foreach ($key in $palette.Keys) {

        try {
            $brush = $converter.ConvertFromString($palette[$key])
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

    # Repaint the navigation, whose active entry is coloured from code rather
    # than from a style trigger.
    if ($ctx.Settings.ContainsKey('LastPage') -and $ctx.Settings['LastPage']) {
        Show-TkPage -Name $ctx.Settings['LastPage']
    }

    Update-TkElevationBadge

    if ($Persist) {
        Save-TkSettings -Confirm:$false
    }

    Write-TkLog -Level Debug -Category 'UI' -Message ('{0} theme applied.' -f $Name)

    return $true
}

<#
.SYNOPSIS
    Fills the theme selector and applies the stored choice.

.DESCRIPTION
    Called once during shell initialisation. The stored theme is applied
    before the window is shown, so there is no flash of the wrong palette.
#>
function Initialize-TkThemeSelector {
    [CmdletBinding()]
    param()

    $ctx      = Get-TkContext
    $selector = Get-TkControl -Name 'ThemeSelect'

    $current = 'Dark'

    if ($ctx.Settings.ContainsKey('Theme') -and $ctx.Settings['Theme'] -in @('Dark', 'Light')) {
        $current = $ctx.Settings['Theme']
    }

    if ($selector) {

        foreach ($name in @('Dark', 'Light')) {
            [void] $selector.Items.Add($name)
        }

        $selector.SelectedItem = $current

        $selector.Add_SelectionChanged({

            $choice = [string] (Get-TkControl -Name 'ThemeSelect').SelectedItem

            if ($choice) {
                Set-TkTheme -Name $choice -Persist | Out-Null
                Set-TkStatus -Text ('{0} theme applied.' -f $choice)
            }
        })
    }

    Set-TkTheme -Name $current | Out-Null
}
