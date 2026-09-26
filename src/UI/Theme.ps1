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
