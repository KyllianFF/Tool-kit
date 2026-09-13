<#
    Toolkit - UI / Dashboard page

    The page the toolkit opens on. It answers the first questions of a support
    call, which machine is this, how is it connected, is anything wrong, and
    hands every problem to the page that deals with it.

    The quick actions are declared as data by Get-TkQuickAction: a page, an
    optional tab, and the function that starts the work. That keeps them
    checkable by a test, and lets the System page show the same set without a
    second copy to drift.
#>

# Last snapshot, kept for the refresh time and for anything that wants the
# figures without reading the machine again.
$script:TkDashboardSnapshot = $null

<#
.SYNOPSIS
    Wires the Dashboard page.
#>
function Initialize-TkDashboardPage {
    [CmdletBinding()]
    param()

    Register-TkClick -Name 'BtnRefreshDashboard' -Action { Update-TkDashboard }
    Register-TkClick -Name 'BtnDashPublicIp'     -Action { Show-TkDashboardPublicIp }

    Add-TkQuickActionPanel -PanelName 'DashQuickActions'
}

<#
.SYNOPSIS
    Reads the machine in the background and redraws the Dashboard.
#>
function Update-TkDashboard {
    [CmdletBinding()]
    param()

    $note = Get-TkControl -Name 'DashHealthNote'

    if ($note) {
        $note.Text = 'Reading the machine...'
    }

    Invoke-TkBackgroundAction -StatusText 'Reading the dashboard...' `
        -ScriptBlock { Get-TkDashboardSnapshot } `
        -OnComplete {
            param($result)

            $snapshot = @($result.Output) | Select-Object -First 1

            if (-not $snapshot) {
                Set-TkStatus -Text 'The dashboard could not be read.'
                return
            }

            $script:TkDashboardSnapshot = $snapshot

            Write-TkDashboardFields -Snapshot $snapshot

            Set-TkStatus -Text ('Dashboard refreshed at {0}.' -f (Get-Date -Format 'HH:mm:ss'))
        }
}

<#
.SYNOPSIS
    Writes a snapshot into the Dashboard controls.

.PARAMETER Snapshot
    Output of Get-TkDashboardSnapshot.
#>
function Write-TkDashboardFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot
    )

    $identity = $Snapshot.Identity
    $os       = $Snapshot.OS
    $adapter  = $Snapshot.Adapter

    $unknown = 'Not available'

    $domain = if (-not $identity) { $unknown }
              elseif ($identity.PartOfDomain) { '{0} (joined)' -f $identity.Domain }
              else { '{0} (workgroup)' -f $identity.Domain }

    $addressing = if (-not $adapter) { $unknown }
                  elseif ([string] $adapter.Dhcp -eq 'Enabled') { 'DHCP' }
                  elseif ([string] $adapter.Dhcp -eq 'Disabled') { 'Static' }
                  else { [string] $adapter.Dhcp }

    # Field name to value, as on the System page: adding a field is one line
    # here and one in the markup.
    $fields = @{
        'DashComputerName' = $env:COMPUTERNAME
        'DashModel'        = if ($identity) { '{0} {1}' -f $identity.Manufacturer, $identity.Model } else { $unknown }
        'DashOs'           = if ($os) { '{0} {1}, build {2}' -f $os.Caption, $os.DisplayVersion, $os.Build } else { $unknown }
        'DashUptime'       = if ($os) { $os.UptimeText } else { $unknown }
        'DashUser'         = if ($identity) { $identity.LoggedOnUser } else { $unknown }
        'DashDomain'       = $domain
        'DashSerial'       = if ($identity) { $identity.SerialNumber } else { $unknown }
        'DashActivation'   = if ($os) { $os.Activation } else { $unknown }

        'DashIpv4'         = if ($adapter -and $adapter.IPv4Address -ne 'None') {
                                 '{0}/{1}' -f $adapter.IPv4Address, $adapter.PrefixLength
                             }
                             else { 'No IPv4 address' }
        'DashAdapter'      = if ($adapter) { '{0}, {1}' -f $adapter.Name, $adapter.LinkSpeed } else { 'No connected adapter' }
        'DashGateway'      = if ($adapter) { $adapter.Gateway } else { $unknown }
        'DashDns'          = if ($adapter -and $adapter.DnsServers) { $adapter.DnsServers } else { 'None' }
        'DashDhcp'         = $addressing
        'DashMac'          = if ($adapter) { $adapter.MacAddress } else { $unknown }
    }

    foreach ($name in $fields.Keys) {

        $control = Get-TkControl -Name $name

        if ($control) {
            $control.Text = [string] $fields[$name]
        }
    }

    # --- Health tiles -----------------------------------------------------
    $panel = Get-TkControl -Name 'DashHealth'

    if ($panel) {

        $panel.Children.Clear()

        foreach ($tile in (ConvertTo-TkDashboardHealth -Snapshot $Snapshot)) {
            [void] $panel.Children.Add((New-TkHealthTile -Tile $tile))
        }
    }

    $note = Get-TkControl -Name 'DashHealthNote'

    if ($note) {
        $note.Text = 'Read at {0}. Click a tile to open the page that deals with it.' -f (Get-Date -Format 'HH:mm')
    }
}

<#
.SYNOPSIS
    Draws one health tile.

.DESCRIPTION
    Tinted and edged by result with an icon, like an audit card, so the row
    reads at a glance and colour is never the only signal. The whole tile is
    the link to the page behind it: a small "details" link would be one more
    thing to find.

.PARAMETER Tile
    Output of New-TkHealthTileData.
#>
function New-TkHealthTile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Tile
    )

    $severityKey = Get-TkSeverityBrushKey -Severity $Tile.Severity

    $border = New-Object System.Windows.Controls.Border
    $border.CornerRadius    = New-Object System.Windows.CornerRadius(7)
    $border.Padding         = New-Object System.Windows.Thickness(12, 10, 12, 10)
    $border.Margin          = New-Object System.Windows.Thickness(0, 0, 8, 0)
    $border.BorderThickness = New-Object System.Windows.Thickness(3, 1, 1, 1)
    $border.Cursor          = [System.Windows.Input.Cursors]::Hand
    $border.Tag             = $Tile.Page
    $border.ToolTip         = 'Open {0}' -f $Tile.Page

    $border.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, $severityKey)

    $tint = Get-TkSeverityTintBrush -Severity $Tile.Severity

    if ($tint) {
        $border.Background = $tint
    }
    else {
        $border.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'SurfaceRaised')
    }

    $stack = New-Object System.Windows.Controls.StackPanel

    # --- Icon and title ---------------------------------------------------
    $header = New-Object System.Windows.Controls.StackPanel
    $header.Orientation = [System.Windows.Controls.Orientation]::Horizontal

    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.Text              = Get-TkSeverityGlyph -Severity $Tile.Severity
    $icon.FontSize          = 13
    $icon.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $icon.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'IconFont')
    $icon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $severityKey)

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text              = $Tile.Title
    $title.FontSize          = 11
    $title.Margin            = New-Object System.Windows.Thickness(6, 0, 0, 0)
    $title.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $title.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

    [void] $header.Children.Add($icon)
    [void] $header.Children.Add($title)
    [void] $stack.Children.Add($header)

    # --- Value ------------------------------------------------------------
    $value = New-Object System.Windows.Controls.TextBlock
    $value.Text         = $Tile.Value
    $value.FontSize     = 16
    $value.FontWeight   = [System.Windows.FontWeights]::SemiBold
    $value.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $value.Margin       = New-Object System.Windows.Thickness(0, 6, 0, 0)
    $value.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextPrimary')

    [void] $stack.Children.Add($value)

    if ($null -ne $Tile.Percent) {

        $bar = New-TkUsageBar -Percent ([double] $Tile.Percent) -Severity $Tile.Severity
        $bar.Margin = New-Object System.Windows.Thickness(0, 6, 0, 0)

        [void] $stack.Children.Add($bar)
    }

    # --- Detail -----------------------------------------------------------
    if ($Tile.Detail) {

        $detail = New-Object System.Windows.Controls.TextBlock
        $detail.Text         = $Tile.Detail
        $detail.FontSize     = 11
        $detail.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $detail.Margin       = New-Object System.Windows.Thickness(0, 4, 0, 0)
        $detail.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

        [void] $stack.Children.Add($detail)
    }

    $border.Child = $stack

    $border.Add_MouseLeftButtonUp({
        # Not named $sender or $eventArgs: both are automatic variables.
        param($clicked, $clickArgs)

        $page = [string] $clicked.Tag

        if ($page) {
            Show-TkPage -Name $page
        }
    })

    return $border
}

<#
.SYNOPSIS
    Returns the quick actions: where each one goes and what it starts.

.DESCRIPTION
    Data rather than handlers, so a test can check that every page, tab and
    function named here exists. A quick action pointing at a renamed tab would
    otherwise open the right page and quietly start nothing.

    Start is the function that begins the work, called with Arguments. Page
    and Tab are where the operator is taken first, so the result appears in
    front of them; an empty Page stays where it is.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkQuickAction {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{
            Id         = 'security-audit'
            Name       = 'Run the security audit'
            Hint       = 'Scores this machine against the CIS and ANSSI controls, with an action on every warning.'
            Glyph      = [string] [char] 0xEA18
            Page       = 'Security'
            TabControl = 'SecurityTabs'
            Tab        = 'Security audit'
            Start      = 'Invoke-TkAuditFromUi'
            Arguments  = @{}
        }
        [pscustomobject] @{
            Id         = 'full-check'
            Name       = 'Run the full diagnostic'
            Hint       = 'Restart state, storage, stability, updates, printing and profiles, in one report.'
            Glyph      = [string] [char] 0xE95E
            Page       = 'Diagnostics'
            TabControl = ''
            Tab        = ''
            Start      = 'Start-TkFullDiagnostic'
            Arguments  = @{}
        }
        [pscustomobject] @{
            Id         = 'support-bundle'
            Name       = 'Collect a support bundle'
            Hint       = 'Everything a ticket needs in one ZIP. Nothing leaves the machine until you send it.'
            Glyph      = [string] [char] 0xE74E
            Page       = 'Diagnostics'
            TabControl = ''
            Tab        = ''
            Start      = 'Invoke-TkSupportBundleFromUi'
            Arguments  = @{}
        }
        [pscustomobject] @{
            Id         = 'windows-update'
            Name       = 'Open Windows Update'
            Hint       = 'Check for updates, resume a pause, or see what waits for a restart.'
            Glyph      = [string] [char] 0xE895
            Page       = ''
            TabControl = ''
            Tab        = ''
            Start      = 'Invoke-TkRemediationFromUi'
            Arguments  = @{ RemediationId = 'open-windows-update' }
        }
    )
}

<#
.SYNOPSIS
    Takes the operator to where a quick action happens, and starts it.

.PARAMETER Id
    Identifier from Get-TkQuickAction.
#>
function Invoke-TkQuickAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Id
    )

    $action = @(Get-TkQuickAction) | Where-Object { $_.Id -eq $Id } | Select-Object -First 1

    if ($null -eq $action) {
        Set-TkStatus -Text ('Unknown quick action: {0}' -f $Id)
        return
    }

    if ($action.Page) {
        Show-TkPage -Name $action.Page
    }

    if ($action.TabControl -and -not (Select-TkTab -TabControlName $action.TabControl -Header $action.Tab)) {

        Write-TkLog -Level Warning -Category 'Interface' -Message (
            'Quick action "{0}": the tab "{1}" was not found.' -f $Id, $action.Tab
        )
    }

    $arguments = $action.Arguments

    & $action.Start @arguments
}

<#
.SYNOPSIS
    Fills a panel with one card per quick action.

.PARAMETER PanelName
    Name of the panel in the markup, a UniformGrid or any other panel.
#>
function Add-TkQuickActionPanel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PanelName
    )

    $panel = Get-TkControl -Name $PanelName

    if ($null -eq $panel) {
        return
    }

    $panel.Children.Clear()

    foreach ($action in (Get-TkQuickAction)) {

        $button = New-Object System.Windows.Controls.Button
        $button.Tag     = $action.Id
        $button.ToolTip = $action.Hint
        $button.SetResourceReference([System.Windows.Controls.Button]::StyleProperty, 'ActionCard')

        $grid = New-Object System.Windows.Controls.Grid

        foreach ($width in @([System.Windows.GridLength]::Auto,
                             (New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)))) {

            $column = New-Object System.Windows.Controls.ColumnDefinition
            $column.Width = $width

            $grid.ColumnDefinitions.Add($column)
        }

        $tile = New-Object System.Windows.Controls.Border
        $tile.SetResourceReference([System.Windows.Controls.Border]::StyleProperty, 'ItemTile')
        $tile.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'Accent')

        $glyph = New-Object System.Windows.Controls.TextBlock
        $glyph.Text = $action.Glyph
        $glyph.SetResourceReference([System.Windows.Controls.TextBlock]::StyleProperty, 'TileGlyph')

        $tile.Child = $glyph

        [System.Windows.Controls.Grid]::SetColumn($tile, 0)
        [void] $grid.Children.Add($tile)

        $text = New-Object System.Windows.Controls.StackPanel
        $text.VerticalAlignment = [System.Windows.VerticalAlignment]::Center

        $name = New-Object System.Windows.Controls.TextBlock
        $name.Text = $action.Name
        $name.SetResourceReference([System.Windows.Controls.TextBlock]::StyleProperty, 'ChoiceTitle')

        $hint = New-Object System.Windows.Controls.TextBlock
        $hint.Text = $action.Hint
        $hint.SetResourceReference([System.Windows.Controls.TextBlock]::StyleProperty, 'ChoiceHint')

        [void] $text.Children.Add($name)
        [void] $text.Children.Add($hint)

        [System.Windows.Controls.Grid]::SetColumn($text, 1)
        [void] $grid.Children.Add($text)

        $button.Content = $grid

        $button.Add_Click({
            param($clicked, $clickArgs)

            Invoke-TkQuickAction -Id ([string] $clicked.Tag)
        })

        [void] $panel.Children.Add($button)
    }
}

<#
.SYNOPSIS
    Asks an outside service for the public address, on request only.

.DESCRIPTION
    Never read with the rest of the Dashboard. It is the one reading that
    leaves the machine, and a tool run on someone else's workstation does not
    contact the internet unless the operator asks it to.
#>
function Show-TkDashboardPublicIp {
    [CmdletBinding()]
    param()

    $label = Get-TkControl -Name 'DashPublicIp'

    if ($label) {
        $label.Text = 'Asking...'
    }

    Invoke-TkBackgroundAction -StatusText 'Asking for the public address...' `
        -ScriptBlock { Get-TkPublicIpAddress } `
        -OnComplete {
            param($result)

            $answer = @($result.Output) | Select-Object -First 1
            $target = Get-TkControl -Name 'DashPublicIp'

            if ($target) {
                $target.Text = if ($answer) { [string] $answer } else { 'Not available' }
            }
        }
}
