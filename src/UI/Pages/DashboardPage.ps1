<#
    Toolkit - UI / Dashboard page

    The page the toolkit opens on. It answers the first questions of a support
    call, which machine is this, how is it connected, is anything wrong, and
    hands every problem to the page that deals with it.

    Each card reads on its own, at the same time as the others, and shows that
    it is reading until its answer arrives. A page that opens empty and stays
    empty for ten seconds reads as broken, however correct it is once it fills.

    The quick actions are declared as data by Get-TkQuickAction: a page, an
    optional tab, and the function that starts the work. That keeps them
    checkable by a test, and lets the System page show the same set without a
    second copy to drift.
#>

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
    Reads the machine in three parallel parts and fills each card as it lands.
#>
function Update-TkDashboard {
    [CmdletBinding()]
    param()

    foreach ($card in @('DashWorkstation', 'DashNetwork', 'DashHealthCard')) {
        Set-TkCardLoading -Name $card -Loading $true
    }

    Invoke-TkBackgroundAction -StatusText 'Reading the workstation...' `
        -ScriptBlock { Get-TkDashboardWorkstation } `
        -OnComplete {
            param($result)

            Write-TkDashboardWorkstation -Part (@($result.Output) | Select-Object -First 1)
            Set-TkCardLoading -Name 'DashWorkstation' -Loading $false
        }

    Invoke-TkBackgroundAction -StatusText 'Reading the network adapters and routes...' `
        -ScriptBlock { Get-TkDashboardNetwork } `
        -OnComplete {
            param($result)

            Write-TkDashboardNetwork -Part (@($result.Output) | Select-Object -First 1)
            Set-TkCardLoading -Name 'DashNetwork' -Loading $false
        }

    Invoke-TkBackgroundAction -StatusText 'Reading restart state, updates, disks and battery...' `
        -ScriptBlock { Get-TkDashboardHealthData } `
        -OnComplete {
            param($result)

            Write-TkDashboardHealth -Part (@($result.Output) | Select-Object -First 1)
            Set-TkCardLoading -Name 'DashHealthCard' -Loading $false
        }
}

<#
.SYNOPSIS
    Writes a whole snapshot at once, for a console session or a render.

.PARAMETER Snapshot
    Output of Get-TkDashboardSnapshot.
#>
function Write-TkDashboardFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot
    )

    Write-TkDashboardWorkstation -Part $Snapshot
    Write-TkDashboardNetwork     -Part $Snapshot
    Write-TkDashboardHealth      -Part $Snapshot

    foreach ($card in @('DashWorkstation', 'DashNetwork', 'DashHealthCard')) {
        Set-TkCardLoading -Name $card -Loading $false
    }
}

<#
.SYNOPSIS
    Fills the Workstation card.

.PARAMETER Part
    Anything with Identity and OS. Null when the part could not be read.
#>
function Write-TkDashboardWorkstation {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Part
    )

    $identity = if ($Part) { $Part.Identity } else { $null }
    $os       = if ($Part) { $Part.OS } else { $null }

    # The readings arrive in English from the background task; what is
    # written here is in the language of the interface.
    $unknown = Get-TkText 'Not available'

    $domain = if (-not $identity) { $unknown }
              elseif ($identity.PartOfDomain) { Get-TkText -Text '{0} (joined)' -ArgumentList $identity.Domain }
              else { Get-TkText -Text '{0} (workgroup)' -ArgumentList $identity.Domain }

    Set-TkFieldText -Field @{
        'DashComputerName' = $env:COMPUTERNAME
        'DashModel'        = if ($identity) { '{0} {1}' -f $identity.Manufacturer, $identity.Model } else { $unknown }
        'DashOs'           = if ($os) { Get-TkText -Text '{0} {1}, build {2}' -ArgumentList $os.Caption, $os.DisplayVersion, $os.Build } else { $unknown }
        'DashUptime'       = if ($os) { ConvertTo-TkLocalText -Text $os.UptimeText } else { $unknown }
        'DashUser'         = if ($identity) { ConvertTo-TkLocalText -Text $identity.LoggedOnUser -Exact } else { $unknown }
        'DashDomain'       = $domain
        'DashSerial'       = if ($identity) { ConvertTo-TkLocalText -Text $identity.SerialNumber -Exact } else { $unknown }
        'DashActivation'   = if ($os) { ConvertTo-TkLocalText -Text $os.Activation -Exact } else { $unknown }
    }
}

<#
.SYNOPSIS
    Fills the Network card.

.PARAMETER Part
    Anything with Adapter and Adapters. Null when the part could not be read.
#>
function Write-TkDashboardNetwork {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Part
    )

    $adapter  = if ($Part) { $Part.Adapter } else { $null }
    # @() around the if, not inside it. An if statement whose branch yields an
    # empty array yields nothing at all, so the variable became null, and
    # passed on as the adapter list that null failed the completion handler:
    # the log recorded it, and the card was left half written.
    $adapters = @(if ($Part) { $Part.Adapters | Where-Object { $null -ne $_ } })

    $unknown    = Get-TkText 'Not available'
    $hasAddress = ($null -ne $adapter -and $adapter.IPv4Address -and $adapter.IPv4Address -ne 'None')

    $addressing = if (-not $adapter) { $unknown }
                  elseif ([string] $adapter.Dhcp -eq 'Enabled') { 'DHCP' }
                  elseif ([string] $adapter.Dhcp -eq 'Disabled') { Get-TkText 'Static' }
                  else { [string] $adapter.Dhcp }

    $adapterLine = if (-not $adapter) { Get-TkText 'No adapter has a usable IPv4 address' }
                   elseif ($adapter.Gateway -eq 'None') { Get-TkText -Text '{0}, {1}, no default gateway' -ArgumentList $adapter.Name, $adapter.LinkSpeed }
                   else { '{0}, {1}' -f $adapter.Name, $adapter.LinkSpeed }

    Set-TkFieldText -Field @{
        'DashIpv4'    = if ($hasAddress) { '{0}/{1}' -f $adapter.IPv4Address, $adapter.PrefixLength } else { Get-TkText 'Not connected' }
        'DashAdapter' = $adapterLine
        'DashGateway' = if ($adapter) { ConvertTo-TkLocalText -Text ([string] $adapter.Gateway) -Exact } else { $unknown }
        'DashDns'     = if ($adapter -and $adapter.DnsServers) { $adapter.DnsServers } else { Get-TkText 'None' }
        'DashDhcp'    = $addressing
        'DashMac'     = if ($adapter) { $adapter.MacAddress } else { $unknown }
    }

    # The other adapters in one line, and no line at all when there are none.
    $others = Get-TkSecondaryAdapterSummary -Adapter $adapters -Primary $adapter
    $label  = Get-TkControl -Name 'DashOtherAdapters'

    if ($label) {
        $label.Text       = $others
        $label.Visibility = if ($others) { [System.Windows.Visibility]::Visible }
                            else { [System.Windows.Visibility]::Collapsed }
    }
}

<#
.SYNOPSIS
    Draws the health tiles.

.PARAMETER Part
    Anything with Reboot, LastHotFix, Volumes, Disks and Battery. Null when the
    part could not be read.
#>
function Write-TkDashboardHealth {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Part
    )

    $panel = Get-TkControl -Name 'DashHealth'
    $note  = Get-TkControl -Name 'DashHealthNote'

    if ($panel) {
        $panel.Children.Clear()
    }

    if ($null -eq $Part) {

        if ($note) {
            $note.Text = Get-TkText 'The health of this machine could not be read. The log has the reason.'
        }

        return
    }

    if ($panel) {
        foreach ($tile in (ConvertTo-TkDashboardHealth -Snapshot $Part)) {
            [void] $panel.Children.Add((New-TkHealthTile -Tile $tile))
        }
    }

    if ($note) {
        $note.Text = Get-TkText -Text 'Read at {0}. Click a tile to open the entry that deals with it.' -ArgumentList (Get-Date -Format 'HH:mm')
    }
}

<#
.SYNOPSIS
    Draws one health tile.

.DESCRIPTION
    Tinted and edged by result with an icon, like an audit card, so the row
    reads at a glance and colour is never the only signal. The whole tile is
    the link to the entry behind it: a small "details" link would be one more
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
    $border.CornerRadius    = New-Object System.Windows.CornerRadius(12)
    $border.Padding         = New-Object System.Windows.Thickness(12, 10, 12, 10)
    # The same gap below as to the right: the tiles wrap onto a second row.
    $border.Margin          = New-Object System.Windows.Thickness(0, 0, 8, 8)
    $border.BorderThickness = New-Object System.Windows.Thickness(3, 1, 1, 1)
    $border.Cursor          = [System.Windows.Input.Cursors]::Hand
    $border.Tag             = $Tile

    # The tile is built in English, by code the reports share; it is shown in
    # the language of the interface. Its Tag keeps the English, which opens it.
    $page = ConvertTo-TkLocalText -Text ([string] $Tile.Page) -Exact

    $border.ToolTip = if ($Tile.Choice) { Get-TkText -Text 'Open {0} on the {1} page' -ArgumentList (ConvertTo-TkLocalText -Text ([string] $Tile.Choice) -Exact), $page }
                      else { Get-TkText -Text 'Open the {0} page' -ArgumentList $page }

    $border.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, $severityKey)

    Set-TkResourceBrush -Element $border -Property Background -Key (Get-TkSeverityTintKey -Severity $Tile.Severity)

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
    $title.Text              = ConvertTo-TkLocalText -Text ([string] $Tile.Title)
    $title.FontSize          = 11
    $title.Margin            = New-Object System.Windows.Thickness(6, 0, 0, 0)
    $title.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $title.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

    [void] $header.Children.Add($icon)
    [void] $header.Children.Add($title)
    [void] $stack.Children.Add($header)

    # --- Value ------------------------------------------------------------
    $value = New-Object System.Windows.Controls.TextBlock
    $value.Text         = ConvertTo-TkLocalText -Text ([string] $Tile.Value)
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
        $detail.Text         = ConvertTo-TkLocalText -Text ([string] $Tile.Detail)
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

        if ($clicked.Tag) {
            Open-TkHealthTileDestination -Tile $clicked.Tag
        }
    })

    return $border
}

<#
.SYNOPSIS
    Opens the page a tile is about, and the entry on it.

.DESCRIPTION
    The page alone was not enough: the battery tile landed on the Hardware page
    with the keyboard test selected, and the reader still had to find the
    battery. Selecting the entry also runs it, the way clicking it would.

.PARAMETER Tile
    Output of New-TkHealthTileData.
#>
function Open-TkHealthTileDestination {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Tile
    )

    Show-TkPage -Name $Tile.Page

    # The tab first: an entry in a tab that is not selected is selected, and
    # runs, out of sight.
    if ($Tile.TabControl -and -not (Select-TkTab -TabControlName $Tile.TabControl -Header $Tile.Tab)) {

        Write-TkLog -Level Warning -Category 'Interface' -Message (
            'Health tile "{0}": no tab titled "{1}" in {2}.' -f $Tile.Title, $Tile.Tab, $Tile.TabControl
        )
    }

    if ($Tile.List -and -not (Select-TkListChoice -ListName $Tile.List -Title $Tile.Choice)) {

        Write-TkLog -Level Warning -Category 'Interface' -Message (
            'Health tile "{0}": no entry titled "{1}" in {2}.' -f $Tile.Title, $Tile.Choice, $Tile.List
        )
    }
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
            TabControl = 'DiagnosticsTabs'
            Tab        = 'Reports'
            Start      = 'Start-TkFullDiagnostic'
            Arguments  = @{}
        }
        [pscustomobject] @{
            Id         = 'support-bundle'
            Name       = 'Collect a support bundle'
            Hint       = 'Everything a ticket needs in one ZIP. Nothing leaves the machine until you send it.'
            Glyph      = [string] [char] 0xE74E
            Page       = 'Diagnostics'
            TabControl = 'DiagnosticsTabs'
            Tab        = 'Reports'
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
        $button.ToolTip = Get-TkText $action.Hint
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
        $name.Text = Get-TkText $action.Name
        $name.SetResourceReference([System.Windows.Controls.TextBlock]::StyleProperty, 'ChoiceTitle')

        $hint = New-Object System.Windows.Controls.TextBlock
        $hint.Text = Get-TkText $action.Hint
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
        $label.Text = Get-TkText 'Asking...'
    }

    Invoke-TkBackgroundAction -StatusText 'Asking for the public address...' `
        -ScriptBlock { Get-TkPublicIpAddress } `
        -OnComplete {
            param($result)

            $answer = @($result.Output) | Select-Object -First 1
            $target = Get-TkControl -Name 'DashPublicIp'

            if ($target) {
                $target.Text = if ($answer) { [string] $answer } else { Get-TkText 'Not available' }
            }
        }
}
