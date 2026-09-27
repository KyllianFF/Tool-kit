<#
    Toolkit - UI / Software page

    Renders the application catalog with a search box and a category filter,
    and drives winget in the background.

    Filtering uses the collection view rather than rebuilding the item source,
    so a selection made before typing in the search box survives the filter.
#>

$script:TkApplicationItems = $null
$script:TkApplicationView  = $null

# Path geometries are parsed once and reused. Parsing is the expensive part,
# and the list rebuilds its items on every filter change.
$script:TkAppIconCache = $null

<#
.SYNOPSIS
    Returns the brand icon for a package, or nothing when there is none.

.DESCRIPTION
    Real publisher icons, drawn as vector outlines rather than bitmaps. An
    outline is a few hundred characters of path data, so the whole set costs
    about ninety kilobytes in the single file build, and it stays sharp at
    any scale and on any display. A set of bitmaps would be several megabytes
    for a worse result.

    They are drawn in one colour on the category tile rather than in the
    brand colours. That is a deliberate choice: a hundred and forty brand
    palettes cannot all stay legible against both themes, and a consistent
    silhouette reads faster in a long list than a wall of competing colours.

    The catalogue is deliberately incomplete. Simple Icons carries no icon
    for most Windows utilities, so roughly a third of the applications have
    none. Those fall back to the icon for their category, which is why this
    returns nothing rather than a placeholder.

.OUTPUTS
    System.Windows.Media.Geometry, or $null.
#>
function Get-TkAppIconGeometry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $PackageId
    )

    if ([string]::IsNullOrWhiteSpace($PackageId)) {
        return $null
    }

    if ($null -eq $script:TkAppIconCache) {

        $script:TkAppIconCache = @{}

        $catalog = Import-TkCatalog -Name 'app-icons'

        if ($catalog -and $catalog.icons) {

            foreach ($entry in $catalog.icons.PSObject.Properties) {

                try {
                    $geometry = [System.Windows.Media.Geometry]::Parse($entry.Value.path)

                    # Frozen so the same geometry can be shared by every
                    # element that draws it, across threads, without copying.
                    $geometry.Freeze()

                    $script:TkAppIconCache[$entry.Name] = $geometry
                }
                catch {
                    Write-TkLog -Level Warning -Category 'UI' -Message (
                        'The icon for {0} could not be parsed and was skipped: {1}' -f
                            $entry.Name, $_.Exception.Message
                    )
                }
            }
        }
    }

    if ($script:TkAppIconCache.ContainsKey($PackageId)) {
        return $script:TkAppIconCache[$PackageId]
    }

    return $null
}

<#
.SYNOPSIS
    Returns the icon character shown on an application tile.

.DESCRIPTION
    The fallback for an application with no brand icon, and the icon used
    everywhere outside the software list. Drawn from the Windows icon font,
    which costs nothing to ship: it is part of the operating system, so there
    is no file to bundle and nothing to download.

    This one says what kind of application it is rather than which one, and
    the tile colour separates the categories. Where a real publisher icon
    exists, Get-TkAppIconGeometry supplies it instead.

    Every code point below was chosen by rendering the font and looking at
    it. An unverified one draws an empty box.

.OUTPUTS
    System.String
#>
function Get-TkCategoryGlyph {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Key
    )

    $glyphs = @{
        'browsers'      = 0xE774  # globe
        'communication' = 0xE8BD  # speech bubble
        'documents'     = 0xE8A5  # page
        'development'   = 0xE943  # braces
        'games'         = 0xE7FC  # game controller
        'microsoft'     = 0xECAA  # window panes
        'multimedia'    = 0xEC4F  # note
        'protools'      = 0xE719  # briefcase
        'networking'    = 0xEC05  # antenna
        'security'      = 0xEA18  # shield
        'selfhosted'    = 0xE968  # server
        'utilities'     = 0xEC7A  # crossed tools
    }

    $point = if ($Key -and $glyphs.ContainsKey($Key)) { $glyphs[$Key] } else { 0xECA5 }

    return [string] [char] $point
}

<#
.SYNOPSIS
    Returns the tile colour for a category.

.DESCRIPTION
    One colour per category, so the eye can group a filtered list without
    reading it. Deliberately fixed rather than themed: these are identity
    colours, and they have to stay recognisable in both palettes. Every one is
    dark enough to carry a white glyph.

.OUTPUTS
    System.Windows.Media.SolidColorBrush
#>
function Get-TkTileBrush {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Key
    )

    $palette = @{
        'browsers'      = '#2F6FD0'
        'communication' = '#2E8B7A'
        'documents'     = '#8A5AA8'
        'development'   = '#3B6EA5'
        'games'         = '#A8484F'
        'microsoft'     = '#2C7BB6'
        'multimedia'    = '#B06A2C'
        'protools'      = '#5B6B8C'
        'networking'    = '#2E7D6B'
        'security'      = '#9B3B4A'
        'selfhosted'    = '#4A7A46'
        'utilities'     = '#6B6B7B'

        # Used by the Tweaks and Fixes lists, which share the tile.
        'tweak'         = '#4A5A8C'
        'fix-low'       = '#4A7A46'
        'fix-medium'    = '#B06A2C'
        'fix-high'      = '#9B3B4A'
    }

    $colour = if ($Key -and $palette.ContainsKey($Key)) { $palette[$Key] } else { '#5B6B8C' }

    $converter = New-Object System.Windows.Media.BrushConverter
    $brush     = $converter.ConvertFromString($colour)

    $brush.Freeze()

    return $brush
}

<#
.SYNOPSIS
    Wires the Software page and loads the catalog.
#>
function Initialize-TkSoftwarePage {
    [CmdletBinding()]
    param()

    $catalog = Import-TkCatalog -Name 'applications'

    if (-not $catalog) {
        Set-TkOutput -ControlName 'WingetStatusText' -Text 'The application catalog could not be loaded.'
        return
    }

    # --- Item source ------------------------------------------------------
    $items = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'

    $categoryNames = @{}

    foreach ($category in $catalog.categories) {
        $categoryNames[$category.id] = $category.name
    }

    foreach ($application in $catalog.applications) {

        $iconGeometry = Get-TkAppIconGeometry -PackageId $application.packageId

        $items.Add([pscustomobject]@{
            IsSelected   = $false
            Id           = $application.id
            Name         = $application.name
            Description  = $application.description
            PackageId    = $application.packageId
            Category     = $application.category
            CategoryName = $categoryNames[$application.category]
            StateText    = ''

            # The real publisher icon where one exists, and the icon for the
            # category where it does not. The template shows whichever of the
            # two is present, so both have to be here.
            IconGeometry = $iconGeometry
            HasIcon      = ($null -ne $iconGeometry)
            Glyph        = Get-TkCategoryGlyph -Key $application.category
            TileBrush    = Get-TkTileBrush     -Key $application.category
        })
    }

    $script:TkApplicationItems = $items

    $list = Get-TkControl -Name 'SoftwareList'

    if ($list) {
        $list.ItemsSource = $items
    }

    $script:TkApplicationView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($items)
    $script:TkApplicationView.Filter = [Predicate[object]] {
        param($item)
        Test-TkApplicationVisible -Item $item
    }

    # --- Category filter --------------------------------------------------
    $combo = Get-TkControl -Name 'SoftwareCategory'

    if ($combo) {

        [void] $combo.Items.Add('All categories')

        foreach ($category in ($catalog.categories | Sort-Object -Property name)) {
            [void] $combo.Items.Add($category.name)
        }

        $combo.SelectedIndex = 0
        $combo.Add_SelectionChanged({ $script:TkApplicationView.Refresh() })
    }

    $search = Get-TkControl -Name 'SoftwareSearch'

    if ($search) {
        $search.Add_TextChanged({ $script:TkApplicationView.Refresh() })
    }

    # --- Actions ----------------------------------------------------------
    Register-TkClick -Name 'BtnInstallSelected'   -Action { Invoke-TkSoftwareAction -Action 'Install' }
    Register-TkClick -Name 'BtnUninstallSelected' -Action { Invoke-TkSoftwareAction -Action 'Uninstall' }
    Register-TkClick -Name 'BtnRefreshInstalled'  -Action { Update-TkInstalledState }
    Register-TkClick -Name 'BtnUpgradeAll'        -Action { Invoke-TkUpgradeAll }

    Register-TkClick -Name 'BtnClearSelection' -Action {

        foreach ($item in $script:TkApplicationItems) {
            $item.IsSelected = $false
        }

        $script:TkApplicationView.Refresh()
        Set-TkStatus -Text 'Selection cleared.'
    }

    # Two columns when the window is wide enough for two.
    if ($list) {
        $list.Add_SizeChanged({ Update-TkSoftwareColumns })
    }

    # Read what is already on the machine the first time the page is opened.
    # Without this the list claims every application is available until
    # somebody presses Refresh, which is a wrong answer rather than a missing
    # one.
    Register-TkFirstShow -PageName 'Software' -Action { Update-TkInstalledState }

    # --- Store apps tab ---------------------------------------------------
    Initialize-TkStoreAppsTab

    # --- Configuration profiles -------------------------------------------
    # The same two buttons head the Software and the Tweaks pages: a profile
    # covers both lists.
    foreach ($page in @('Software', 'Tweaks')) {
        Register-TkClick -Name ('BtnSaveConfigProfile{0}' -f $page) -Action { Save-TkConfigProfileFromUi }
        Register-TkClick -Name ('BtnLoadConfigProfile{0}' -f $page) -Action { Import-TkConfigProfileFromUi }
    }

    Update-TkWingetStatusText
}

<#
.SYNOPSIS
    Sets the application list to one or two columns for the current width.

.DESCRIPTION
    Two columns halve the scrolling through a hundred and forty entries, but
    only while each card still has room for a name and a line of description.
    Below the threshold the second column would turn both into ellipses, so
    the list drops back to one.

    The panel is found through the visual tree because it is declared in an
    ItemsPanelTemplate and so has no name the window can resolve.
#>
function Update-TkSoftwareColumns {
    [CmdletBinding()]
    param()

    $list = Get-TkControl -Name 'SoftwareList'

    if ($null -eq $list) {
        return
    }

    $panel = Find-TkVisualChild -Parent $list -TypeName 'UniformGrid'

    if ($null -eq $panel) {
        return
    }

    # Measured against the card contents: below this a two column card cannot
    # show a description without trimming it to nothing.
    $columns = if ($list.ActualWidth -ge 860) { 2 } else { 1 }

    if ($panel.Columns -ne $columns) {
        $panel.Columns = $columns
    }
}

<#
.SYNOPSIS
    Decides whether a catalog entry passes the current filters.

.OUTPUTS
    System.Boolean
#>
function Test-TkApplicationVisible {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    # A selected item stays visible whatever the filter, so the user can see
    # what is about to be installed.
    if ($Item.IsSelected) {
        return $true
    }

    $combo = Get-TkControl -Name 'SoftwareCategory'

    if ($combo -and $combo.SelectedIndex -gt 0) {

        if ($Item.CategoryName -ne [string] $combo.SelectedItem) {
            return $false
        }
    }

    $search = Get-TkControl -Name 'SoftwareSearch'

    if ($search -and -not [string]::IsNullOrWhiteSpace($search.Text)) {

        $term = $search.Text.Trim()

        $haystack = '{0} {1} {2}' -f $Item.Name, $Item.Description, $Item.PackageId

        if ($haystack -notlike ('*{0}*' -f $term)) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Reports whether winget is usable, in the page header.
#>
function Update-TkWingetStatusText {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Checking winget...' `
        -ScriptBlock { Get-TkWingetStatus } `
        -OnComplete {
            param($result)

            $status  = @($result.Output) | Select-Object -First 1
            $control = Get-TkControl -Name 'WingetStatusText'

            if (-not $control -or -not $status) {
                return
            }

            if ($status.Available) {
                $control.Text = 'winget {0} - installs come from the official Microsoft source only.' -f $status.Version
            }
            else {
                $control.Text = $status.Message
            }
        }
}

<#
.SYNOPSIS
    Installs or removes the selected applications.

.PARAMETER Action
    Install or Uninstall.
#>
function Invoke-TkSoftwareAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Install', 'Uninstall')]
        [string] $Action
    )

    $selected = @($script:TkApplicationItems | Where-Object { $_.IsSelected })

    if ($selected.Count -eq 0) {
        Set-TkStatus -Text 'Nothing is selected.'
        return
    }

    # The warning used to say the opposite, that installs need elevation and
    # will fail without it. That is not how winget works: it is meant to run
    # as the signed in user, Windows raises its own prompt for an installer
    # that needs rights, and a package that installs into the user profile
    # needs none at all. Requiring elevation only hid those prompts and shut
    # standard users out of installs they were entitled to make.
    if (Test-TkIsElevated) {

        Write-TkLog -Level Information -Category 'Software' -Message (
            'Installing from an elevated instance, so Windows will not prompt for rights. ' +
            'Anything installed now goes in machine wide where the package allows it.'
        )
    }

    $names = ($selected | ForEach-Object { $_.Name }) -join ', '

    $confirmed = Confirm-TkAction -Title ('{0} {1} application(s)' -f $Action, $selected.Count) -Message (
        "{0}:`n`n{1}`n`nContinue?" -f $Action, $names
    )

    if (-not $confirmed) {
        return
    }

    $packageIds = @($selected | ForEach-Object { $_.PackageId })

    # Named parameters, not a positional list: a positional @($ids, $verb) is
    # flattened by PowerShell into one argument per identifier followed by the
    # verb, and the script block then binds a single identifier to $ids.
    Invoke-TkBackgroundAction -StatusText ('{0}ing {1} application(s)...' -f $Action, $packageIds.Count) `
        -ParameterList @{ ids = $packageIds; verb = $Action } `
        -ScriptBlock {
            param($ids, $verb)

            $results = @()

            foreach ($id in $ids) {

                if ($verb -eq 'Install') {
                    $ok = Install-TkWingetPackage -PackageId $id -Confirm:$false
                }
                else {
                    $ok = Uninstall-TkWingetPackage -PackageId $id -Confirm:$false
                }

                $results += [pscustomobject]@{ PackageId = $id; Success = $ok }
            }

            return $results
        } `
        -OnComplete {
            param($result)

            $rows      = @($result.Output)
            $succeeded = @($rows | Where-Object { $_.Success }).Count

            Set-TkStatus -Text ('{0} of {1} package(s) completed successfully.' -f $succeeded, $rows.Count)

            Update-TkInstalledState
        }
}

<#
.SYNOPSIS
    Upgrades every package winget reports as upgradable.
#>
function Invoke-TkUpgradeAll {
    [CmdletBinding()]
    param()

    $confirmed = Confirm-TkAction -Title 'Upgrade everything' -Message (
        "Upgrade every package winget reports as out of date?`n`nThis can restart applications and takes a while on a machine that has not been updated recently."
    )

    if (-not $confirmed) {
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Upgrading packages...' `
        -ScriptBlock {

            $upgradable = Get-TkUpgradablePackage

            if ($upgradable.Count -eq 0) {
                return 'Everything is up to date.'
            }

            $results = Install-TkPackageBatch -PackageId @($upgradable | ForEach-Object { $_.Id }) -Confirm:$false

            return ('{0} of {1} package(s) upgraded.' -f
                @($results | Where-Object { $_.Success }).Count, $results.Count)
        } `
        -OnComplete {
            param($result)

            Set-TkStatus -Text ([string] (@($result.Output) | Select-Object -Last 1))
            Update-TkInstalledState
        }
}

<#
.SYNOPSIS
    Marks catalog entries that are already installed.
#>
function Update-TkInstalledState {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading installed packages...' `
        -ScriptBlock {

            # HashSet does not survive the runspace boundary well; return a
            # plain array and rebuild the lookup on the UI thread.
            return @(Get-TkInstalledPackageId)
        } `
        -OnComplete {
            param($result)

            $installed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

            foreach ($id in @($result.Output)) {

                if ($id) {
                    [void] $installed.Add([string] $id)
                }
            }

            foreach ($item in $script:TkApplicationItems) {

                $item.StateText = if ($installed.Contains($item.PackageId)) { 'Installed' } else { '' }
            }

            # ItemsSource is reassigned because the item objects do not raise
            # change notifications on their own.
            $list = Get-TkControl -Name 'SoftwareList'

            if ($list) {
                $list.Items.Refresh()
            }

            Set-TkStatus -Text ('{0} installed package(s) detected.' -f $installed.Count)
        }
}


<#
.SYNOPSIS
    Wires the Store apps tab: the list, its filter and its two buttons.

.DESCRIPTION
    The apps are read the first time the tab is opened: Get-AppxPackage takes
    a moment, and most visits to the Software page are for winget.
#>
function Initialize-TkStoreAppsTab {
    [CmdletBinding()]
    param()

    $script:TkStoreAppItems  = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $script:TkStoreAppLoaded = $false

    $list = Get-TkControl -Name 'StoreAppList'

    if ($list) {
        $list.ItemsSource = $script:TkStoreAppItems
    }

    $script:TkStoreAppView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:TkStoreAppItems)
    $script:TkStoreAppView.Filter = [Predicate[object]] {
        param($item)
        Test-TkStoreAppVisible -Item $item
    }

    $filter = Get-TkControl -Name 'StoreAppFilter'

    if ($filter) {
        foreach ($choice in @('All listed apps', 'Rarely used', 'Optional')) { [void] $filter.Items.Add($choice) }
        $filter.SelectedIndex = 0
        $filter.Add_SelectionChanged({ $script:TkStoreAppView.Refresh() })
    }

    $search = Get-TkControl -Name 'StoreAppSearch'

    if ($search) {
        $search.Add_TextChanged({ $script:TkStoreAppView.Refresh() })
    }

    Register-TkClick -Name 'BtnRemoveStoreApps'  -Action { Invoke-TkRemoveStoreAppsFromUi }
    Register-TkClick -Name 'BtnRefreshStoreApps' -Action { Update-TkStoreAppList }

    $tabs = Get-TkControl -Name 'SoftwareTabs'

    if ($tabs) {
        $tabs.Add_SelectionChanged({
            param($source, $routed)

            # The event also bubbles up from the lists and boxes inside the tabs.
            if ($routed.OriginalSource -ne $source) { return }

            $tab = $source.SelectedItem

            if ($tab -and [string] $tab.Header -eq 'Store apps' -and -not $script:TkStoreAppLoaded) {
                Update-TkStoreAppList
            }
        })
    }
}

<#
.SYNOPSIS
    Decides whether a Store app passes the filter and the search.

.OUTPUTS
    System.Boolean
#>
function Test-TkStoreAppVisible {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    if ($Item.IsSelected) {
        return $true
    }

    switch ([string] (Get-TkSelectedText -Name 'StoreAppFilter')) {
        'Rarely used' { if ($Item.Category -ne 'bloat')    { return $false } }
        'Optional'    { if ($Item.Category -ne 'optional') { return $false } }
    }

    $search = Get-TkControl -Name 'StoreAppSearch'

    if ($search -and -not [string]::IsNullOrWhiteSpace($search.Text)) {
        if (('{0} {1} {2}' -f $Item.Label, $Item.Description, $Item.Name) -notlike ('*{0}*' -f $search.Text.Trim())) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Reads the catalogue apps installed for this account into the list.
#>
function Update-TkStoreAppList {
    [CmdletBinding()]
    param()

    $status = Get-TkControl -Name 'StoreAppStatus'

    if ($status) {
        $status.Text = 'Reading the installed Store apps...'
    }

    Invoke-TkBackgroundAction -StatusText 'Reading the Store apps...' `
        -ScriptBlock { Get-TkStoreApp } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Apps'] } | Select-Object -First 1

            if (-not $report) {
                return
            }

            $script:TkStoreAppLoaded = $true
            $script:TkStoreAppItems.Clear()

            foreach ($app in @($report.Apps)) {
                $script:TkStoreAppItems.Add([pscustomobject] @{
                    IsSelected  = $false
                    Name        = $app.Name
                    Label       = $app.Label
                    Category    = $app.Category
                    Description = $app.Description
                    Version     = $app.Version
                    Badge       = if ($app.Category -eq 'bloat') { 'Rarely used' } else { 'Optional' }
                    Glyph       = [string] [char] 0xE719
                    TileBrush   = Get-TkTileBrush -Key 'microsoft'
                })
            }

            $apps     = @($report.Apps)
            $rarely   = @($apps | Where-Object { $_.Category -eq 'bloat' }).Count
            $label    = Get-TkControl -Name 'StoreAppStatus'

            if ($label) {
                $label.Text = if (-not $report.Available) {
                    $report.Reason
                }
                elseif ($apps.Count -eq 0) {
                    'None of the apps this toolkit removes is installed for this account.'
                }
                else {
                    '{0} app(s) from the list are installed: {1} rarely used, {2} optional. Tick the ones to remove.' -f $apps.Count, $rarely, ($apps.Count - $rarely)
                }
            }
        }
}

<#
.SYNOPSIS
    Removes the ticked Store apps, after a confirmation and a single UAC prompt.
#>
function Invoke-TkRemoveStoreAppsFromUi {
    [CmdletBinding()]
    param()

    $selected = @($script:TkStoreAppItems | Where-Object { $_.IsSelected })

    if ($selected.Count -eq 0) {
        Set-TkStatus -Text 'Tick the apps to remove first.'
        return
    }

    $confirmed = Confirm-TkAction -Title 'Remove Store apps' -Message (
        "Remove {0} app(s) for every account on this PC, new accounts included?`n`n{1}`n`nAn app removed by mistake comes back from the Microsoft Store." -f
            $selected.Count, ((@($selected | ForEach-Object { $_.Label })) -join ', ')
    )

    if (-not $confirmed) {
        return
    }

    # A standard user gets a single UAC prompt for this action; an elevated
    # instance runs it in place.
    $status = if (Test-TkIsElevated) { 'Removing the Store apps...' } else { 'Waiting for administrator consent...' }

    Start-TkPrivilegedAction -Name 'RemoveStoreApps' -StatusText $status -Parameters @{
        Names = @($selected | ForEach-Object { $_.Name })
    } -OnResult {
        param($outcome)
        $null = $outcome
        Update-TkStoreAppList
    }
}

# ---------------------------------------------------------------------------
# Configuration profiles
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Saves the ticked applications and tweaks to a profile file.
#>
function Save-TkConfigProfileFromUi {
    [CmdletBinding()]
    param()

    $applications = @($script:TkApplicationItems | Where-Object { $_ -and $_.IsSelected } | ForEach-Object { [string] $_.Id })
    $tweaks       = @($script:TkTweakItems | Where-Object { $_ -and $_.IsSelected } | ForEach-Object { [string] $_.Id })

    if ($applications.Count -eq 0 -and $tweaks.Count -eq 0) {
        Set-TkStatus -Text 'Tick applications on Software or tweaks on Tweaks first: the profile saves what is ticked.'
        return
    }

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title            = 'Save a configuration profile'
    $dialog.Filter           = 'Toolkit profile (*.json)|*.json'
    $dialog.FileName         = 'workstation-profile.json'
    $dialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')

    if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
        return
    }

    $name    = [System.IO.Path]::GetFileNameWithoutExtension($dialog.FileName)
    $configProfile = New-TkConfigProfile -Name $name -ApplicationId $applications -TweakId $tweaks

    try {
        [System.IO.File]::WriteAllText($dialog.FileName, ($configProfile | ConvertTo-Json -Depth 4),
                                       (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        Write-TkLog -Level Error -Category 'Profiles' -Message ('The profile could not be written: {0}' -f $_.Exception.Message)
        return
    }

    Add-TkJournalEntry -Name 'Configuration profile saved' -Category 'Software' -Detail (
        '{0}: {1} application(s), {2} tweak(s)' -f $dialog.FileName, $applications.Count, $tweaks.Count
    )

    Set-TkStatus -Text ('Profile saved: {0} application(s) and {1} tweak(s) in {2}' -f $applications.Count, $tweaks.Count, $dialog.FileName)
}

<#
.SYNOPSIS
    Ticks the applications and tweaks of a saved profile.

.DESCRIPTION
    Only ticks: installing and applying stay on their own buttons, with their
    confirmation and their elevation. What the catalogues of this toolkit do
    not know is left out and named.
#>
function Import-TkConfigProfileFromUi {
    [CmdletBinding()]
    param()

    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title            = 'Load a configuration profile'
    $dialog.Filter           = 'Toolkit profile (*.json)|*.json|All files (*.*)|*.*'
    $dialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')

    if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
        return
    }

    try {
        if ((Get-Item -LiteralPath $dialog.FileName -ErrorAction Stop).Length -gt 256KB) {
            Set-TkStatus -Text 'The file is too large to be a toolkit profile.'
            return
        }

        $text = [System.IO.File]::ReadAllText($dialog.FileName)
    }
    catch {
        Set-TkStatus -Text ('The profile could not be read: {0}' -f $_.Exception.Message)
        return
    }

    $configProfile = Read-TkConfigProfile -Json $text `
        -KnownApplication @($script:TkApplicationItems | ForEach-Object { [string] $_.Id }) `
        -KnownTweak @($script:TkTweakItems | ForEach-Object { [string] $_.Id })

    if ($configProfile.Error) {
        Show-TkDialog -Title 'Load profile' -Kind 'Warning' -NoticeOnly -Message $configProfile.Error | Out-Null
        return
    }

    $ticked = Set-TkConfigProfileSelection -ConfigProfile $configProfile `
        -ApplicationItem @($script:TkApplicationItems) -TweakItem @($script:TkTweakItems) -Confirm:$false

    if ($script:TkApplicationView) { $script:TkApplicationView.Refresh() }
    if ($script:TkTweakView)       { $script:TkTweakView.Refresh() }

    $message = ('Profile "{0}": {1} application(s) ticked on Software and {2} tweak(s) ticked on Tweaks.' -f $configProfile.Name, $ticked.Applications, $ticked.Tweaks) +
               "`n`nNothing is installed or applied yet: review the ticks, then use Install selected and Apply selected."

    if (@($configProfile.Unknown).Count -gt 0) {
        $message += "`n`nLeft out, unknown to this toolkit: {0}." -f (@($configProfile.Unknown) -join ', ')
    }

    Show-TkDialog -Title 'Profile loaded' -Kind 'Information' -NoticeOnly -Message $message | Out-Null
    Set-TkStatus -Text ('Profile loaded: {0} application(s), {1} tweak(s) ticked.' -f $ticked.Applications, $ticked.Tweaks)
}
