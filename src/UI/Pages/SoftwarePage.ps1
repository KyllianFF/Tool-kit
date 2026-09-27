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

    # --- Installed Apps tab -----------------------------------------------
    Initialize-TkInstalledAppsTab

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
    Wires the Installed Apps tab: the list, its filter, search, sort and buttons.

.DESCRIPTION
    The applications are read the first time the tab is opened: asking
    winget and every package manager takes a while, and most visits to the
    Software page are to install something.
#>
function Initialize-TkInstalledAppsTab {
    [CmdletBinding()]
    param()

    $script:TkInstalledAppItems  = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $script:TkInstalledAppLoaded = $false
    $script:TkInstalledAppSort   = [pscustomobject] @{ Property = 'Name'; Descending = $false }
    $script:TkInstalledAppKeys   = @('all')

    $list = Get-TkControl -Name 'InstalledAppList'
    if ($list) { $list.ItemsSource = $script:TkInstalledAppItems }

    $script:TkInstalledAppView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:TkInstalledAppItems)
    $script:TkInstalledAppView.Filter = [Predicate[object]] {
        param($item)
        Test-TkInstalledAppVisible -Item $item
    }

    $filter = Get-TkControl -Name 'InstalledAppFilter'
    if ($filter) {
        [void] $filter.Items.Add('All sources')
        $filter.SelectedIndex = 0
        $filter.Add_SelectionChanged({ $script:TkInstalledAppView.Refresh() })
    }

    $mode = Get-TkControl -Name 'InstalledAppMode'
    if ($mode) {
        [void] $mode.Items.Add('Automatic (silent)')
        [void] $mode.Items.Add('Manual (its own window)')
        $mode.SelectedIndex = 0
    }

    $search = Get-TkControl -Name 'InstalledAppSearch'
    if ($search) { $search.Add_TextChanged({ $script:TkInstalledAppView.Refresh() }) }

    $all = Get-TkControl -Name 'InstalledAppAll'
    if ($all) {
        $all.Add_Click({
            param($source, $clickArgs)
            $null = $clickArgs
            $tick = [bool] $source.IsChecked
            foreach ($item in @($script:TkInstalledAppView)) { $item.IsSelected = $tick }
            $script:TkInstalledAppView.Refresh()
        })
    }

    foreach ($name in @('Name', 'Id', 'Version', 'Available', 'Source')) {
        $button = Get-TkControl -Name ('BtnSortInstalled{0}' -f $name)
        if ($button) {
            $button.Add_Click({
                param($source, $clickArgs)
                $null = $clickArgs
                Set-TkInstalledAppSort -Property ([string] $source.Tag)
            })
        }
    }

    Register-TkClick -Name 'BtnUpdateInstalledApps'    -Action { Invoke-TkInstalledAppActionFromUi -Operation 'Update' }
    Register-TkClick -Name 'BtnUninstallInstalledApps' -Action { Invoke-TkInstalledAppActionFromUi -Operation 'Uninstall' }
    Register-TkClick -Name 'BtnRefreshInstalledApps'   -Action { Update-TkInstalledAppList }

    # A batch runs one application at a time; the clock redraws where it is.
    $script:TkAppQueue      = $null
    $script:TkAppQueueTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:TkAppQueueTimer.Interval = [TimeSpan]::FromSeconds(1)
    $script:TkAppQueueTimer.Add_Tick({ Update-TkInstalledAppProgress })

    Register-TkClick -Name 'BtnStopInstalledApps' -Action {
        if ($script:TkAppQueue -and -not $script:TkAppQueue.Finished) {
            $script:TkAppQueue.Stop = $true
            (Get-TkControl -Name 'BtnStopInstalledApps').IsEnabled = $false
            Update-TkInstalledAppProgress
        }
    }

    $tabs = Get-TkControl -Name 'SoftwareTabs'
    if ($tabs) {
        $tabs.Add_SelectionChanged({
            param($source, $routed)

            # The event also bubbles up from the lists and boxes inside the tabs.
            if ($routed.OriginalSource -ne $source) { return }

            $tab = $source.SelectedItem
            if ($tab -and [string] $tab.Header -eq 'Installed Apps' -and -not $script:TkInstalledAppLoaded) {
                Update-TkInstalledAppList
            }
        })
    }
}

<#
.SYNOPSIS
    Decides whether a row passes the filter and the search. A ticked row always shows.

.OUTPUTS
    System.Boolean
#>
function Test-TkInstalledAppVisible {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] $Item
    )

    if ($Item.IsSelected) { return $true }

    $filter = Get-TkControl -Name 'InstalledAppFilter'
    $index  = if ($filter) { $filter.SelectedIndex } else { 0 }
    $key    = if ($index -ge 0 -and $index -lt @($script:TkInstalledAppKeys).Count) { $script:TkInstalledAppKeys[$index] } else { 'all' }

    switch -Regex ($key) {
        '^updates$'      { if (-not $Item.Available) { return $false } }
        '^preinstalled$' { if (-not $Item.Preinstalled) { return $false } }
        '^source:(.+)$'  { if ($Item.Source -ne $Matches[1]) { return $false } }
    }

    $search = Get-TkControl -Name 'InstalledAppSearch'
    if ($search -and -not [string]::IsNullOrWhiteSpace($search.Text)) {
        if (('{0} {1} {2}' -f $Item.Name, $Item.Id, $Item.Source) -notlike ('*{0}*' -f $search.Text.Trim())) { return $false }
    }

    return $true
}

<#
.SYNOPSIS
    Sorts the list by a column; the same column again reverses the order.
#>
function Set-TkInstalledAppSort {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [ValidateSet('Name', 'Id', 'Version', 'Available', 'Source')] [string] $Property
    )

    if (-not $PSCmdlet.ShouldProcess('installed apps', ('Sort by {0}' -f $Property))) { return }

    $descending = ($script:TkInstalledAppSort.Property -eq $Property -and -not $script:TkInstalledAppSort.Descending)
    $script:TkInstalledAppSort = [pscustomobject] @{ Property = $Property; Descending = $descending }

    $sorted = @($script:TkInstalledAppItems | Sort-Object -Property @{ Expression = $Property; Descending = $descending }, @{ Expression = 'Name'; Descending = $false })
    $script:TkInstalledAppItems.Clear()
    foreach ($item in $sorted) { $script:TkInstalledAppItems.Add($item) }
}

<#
.SYNOPSIS
    Fills the filter with each source found and its count.
#>
function Update-TkInstalledAppFilterChoice {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Item = @()
    )

    $filter = Get-TkControl -Name 'InstalledAppFilter'
    if (-not $filter -or -not $PSCmdlet.ShouldProcess('installed apps', 'Fill the filter')) { return }

    $keys   = New-Object System.Collections.Generic.List[string]
    $labels = New-Object System.Collections.Generic.List[string]
    $add    = { param($key, $label) $keys.Add($key); $labels.Add($label) }

    & $add 'all' ('All sources ({0})' -f $Item.Count)
    & $add 'updates' ('Updates available ({0})' -f @($Item | Where-Object Available).Count)
    $preinstalled = @($Item | Where-Object Preinstalled).Count
    if ($preinstalled -gt 0) { & $add 'preinstalled' ('Preinstalled Windows apps ({0})' -f $preinstalled) }
    foreach ($group in @($Item | Group-Object -Property Source | Sort-Object -Property Count -Descending)) {
        & $add ('source:{0}' -f $group.Name) ('{0} ({1})' -f $group.Name, $group.Count)
    }

    $script:TkInstalledAppKeys = @($keys.ToArray())
    $filter.Items.Clear()
    foreach ($label in $labels) { [void] $filter.Items.Add($label) }
    $filter.SelectedIndex = 0
}

<#
.SYNOPSIS
    Reads every installed application into the list.
#>
function Update-TkInstalledAppList {
    [CmdletBinding()]
    param()

    $script:TkInstalledAppLoaded = $true
    $status = Get-TkControl -Name 'InstalledAppStatus'
    if ($status) { $status.Text = 'Reading every installed application: winget, the Microsoft Store, the game launchers and the package managers. This can take a minute...' }

    Invoke-TkBackgroundAction -StatusText 'Reading the installed applications...' `
        -ScriptBlock { Get-TkInstalledApplication } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Items'] } | Select-Object -First 1
            if (-not $report) { return }

            $items = @($report.Items)
            $script:TkInstalledAppItems.Clear()
            $sort = $script:TkInstalledAppSort
            foreach ($item in @($items | Sort-Object -Property @{ Expression = $sort.Property; Descending = $sort.Descending }, @{ Expression = 'Name'; Descending = $false })) {
                $script:TkInstalledAppItems.Add($item)
            }
            Update-TkInstalledAppFilterChoice -Item $items -Confirm:$false

            $sources = @($items | Group-Object -Property Source | Sort-Object -Property Count -Descending | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
            $text    = '{0} application(s): {1}. {2} update(s) known.' -f $items.Count, ($sources -join ', '), @($items | Where-Object Available).Count
            if (@($report.Notes).Count -gt 0) { $text += ' ' + (@($report.Notes) -join ' ') }

            $label = Get-TkControl -Name 'InstalledAppStatus'
            if ($label) { $label.Text = $text }
            Set-TkStatus -Text ('{0} installed application(s) read.' -f $items.Count)
        }
}

<#
.SYNOPSIS
    Shows a state on a row: Waiting, Running, Done, Failed or Handoff, with its text.
#>
function Set-TkInstalledAppState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Item,
        [Parameter(Mandatory)] [ValidateSet('Waiting', 'Running', 'Done', 'Failed', 'Handoff')] [string] $Kind,
        [Parameter()] [AllowEmptyString()] [string] $Text = ''
    )

    if (-not $PSCmdlet.ShouldProcess([string] $Item.Name, 'Show the state')) { return }

    $Item.StateKind = $Kind
    $Item.StateText = $Text
    if ($Kind -in @('Done', 'Handoff')) { $Item.IsSelected = $false }
    $script:TkInstalledAppView.Refresh()
}

<#
.SYNOPSIS
    Shows the outcome of the elevated operations on their rows.
#>
function Set-TkInstalledAppResult {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Result = @()
    )

    if (-not $PSCmdlet.ShouldProcess('installed apps', 'Show the results')) { return }

    foreach ($outcome in ($Result | Where-Object { $_ })) {
        foreach ($item in @($script:TkInstalledAppItems | Where-Object { $_.Name -eq $outcome.Name -and $_.Source -eq $outcome.Source })) {
            Set-TkInstalledAppState -Item $item -Kind $(if ($outcome.Ok) { 'Done' } else { 'Failed' }) -Text ([string] $outcome.Text) -Confirm:$false
        }
    }
}

<#
.SYNOPSIS
    Updates or uninstalls the ticked rows, after a confirmation.
#>
function Invoke-TkInstalledAppActionFromUi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Update', 'Uninstall')] [string] $Operation
    )

    if ($script:TkAppQueue -and -not $script:TkAppQueue.Finished) {
        Set-TkStatus -Text 'A batch is already running: wait for it, or stop it after the current application.'
        return
    }

    $selected = @($script:TkInstalledAppItems | Where-Object { $_.IsSelected })
    if ($selected.Count -eq 0) {
        Set-TkStatus -Text 'Tick the applications first.'
        return
    }

    if ($Operation -eq 'Update') {
        $skipped  = @($selected | Where-Object { -not $_.Available -and $_.Manager -notin @('scoop', 'dotnet', 'cargo') })
        $selected = @($selected | Where-Object { $_.Available -or $_.Manager -in @('scoop', 'dotnet', 'cargo') })
        if ($selected.Count -eq 0) {
            Set-TkStatus -Text 'None of the ticked applications has a known update.'
            return
        }
    }
    else {
        $skipped = @()
    }

    $modeBox = Get-TkControl -Name 'InstalledAppMode'
    $mode    = if ($modeBox -and $modeBox.SelectedIndex -eq 1) { 'Interactive' } else { 'Silent' }
    $verb    = if ($Operation -eq 'Update') { 'Update' } else { 'Uninstall' }
    $lines   = @($selected | Select-Object -First 25 | ForEach-Object { '- {0}  ({1}{2})' -f $_.Name, $_.Source, $(if ($_.Available -and $Operation -eq 'Update') { ', to ' + $_.Available } else { '' }) })
    if ($selected.Count -gt 25) { $lines += '- ... and {0} more' -f ($selected.Count - 25) }

    $message = "{0} {1} application(s), one after the other, {2}:`n`n{3}" -f $verb, $selected.Count, $(if ($mode -eq 'Silent') { 'silently' } else { 'each in its own window' }), ($lines -join "`n")
    if ($skipped.Count -gt 0) { $message += "`n`n{0} ticked row(s) without a known update are left out." -f $skipped.Count }
    $games = @($selected | Where-Object Manager -eq 'launcher').Count
    if ($Operation -eq 'Uninstall' -and $games -gt 0) { $message += "`n`n{0} game(s) are handed to their launcher, which asks in its own window; the list goes on meanwhile." -f $games }
    $admin = @($selected | Where-Object { $_.Elevated -or ($_.Preinstalled -and $Operation -eq 'Uninstall') }).Count
    if ($admin -gt 0) { $message += "`n`n{0} need administrator rights: one UAC prompt, after the others." -f $admin }
    if (@($selected | Where-Object { $_.Preinstalled -and $Operation -eq 'Uninstall' }).Count -gt 0) {
        $message += "`n`nThe preinstalled Windows apps are removed for every account, new ones included; they come back from the Microsoft Store."
    }

    if (-not (Confirm-TkAction -Title ('{0} applications' -f $verb) -Message $message)) { return }

    Start-TkInstalledAppQueue -Item $selected -Operation $Operation -Mode $mode -Confirm:$false
}

<#
.SYNOPSIS
    Starts a batch: every row waiting, then one application at a time.

.DESCRIPTION
    Each application runs in a background task of its own, and the next
    starts when it ends, so the rows show where the batch is and the Stop
    button can end it between two applications.
#>
function Start-TkInstalledAppQueue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [object[]] $Item,
        [Parameter(Mandatory)] [ValidateSet('Update', 'Uninstall')] [string] $Operation,
        [Parameter()] [ValidateSet('Silent', 'Interactive')] [string] $Mode = 'Silent'
    )

    if (-not $PSCmdlet.ShouldProcess('installed apps', $Operation)) { return }

    $steps = @(New-TkInstalledAppQueue -Item $Item -Operation $Operation -Mode $Mode -Tool (Get-TkPackageTool))

    $script:TkAppQueue = [pscustomobject] @{
        Steps       = $steps
        Index       = 0
        Operation   = $Operation
        Results     = New-Object System.Collections.Generic.List[object]
        Elevated    = New-Object System.Collections.Generic.List[object]
        Stop        = $false
        Finished    = $false
        Current     = ''
        ItemStarted = Get-Date
        Done        = 0
        Failed      = 0
        Handed      = 0
        Phase       = 'Running'
    }

    foreach ($step in $steps) {
        $waiting = if ($step.Plan.Kind -eq 'Elevated') { 'waiting for administrator rights' } else { 'waiting' }
        Set-TkInstalledAppState -Item $step.Item -Kind 'Waiting' -Text $waiting -Confirm:$false
    }

    Set-TkInstalledAppBusy -Busy $true -Confirm:$false
    Step-TkInstalledAppQueue
}

<#
.SYNOPSIS
    Starts the next application of the batch, or ends the batch.
#>
function Step-TkInstalledAppQueue {
    [CmdletBinding()]
    param()

    $queue = $script:TkAppQueue
    $verb  = if ($queue.Operation -eq 'Update') { 'updating' } else { 'uninstalling' }

    while ($queue.Index -lt $queue.Steps.Count -and -not $queue.Stop) {

        $step = $queue.Steps[$queue.Index]

        if ($step.Plan.Kind -eq 'Elevated') {
            $queue.Elevated.Add($step)
            $queue.Index++
            continue
        }

        if ($step.Plan.Kind -eq 'None') {
            Set-TkInstalledAppState -Item $step.Item -Kind 'Failed' -Text ('not run: {0}' -f $step.Plan.Note) -Confirm:$false
            $queue.Results.Add([pscustomobject] @{ Name = $step.Item.Name; Source = $step.Item.Source; Ok = $false; Text = $step.Plan.Note })
            $queue.Failed++
            $queue.Index++
            continue
        }

        $queue.Current     = [string] $step.Item.Name
        $queue.ItemStarted = Get-Date
        Set-TkInstalledAppState -Item $step.Item -Kind 'Running' -Text ('{0}...' -f $verb) -Confirm:$false
        Update-TkInstalledAppProgress

        Invoke-TkBackgroundAction -StatusText ('{0} {1}...' -f (Get-Culture).TextInfo.ToTitleCase($verb), $step.Item.Name) `
            -ParameterList @{ plan = $step.Plan } `
            -ScriptBlock {
                param($plan)
                Invoke-TkInstalledAppCommand -Plan $plan -Confirm:$false
            } `
            -OnComplete {
                param($result)
                Complete-TkInstalledAppStep -Result $result
            }
        return
    }

    Complete-TkInstalledAppQueue
}

<#
.SYNOPSIS
    Records how the application that just ran ended, and starts the next.
#>
function Complete-TkInstalledAppStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result
    )

    $queue   = $script:TkAppQueue
    $step    = $queue.Steps[$queue.Index]
    $outcome = @($Result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Ok'] } | Select-Object -Last 1

    if (-not $outcome) {
        $why = if (@($Result.Errors).Count -gt 0) { [string] @($Result.Errors)[0] } else { 'no result came back' }
        $outcome = [pscustomobject] @{ Ok = $false; Text = $why }
    }

    $kind = if (-not $outcome.Ok) { 'Failed' } elseif ($step.Plan.Kind -eq 'Handoff') { 'Handoff' } else { 'Done' }
    $word = if ($queue.Operation -eq 'Update') { 'updated' } else { 'removed' }
    $text = switch ($kind) {
        'Handoff' { [string] $step.Plan.Note }
        'Done'    { if ($step.Plan.Note) { '{0} ({1})' -f $word, $step.Plan.Note } else { $word } }
        default   { [string] $outcome.Text }
    }

    Set-TkInstalledAppState -Item $step.Item -Kind $kind -Text $text -Confirm:$false
    $queue.Results.Add([pscustomobject] @{ Name = $step.Item.Name; Source = $step.Item.Source; Ok = [bool] $outcome.Ok; Text = $text })
    switch ($kind) { 'Failed' { $queue.Failed++ } 'Handoff' { $queue.Handed++ } default { $queue.Done++ } }

    $queue.Index++
    Step-TkInstalledAppQueue
}

<#
.SYNOPSIS
    Ends the batch: what was not run, the journal, then the elevated part if any.
#>
function Complete-TkInstalledAppQueue {
    [CmdletBinding()]
    param()

    $queue = $script:TkAppQueue

    if ($queue.Stop) {
        for ($i = $queue.Index; $i -lt $queue.Steps.Count; $i++) {
            Set-TkInstalledAppState -Item $queue.Steps[$i].Item -Kind 'Waiting' -Text 'not run: stopped' -Confirm:$false
        }
        foreach ($step in $queue.Elevated) {
            Set-TkInstalledAppState -Item $step.Item -Kind 'Waiting' -Text 'not run: stopped' -Confirm:$false
        }
        $queue.Elevated.Clear()
    }

    Write-TkInstalledAppJournal -Operation $queue.Operation -Result $queue.Results.ToArray() -Confirm:$false

    if ($queue.Elevated.Count -eq 0) {
        Stop-TkInstalledAppQueue
        return
    }

    $queue.Phase       = 'Elevated'
    $queue.ItemStarted = Get-Date
    foreach ($step in $queue.Elevated) {
        Set-TkInstalledAppState -Item $step.Item -Kind 'Running' -Text 'running with administrator rights...' -Confirm:$false
    }
    Update-TkInstalledAppProgress

    $status = if (Test-TkIsElevated) { 'Running the operations that need administrator rights...' } else { 'Waiting for administrator consent...' }
    Start-TkPrivilegedAction -Name 'ManagePackages' -StatusText $status -Parameters @{
        Items = @($queue.Elevated | ForEach-Object {
            @{ Manager = $(if ($_.Item.Preinstalled) { 'appx' } else { [string] $_.Item.Manager }); Operation = $queue.Operation; Name = $_.Plan.Name; Label = $_.Item.Name }
        })
    } -OnResult {
        param($elevated)
        Complete-TkInstalledAppElevated -Outcome $elevated
    }
}

<#
.SYNOPSIS
    Shows the outcome of the elevated part, a cancelled UAC prompt included, and ends the batch.
#>
function Complete-TkInstalledAppElevated {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] $Outcome
    )

    $queue   = $script:TkAppQueue
    $results = if ($Outcome -and $Outcome.PSObject.Properties['Results']) { @($Outcome.Results) } else { @() }

    if ($results.Count -gt 0) {
        Set-TkInstalledAppResult -Result $results -Confirm:$false
        foreach ($item in $results) { if ($item.Ok) { $queue.Done++ } else { $queue.Failed++ } }
        Write-TkInstalledAppJournal -Operation $queue.Operation -Result $results -Confirm:$false
    }
    else {
        $why = if ($Outcome -and $Outcome.Message) { [string] $Outcome.Message } else { 'administrator rights were not granted' }
        foreach ($step in $queue.Elevated) {
            Set-TkInstalledAppState -Item $step.Item -Kind 'Failed' -Text ('not run: {0}' -f $why) -Confirm:$false
            $queue.Failed++
        }
    }

    Stop-TkInstalledAppQueue
}

<#
.SYNOPSIS
    Ends the batch and says how it went.
#>
function Stop-TkInstalledAppQueue {
    [CmdletBinding()]
    param()

    $queue = $script:TkAppQueue
    $queue.Finished = $true
    $queue.Phase    = 'Finished'

    $verb = if ($queue.Operation -eq 'Update') { 'Updates' } else { 'Uninstalls' }
    $text = '{0} finished: {1} done, {2} failed' -f $verb, $queue.Done, $queue.Failed
    if ($queue.Handed -gt 0) { $text += ', {0} handed to a launcher (finish them in its window)' -f $queue.Handed }
    if ($queue.Stop) { $text += ', the rest stopped' }
    $text += '. Refresh to read the list again.'

    Set-TkInstalledAppBusy -Busy $false -Confirm:$false
    $label = Get-TkControl -Name 'InstalledAppProgressText'
    if ($label) { $label.Text = $text }
    $bar = Get-TkControl -Name 'InstalledAppProgressBar'
    if ($bar) { $bar.Value = 1 }
    Set-TkStatus -Text $text
}

<#
.SYNOPSIS
    Shows or ends the running state of the tab: progress panel, buttons, clock.
#>
function Set-TkInstalledAppBusy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [bool] $Busy
    )

    if (-not $PSCmdlet.ShouldProcess('installed apps', 'Show the running state')) { return }

    foreach ($name in @('BtnUpdateInstalledApps', 'BtnUninstallInstalledApps', 'BtnRefreshInstalledApps')) {
        $button = Get-TkControl -Name $name
        if ($button) { $button.IsEnabled = -not $Busy }
    }

    $stop = Get-TkControl -Name 'BtnStopInstalledApps'
    if ($stop) {
        $stop.IsEnabled  = $Busy
        $stop.Visibility = if ($Busy) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    }

    $panel = Get-TkControl -Name 'InstalledAppProgress'
    if ($panel) { $panel.Visibility = [System.Windows.Visibility]::Visible }

    if ($Busy) { $script:TkAppQueueTimer.Start() } else { $script:TkAppQueueTimer.Stop() }
}

<#
.SYNOPSIS
    Redraws the progress line and bar; called every second while a batch runs.
#>
function Update-TkInstalledAppProgress {
    [CmdletBinding()]
    param()

    $queue = $script:TkAppQueue
    if (-not $queue -or $queue.Finished) { return }

    $seconds = [int] ((Get-Date) - $queue.ItemStarted).TotalSeconds
    $text = if ($queue.Phase -eq 'Elevated') {
        '{0} application(s) with administrator rights ({1} s): accept the UAC prompt if it is waiting. {2} done, {3} failed so far.' -f $queue.Elevated.Count, $seconds, $queue.Done, $queue.Failed
    }
    else {
        Format-TkInstalledAppProgress -Operation $queue.Operation -Position ([math]::Min($queue.Index + 1, $queue.Steps.Count)) -Count $queue.Steps.Count `
                                      -Name $queue.Current -Seconds $seconds -Done ($queue.Done + $queue.Handed) -Failed $queue.Failed -Stopping:$queue.Stop
    }

    $label = Get-TkControl -Name 'InstalledAppProgressText'
    if ($label) { $label.Text = $text }
    $bar = Get-TkControl -Name 'InstalledAppProgressBar'
    if ($bar -and $queue.Steps.Count -gt 0) { $bar.Value = $queue.Index / $queue.Steps.Count }
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
