<#
    Toolkit - UI / Tweaks page

    Same shape as the software page: a filtered list with checkboxes and two
    batch actions. The state column reads the registry directly rather than
    remembering what was clicked, so it stays correct after a tweak was
    applied by group policy or by another tool.
#>

$script:TkTweakItems = $null
$script:TkTweakView  = $null

<#
.SYNOPSIS
    Wires the Tweaks page and loads the catalog.
#>
function Initialize-TkTweaksPage {
    [CmdletBinding()]
    param()

    $catalog = Import-TkCatalog -Name 'tweaks'

    if (-not $catalog) {
        return
    }

    $categoryNames = @{}

    foreach ($category in $catalog.categories) {
        $categoryNames[$category.id] = $category.name
    }

    $items = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'

    foreach ($tweak in $catalog.tweaks) {

        $items.Add([pscustomobject]@{
            IsSelected   = $false
            Id           = $tweak.id
            Name         = $tweak.name
            Description  = $tweak.description
            Impact       = $tweak.impact
            Category     = $tweak.category
            CategoryName = $categoryNames[$tweak.category]
            StateText    = ''
            Definition   = $tweak
        })
    }

    $script:TkTweakItems = $items

    $list = Get-TkControl -Name 'TweakList'

    if ($list) {
        $list.ItemsSource = $items
    }

    $script:TkTweakView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($items)
    $script:TkTweakView.Filter = [Predicate[object]] {
        param($item)
        Test-TkTweakVisible -Item $item
    }

    $combo = Get-TkControl -Name 'TweakCategory'

    if ($combo) {

        [void] $combo.Items.Add('All categories')

        foreach ($category in $catalog.categories) {
            [void] $combo.Items.Add($category.name)
        }

        $combo.SelectedIndex = 0
        $combo.Add_SelectionChanged({ $script:TkTweakView.Refresh() })
    }

    $search = Get-TkControl -Name 'TweakSearch'

    if ($search) {
        $search.Add_TextChanged({ $script:TkTweakView.Refresh() })
    }

    Register-TkClick -Name 'BtnApplyTweaks'   -Action { Invoke-TkTweakUiAction -Action 'Apply' }
    Register-TkClick -Name 'BtnRevertTweaks'  -Action { Invoke-TkTweakUiAction -Action 'Revert' }
    Register-TkClick -Name 'BtnRefreshTweaks' -Action { Update-TkTweakState }

    Update-TkTweakState
}

<#
.SYNOPSIS
    Decides whether a tweak passes the current filters.

.OUTPUTS
    System.Boolean
#>
function Test-TkTweakVisible {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    if ($Item.IsSelected) {
        return $true
    }

    $combo = Get-TkControl -Name 'TweakCategory'

    if ($combo -and $combo.SelectedIndex -gt 0) {

        if ($Item.CategoryName -ne [string] $combo.SelectedItem) {
            return $false
        }
    }

    $search = Get-TkControl -Name 'TweakSearch'

    if ($search -and -not [string]::IsNullOrWhiteSpace($search.Text)) {

        $haystack = '{0} {1}' -f $Item.Name, $Item.Description

        if ($haystack -notlike ('*{0}*' -f $search.Text.Trim())) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Re-reads the applied state of every tweak.

.DESCRIPTION
    Registry reads are cheap, so this runs on the UI thread and the list is
    correct the moment the page appears.
#>
function Update-TkTweakState {
    [CmdletBinding()]
    param()

    if (-not $script:TkTweakItems) {
        return
    }

    $applied = 0

    foreach ($item in $script:TkTweakItems) {

        $isApplied = Test-TkTweakApplied -Tweak $item.Definition

        $item.StateText = if ($isApplied) { 'Applied' } else { '' }

        if ($isApplied) {
            $applied++
        }
    }

    $list = Get-TkControl -Name 'TweakList'

    if ($list) {
        $list.Items.Refresh()
    }

    Set-TkStatus -Text ('{0} of {1} tweak(s) currently applied.' -f $applied, $script:TkTweakItems.Count)
}

<#
.SYNOPSIS
    Applies or reverts the selected tweaks.

.PARAMETER Action
    Apply or Revert.
#>
function Invoke-TkTweakUiAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Apply', 'Revert')]
        [string] $Action
    )

    $selected = @($script:TkTweakItems | Where-Object { $_.IsSelected })

    if ($selected.Count -eq 0) {
        Set-TkStatus -Text 'No tweak is selected.'
        return
    }

    $needsElevation = @($selected | Where-Object { $_.Definition.requiresElevation })

    if ($needsElevation.Count -gt 0 -and -not (Test-TkIsElevated)) {

        Set-TkStatus -Text ('{0} of the selected tweaks need an elevated instance.' -f $needsElevation.Count)

        Write-TkLog -Level Warning -Category 'Tweaks' -Message (
            'Restart as administrator to apply: {0}' -f (($needsElevation | ForEach-Object { $_.Name }) -join ', ')
        )

        return
    }

    $highImpact = @($selected | Where-Object { $_.Impact -eq 'High' })

    $message = "{0} {1} tweak(s):`n`n{2}" -f $Action, $selected.Count,
        (($selected | ForEach-Object { '- ' + $_.Name }) -join "`n")

    if ($highImpact.Count -gt 0) {
        $message += "`n`nSome of these are marked high impact. Read their description before continuing."
    }

    $message += "`n`nA system restore point is created first."

    if (-not (Confirm-TkAction -Title ('{0} tweaks' -f $Action) -Message $message)) {
        return
    }

    $ids = @($selected | ForEach-Object { $_.Id })

    Invoke-TkBackgroundAction -StatusText ('{0}ing {1} tweak(s)...' -f $Action, $ids.Count) `
        -ParameterList @{ tweakIds = $ids; verb = $Action } `
        -ScriptBlock {
            param($tweakIds, $verb)

            return Invoke-TkTweakBatch -TweakId $tweakIds -Action $verb -Confirm:$false
        } `
        -OnComplete {
            param($result)

            $summary = @($result.Output) | Select-Object -Last 1

            if ($summary) {

                Set-TkStatus -Text ('{0}: {1} succeeded, {2} failed.' -f $Action, $summary.Applied, $summary.Failed)

                if ($summary.RequiresRestart) {

                    [System.Windows.MessageBox]::Show(
                        (Get-TkContext).Window,
                        'One or more of these changes only takes effect after a restart.',
                        'Restart required',
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information) | Out-Null
                }
            }

            Update-TkTweakState
        }
}
