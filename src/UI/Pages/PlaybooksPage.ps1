<#
    Toolkit - UI / Playbooks page

    Draws a chosen troubleshooting playbook as a list of step cards, and takes
    the operator to where each step happens. The steps are data, from
    Get-TkPlaybook; this file only lays them out and navigates.
#>

<#
.SYNOPSIS
    Wires the Playbooks page.
#>
function Initialize-TkPlaybooksPage {
    [CmdletBinding()]
    param()

    $choices = Get-TkControl -Name 'PlaybookChoices'

    if ($choices) {

        $choices.Add_SelectionChanged({
            $list  = Get-TkControl -Name 'PlaybookChoices'
            $title = Get-TkItemTitle -Item $list.SelectedItem
            if ($title) { Show-TkPlaybook -Title $title }
        })

        if ($choices.Items.Count -gt 0) {
            $choices.SelectedIndex = 0
        }
    }
}

<#
.SYNOPSIS
    Draws the steps of a playbook, one card each.

.PARAMETER Title
    The playbook's title, as shown in the chooser.
#>
function Show-TkPlaybook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title
    )

    $panel = Get-TkControl -Name 'PlaybookSteps'

    if (-not $panel) {
        return
    }

    $playbook = @(Get-TkPlaybook) | Where-Object { $_.Title -eq $Title } | Select-Object -First 1

    $panel.Children.Clear()

    if (-not $playbook) {
        return
    }

    # --- When to use it ---------------------------------------------------
    $symptom = New-Object System.Windows.Controls.TextBlock
    $symptom.Text         = 'When to use this: {0}' -f $playbook.Symptom
    $symptom.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $symptom.Margin       = New-Object System.Windows.Thickness(4, 4, 4, 12)
    Set-TkResourceBrush -Element $symptom -Property Foreground -Key 'TextMuted'
    [void] $panel.Children.Add($symptom)

    # --- One card per step ------------------------------------------------
    $number = 0

    foreach ($step in @($playbook.Steps)) {

        $index = $number
        $number++

        $border = New-Object System.Windows.Controls.Border
        $border.CornerRadius    = New-Object System.Windows.CornerRadius(12)
        $border.BorderThickness = New-Object System.Windows.Thickness(1)
        $border.Padding         = New-Object System.Windows.Thickness(14, 12, 14, 12)
        $border.Margin          = New-Object System.Windows.Thickness(4, 0, 4, 10)
        Set-TkResourceBrush -Element $border -Property Background  -Key 'Surface'
        Set-TkResourceBrush -Element $border -Property BorderBrush -Key 'BorderSubtle'

        $stack = New-Object System.Windows.Controls.StackPanel

        $heading = New-Object System.Windows.Controls.TextBlock
        $heading.Text         = '{0}. {1}  -  {2}' -f ($index + 1), $step.Kind, $step.Title
        $heading.FontSize     = 14
        $heading.FontWeight   = [System.Windows.FontWeights]::SemiBold
        $heading.TextWrapping = [System.Windows.TextWrapping]::Wrap
        Set-TkResourceBrush -Element $heading -Property Foreground -Key 'TextPrimary'
        [void] $stack.Children.Add($heading)

        $detail = New-Object System.Windows.Controls.TextBlock
        $detail.Text         = $step.Detail
        $detail.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $detail.Margin       = New-Object System.Windows.Thickness(0, 4, 0, 0)
        Set-TkResourceBrush -Element $detail -Property Foreground -Key 'TextMuted'
        [void] $stack.Children.Add($detail)

        if ($step.Page) {

            $button = New-Object System.Windows.Controls.Button
            $button.Content             = 'Go to this step'
            $button.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
            $button.Margin              = New-Object System.Windows.Thickness(0, 10, 0, 0)
            $button.Padding             = New-Object System.Windows.Thickness(12, 6, 12, 6)

            $playbookId = $playbook.Id
            $stepIndex  = $index
            $button.Add_Click({ Invoke-TkPlaybookStep -PlaybookId $playbookId -Order $stepIndex }.GetNewClosure())

            [void] $stack.Children.Add($button)
        }

        $border.Child = $stack
        [void] $panel.Children.Add($border)
    }
}

<#
.SYNOPSIS
    Takes the operator to where a playbook step happens, and runs it.

.DESCRIPTION
    Reuses the same navigation the dashboard tiles use: show the page, select
    the tab, then select the entry in its chooser, which runs a read-only report
    where the step points at one. A step that only points at a page leaves the
    operator there to act.

.PARAMETER PlaybookId
    The playbook's Id.

.PARAMETER Order
    The zero-based index of the step within the playbook.
#>
function Invoke-TkPlaybookStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PlaybookId,

        [Parameter(Mandatory)]
        [int] $Order
    )

    $playbook = @(Get-TkPlaybook) | Where-Object { $_.Id -eq $PlaybookId } | Select-Object -First 1

    if (-not $playbook) {
        return
    }

    $steps = @($playbook.Steps)

    if ($Order -lt 0 -or $Order -ge $steps.Count) {
        return
    }

    $step = $steps[$Order]

    if ($step.Page) {
        Show-TkPage -Name $step.Page
    }

    if ($step.TabControl -and -not (Select-TkTab -TabControlName $step.TabControl -Header $step.Tab)) {
        Write-TkLog -Level Warning -Category 'Interface' -Message (
            'Playbook "{0}" step "{1}": no tab titled "{2}" in {3}.' -f $playbook.Title, $step.Title, $step.Tab, $step.TabControl
        )
    }

    if ($step.List -and -not (Select-TkListChoice -ListName $step.List -Title $step.Choice)) {
        Write-TkLog -Level Warning -Category 'Interface' -Message (
            'Playbook "{0}" step "{1}": no entry titled "{2}" in {3}.' -f $playbook.Title, $step.Title, $step.Choice, $step.List
        )
    }

    Set-TkStatus -Text ('{0}: {1}' -f $playbook.Title, $step.Title)
}
