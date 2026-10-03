<#
    Toolkit - UI / Possible causes (a tab of the Diagnostics page)

    Shows what the diagnosis rules conclude, on this machine or on a report
    document saved earlier: each possible cause with its confidence, the
    evidence it rests on, and buttons that take the technician to the next
    step. A button opens a report, a page or a topic; it never runs a fix,
    which keeps its own confirmation on its own page.
#>

# The last evaluation, for the view. Set through Set-TkHypothesisResult: a
# completion handler cannot reach this file's scope.
$script:TkHypothesisResult = $null
$script:TkHypothesisSource = ''

<#
.SYNOPSIS
    Keeps the last evaluation, and what it was made on.
#>
function Set-TkHypothesisResult {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [AllowNull()] $Result,
        [Parameter()] [AllowEmptyString()] [string] $Source = ''
    )

    if ($PSCmdlet.ShouldProcess('possible causes', 'Remember the evaluation')) {
        $script:TkHypothesisResult = $Result
        $script:TkHypothesisSource = $Source
    }
}

<#
.SYNOPSIS
    Wires the Possible causes tab.
#>
function Initialize-TkHypothesesTab {
    [CmdletBinding()]
    param()

    Register-TkClick -Name 'BtnHypothesesRun'  -Action { Invoke-TkHypothesesFromUi }
    Register-TkClick -Name 'BtnHypothesesOpen' -Action { Open-TkHypothesesDocumentFromUi }

    $document = New-TkFlowDocument
    Add-TkParagraph -Document $document -Muted -Text 'Look for causes on this machine, or read a report document saved earlier, such as a request for support a user sent.'
    Set-TkDocument -ControlName 'HypothesesOutput' -Document $document
}

<#
.SYNOPSIS
    Collects what the rules read on this machine, in the background, and
    shows what they conclude.
#>
function Invoke-TkHypothesesFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the reports the rules cross...' `
        -ScriptBlock { Get-TkHypothesisReport } `
        -OnComplete {
            param($result)

            $evaluation = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Matched'] } | Select-Object -Last 1

            if (-not $evaluation) {
                Set-TkStatus -Text $(if (@($result.Errors).Count) { 'The rules could not be evaluated: {0}' -f @($result.Errors)[0] } else { 'The rules could not be evaluated.' })
                return
            }

            Set-TkHypothesisResult -Result $evaluation -Source ('this machine ({0})' -f $env:COMPUTERNAME) -Confirm:$false
            Write-TkHypothesisView
            Set-TkStatus -Text ('{0} possible cause(s) found by {1} rule(s).' -f @($evaluation.Matched).Count, $evaluation.Rules)
        }
}

<#
.SYNOPSIS
    Reads a saved report document and shows what the rules conclude on it.

.DESCRIPTION
    The document is read as it was: dates are judged against the moment it
    was collected, and a rule whose reports it does not hold is named.
#>
function Open-TkHypothesesDocumentFromUi {
    [CmdletBinding()]
    param()

    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title  = 'Read a saved report'
    $dialog.Filter = 'Report document (*.json)|*.json'

    if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
        return
    }

    try {
        $document   = Read-TkReportDocument -Path $dialog.FileName
        $evaluation = Resolve-TkHypothesis -Document $document
    }
    catch {
        Set-TkStatus -Text ('{0} could not be read as a report document: {1}' -f [System.IO.Path]::GetFileName($dialog.FileName), $_.Exception.Message)
        return
    }

    $computer = [string] (Get-TkRulePath -Data $document -Path 'Computer')
    Set-TkHypothesisResult -Result $evaluation -Source ('{0}{1}' -f [System.IO.Path]::GetFileName($dialog.FileName), $(if ($computer) { ', from {0}' -f $computer } else { '' })) -Confirm:$false
    Write-TkHypothesisView
    Set-TkStatus -Text ('{0} possible cause(s) in {1}.' -f @($evaluation.Matched).Count, [System.IO.Path]::GetFileName($dialog.FileName))
}

<#
.SYNOPSIS
    Goes where a possible cause's next step is: a report, the fixes, a topic.

.DESCRIPTION
    Navigation only. A fix is not run from here: its page lists it, with its
    explanation and its confirmation.
#>
function Invoke-TkHypothesisAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Target
    )

    $kind  = [string] $Target.Kind
    $value = [string] $Target.Value

    switch ($kind) {

        'report' {
            Show-TkPage -Name 'Diagnostics'
            [void] (Select-TkTab -TabControlName 'DiagnosticsTabs' -Header 'Reports')
            [void] (Select-TkListChoice -ListName 'DiagnosticChoices' -Title $value)
        }

        'fix' {
            $fix = @((Import-TkCatalog -Name 'fixes').fixes | Where-Object { $_.id -eq $value }) | Select-Object -First 1
            Show-TkPage -Name 'Fixes'
            [void] (Select-TkTab -TabControlName 'FixesTabs' -Header 'Fixes')
            Set-TkStatus -Text ('Run "{0}" from this page: it says what it does, and asks before it starts.' -f $(if ($fix) { $fix.name } else { $value }))
        }

        'topic' {
            $topic = @((Import-TkCatalog -Name 'network-knowledge').topics | Where-Object { $_.id -eq $value }) | Select-Object -First 1
            Show-TkPage -Name 'Knowledge'
            [void] (Select-TkTab -TabControlName 'KnowledgeTabs' -Header 'Topics')
            $search = Get-TkControl -Name 'KnowledgeSearch'
            if ($search) { $search.Text = '' }
            if ($topic) { [void] (Select-TkListChoice -ListName 'KnowledgeList' -Title ([string] $topic.title)) }
        }
    }
}

<#
.SYNOPSIS
    The buttons of a possible cause's next step, in a row under it.
#>
function Add-TkHypothesisButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Windows.Documents.FlowDocument] $Document,
        [Parameter(Mandatory)] $Action
    )

    $targets = New-Object System.Collections.Generic.List[object]

    if ($Action.Report) {
        $targets.Add(@{ Kind = 'report'; Value = [string] $Action.Report; Label = 'Open the {0} report' -f $Action.Report })
    }
    if ($Action.Fix) {
        $fix = @((Import-TkCatalog -Name 'fixes').fixes | Where-Object { $_.id -eq $Action.Fix }) | Select-Object -First 1
        $targets.Add(@{ Kind = 'fix'; Value = [string] $Action.Fix; Label = 'Go to the fix: {0}' -f $(if ($fix) { $fix.name } else { $Action.Fix }) })
    }
    if ($Action.Topic) {
        $topic = @((Import-TkCatalog -Name 'network-knowledge').topics | Where-Object { $_.id -eq $Action.Topic }) | Select-Object -First 1
        $targets.Add(@{ Kind = 'topic'; Value = [string] $Action.Topic; Label = 'Read: {0}' -f $(if ($topic) { $topic.title } else { $Action.Topic }) })
    }

    if ($targets.Count -eq 0) {
        return
    }

    $panel = New-Object System.Windows.Controls.WrapPanel
    $panel.Margin = New-Object System.Windows.Thickness(0, 0, 0, 14)

    foreach ($target in $targets) {
        $button = New-Object System.Windows.Controls.Button
        $button.Content = $target.Label
        $button.Tag     = $target
        $button.Margin  = New-Object System.Windows.Thickness(0, 0, 10, 0)
        $button.Cursor  = [System.Windows.Input.Cursors]::Hand
        $button.Add_Click({
            # Not named $sender or $eventArgs: both are automatic variables.
            param($clicked, $clickArgs)
            $null = $clickArgs
            Invoke-TkHypothesisAction -Target $clicked.Tag
        })
        [void] $panel.Children.Add($button)
    }

    $Document.Blocks.Add((New-Object System.Windows.Documents.BlockUIContainer($panel)))
}

<#
.SYNOPSIS
    Shows the last evaluation: the possible causes, then what could not be
    evaluated.
#>
function Write-TkHypothesisView {
    [CmdletBinding()]
    param()

    $evaluation = $script:TkHypothesisResult
    if (-not $evaluation) {
        return
    }

    $document = New-TkFlowDocument
    $matched  = @($evaluation.Matched)

    Add-TkHeading -Document $document -Level 1 -Text $(if ($matched.Count) { '{0} possible cause(s)' -f $matched.Count } else { 'No likely cause found' })
    Add-TkParagraph -Document $document -Muted -Text ('{0} rule(s) evaluated on {1}, as it was on {2}. A cause is a lead to check, never a certainty.' -f
        $evaluation.Rules, $script:TkHypothesisSource, ([datetime] $evaluation.At).ToString('yyyy-MM-dd HH:mm'))

    if ($matched.Count -eq 0) {
        Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'No rule found a likely cause in what was read' `
            -Note 'The rules look at crashes, storage, updates, restarts, memory, devices, network and proxy. The reports themselves may still show something worth a look.'
    }

    foreach ($item in $matched) {

        Add-TkSeverityLine -Document $document -Severity $item.Severity -Heading ('{0} confidence  -  {1}' -f $item.Confidence, $item.Title) `
            -Note $item.Explanation -Action $item.Action.Advice

        # The label on the first line of its group only, so the lines read as
        # a list under it.
        $rows = @(foreach ($evidence in @($item.Evidence)) {
            $first = $true
            foreach ($line in @($evidence.Lines)) {
                , @($(if ($first) { $evidence.Label } else { '' }), [string] $line)
                $first = $false
            }
        })
        if ($rows.Count -gt 0) {
            Add-TkTable -Document $document -Column @('Evidence', 'What was seen') -Weight @(1.6, 3.4) -Row $rows
        }

        Add-TkHypothesisButton -Document $document -Action $item.Action
    }

    $skipped = @($evaluation.NotEvaluated)
    if ($skipped.Count -gt 0) {
        Add-TkHeading -Document $document -Level 2 -Text ('Not evaluated: {0} rule(s)' -f $skipped.Count)
        Add-TkBulletList -Document $document -Item @($skipped | ForEach-Object { '{0}: {1}' -f $_.Title, $_.Reason })
    }

    Set-TkDocument -ControlName 'HypothesesOutput' -Document $document
}
