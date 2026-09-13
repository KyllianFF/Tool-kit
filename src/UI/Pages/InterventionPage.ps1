<#
    Toolkit - UI / Intervention page

    The journal of what was done on this machine, and the report of the visit.
    The journal fills itself: every fix, tweak, installation, audit correction,
    audit and report run through the toolkit is written as it happens. The
    technician adds the ticket reference and the notes, and the report puts the
    machine, its health, the audit and the operations on one page.
#>

# What the report needs from the page while the machine is read in the
# background. A completion handler runs later, outside the function that
# started the work, so it reads this rather than that function's variables.
$script:TkPendingReport = $null

<#
.SYNOPSIS
    Wires the Intervention page.
#>
function Initialize-TkInterventionPage {
    [CmdletBinding()]
    param()

    $period = Get-TkControl -Name 'JournalPeriod'

    if ($period) {

        foreach ($name in @('This session', 'Today', 'Last 7 days')) {
            [void] $period.Items.Add($name)
        }

        # Selected before the handler is attached, so filling the list does not
        # read the journal of a page nobody has opened.
        $period.SelectedItem = 'Today'
        $period.Add_SelectionChanged({ Update-TkJournalView })
    }

    $technician = Get-TkControl -Name 'InterventionTechnician'

    if ($technician -and -not $technician.Text) {
        $technician.Text = $env:USERNAME
    }

    Register-TkClick -Name 'BtnJournalRefresh'     -Action { Update-TkJournalView }
    Register-TkClick -Name 'BtnJournalFolder'      -Action { Start-Process -FilePath 'explorer.exe' -ArgumentList (Get-TkJournalFolder) }
    Register-TkClick -Name 'BtnInterventionReport' -Action { New-TkInterventionReportFromUi }

    Register-TkFirstShow -PageName 'Intervention' -Action { Update-TkJournalView }
}

<#
.SYNOPSIS
    Turns a period choice into what the journal is read with.

.PARAMETER Choice
    This session, Today or Last 7 days.

.PARAMETER Now
    The current time, a parameter so tests do not depend on the clock.

.OUTPUTS
    PSCustomObject with Label, Since and Session.
#>
function Get-TkJournalPeriod {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Choice = 'Today',

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    switch ($Choice) {

        # A session can run past midnight, so it looks back two days and
        # relies on the session identifier to keep only its own operations.
        'This session' {
            return [pscustomobject] @{ Label = 'This session'; Since = $Now.Date.AddDays(-2); Session = $script:TkSessionId }
        }

        'Last 7 days' {
            return [pscustomobject] @{ Label = 'The last 7 days'; Since = $Now.Date.AddDays(-6); Session = '' }
        }

        default {
            return [pscustomobject] @{ Label = 'Today'; Since = $Now.Date; Session = '' }
        }
    }
}

<#
.SYNOPSIS
    Returns the period selected on the page.
#>
function Get-TkSelectedJournalPeriod {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $period = Get-TkControl -Name 'JournalPeriod'

    return (Get-TkJournalPeriod -Choice $(if ($period -and $period.SelectedItem) { [string] $period.SelectedItem } else { 'Today' }))
}

<#
.SYNOPSIS
    Shows the journal for the selected period, most recent first.
#>
function Update-TkJournalView {
    [CmdletBinding()]
    param()

    $period  = Get-TkSelectedJournalPeriod
    $entries = @(Get-TkJournalEntry -Since $period.Since -Session $period.Session)

    $document = New-TkFlowDocument

    if ($entries.Count -eq 0) {

        Add-TkParagraph -Document $document -Muted -Text (
            'Nothing was run through the toolkit in this period. Fixes, tweaks, installations, audit corrections, audits and reports appear here as they run.'
        )
    }
    else {
        $changes = @($entries | Where-Object { $_.Kind -eq 'Change' }).Count
        $failed  = @($entries | Where-Object { $_.Outcome -ne 'Done' }).Count

        Add-TkParagraph -Document $document -Text (
            '{0} operation(s) in {1}: {2} change(s) to the machine, {3} failed.' -f $entries.Count, $period.Label.ToLowerInvariant(), $changes, $failed
        )

        Add-TkTable -Document $document -Column @('Time', 'Kind', 'Operation', 'Outcome') -Weight @(0.9, 0.8, 3.2, 0.6) `
            -Row @($entries | Sort-Object -Property Time -Descending | ForEach-Object {
                , @(([datetime] $_.Time).ToString('MM-dd HH:mm'), $_.Kind, $_.Name, $_.Outcome)
            })
    }

    Set-TkDocument -ControlName 'JournalOutput' -Document $document
}

<#
.SYNOPSIS
    Reads the machine in the background, then writes and opens the report.
#>
function New-TkInterventionReportFromUi {
    [CmdletBinding()]
    param()

    $period = Get-TkSelectedJournalPeriod

    $script:TkPendingReport = [pscustomobject] @{
        Technician = (Get-TkControl -Name 'InterventionTechnician').Text
        Ticket     = (Get-TkControl -Name 'InterventionTicket').Text
        Notes      = (Get-TkControl -Name 'InterventionNotes').Text
        Period     = $period
        Audit      = $(if ($script:TkLastAudit) {
                           [pscustomobject] @{ Score = Get-TkAuditScore -Finding $script:TkLastAudit; Findings = @($script:TkLastAudit) }
                       } else { $null })
    }

    Invoke-TkBackgroundAction -StatusText 'Reading the machine for the intervention report...' `
        -ScriptBlock { Get-TkDashboardSnapshot } `
        -OnComplete {
            param($result)

            $snapshot = @($result.Output) | Select-Object -First 1
            $pending  = $script:TkPendingReport
            $ctx      = Get-TkContext

            $report = [pscustomobject] @{
                Computer    = $env:COMPUTERNAME
                GeneratedAt = Get-Date
                Toolkit     = '{0} {1} ({2})' -f $ctx.AppName, $ctx.Version, $ctx.Commit
                Technician  = $pending.Technician
                Ticket      = $pending.Ticket
                Notes       = $pending.Notes
                Period      = $pending.Period.Label
                Identity    = $(if ($snapshot) { $snapshot.Identity } else { $null })
                OS          = $(if ($snapshot) { $snapshot.OS } else { $null })
                Tiles       = @(if ($snapshot) { ConvertTo-TkDashboardHealth -Snapshot $snapshot })
                Audit       = $pending.Audit
                Entries     = @(Get-TkJournalEntry -Since $pending.Period.Since -Session $pending.Period.Session)
            }

            $dialog = New-Object Microsoft.Win32.SaveFileDialog
            $dialog.Title    = 'Save the intervention report'
            $dialog.Filter   = 'Web page (*.html)|*.html'
            $dialog.FileName = '{0}-intervention-{1}.html' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm')

            if (-not $dialog.ShowDialog()) {
                Set-TkStatus -Text 'The intervention report was not saved.'
                return
            }

            try {
                [System.IO.File]::WriteAllText($dialog.FileName, (ConvertTo-TkInterventionHtml -Report $report),
                                               (New-Object System.Text.UTF8Encoding($false)))
            }
            catch {
                Write-TkLog -Level Error -Category 'Report' -Message ('The intervention report could not be written: {0}' -f $_.Exception.Message)
                return
            }

            Add-TkJournalEntry -Name 'Intervention report written' -Category 'Report' -Detail $dialog.FileName
            Set-TkStatus -Text ('Intervention report written to {0}' -f $dialog.FileName)

            # Opened with whatever the operator uses for web pages. The file is
            # local and has no script or outside link in it.
            try {
                Start-Process -FilePath $dialog.FileName -ErrorAction Stop
            }
            catch {
                Write-TkLog -Level Warning -Category 'Report' -Message ('The report was written but could not be opened: {0}' -f $_.Exception.Message)
            }

            Update-TkJournalView
        }
}
