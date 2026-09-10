<#
    Toolkit - UI / Diagnostics page

    Seven read only checks a technician runs on a support call, plus a full
    pass that runs them all in order. The order is the point: a machine
    waiting for a reboot, or with a full disk, explains most complaints
    before anything else is worth looking at.

    Also hosts the hardening tab on the Security page, because it renders the
    same way and there is no reason to duplicate the plumbing.
#>

$script:TkLastDiagnostic     = $null
$script:TkLastDiagnosticName = ''

<#
.SYNOPSIS
    Wires the Diagnostics page and the Hardening tab.
#>
function Initialize-TkDiagnosticsPage {
    [CmdletBinding()]
    param()

    # The chooser drives the page: selecting an entry runs it. Index order
    # matches the ListBox declared in the markup.
    $choices = Get-TkControl -Name 'DiagnosticChoices'

    if ($choices) {

        $choices.Add_SelectionChanged({

            switch ((Get-TkControl -Name 'DiagnosticChoices').SelectedIndex) {
                0 { Invoke-TkDiagnosticOverview ; break }
                1 { Show-TkRebootStatus         ; break }
                2 { Show-TkStorageHealth        ; break }
                3 { Show-TkStabilityReport      ; break }
                4 { Show-TkUpdateHistory        ; break }
                5 { Show-TkPrintingReport       ; break }
                6 { Show-TkUserContext          ; break }
            }
        })
    }

    Register-TkClick -Name 'BtnDiagExport' -Action {
        Export-TkDiagnosticReport -ControlName 'DiagnosticsOutput'
    }

    Register-TkClick -Name 'BtnHardening'       -Action { Show-TkHardeningCheck }
    Register-TkClick -Name 'BtnExportHardening' -Action {
        Export-TkDiagnosticReport -ControlName 'HardeningOutput'
    }
}

<#
.SYNOPSIS
    Records a report so the export button has something to write.
#>
function Set-TkLastDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Data
    )

    $script:TkLastDiagnostic     = $Data
    $script:TkLastDiagnosticName = $Name
}

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Shows whether the machine is waiting for a restart.
#>
function Show-TkRebootStatus {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Checking for a pending reboot...' `
        -ScriptBlock { Get-TkPendingRebootStatus } `
        -OnComplete {
            param($result)

            $status = @($result.Output) | Select-Object -First 1

            Set-TkLastDiagnostic -Name 'pending-reboot' -Data $status

            $document = New-TkFlowDocument

            Add-TkHeading -Document $document -Text 'Pending reboot' -Level 1

            Add-TkSeverityLine -Document $document `
                -Severity $(if ($status.Pending) { 'Warning' } else { 'Pass' }) `
                -Heading $(if ($status.Pending) { 'A restart is pending' } else { 'No restart pending' }) `
                -Detail ('up {0}' -f $status.Uptime) `
                -Note 'Windows records a pending reboot in several unrelated places and no single one is authoritative, which is why "have you restarted it" so often produces "yes" and no improvement.'

            foreach ($reason in $status.Reasons) {
                Add-TkSeverityLine -Document $document -Severity 'Info' -Heading $reason
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows disk health and free space.
#>
function Show-TkStorageHealth {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading disk health...' `
        -ScriptBlock { Get-TkStorageHealth } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)
            Set-TkLastDiagnostic -Name 'storage' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Storage health' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"The machine is slow" is answered by a failing disk or a full volume far more often than by anything else.'
            )

            foreach ($row in ($rows | Where-Object { $_.Severity -ne 'Pass' })) {

                # A full volume has one safe first move: clear the temporary
                # files and measure again.
                $remediation = if ($row.Kind -eq 'Volume') { 'clear-temp' } else { '' }

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Name) `
                    -Detail $row.Health -Note $row.Notes -RemediationId $remediation
            }

            Add-TkHeading -Document $document -Text 'Every drive and volume' -Level 2

            Add-TkTable -Document $document `
                -Column @('Kind', 'Name', 'Size', 'Type', 'State', 'Wear %', 'Temp C') `
                -Weight @(0.7, 1.8, 0.9, 0.7, 1.4, 0.6, 0.6) `
                -Row @($rows | ForEach-Object {
                    , @($_.Kind, $_.Name, $_.Size, $_.MediaType, $_.Health, $_.WearPercent, $_.TemperatureC)
                })

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows crashes, bug checks and unexpected shutdowns.
#>
function Show-TkStabilityReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the crash history...' `
        -ScriptBlock { Get-TkStabilityReport -Days 14 } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)
            Set-TkLastDiagnostic -Name 'stability' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Stability' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'Three different questions behind "it keeps crashing": did Windows itself stop, did one application stop, or did the machine simply lose power. Each has a different cause.'
            )

            foreach ($row in $rows) {

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}{1}' -f $row.Kind, $(if ($row.Source) { ': ' + $row.Source } else { '' })) `
                    -Detail $(if ($row.When) { ([datetime] $row.When).ToString('yyyy-MM-dd HH:mm') } else { '' }) `
                    -Note $row.Detail
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows the recent Windows Update history.
#>
function Show-TkUpdateHistory {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the update history...' `
        -ScriptBlock { Get-TkUpdateHistory -Count 40 } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)
            Set-TkLastDiagnostic -Name 'updates' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Update history' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'Read through the update session interface rather than Get-HotFix, which only reports servicing packages and misses driver and feature updates entirely. Those are the ones that break things.'
            )

            $failures = @($rows | Where-Object { $_.Severity -in @('Fail', 'Warning') })

            foreach ($row in $failures) {

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading $row.Title -Detail $row.Outcome `
                    -Note ('{0} on {1}' -f $row.Code, ([datetime] $row.When).ToString('yyyy-MM-dd'))
            }

            if ($failures.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'No failed update in the recent history'
            }

            Add-TkHeading -Document $document -Text 'Recent updates' -Level 2

            Add-TkTable -Document $document -Column @('Date', 'Outcome', 'Update') `
                -Weight @(0.9, 0.9, 3.2) `
                -Row @($rows | ForEach-Object {
                    , @(([datetime] $_.When).ToString('yyyy-MM-dd'), $_.Outcome, $_.Title)
                })

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows the printing subsystem.
#>
function Show-TkPrintingReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the printing subsystem...' `
        -ScriptBlock { Get-TkPrintingReport } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)
            Set-TkLastDiagnostic -Name 'printing' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Printing' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"It will not print" is nearly always one of four things: the printer is offline, the queue is jammed, the port points somewhere unreachable, or the spooler has stopped.'
            )

            foreach ($row in $rows) {

                # The spooler is the one printing problem with a safe one step
                # correction, so it is the one that gets a button.
                $remediation = if ($row.Kind -eq 'Spooler' -and $row.Severity -eq 'Fail') { 'start-spooler' } else { '' }

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Name) `
                    -Detail $row.Status -Note $row.Detail -RemediationId $remediation
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows profiles, mapped drives, domain state and logon timing.
#>
function Show-TkUserContext {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading profiles and policy, this measures profile sizes...' `
        -ScriptBlock { Get-TkUserContextReport } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)
            Set-TkLastDiagnostic -Name 'user-context' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Profiles and policy' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'The context of a support call: who is signed in, how large their profile is, what is mapped, and how long policy takes to apply. A roaming profile of twelve gigabytes explains a slow logon better than any amount of network testing.'
            )

            foreach ($row in $rows) {

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Name) `
                    -Detail $row.Value -Note $row.Detail
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Runs every diagnostic in the order a call is normally worked.
#>
function Invoke-TkDiagnosticOverview {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Running the full check, this takes a minute...' `
        -ScriptBlock {

            [pscustomobject]@{
                Reboot    = Get-TkPendingRebootStatus
                Storage   = Get-TkStorageHealth
                Stability = Get-TkStabilityReport -Days 14
                Printing  = Get-TkPrintingReport
                Context   = Get-TkUserContextReport
            }
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                return
            }

            Set-TkLastDiagnostic -Name 'full-check' -Data $report

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text ('Diagnostics for {0}' -f $env:COMPUTERNAME) -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'In the order a call is normally worked. A machine waiting for a reboot, or with a full disk, explains most complaints before anything else is worth looking at.'
            )

            # --- Reboot -------------------------------------------------
            Add-TkHeading -Document $document -Text '1. Is it waiting for a restart' -Level 2

            Add-TkSeverityLine -Document $document `
                -Severity $(if ($report.Reboot.Pending) { 'Warning' } else { 'Pass' }) `
                -Heading $(if ($report.Reboot.Pending) { 'A restart is pending' } else { 'No restart pending' }) `
                -Detail ('up {0}' -f $report.Reboot.Uptime) `
                -Note (($report.Reboot.Reasons -join ' ') )

            # --- Storage ------------------------------------------------
            Add-TkHeading -Document $document -Text '2. Storage' -Level 2

            $storageProblems = @($report.Storage | Where-Object { $_.Severity -ne 'Pass' })

            if ($storageProblems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'Every drive healthy, every volume with room'
            }
            else {
                foreach ($row in $storageProblems) {
                    Add-TkSeverityLine -Document $document -Severity $row.Severity `
                        -Heading ('{0}: {1}' -f $row.Kind, $row.Name) -Detail $row.Health -Note $row.Notes
                }
            }

            # --- Stability ----------------------------------------------
            Add-TkHeading -Document $document -Text '3. Stability' -Level 2

            foreach ($row in @($report.Stability | Select-Object -First 6)) {
                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}{1}' -f $row.Kind, $(if ($row.Source) { ': ' + $row.Source } else { '' })) `
                    -Note $row.Detail
            }

            # --- Printing -----------------------------------------------
            Add-TkHeading -Document $document -Text '4. Printing' -Level 2

            $printProblems = @($report.Printing | Where-Object { $_.Severity -ne 'Pass' })

            if ($printProblems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'Spooler running, no printer reporting a problem'
            }
            else {
                foreach ($row in $printProblems) {
                    Add-TkSeverityLine -Document $document -Severity $row.Severity `
                        -Heading ('{0}: {1}' -f $row.Kind, $row.Name) -Detail $row.Status -Note $row.Detail
                }
            }

            # --- Context ------------------------------------------------
            Add-TkHeading -Document $document -Text '5. Profiles, drives and policy' -Level 2

            foreach ($row in $report.Context) {
                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Name) -Detail $row.Value -Note $row.Detail
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
            Set-TkStatus -Text 'Full check finished.'
        }
}

# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Runs the hardening check and renders it grouped by area.
#>
function Show-TkHardeningCheck {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Checking the hardening controls...' `
        -ScriptBlock { Invoke-TkHardeningCheck } `
        -OnComplete {
            param($result)

            $findings = @($result.Output)
            Set-TkLastDiagnostic -Name 'hardening' -Data $findings

            $document = New-TkFlowDocument

            Add-TkHeading -Document $document -Text 'Hardening' -Level 1

            $failing = @($findings | Where-Object { $_.Severity -eq 'Fail' }).Count
            $warning = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count

            Add-TkParagraph -Document $document -Muted -Text (
                '{0} controls checked: {1} failing, {2} worth attention. These decide whether an intrusion stays on one machine or reaches the whole estate.' -f
                    $findings.Count, $failing, $warning
            )

            foreach ($area in (@($findings | ForEach-Object { $_.Area }) | Select-Object -Unique)) {

                Add-TkHeading -Document $document -Text $area -Level 2

                foreach ($finding in ($findings | Where-Object { $_.Area -eq $area })) {

                    Add-TkFindingCard -Document $document -Severity $finding.Severity `
                        -Title $finding.Name -State $finding.State -Detail $finding.Why `
                        -Action $finding.Fix -RemediationId $finding.RemediationId
                }
            }

            Set-TkDocument -ControlName 'HardeningOutput' -Document $document
            Set-TkStatus -Text ('Hardening: {0} failing, {1} warnings.' -f $failing, $warning)
        }
}

<#
.SYNOPSIS
    Writes the last rendered report to a JSON file.

.PARAMETER ControlName
    Only used to keep the two export buttons distinguishable in the log.
#>
function Export-TkDiagnosticReport {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $ControlName = ''
    )

    if (-not $script:TkLastDiagnostic) {
        Set-TkStatus -Text 'Run a check first.'
        return
    }

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title    = 'Export the report'
    $dialog.Filter   = 'JSON report (*.json)|*.json'
    $dialog.FileName = '{0}-{1}-{2}.json' -f $env:COMPUTERNAME, $script:TkLastDiagnosticName, (Get-Date -Format 'yyyyMMdd')

    if (-not $dialog.ShowDialog()) {
        return
    }

    try {
        [pscustomobject]@{
            Computer    = $env:COMPUTERNAME
            Report      = $script:TkLastDiagnosticName
            GeneratedAt = (Get-Date).ToString('s')
            Toolkit     = (Get-TkContext).Version
            Data        = $script:TkLastDiagnostic
        } | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath $dialog.FileName -Encoding UTF8 -ErrorAction Stop

        Set-TkStatus -Text ('Report written to {0}' -f $dialog.FileName)
    }
    catch {
        Write-TkLog -Level Error -Category 'Diagnostics' -Message (
            'The report could not be written: {0}' -f $_.Exception.Message
        )
    }
}
