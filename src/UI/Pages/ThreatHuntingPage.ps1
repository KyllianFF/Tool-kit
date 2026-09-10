<#
    Toolkit - UI / Threat hunting tab

    Renders the four read only investigations as formatted documents rather
    than as tables of text, because each one needs a verdict next to the data:
    a list of eighty autostart entries is useless without the two that matter
    being visible.

    Severity is shown as a coloured marker, so a report can be read at arm's
    length before anything is examined in detail.
#>

# The last report rendered, kept so the export button has something to write.
$script:TkLastHuntReport = $null
$script:TkLastHuntName   = ''

<#
.SYNOPSIS
    Wires the Threat hunting tab.
#>
function Initialize-TkThreatHuntingPage {
    [CmdletBinding()]
    param()

    $choices = Get-TkControl -Name 'HuntChoices'

    if ($choices) {

        $choices.Add_SelectionChanged({

            switch ((Get-TkControl -Name 'HuntChoices').SelectedIndex) {
                0 { Invoke-TkEventTriageFromUi           ; break }
                1 { Invoke-TkPersistenceFromUi           ; break }
                2 { Invoke-TkExposureFromUi              ; break }
                3 { Invoke-TkCertificateInventoryFromUi  ; break }
            }
        })
    }

    Register-TkClick -Name 'BtnCheckEndpointCerts' -Action { Invoke-TkEndpointCertificateFromUi }
    Register-TkClick -Name 'BtnExportHunt'         -Action { Export-TkHuntReportFromUi }
}

<#
.SYNOPSIS
    Adds a finding to a document.

.DESCRIPTION
    Kept as a thin wrapper over Add-TkFindingCard so every existing caller
    draws a card without being rewritten. The old flat layout put a page of
    findings in one undifferentiated block; a card gives each one a boundary.

.PARAMETER Heading
    What the finding is about.

.PARAMETER Detail
    The measured value, shown to the right of the heading.

.PARAMETER Note
    The explanation, set underneath.

.PARAMETER Action
    What to change, shown in its own band.

.PARAMETER RemediationId
    Key into the remediation allow list, when a safe correction exists.
#>
function Add-TkSeverityLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Documents.FlowDocument] $Document,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Severity,

        [Parameter(Mandatory)]
        [string] $Heading,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Detail = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Note = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Action = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $RemediationId = ''
    )

    Add-TkFindingCard -Document $Document -Severity $Severity -Title $Heading `
                      -State $Detail -Detail $Note -Action $Action `
                      -RemediationId $RemediationId
}

<#
.SYNOPSIS
    Confirms a correction, showing exactly what will run, then applies it.

.DESCRIPTION
    The confirmation shows the command rather than a description of it. A
    button that changes a machine without saying what it is about to do is
    not something a technician should trust, and the operator is the one who
    has to answer for the change afterwards.

.PARAMETER RemediationId
    Key into the remediation allow list.
#>
function Invoke-TkRemediationFromUi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $RemediationId
    )

    $table = Get-TkRemediationTable

    if (-not $table.ContainsKey($RemediationId)) {
        Set-TkStatus -Text ('Unknown correction: {0}' -f $RemediationId)
        return
    }

    $entry = $table[$RemediationId]

    if ($entry.Elevated -and -not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'This correction needs an elevated instance.'
        return
    }

    $message = @(
        $entry.Explanation
        ''
        'This will run:'
        ''
        '    ' + $entry.Command
        ''
        'To undo it: ' + $entry.Reversible
        ''
        'Apply it now?'
    ) -join [Environment]::NewLine

    if (-not (Confirm-TkAction -Title $entry.Name -Message $message)) {
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Applying: {0}...' -f $entry.Name) `
        -ParameterList @{ id = $RemediationId } `
        -ScriptBlock {
            param($id)
            Invoke-TkRemediation -Id $id -Confirm:$false
        } `
        -OnComplete {
            param($result)

            if (@($result.Output) -contains $true) {
                Set-TkStatus -Text ('Applied: {0}. Re-run the check to confirm.' -f $entry.Name)
            }
            else {
                Set-TkStatus -Text ('Failed: {0}. See the output panel.' -f $entry.Name)
            }
        }.GetNewClosure()
}

# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Runs the event log triage and renders it.
#>
function Invoke-TkEventTriageFromUi {
    [CmdletBinding()]
    param()

    if (-not (Test-TkIsElevated)) {

        $document = New-TkFlowDocument
        Add-TkHeading   -Document $document -Text 'Event log triage' -Level 1
        Add-TkParagraph -Document $document -Text (
            'The Security log is not readable without administrator rights, so this needs an elevated instance. Restart from the button in the header.'
        )

        Set-TkDocument -ControlName 'HuntOutput' -Document $document
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Reading the event logs, this takes a moment...' `
        -ScriptBlock { Get-TkSecurityEventSummary -Days 7 } `
        -OnComplete {
            param($result)

            $findings = @($result.Output)

            $script:TkLastHuntReport = $findings
            $script:TkLastHuntName   = 'event-triage'

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Event log triage' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'The last seven days of the Security and System logs, summarised. Counts matter more than individual records: one account with three hundred failed logons overnight is a story, three failures across a week is a typo.'
            )

            foreach ($finding in $findings) {

                Add-TkSeverityLine -Document $document -Severity $finding.Severity `
                    -Heading ('{0} ({1})' -f $finding.Category, $finding.Count) `
                    -Detail $finding.Detail -Note $finding.Assessment
            }

            Set-TkDocument -ControlName 'HuntOutput' -Document $document
            Set-TkStatus -Text ('Event triage: {0} categories reviewed.' -f $findings.Count)
        }
}

<#
.SYNOPSIS
    Runs the persistence sweep and renders it.
#>
function Invoke-TkPersistenceFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Sweeping the automatic start points...' `
        -ScriptBlock { Get-TkPersistenceItem } `
        -OnComplete {
            param($result)

            $items = @($result.Output)

            $script:TkLastHuntReport = $items
            $script:TkLastHuntName   = 'persistence'

            $outside    = @($items | Where-Object { -not $_.InWindows })
            $suspicious = @($items | Where-Object { $_.Suspicious })

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Automatic start points' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '{0} entries in total, {1} outside the Windows directory. The whole skill in reading this list is ignoring the entries that are supposed to be there, so the ones that ship with Windows are separated out below.' -f
                    $items.Count, $outside.Count
            )

            if ($suspicious.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Worth a look first' -Level 2

                foreach ($item in $suspicious) {

                    Add-TkSeverityLine -Document $document -Severity 'Warning' `
                        -Heading ('{0}: {1}' -f $item.Kind, $item.Name) `
                        -Detail $item.Command -Note ('Because it {0}.' -f $item.Concerns)
                }
            }
            else {
                Add-TkSeverityLine -Document $document -Severity 'Pass' `
                    -Heading 'Nothing stood out' `
                    -Note 'No autostart entry is unsigned, missing, running from a user writable folder, or carrying encoding markers on its command line.'
            }

            Add-TkHeading -Document $document -Text 'Everything outside the Windows directory' -Level 2

            # The comma is required. Without it PowerShell flattens the inner
            # arrays into one long list of values and every row ends up with a
            # single cell, which is why these tables rendered as a list.
            $rows = @($outside | ForEach-Object {
                , @($_.Kind, $_.Name, $_.Signer, $_.Command)
            })

            if ($rows.Count -gt 0) {
                Add-TkTable -Document $document `
                            -Column @('Kind', 'Name', 'Signed by', 'Command') -Row $rows
            }
            else {
                Add-TkParagraph -Document $document -Muted -Text 'Nothing.'
            }

            Set-TkDocument -ControlName 'HuntOutput' -Document $document
            Set-TkStatus -Text ('{0} start points, {1} worth reviewing.' -f $items.Count, $suspicious.Count)
        }
}

<#
.SYNOPSIS
    Runs the exposure analysis and renders it.
#>
function Invoke-TkExposureFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Joining listening sockets to the firewall policy...' `
        -ScriptBlock { Get-TkExposureReport } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)

            $script:TkLastHuntReport = $rows
            $script:TkLastHuntName   = 'exposure'

            $exposed  = @($rows | Where-Object { $_.Exposed })
            $loopback = @($rows | Where-Object { $_.Severity -eq 'Pass' })

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Network exposure' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'A listening socket is not an exposed service. This joins what is listening to the inbound allow rules actually enabled in the firewall, so what you see is what a packet from the network can reach. {0} sockets listening, {1} reachable, {2} bound to loopback only.' -f
                    $rows.Count, $exposed.Count, $loopback.Count
            )

            if ($exposed.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Reachable from the network' -Level 2

                foreach ($row in $exposed) {

                    $label = if ($row.Service) { '{0} ({1})' -f $row.Port, $row.Service } else { [string] $row.Port }

                    Add-TkSeverityLine -Document $document -Severity $row.Severity `
                        -Heading ('Port {0}' -f $label) `
                        -Detail ('{0} on {1}' -f $row.ProcessName, $row.Address) `
                        -Note $row.Reason
                }
            }
            else {
                Add-TkSeverityLine -Document $document -Severity 'Pass' `
                    -Heading 'Nothing is reachable inbound' `
                    -Note 'Every listening socket is either bound to loopback or has no matching inbound allow rule.'
            }

            Add-TkHeading -Document $document -Text 'Everything listening' -Level 2

            Add-TkTable -Document $document -Column @('Port', 'Service', 'Address', 'Process', 'Reachable') `
                        -Row @($rows | ForEach-Object {
                            , @($_.Port, $_.Service, $_.Address, $_.ProcessName, $(if ($_.Exposed) { 'yes' } else { 'no' }))
                        })

            Set-TkDocument -ControlName 'HuntOutput' -Document $document
            Set-TkStatus -Text ('{0} listening, {1} reachable from the network.' -f $rows.Count, $exposed.Count)
        }
}

<#
.SYNOPSIS
    Inventories the local certificate stores and renders the result.
#>
function Invoke-TkCertificateInventoryFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the certificate stores...' `
        -ScriptBlock { Get-TkCertificateInventory } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)

            $script:TkLastHuntReport = $rows
            $script:TkLastHuntName   = 'certificates'

            $problems = @($rows | Where-Object { $_.Severity -ne 'Pass' })

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Certificate inventory' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '{0} certificates in the machine and user personal stores, {1} needing attention. An expired internal certificate is the most common self inflicted outage there is, and it is almost always found by users rather than by monitoring.' -f
                    $rows.Count, $problems.Count
            )

            foreach ($row in $problems) {

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading $row.Subject `
                    -Detail ('{0} days left, expires {1}' -f $row.DaysRemaining, $row.NotAfter.ToString('yyyy-MM-dd')) `
                    -Note ('{0}. Store: {1}.' -f $row.Concerns, $row.Store)
            }

            if ($problems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'Nothing expiring or weak'
            }

            Add-TkHeading -Document $document -Text 'Every certificate held' -Level 2

            Add-TkTable -Document $document -Column @('Days', 'Subject', 'Algorithm', 'Store') `
                        -Row @($rows | ForEach-Object {
                            , @($_.DaysRemaining, $_.Subject, $_.Algorithm, $_.Store)
                        })

            Set-TkDocument -ControlName 'HuntOutput' -Document $document
            Set-TkStatus -Text ('{0} certificates, {1} needing attention.' -f $rows.Count, $problems.Count)
        }
}

<#
.SYNOPSIS
    Checks the certificate expiry of a list of endpoints.
#>
function Invoke-TkEndpointCertificateFromUi {
    [CmdletBinding()]
    param()

    $text = (Get-TkControl -Name 'CertEndpoints').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        Set-TkStatus -Text 'List the endpoints to check, separated by commas.'
        return
    }

    $endpoints = @($text -split '[,;\s]+' | Where-Object { $_ })

    Invoke-TkBackgroundAction -StatusText ('Checking {0} endpoint(s)...' -f $endpoints.Count) `
        -ParameterList @{ targets = $endpoints } `
        -ScriptBlock {
            param($targets)
            Test-TkEndpointCertificate -Endpoint $targets
        } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)

            $script:TkLastHuntReport = $rows
            $script:TkLastHuntName   = 'endpoint-certificates'

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Endpoint certificate expiry' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'The monitoring nobody sets up. Keep the list of services that matter here and check it before the renewal window, not after the outage.'
            )

            foreach ($row in $rows) {

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading $row.Endpoint `
                    -Detail $(if ($null -ne $row.DaysRemaining) { '{0} days left' -f $row.DaysRemaining } else { 'no answer' }) `
                    -Note $row.Verdict
            }

            Set-TkDocument -ControlName 'HuntOutput' -Document $document
            Set-TkStatus -Text ('{0} endpoint(s) checked.' -f $rows.Count)
        }
}

<#
.SYNOPSIS
    Writes the last report to a JSON file.
#>
function Export-TkHuntReportFromUi {
    [CmdletBinding()]
    param()

    if (-not $script:TkLastHuntReport) {
        Set-TkStatus -Text 'Run one of the investigations first.'
        return
    }

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title    = 'Export the report'
    $dialog.Filter   = 'JSON report (*.json)|*.json'
    $dialog.FileName = '{0}-{1}-{2}.json' -f $env:COMPUTERNAME, $script:TkLastHuntName, (Get-Date -Format 'yyyyMMdd')

    if (-not $dialog.ShowDialog()) {
        return
    }

    try {
        [pscustomobject]@{
            Computer    = $env:COMPUTERNAME
            Report      = $script:TkLastHuntName
            GeneratedAt = (Get-Date).ToString('s')
            Toolkit     = (Get-TkContext).Version
            Findings    = $script:TkLastHuntReport
        } | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath $dialog.FileName -Encoding UTF8 -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Hunting' -Message (
            'Report written to {0}' -f $dialog.FileName
        )

        Set-TkStatus -Text ('Report written to {0}' -f $dialog.FileName)
    }
    catch {
        Write-TkLog -Level Error -Category 'Hunting' -Message (
            'The report could not be written: {0}' -f $_.Exception.Message
        )
    }
}
