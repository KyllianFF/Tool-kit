<#
    Toolkit - UI / Diagnostics page

    Seven read only reports a technician runs on a support call, plus a full
    check that runs the essential ones in order. Get-TkDiagnosticReport ties
    each entry of the list to the function behind it. The order is the point: a machine
    waiting for a reboot, or with a full disk, explains most complaints
    before anything else is worth looking at.

    Also hosts the hardening tab on the Security page, because it renders the
    same way and there is no reason to duplicate the plumbing.
#>

$script:TkLastDiagnostic     = $null
$script:TkLastDiagnosticName = ''

<#
.SYNOPSIS
    Wires the Diagnostics page.
#>
function Initialize-TkDiagnosticsPage {
    [CmdletBinding()]
    param()

    # The chooser drives the page: selecting an entry runs it. The entry is
    # found by its title in Get-TkDiagnosticReport, so inserting a report in
    # the markup cannot shift every entry below it onto the wrong function.
    $choices = Get-TkControl -Name 'DiagnosticChoices'

    if ($choices) {

        $choices.Add_SelectionChanged({

            $list  = Get-TkControl -Name 'DiagnosticChoices'
            $title = Get-TkItemTitle -Item $list.SelectedItem

            $report = @(Get-TkDiagnosticReport) | Where-Object { $_.Title -eq $title } | Select-Object -First 1

            if ($report) {
                & $report.Show
            }
        })
    }

    Register-TkClick -Name 'BtnDiagExport' -Action {
        Export-TkDiagnosticReport -ControlName 'DiagnosticsOutput'
    }

    Register-TkClick -Name 'BtnSupportBundle' -Action { Invoke-TkSupportBundleFromUi }

}

<#
.SYNOPSIS
    Starts the full check as though it had been chosen in the list.

.DESCRIPTION
    The entry is selected rather than the report called directly, so the list
    shows what is running. Select-TkListChoice clears the selection first, so
    it starts even when the entry is already selected.
#>
function Start-TkFullDiagnostic {
    [CmdletBinding()]
    param()

    if (-not (Select-TkListChoice -ListName 'DiagnosticChoices' -Title 'Full check')) {
        Invoke-TkDiagnosticOverview
    }
}

<#
.SYNOPSIS
    Builds the support bundle in the background and opens the folder.

.DESCRIPTION
    A background action because it reads the whole machine and can take a
    minute; the interface stays live while it runs, the same as every other
    diagnostic. When it finishes it selects the ZIP in Explorer so the
    operator can attach it without hunting for the path.
#>
function Invoke-TkSupportBundleFromUi {
    [CmdletBinding()]
    param()

    Set-TkStatus -Text 'Building the support bundle. This reads the whole machine and can take a minute...'

    Invoke-TkBackgroundAction -StatusText 'Building the support bundle...' `
        -ScriptBlock { New-TkSupportBundle } `
        -OnComplete {
            param($result)

            $path = @($result.Output) | Where-Object { $_ } | Select-Object -Last 1

            if (-not $path) {
                Set-TkStatus -Text 'The support bundle could not be created. See the output for details.'
                return
            }

            Set-TkStatus -Text ('Support bundle written to {0}' -f $path)

            # Select it in Explorer rather than opening it, so the operator can
            # drag it straight onto a ticket.
            try {
                Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"{0}"' -f $path) -ErrorAction Stop
            }
            catch {
                Write-TkLog -Level Warning -Category 'Bundle' -Message (
                    'The bundle was written but Explorer could not be opened at it: {0}' -f $_.Exception.Message
                )
            }
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

    # Recorded when the report is shown, which is when it was actually read.
    Add-TkJournalEntry -Name ('Report: {0}' -f $Name) -Category 'Diagnostics'
}

<#
.SYNOPSIS
    Lists the reports of the Diagnostics page and the function behind each.

.DESCRIPTION
    The single table between the entries of the chooser and the code. A test
    checks that every entry in the markup has a row here and that every
    function named exists.

.OUTPUTS
    PSCustomObject[] with Title and Show.
#>
function Get-TkDiagnosticReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Title = 'Full check';          Show = 'Invoke-TkDiagnosticOverview' }
        [pscustomobject] @{ Title = 'Pending reboot';      Show = 'Show-TkRebootStatus' }
        [pscustomobject] @{ Title = 'Storage health';      Show = 'Show-TkStorageHealth' }
        [pscustomobject] @{ Title = 'Devices';             Show = 'Show-TkDeviceReport' }
        [pscustomobject] @{ Title = 'Crashes';             Show = 'Show-TkStabilityReport' }
        [pscustomobject] @{ Title = 'Sign-in and management'; Show = 'Show-TkIdentityReport' }
        [pscustomobject] @{ Title = 'Update history';      Show = 'Show-TkUpdateHistory' }
        [pscustomobject] @{ Title = 'Printing';            Show = 'Show-TkPrintingReport' }
        [pscustomobject] @{ Title = 'Profiles and policy'; Show = 'Show-TkUserContext' }
    )
}

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Shows the devices Device Manager flags.
#>
function Show-TkDeviceReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the devices...' `
        -ScriptBlock { Get-TkDeviceProblem } `
        -OnComplete {
            param($result)

            $rows = @($result.Output | Where-Object { $_ })
            Set-TkLastDiagnostic -Name 'devices' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Devices' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"My headset does not work" is a device with a problem code far more often than anything the user can describe. Each code says a different thing: a missing driver, a device Windows stopped, one waiting for a restart.'
            )

            if ($rows.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'No device reports a problem'
            }

            foreach ($row in $rows) {

                # Informational codes, such as a device disabled on purpose,
                # need no button.
                $remediation = if ($row.Severity -ne 'Info') { 'open-device-manager' } else { '' }

                Add-TkSeverityLine -Document $document -Severity $row.Severity -Heading $row.Name `
                    -Detail ('Code {0}' -f $row.Code) `
                    -Note ((@($row.Meaning, $row.Hint) | Where-Object { $_ }) -join ' ') `
                    -Action $row.Action -RemediationId $remediation
            }

            if ($rows.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Identifiers' -Level 2
                Add-TkParagraph -Document $document -Muted -Text (
                    'The hardware identifier is what to search for on the manufacturer site when a driver is missing: VEN or VID is the vendor, DEV or PID the product.'
                )

                Add-TkTable -Document $document -Column @('Device', 'Code', 'Class', 'Hardware identifier') `
                    -Weight @(1.8, 0.5, 0.7, 2.2) `
                    -Row @($rows | ForEach-Object { , @($_.Name, [string] $_.Code, $_.Class, $_.DeviceId) })
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

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
    Shows how the device is joined and managed, and whether sign-in can work.
#>
function Show-TkIdentityReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading sign-in and management...' `
        -ScriptBlock { Get-TkIdentityHealth } `
        -OnComplete {
            param($result)

            $rows = @($result.Output | Where-Object { $_ })
            Set-TkLastDiagnostic -Name 'sign-in' -Data $rows

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Sign-in and management' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"I cannot sign in", "Outlook keeps asking for my password" and "the policy never arrived" are answered here: how the device is joined, its single sign-on token, the domain controller it reaches, the clock Kerberos depends on, and whether an MDM manages it.'
            )

            foreach ($row in $rows) {

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Value) `
                    -Note $row.Detail -RemediationId $row.RemediationId
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
        -ScriptBlock {
            [pscustomobject] @{
                Stability = @(Get-TkStabilityReport -Days 14)
                Crashes   = @(Get-TkCrashHistory -Days 90)
            }
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                return
            }

            $rows    = @($report.Stability | Where-Object { $_ })
            $crashes = @($report.Crashes   | Where-Object { $_ })
            $blue    = @($crashes | Where-Object { $_.Code -ne 0 })
            $resets  = @($crashes | Where-Object { $_.Code -eq 0 })

            Set-TkLastDiagnostic -Name 'stability' -Data $report

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Stability' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'Three different questions behind "it keeps crashing": did Windows itself stop, did one application stop, or did the machine simply lose power. Each has a different cause.'
            )

            # --- Blue screens and hard resets --------------------------------
            Add-TkHeading -Document $document -Text 'Blue screens and hard resets, last 90 days' -Level 2

            if ($crashes.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'No blue screen or hard reset in 90 days'
            }

            $recurring = @(Get-TkRecurringCrashDriver -Crash $crashes)

            if ($recurring.Count -gt 0) {

                Add-TkSeverityLine -Document $document -Severity 'Warning' `
                    -Heading 'Kernel drivers registered before several blue screens' `
                    -Detail ((@($recurring | ForEach-Object { '{0} ({1} of {2})' -f $_.Name, $_.Crashes, $blue.Count })) -join ', ') `
                    -Note 'The same driver in front of several crashes is the first one to update or uninstall. It is a correlation, not a proof: monitoring and overclocking tools register their driver every time they start.'
            }

            foreach ($crash in $blue) {

                $info    = $crash.Info
                $drivers = @($crash.Drivers | Where-Object { $_ })

                $note = @(
                    $info.Meaning
                    $(if ($info.KindName) { 'Usual cause: {0}.' -f $info.KindName.ToLowerInvariant() })
                    $(if ($drivers.Count -gt 0) { 'Kernel drivers registered in the 7 days before: {0}.' -f ((@($drivers | ForEach-Object { $_.Name })) -join ', ') })
                    $(if ($crash.DumpPath) { 'Dump: {0}. Reading it needs administrator rights and WinDbg (winget install Microsoft.WinDbg), then !analyze -v.' -f $crash.DumpPath })
                ) | Where-Object { $_ }

                Add-TkSeverityLine -Document $document -Severity $crash.Severity `
                    -Heading ('{0} {1}' -f $info.CodeHex, $info.Name) `
                    -Detail ('{0}, {1}' -f $crash.Kind, ([datetime] $crash.When).ToString('yyyy-MM-dd HH:mm')) `
                    -Note ($note -join ' ') `
                    -Action (@($info.Steps) -join ' ')
            }

            if ($resets.Count -gt 0) {

                Add-TkSeverityLine -Document $document -Severity 'Warning' `
                    -Heading ('{0} hard reset(s) or power loss(es)' -f $resets.Count) `
                    -Detail ('last on {0}' -f ([datetime] $resets[0].When).ToString('yyyy-MM-dd HH:mm')) `
                    -Note 'The session ended with no shutdown and no stop code: the power was lost, the power button was held, or the machine froze and had to be reset.'
            }

            # --- The other signals -------------------------------------------
            Add-TkHeading -Document $document -Text 'Other signals, last 14 days' -Level 2

            # Blue screens are described above, with more than a line each.
            foreach ($row in ($rows | Where-Object { $_.Kind -ne 'Bug check' })) {

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
                Devices   = @(Get-TkDeviceProblem)
                Stability = Get-TkStabilityReport -Days 14
                Crashes   = @(Get-TkCrashHistory -Days 30)
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

            # --- Devices ------------------------------------------------
            Add-TkHeading -Document $document -Text '3. Devices' -Level 2

            $deviceProblems = @($report.Devices | Where-Object { $_ -and $_.Severity -ne 'Info' })

            if ($deviceProblems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'No device reports a problem'
            }
            else {
                foreach ($row in $deviceProblems) {
                    Add-TkSeverityLine -Document $document -Severity $row.Severity -Heading $row.Name `
                        -Detail ('Code {0}' -f $row.Code) -Note $row.Meaning -Action $row.Action `
                        -RemediationId 'open-device-manager'
                }
            }

            # --- Stability ----------------------------------------------
            Add-TkHeading -Document $document -Text '4. Stability' -Level 2

            foreach ($crash in @($report.Crashes | Where-Object { $_ -and $_.Code -ne 0 })) {
                Add-TkSeverityLine -Document $document -Severity 'Fail' `
                    -Heading ('{0} {1}' -f $crash.Info.CodeHex, $crash.Info.Name) `
                    -Detail ([datetime] $crash.When).ToString('yyyy-MM-dd HH:mm') `
                    -Note ('{0} The Crashes report lists the drivers registered before it.' -f $crash.Info.Meaning)
            }

            foreach ($row in @($report.Stability | Where-Object { $_.Kind -ne 'Bug check' } | Select-Object -First 6)) {
                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}{1}' -f $row.Kind, $(if ($row.Source) { ': ' + $row.Source } else { '' })) `
                    -Note $row.Detail
            }

            # --- Printing -----------------------------------------------
            Add-TkHeading -Document $document -Text '5. Printing' -Level 2

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
            Add-TkHeading -Document $document -Text '6. Profiles, drives and policy' -Level 2

            foreach ($row in $report.Context) {
                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Name) -Detail $row.Value -Note $row.Detail
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
            Set-TkStatus -Text 'Full check finished.'
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
