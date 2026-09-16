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
        [pscustomobject] @{ Title = 'Disk space';          Show = 'Show-TkDiskSpaceReport' }
        [pscustomobject] @{ Title = 'Performance';         Show = 'Show-TkPerformanceReport' }
        [pscustomobject] @{ Title = 'Devices';             Show = 'Show-TkDeviceReport' }
        [pscustomobject] @{ Title = 'Crashes';             Show = 'Show-TkStabilityReport' }
        [pscustomobject] @{ Title = 'Wi-Fi';               Show = 'Show-TkWifiReport' }
        [pscustomobject] @{ Title = 'Proxy';               Show = 'Show-TkProxyReport' }
        [pscustomobject] @{ Title = 'Sign-in and management'; Show = 'Show-TkIdentityReport' }
        [pscustomobject] @{ Title = 'Update history';      Show = 'Show-TkUpdateHistory' }
        [pscustomobject] @{ Title = 'Software support';    Show = 'Show-TkSoftwareLifecycleReport' }
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
    Shows where the disk space went: drive fill, the biggest folders and files,
    and the caches safe to empty.
#>
function Show-TkDiskSpaceReport {
    [CmdletBinding()]
    param()

    # Overridable so a test or an off-screen render can point the scan at a
    # small folder instead of the whole system drive.
    $root = if ($script:TkDiskSpaceRoot) { $script:TkDiskSpaceRoot } else { '{0}\' -f $env:SystemDrive }

    Invoke-TkBackgroundAction -StatusText ('Scanning {0} for the biggest folders and files, this can take a minute...' -f $root) `
        -ArgumentList @($root) `
        -ScriptBlock {
            param($scanRoot)

            [pscustomobject] @{
                Drives  = @(Get-TkDriveSpace)
                Usage   = Get-TkDiskUsageScan -Path $scanRoot -TopFolders 15 -TopFiles 20
                Cleanup = @(Get-TkCleanupCandidate)
            }
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Usage'] } | Select-Object -First 1

            if (-not $report) {
                return
            }

            Set-TkLastDiagnostic -Name 'disk-space' -Data $report

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Disk space' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"The disk is full" has an answer once it is split up: how full each drive is, which folders and files hold the most, and the caches that are safe to empty. The scan only reads sizes and follows no junctions; nothing here is deleted.'
            )

            # --- Drives -------------------------------------------------------
            foreach ($drive in @($report.Drives)) {
                Add-TkSeverityLine -Document $document -Severity $drive.Severity `
                    -Heading ('Drive {0}{1}' -f $drive.Name, $(if ($drive.Label) { ' ({0})' -f $drive.Label } else { '' })) `
                    -Detail ('{0} free of {1}' -f (Format-TkBytes -Bytes $drive.FreeBytes), (Format-TkBytes -Bytes $drive.TotalBytes)) `
                    -Note ('{0}% free, {1} used.' -f $drive.FreePercent, (Format-TkBytes -Bytes $drive.UsedBytes))
            }

            # --- Biggest folders ---------------------------------------------
            $folders = @($report.Usage.Folders)

            if ($folders.Count -gt 0) {

                Add-TkHeading -Document $document -Text ('Biggest folders on {0}' -f $report.Usage.Root) -Level 2

                Add-TkTable -Document $document -Column @('Folder', 'Size') -Weight @(3.5, 1.0) `
                    -Row @($folders | ForEach-Object { , @($_.Name, (Format-TkBytes -Bytes $_.Bytes)) })
            }

            # --- Biggest files -----------------------------------------------
            $files = @($report.Usage.Files)

            if ($files.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Biggest files' -Level 2

                Add-TkTable -Document $document -Column @('File', 'Size') -Weight @(3.5, 1.0) `
                    -Row @($files | ForEach-Object { , @($_.Path, (Format-TkBytes -Bytes $_.Bytes)) })
            }

            # --- Safe to clean up --------------------------------------------
            $cleanup     = @($report.Cleanup | Where-Object { $_.Exists -and $_.Bytes -gt 0 } | Sort-Object -Property Bytes -Descending)
            $reclaimable = ($cleanup | Measure-Object -Property Bytes -Sum).Sum

            Add-TkHeading -Document $document -Text 'Safe to clean up' -Level 2

            if ($cleanup.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'The usual caches are already empty or missing'
            }
            else {
                Add-TkParagraph -Document $document -Muted -Text (
                    'About {0} could be freed. Nothing was deleted: empty these with Storage Sense or Disk Cleanup, or by hand once you have checked them. Emptying a system location needs administrator rights.' -f (Format-TkBytes -Bytes $reclaimable)
                )

                Add-TkTable -Document $document -Column @('Location', 'Size', 'What it is') -Weight @(1.6, 0.7, 2.7) `
                    -Row @($cleanup | ForEach-Object { , @($_.Name, (Format-TkBytes -Bytes $_.Bytes), (('{0} {1}' -f $(if ($_.Scope -eq 'System') { '(admin)' } else { '' }), $_.Note)).Trim()) })
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows what the machine is doing, what starts with it, and how long start
    up takes.
#>
function Show-TkPerformanceReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Measuring what the machine is doing...' `
        -ScriptBlock {
            [pscustomobject] @{
                Snapshot = Get-TkPerformanceSnapshot
                Startup  = @(Get-TkStartupProgram)
                Boot     = Get-TkBootPerformance -Days 30
            }
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Snapshot'] } | Select-Object -First 1

            if (-not $report) {
                return
            }

            Set-TkLastDiagnostic -Name 'performance' -Data $report

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Performance' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"The machine is slow" has an answer once it is split up: what is using the processor, the memory and the disks right now, what starts with Windows, and how long start up takes and what slows it.'
            )

            foreach ($finding in @(Get-TkPerformanceFinding -Snapshot $report.Snapshot -Startup @($report.Startup) -Boot $report.Boot)) {
                Add-TkSeverityLine -Document $document -Severity $finding.Severity -Heading $finding.Heading `
                    -Detail $finding.Detail -Note $finding.Note
            }

            $applications = @($report.Snapshot.Applications | Sort-Object -Property @{ Expression = 'CpuPercent'; Descending = $true },
                                                                                   @{ Expression = 'MemoryMB'; Descending = $true } |
                              Select-Object -First 12)

            if ($applications.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Applications using the most right now' -Level 2

                Add-TkTable -Document $document -Column @('Application', 'Processes', 'CPU %', 'Memory MB', 'Disk KB/s') `
                    -Weight @(2.2, 0.8, 0.7, 0.9, 0.9) `
                    -Row @($applications | ForEach-Object {
                        , @($_.Name, [string] $_.Instances, [string] $_.CpuPercent, [string] $_.MemoryMB, [string] $_.IoKBps)
                    })
            }

            $startup = @($report.Startup | Where-Object { $_ })

            if ($startup.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Programs that start with Windows' -Level 2

                Add-TkTable -Document $document -Column @('Program', 'For', 'State', 'Command') `
                    -Weight @(1.6, 0.8, 0.7, 3.0) `
                    -Row @($startup | ForEach-Object {
                        , @($_.Name, $_.Scope, $(if ($_.Enabled) { 'Runs' } else { 'Disabled' }), $_.Command)
                    })
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows the Wi-Fi connection: signal, band, rate, security and drops.
#>
function Show-TkWifiReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the Wi-Fi connection...' `
        -ScriptBlock { Get-TkWifiStatus -Days 7 } `
        -OnComplete {
            param($result)

            $status = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Interfaces'] } | Select-Object -First 1

            if (-not $status) {
                return
            }

            Set-TkLastDiagnostic -Name 'wifi' -Data $status

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Wi-Fi' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                '"The Wi-Fi is bad" covers causes that look alike from the chair: a weak signal, a crowded 2.4 GHz channel, a low link rate, an old standard, or a connection that keeps dropping. Read from the Wi-Fi API rather than netsh, so the display language does not matter.'
            )

            foreach ($finding in @(Get-TkWifiFinding -Status $status)) {
                Add-TkSeverityLine -Document $document -Severity $finding.Severity -Heading $finding.Heading `
                    -Detail $finding.Detail -Note $finding.Note -RemediationId $finding.RemediationId
            }

            foreach ($adapter in @($status.Interfaces | Where-Object { $_ })) {

                $connected = if ($adapter.Connection) { $adapter.Connection.Bssid } else { '' }
                $networks  = @($adapter.Networks | Sort-Object -Property Rssi -Descending | Select-Object -First 20)

                if ($networks.Count -gt 0) {

                    Add-TkHeading -Document $document -Text 'Networks in range' -Level 2
                    Add-TkParagraph -Document $document -Muted -Text (
                        'As last seen by the adapter. Above -67 dBm is good for calls, below -80 dBm is barely usable. Several rows with one name are the bands and access points of one network.'
                    )

                    Add-TkTable -Document $document -Column @('Network', 'Signal', 'Band', 'Channel', 'Standard', 'Access point') `
                        -Weight @(1.9, 0.7, 0.7, 0.6, 1.2, 1.3) `
                        -Row @($networks | ForEach-Object {
                            $name = if ($_.Ssid) { $_.Ssid } else { '(hidden)' }

                            , @($(if ($_.Bssid -eq $connected) { $name + ' (connected)' } else { $name }),
                                ('{0} dBm' -f [string] $_.Rssi), $_.Band, [string] $_.Channel, $_.Standard, $_.Bssid)
                        })
                }

                $recent = @($adapter.Events | Where-Object { $_ -and $_.Kind -ne 'Connected' } |
                            Sort-Object -Property When -Descending | Select-Object -First 12)

                if ($recent.Count -gt 0) {

                    Add-TkHeading -Document $document -Text 'Recent disconnections and failed attempts' -Level 2

                    Add-TkTable -Document $document -Column @('When', 'Event', 'Network', 'Reason') `
                        -Weight @(1.1, 0.8, 1.2, 3.0) `
                        -Row @($recent | ForEach-Object {
                            , @(([datetime] $_.When).ToString('yyyy-MM-dd HH:mm'),
                                $(if ($_.Expected) { $_.Kind + ' (expected)' } else { $_.Kind }), $_.Ssid, $_.Reason)
                        })
                }
            }

            Set-TkDocument -ControlName 'DiagnosticsOutput' -Document $document
        }
}

<#
.SYNOPSIS
    Shows the three proxy settings, whether each one answers, and what
    automatic detection finds.
#>
function Show-TkProxyReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the proxy settings and checking they answer...' `
        -ScriptBlock {
            $setting = Get-TkProxySetting

            [pscustomobject] @{
                Setting = $setting
                Probe   = Invoke-TkProxyProbe -Setting $setting
            }
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Setting'] } | Select-Object -First 1

            if (-not $report) {
                return
            }

            Set-TkLastDiagnostic -Name 'proxy' -Data $report

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Proxy' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'Windows keeps three proxy settings and each program reads one of them. A difference between them is why the web works while Windows Update fails, or the browser works while git does not.'
            )

            foreach ($finding in @(Get-TkProxyFinding -Setting $report.Setting -Probe $report.Probe)) {
                Add-TkSeverityLine -Document $document -Severity $finding.Severity -Heading $finding.Heading `
                    -Detail $finding.Detail -Note $finding.Note -RemediationId $finding.RemediationId
            }

            Add-TkHeading -Document $document -Text 'Where each program looks' -Level 2

            $rows = @(
                , @('Applications (WinINET)', 'Browsers, Office, most applications', (Format-TkProxyDescription -Setting $report.Setting.User))
                , @('Services (WinHTTP)', 'Windows Update, BITS, Defender, Intune', (Format-TkProxyDescription -Setting $report.Setting.Machine))
            )

            foreach ($variable in @($report.Setting.Environment | Where-Object { $_ })) {
                $rows += , @(('{0} ({1})' -f $variable.Name, $variable.Scope), 'git, curl, Python, Node', $variable.Value)
            }

            Add-TkTable -Document $document -Column @('Setting', 'Read by', 'Value') -Weight @(1.2, 1.5, 2.6) -Row $rows

            $targets = @($report.Probe.Targets | Where-Object { $_ })

            if ($targets.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Checked' -Level 2

                Add-TkTable -Document $document -Column @('Address', 'Answers', 'Time') -Weight @(2.4, 0.8, 0.8) `
                    -Row @($targets | ForEach-Object {
                        , @($_.Address, $(if ($_.Open) { 'Yes' } else { 'No' }), ('{0} ms' -f [string] $_.ResponseMs))
                    })
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

                # The code explained from the reference, and where to read what
                # to try for it.
                $note = @(
                    ('{0} on {1}.' -f $row.Code, ([datetime] $row.When).ToString('yyyy-MM-dd'))
                    $(if ($row.PSObject.Properties['Meaning'] -and $row.Meaning) { $row.Meaning })
                    'Knowledge base, Windows codes says what to try for this code.'
                ) | Where-Object { $_ }

                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading $row.Title -Detail $row.Outcome `
                    -Note ($note -join ' ')
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
    Writes one row of the software support report as a finding line.

.PARAMETER Document
    The document to write in.

.PARAMETER Row
    A row of Get-TkSoftwareLifecycleReport, for Windows or a program.
#>
function Add-TkLifecycleLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Document,
        [Parameter(Mandatory)] [pscustomobject] $Row
    )

    $actionable = $Row.Severity -in @('Fail', 'Warning')

    $note = @(
        $(if (@($Row.Installed).Count -gt 0) { 'Installed: {0}.' -f ((@($Row.Installed) | Where-Object { $_ }) -join '; ') })
        $Row.Note
        $(if ($actionable -and $Row.Replacement) { 'Move to: {0}' -f $Row.Replacement })
    ) | Where-Object { $_ }

    $remediation = if (-not $actionable) { '' } elseif ($Row.ProductId -eq 'windows') { 'open-windows-update' } else { 'open-installed-apps' }

    Add-TkSeverityLine -Document $Document -Severity $Row.Severity -Heading $Row.Title `
        -Detail (Format-TkLifecycleDetail -Row $Row) -Note ($note -join ' ') -RemediationId $remediation
}

<#
.SYNOPSIS
    Shows whether Windows and the installed programs still receive security fixes.
#>
function Show-TkSoftwareLifecycleReport {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the installed programs...' `
        -ScriptBlock { Get-TkSoftwareLifecycleReport } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                return
            }

            Set-TkLastDiagnostic -Name 'software-support' -Data $report

            $document = New-TkFlowDocument

            Add-TkHeading   -Document $document -Text 'Software support' -Level 1
            Add-TkParagraph -Document $document -Muted -Text (
                'Software past its end of support gets no security fix again: every vulnerability found after that date stays open for good. Windows is judged from its edition and build, the installed programs against the dates their vendors publish, reviewed in {0}. A program the catalog does not list is not judged.' -f $report.Reviewed
            )

            Add-TkHeading -Document $document -Text 'Windows' -Level 2
            Add-TkLifecycleLine -Document $document -Row $report.Windows

            Add-TkHeading -Document $document -Text 'Programs' -Level 2

            $recognised = @($report.Programs | Where-Object { $_ })
            $problems   = @($recognised | Where-Object { $_.Severity -ne 'Pass' })

            if ($problems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'No recognised program is past or near its end of support'
            }

            foreach ($row in $problems) {
                Add-TkLifecycleLine -Document $document -Row $row
            }

            if ($recognised.Count -gt 0) {

                Add-TkHeading -Document $document -Text 'Recognised programs' -Level 2

                Add-TkTable -Document $document -Column @('Program', 'Version', 'Support ends', 'Status') `
                    -Weight @(2.0, 1.6, 0.9, 0.8) `
                    -Row @($recognised | ForEach-Object {
                        , @($_.Title, $_.Version, $(if ($_.Ends) { $_.Ends } else { '-' }), $_.Status)
                    })
            }

            Add-TkParagraph -Document $document -Muted -Text (
                '{0} programs installed, {1} of them recognised. A vendor can extend a date, as Microsoft does with Extended Security Updates: read the reference before retiring anything.' -f $report.InstalledCount, $recognised.Count
            )

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
                Wifi      = Get-TkWifiStatus -Days 7
                Proxy     = & {
                                $setting = Get-TkProxySetting
                                [pscustomobject] @{ Setting = $setting; Probe = Invoke-TkProxyProbe -Setting $setting }
                            }
                Context   = Get-TkUserContextReport
                Software  = Get-TkSoftwareLifecycleReport
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

            # --- Network access -----------------------------------------
            Add-TkHeading -Document $document -Text '6. Wi-Fi and proxy' -Level 2

            $accessProblems = @(@(Get-TkWifiFinding -Status $report.Wifi) + @(Get-TkProxyFinding -Setting $report.Proxy.Setting -Probe $report.Proxy.Probe) |
                                Where-Object { $_ -and $_.Severity -in @('Warning', 'Fail') })

            if ($accessProblems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'Nothing wrong with the Wi-Fi or the proxy'
            }
            else {
                foreach ($row in $accessProblems) {
                    Add-TkSeverityLine -Document $document -Severity $row.Severity -Heading $row.Heading `
                        -Detail $row.Detail -Note $row.Note -RemediationId $row.RemediationId
                }
            }

            # --- Context ------------------------------------------------
            Add-TkHeading -Document $document -Text '7. Profiles, drives and policy' -Level 2

            foreach ($row in $report.Context) {
                Add-TkSeverityLine -Document $document -Severity $row.Severity `
                    -Heading ('{0}: {1}' -f $row.Kind, $row.Name) -Detail $row.Value -Note $row.Detail
            }

            # --- Software support ---------------------------------------
            Add-TkHeading -Document $document -Text '8. Software support' -Level 2

            $softwareProblems = @(@($report.Software.Windows) + @($report.Software.Programs) |
                                  Where-Object { $_ -and $_.Severity -in @('Warning', 'Fail') })

            if ($softwareProblems.Count -eq 0) {
                Add-TkSeverityLine -Document $document -Severity 'Pass' -Heading 'Windows and the recognised programs still receive security fixes'
            }
            else {
                foreach ($row in $softwareProblems) {
                    Add-TkLifecycleLine -Document $document -Row $row
                }
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
