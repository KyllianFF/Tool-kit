<#
    Toolkit - UI / Fleet page

    The report documents of many machines, read from one folder, and summed
    up for whoever runs the fleet. Reading is in the background, and the view
    is drawn again from what was read.
#>

# The last folder read. Set through Set-TkFleetResult: a completion handler
# cannot reach this file's scope.
$script:TkFleetResult = $null

<#
.SYNOPSIS
    Keeps the last fleet read, for the view and the export.
#>
function Set-TkFleetResult {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [AllowNull()]
        $Result
    )

    if ($PSCmdlet.ShouldProcess('fleet view', 'Remember the folder read')) {
        $script:TkFleetResult = $Result
    }
}

<#
.SYNOPSIS
    Wires the Fleet page.
#>
function Initialize-TkFleetPage {
    [CmdletBinding()]
    param()

    $folder = Get-TkControl -Name 'FleetFolder'
    if ($folder) {
        $folder.Text = [string] (Get-TkContext).Settings['FleetFolder']
        $folder.Add_KeyDown({
            param($source, $keyArgs)
            $null = $source
            if ($keyArgs.Key -eq [System.Windows.Input.Key]::Enter) { Invoke-TkFleetReadFromUi }
        })
    }

    Register-TkClick -Name 'BtnFleetBrowse' -Action {
        $picked = Select-TkFolderPath -Description 'Choose the folder the machines drop their reports in.' -Start ([string] (Get-TkControl -Name 'FleetFolder').Text)
        if ($picked) { (Get-TkControl -Name 'FleetFolder').Text = $picked }
    }
    Register-TkClick -Name 'BtnFleetRead'   -Action { Invoke-TkFleetReadFromUi }
    Register-TkClick -Name 'BtnFleetExport' -Action { Export-TkFleetFromUi }

    $document = New-TkFlowDocument
    Add-TkParagraph -Document $document -Muted -Text 'Choose the folder the machines drop their report documents in, and Read the folder.'
    Set-TkDocument -ControlName 'FleetOutput' -Document $document
}

<#
.SYNOPSIS
    Reads the folder chosen, in the background, and shows the fleet.
#>
function Invoke-TkFleetReadFromUi {
    [CmdletBinding()]
    param()

    $folder = ([string] (Get-TkControl -Name 'FleetFolder').Text).Trim()

    if (-not $folder) {
        Set-TkStatus -Text 'Choose the folder of the reports first.'
        return
    }

    $settings = (Get-TkContext).Settings
    if ([string] $settings['FleetFolder'] -ne $folder) {
        $settings['FleetFolder'] = $folder
        Save-TkSettings
    }

    Invoke-TkBackgroundAction -StatusText ('Reading the reports in {0}...' -f $folder) -ParameterList @{ folder = $folder } `
        -ScriptBlock { param($folder) Read-TkFleetFolder -Path $folder } `
        -OnComplete {
            param($result)

            $fleet = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Machines'] } | Select-Object -Last 1

            if (-not $fleet) {
                Set-TkStatus -Text $(if (@($result.Errors).Count) { [string] @($result.Errors)[0] } else { 'The folder could not be read.' })
                return
            }

            Set-TkFleetResult -Result $fleet -Confirm:$false
            Write-TkFleetView
            Set-TkStatus -Text ('{0} machine(s) read, {1} file(s) set aside.' -f @($fleet.Machines).Count, @($fleet.Skipped).Count)
        }
}

<#
.SYNOPSIS
    Shows the fleet last read.
#>
function Write-TkFleetView {
    [CmdletBinding()]
    param()

    $fleet = $script:TkFleetResult

    if (-not $fleet) {
        return
    }

    $summary  = Get-TkFleetSummary -Machine @($fleet.Machines)
    $document = New-TkFlowDocument

    Add-TkHeading   -Document $document -Text ('{0} machine(s)' -f $summary.Machines) -Level 1
    Add-TkParagraph -Document $document -Muted -Text (
        'The latest report of each machine in {0}, told apart by its MachineId so a renamed or a pseudonymised machine stays one. Each machine writes its own report: this says what the machines declare.' -f $fleet.Folder
    )

    if ($summary.Machines -eq 0) {
        Add-TkSeverityLine -Document $document -Severity 'Info' -Heading 'No report document in this folder' -Note 'The machines write theirs with -Report All -OutFile into it.'
    }
    else {
        Add-TkSeverityLine -Document $document -Severity $(if ($summary.Fail) { 'Fail' } elseif ($summary.Warning) { 'Warning' } else { 'Pass' }) `
            -Heading ('Worst judgement: {0} fail, {1} warning, {2} pass' -f $summary.Fail, $summary.Warning, $summary.Pass)
        Add-TkSeverityLine -Document $document -Severity $(if ($summary.Windows11.NotReady) { 'Warning' } else { 'Info' }) `
            -Heading ('Windows 11: {0} ready, {1} after changes, {2} not ready, {3} to check' -f $summary.Windows11.Ready, $summary.Windows11.ReadyAfterChanges, $summary.Windows11.NotReady, $summary.Windows11.Check) `
            -Note $(if ($summary.Windows11.Unknown) { '{0} machine(s) without the Readiness report.' -f $summary.Windows11.Unknown } else { '' })
        Add-TkSeverityLine -Document $document -Severity $(if ($summary.Renewal.Replace) { 'Warning' } else { 'Info' }) `
            -Heading ('Renewal: {0} keep, {1} upgrade, {2} replace' -f $summary.Renewal.Keep, $summary.Renewal.Upgrade, $summary.Renewal.Replace)
        if ($summary.WindowsOutOfSupport) {
            Add-TkSeverityLine -Document $document -Severity 'Fail' -Heading ('{0} machine(s) on a Windows out of support' -f $summary.WindowsOutOfSupport)
        }
        if ($null -ne $summary.AuditAverage) {
            Add-TkSeverityLine -Document $document -Severity 'Info' -Heading ('Audit score: {0} on average over {1} machine(s)' -f $summary.AuditAverage, $summary.AuditScored)
        }
        if ($summary.Stale) {
            Add-TkSeverityLine -Document $document -Severity 'Warning' -Heading ('{0} report(s) older than {1} days' -f $summary.Stale, $summary.StaleDays) -Note 'Their machine may have changed since.'
        }
        if ($summary.JournalBroken) {
            Add-TkSeverityLine -Document $document -Severity 'Warning' -Heading ('{0} machine(s) whose journal chain is broken' -f $summary.JournalBroken)
        }

        Add-TkHeading -Document $document -Text 'Machines' -Level 2
        Add-TkTable -Document $document -Column @('Computer', 'Report of', 'Worst', 'Audit', 'Windows 11', 'Renewal', 'Restart') -Weight @(1.5, 1.1, 0.7, 0.6, 1.2, 0.8, 0.7) `
            -Row @($fleet.Machines | ForEach-Object {
                , @($_.Computer, $_.GeneratedAt.ToString('yyyy-MM-dd HH:mm'), $_.Worst, $(if ($null -ne $_.AuditScore) { [string] $_.AuditScore } else { '-' }), $_.Windows11, $_.Renewal, $(if ($_.RebootPending) { 'pending' } else { '' }))
            })

        $controls = @($summary.Controls | Where-Object { $_.Fail -or $_.Warning } | Select-Object -First 25)
        if ($controls.Count -gt 0) {
            Add-TkHeading -Document $document -Text 'Audit controls failing somewhere' -Level 2
            Add-TkTable -Document $document -Column @('Control', 'Fail', 'Warning', 'Pass', 'Not passing on') -Weight @(2.4, 0.5, 0.6, 0.5, 2.4) `
                -Row @($controls | ForEach-Object { , @(('{0} {1}' -f $_.Id, $_.Name), [string] $_.Fail, [string] $_.Warning, [string] $_.Pass, (Format-TkFleetControlSpread -Control $_)) })
        }
    }

    if (@($fleet.Skipped).Count -gt 0) {
        Add-TkHeading -Document $document -Text 'Files set aside' -Level 2
        Add-TkTable -Document $document -Column @('File', 'Why') -Weight @(1.5, 3.5) -Row @($fleet.Skipped | Select-Object -First 30 | ForEach-Object { , @($_.File, $_.Reason) })
    }

    Set-TkDocument -ControlName 'FleetOutput' -Document $document
}

<#
.SYNOPSIS
    Saves the fleet view as one HTML page, pseudonymised as the privacy of exports asks.
#>
function Export-TkFleetFromUi {
    [CmdletBinding()]
    param()

    $fleet = $script:TkFleetResult

    if (-not $fleet -or @($fleet.Machines).Count -eq 0) {
        Set-TkStatus -Text 'Read a folder with reports in it first.'
        return
    }

    $level  = Get-TkExportPrivacyLevel
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title    = 'Export the fleet view'
    $dialog.Filter   = 'Web page (*.html)|*.html'
    $dialog.FileName = 'fleet-{0}.html' -f (Get-Date -Format 'yyyyMMdd')

    if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
        return
    }

    try {
        $html = ConvertTo-TkFleetHtml -Fleet $fleet -Summary (Get-TkFleetSummary -Machine @($fleet.Machines))
        $safe = Protect-TkExportText -Text $html -Level $level -Label 'fleet-view'
        [System.IO.File]::WriteAllText($dialog.FileName, $safe.Text, (New-Object System.Text.UTF8Encoding($false)))
        Set-TkStatus -Text ('Fleet view written to {0}.{1}' -f $dialog.FileName, (Format-TkPrivacyNote -Result $safe))
    }
    catch {
        Write-TkLog -Level Error -Category 'Report' -Message ('The fleet view could not be written: {0}' -f $_.Exception.Message)
    }
}
