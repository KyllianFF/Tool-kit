<#
    Toolkit - Features / Reporting: fleet view

    The toolkit judges one machine at a time; a manager needs the whole
    fleet: health, compliance, what is out of support, what to renew. Without
    a server or an agent: the machines drop their report documents in a
    folder, by a GPO startup script, an RMM or a technician,

        & $toolkit -Report All -AuditLevel Full -OutFile "\\server\fleet$\$env:COMPUTERNAME.json"

    and this reads the folder. Each document is read by its versioned format
    (docs/REPORT-FORMAT.md): a file that is not a report, or one of a newer
    major version, is set aside and named. Machines are told apart by their
    MachineId, so a renamed or a pseudonymised machine stays one machine, and
    the latest document of each is the one judged.

    A machine writes its own report: the view says what the machines declare,
    and it cannot prove anything about one that lies.
#>

<#
.SYNOPSIS
    Reads the fleet one document stands for: the facts a manager reads.

.DESCRIPTION
    Pure. Every value is read from the document by its path, and is empty
    when that report was not collected.

.OUTPUTS
    PSCustomObject
#>
function ConvertTo-TkFleetMachine {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Document,
        [Parameter()] [AllowEmptyString()] [string] $File = ''
    )

    $value = { param($path) Get-TkDocumentValue -Data $Document -Path $path }
    $ok    = { param($report) [string] (& $value ('Reports.{0}.Status' -f $report)) -eq 'Ok' }

    $when = [datetime]::MinValue
    [void] [datetime]::TryParse([string] (& $value 'GeneratedAt'), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $when)

    $machineId = [string] (& $value 'MachineId')
    $computer  = [string] (& $value 'Computer')

    $findings = @()
    if (& $ok 'Audit') {
        $findings = @(@(& $value 'Reports.Audit.Data.Findings') | Where-Object { $_ } | ForEach-Object {
            [pscustomobject] @{ Id = [string] (Get-TkDocumentValue -Data $_ -Path 'Id'); Name = [string] (Get-TkDocumentValue -Data $_ -Path 'Name'); Status = [string] (Get-TkDocumentValue -Data $_ -Path 'Status') }
        })
    }

    $reports = & $value 'Reports'
    $failed  = @(if ($reports -is [System.Collections.IDictionary]) { @($reports.Keys | Where-Object { [string] (Get-TkDocumentValue -Data $reports[$_] -Path 'Status') -eq 'Failed' }) })

    return [pscustomobject] @{
        Key            = $(if ($machineId) { 'id:' + $machineId } else { 'name:' + $computer.ToLowerInvariant() })
        Computer       = $computer
        MachineId      = $machineId
        GeneratedAt    = $when
        Toolkit        = [string] (& $value 'Toolkit.Version')
        Privacy        = [string] (& $value 'Privacy')
        Elevated       = [bool] (& $value 'Elevated')
        Worst          = [string] (& $value 'Summary.Worst')
        AuditScore     = $(if (& $ok 'Audit') { & $value 'Reports.Audit.Data.Score.Score' } else { $null })
        AuditLevel     = [string] (& $value 'Reports.Audit.Data.Level')
        Findings       = $findings
        Windows11      = $(if (& $ok 'Readiness') { [string] (& $value 'Reports.Readiness.Data.Windows11.Verdict') } else { '' })
        Renewal        = $(if (& $ok 'Readiness') { [string] (& $value 'Reports.Readiness.Data.Renewal.Verdict') } else { '' })
        WindowsSupport = $(if (& $ok 'Lifecycle') { [string] (& $value 'Reports.Lifecycle.Data.Windows.Severity') } else { '' })
        RebootPending  = $(if (& $ok 'Reboot') { [bool] (& $value 'Reports.Reboot.Data.Pending') } else { $null })
        JournalValid   = $(if (& $ok 'Journal') { [bool] (& $value 'Reports.Journal.Data.Valid') } else { $null })
        Failed         = $failed
        File           = $File
        Documents      = 1
    }
}

<#
.SYNOPSIS
    Reads a folder of report documents into the latest one of each machine.

.PARAMETER Path
    The folder the machines drop their documents in.

.PARAMETER Now
    Today, a parameter so tests do not depend on the clock.

.OUTPUTS
    PSCustomObject with Folder, Machines (the latest of each, newest first)
    and Skipped (each file set aside, with the reason).
#>
function Read-TkFleetFolder {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter()] [switch] $Recurse
    )

    if (-not [System.IO.Directory]::Exists($Path)) {
        throw ('The folder {0} does not exist, or cannot be read.' -f $Path)
    }

    $latest  = @{}
    $counts  = @{}
    $skipped = New-Object System.Collections.Generic.List[object]

    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Filter '*.json' -File -Recurse:$Recurse -ErrorAction SilentlyContinue)) {

        try {
            $document = Read-TkReportDocument -Path $file.FullName
        }
        catch {
            $skipped.Add([pscustomobject] @{ File = $file.Name; Reason = $_.Exception.Message })
            continue
        }

        $machine = ConvertTo-TkFleetMachine -Document $document -File $file.FullName

        if (-not $counts.ContainsKey($machine.Key)) { $counts[$machine.Key] = 0 }
        $counts[$machine.Key]++

        if (-not $latest.ContainsKey($machine.Key) -or $machine.GeneratedAt -gt $latest[$machine.Key].GeneratedAt) {
            $latest[$machine.Key] = $machine
        }
    }

    $machines = @($latest.Values | ForEach-Object { $_.Documents = $counts[$_.Key]; $_ } | Sort-Object -Property GeneratedAt -Descending)

    return [pscustomobject] @{ Folder = $Path; Machines = $machines; Skipped = @($skipped.ToArray()) }
}

<#
.SYNOPSIS
    Sums the fleet up: health, Windows 11, renewal, support, and each audit control across the machines.

.DESCRIPTION
    Pure. A machine whose latest document is older than StaleDays is counted
    apart: its state may have moved since.

.OUTPUTS
    PSCustomObject
#>
function Get-TkFleetSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Machine,
        [Parameter()] [int] $StaleDays = 30,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $count = { param($items, $property, $value) @($items | Where-Object { [string] $_.$property -eq $value }).Count }

    $controls = @{}
    foreach ($item in $Machine) {
        foreach ($finding in @($item.Findings)) {
            if (-not $finding.Id) { continue }
            if (-not $controls.ContainsKey($finding.Id)) {
                $controls[$finding.Id] = [pscustomobject] @{ Id = $finding.Id; Name = $finding.Name; Pass = 0; Warning = 0; Fail = 0; Other = 0; FailingOn = New-Object System.Collections.Generic.List[string]; WarningOn = New-Object System.Collections.Generic.List[string] }
            }
            $control = $controls[$finding.Id]
            switch ($finding.Status) {
                'Pass'    { $control.Pass++ }
                'Warning' { $control.Warning++; $control.WarningOn.Add($item.Computer) }
                'Fail'    { $control.Fail++; $control.FailingOn.Add($item.Computer) }
                default   { $control.Other++ }
            }
        }
    }

    $scored  = @($Machine | Where-Object { $null -ne $_.AuditScore })
    $average = if ($scored.Count -gt 0) { [math]::Round((@($scored | ForEach-Object { [double] $_.AuditScore }) | Measure-Object -Average).Average, 0) } else { $null }

    return [pscustomobject] @{
        Machines        = @($Machine).Count
        Fail            = & $count $Machine 'Worst' 'Fail'
        Warning         = & $count $Machine 'Worst' 'Warning'
        Pass            = & $count $Machine 'Worst' 'Pass'
        Stale           = @($Machine | Where-Object { ($Now - $_.GeneratedAt).TotalDays -gt $StaleDays }).Count
        StaleDays       = $StaleDays
        Pseudonymised   = @($Machine | Where-Object { $_.Privacy -in @('Personal', 'Strict') }).Count
        RebootPending   = @($Machine | Where-Object { $_.RebootPending -eq $true }).Count
        JournalBroken   = @($Machine | Where-Object { $_.JournalValid -eq $false }).Count
        Windows11       = [ordered] @{ Ready = & $count $Machine 'Windows11' 'Ready'; ReadyAfterChanges = & $count $Machine 'Windows11' 'ReadyAfterChanges'; NotReady = & $count $Machine 'Windows11' 'NotReady'; Check = & $count $Machine 'Windows11' 'Check'; Unknown = @($Machine | Where-Object { -not $_.Windows11 }).Count }
        Renewal         = [ordered] @{ Keep = & $count $Machine 'Renewal' 'Keep'; Upgrade = & $count $Machine 'Renewal' 'Upgrade'; Replace = & $count $Machine 'Renewal' 'Replace' }
        WindowsOutOfSupport = & $count $Machine 'WindowsSupport' 'Fail'
        AuditScored     = $scored.Count
        AuditAverage    = $average
        Exposed         = @($scored | Sort-Object -Property @{ Expression = { [double] $_.AuditScore } } | Select-Object -First 10)
        Controls        = @($controls.Values | Sort-Object -Property @{ Expression = { $_.Fail }; Descending = $true }, @{ Expression = { $_.Warning }; Descending = $true }, Id)
    }
}

<#
.SYNOPSIS
    The machines an audit control does not pass on: the fails, then the warnings.

.OUTPUTS
    System.String
#>
function Format-TkFleetControlSpread {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Control,
        [Parameter()] [int] $First = 8
    )

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@{ Label = 'fail'; Names = $Control.FailingOn }, @{ Label = 'warning'; Names = $Control.WarningOn })) {
        $names = @($pair.Names)
        if ($names.Count -eq 0) { continue }
        $text = ($names | Select-Object -First $First) -join ', '
        if ($names.Count -gt $First) { $text += (' and {0} more' -f ($names.Count - $First)) }
        $parts.Add(('{0}: {1}' -f $pair.Label, $text))
    }
    return ($parts -join '; ')
}

<#
.SYNOPSIS
    The fleet view as one HTML page, for a meeting or a committee.

.DESCRIPTION
    Pure. Styles inline, no script and no link outside the file; every value
    is HTML encoded, since computer names and control names are data.

.OUTPUTS
    System.String
#>
function ConvertTo-TkFleetHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Fleet,
        [Parameter(Mandatory)] $Summary,
        [Parameter()] [datetime] $When = (Get-Date),
        [Parameter()] [string] $Toolkit = ('{0} {1}' -f (Get-TkContext).AppName, (Get-TkContext).Version)
    )

    $h    = { param($value) ConvertTo-TkHtmlText -Text $value }
    $html = New-Object System.Text.StringBuilder

    [void] $html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Fleet view</title><style>')
    [void] $html.AppendLine('body{font-family:"Segoe UI",Arial,sans-serif;color:#1b1f27;margin:0;background:#f3f4f7}main{max-width:1100px;margin:24px auto;background:#fff;padding:32px 40px;border:1px solid #d0d5dd;border-radius:8px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #d0d5dd;padding-bottom:6px}.muted{color:#5c6675;font-size:13px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e6e9ee;vertical-align:top}th{background:#edeff3}.fail{color:#c0342b;font-weight:600}.warn{color:#9a6700;font-weight:600}.pass{color:#1a7f37}')
    [void] $html.AppendLine('</style></head><body><main>')
    [void] $html.AppendLine(('<h1>Fleet view</h1><div class="muted">{0} machine(s), read on {1} from {2}. Each machine writes its own report: this says what the machines declare.</div>' -f $Summary.Machines, (& $h $When.ToString('yyyy-MM-dd HH:mm')), (& $h $Fleet.Folder)))

    [void] $html.AppendLine('<h2>At a glance</h2><table>')
    # Objects rather than two element arrays: a list of inline arrays is
    # flattened into one list of strings.
    $rows = @(
        [pscustomobject] @{ Label = 'Worst judgement'; Value = ('{0} fail, {1} warning, {2} pass' -f $Summary.Fail, $Summary.Warning, $Summary.Pass) }
        [pscustomobject] @{ Label = 'Windows 11'; Value = ('{0} ready, {1} ready after changes, {2} not ready, {3} to check, {4} not collected' -f $Summary.Windows11.Ready, $Summary.Windows11.ReadyAfterChanges, $Summary.Windows11.NotReady, $Summary.Windows11.Check, $Summary.Windows11.Unknown) }
        [pscustomobject] @{ Label = 'Renewal'; Value = ('{0} keep, {1} upgrade, {2} replace' -f $Summary.Renewal.Keep, $Summary.Renewal.Upgrade, $Summary.Renewal.Replace) }
        [pscustomobject] @{ Label = 'Windows out of support'; Value = [string] $Summary.WindowsOutOfSupport }
        [pscustomobject] @{ Label = 'Audit score'; Value = $(if ($null -ne $Summary.AuditAverage) { '{0} on average over {1} machine(s)' -f $Summary.AuditAverage, $Summary.AuditScored } else { 'No audit collected' }) }
        [pscustomobject] @{ Label = 'Restart pending'; Value = [string] $Summary.RebootPending }
        [pscustomobject] @{ Label = ('Reports older than {0} days' -f $Summary.StaleDays); Value = [string] $Summary.Stale }
    )
    foreach ($row in $rows) { [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $h $row.Label), (& $h $row.Value))) }
    [void] $html.AppendLine('</table>')

    $class = { param($worst) switch ([string] $worst) { 'Fail' { 'fail' } 'Warning' { 'warn' } 'Pass' { 'pass' } default { '' } } }

    [void] $html.AppendLine('<h2>Machines</h2><table><tr><th>Computer</th><th>Report of</th><th>Worst</th><th>Audit</th><th>Windows 11</th><th>Renewal</th><th>Restart</th><th>Toolkit</th></tr>')
    foreach ($item in @($Fleet.Machines)) {
        [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td class="{2}">{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f
            (& $h $item.Computer), (& $h $item.GeneratedAt.ToString('yyyy-MM-dd HH:mm')), (& $class $item.Worst), (& $h $item.Worst),
            (& $h $(if ($null -ne $item.AuditScore) { $item.AuditScore } else { '-' })), (& $h $item.Windows11), (& $h $item.Renewal),
            (& $h $(if ($item.RebootPending) { 'pending' } else { '' })), (& $h $item.Toolkit)))
    }
    [void] $html.AppendLine('</table>')

    if (@($Summary.Controls).Count -gt 0) {
        [void] $html.AppendLine('<h2>Audit controls across the fleet</h2><table><tr><th>Control</th><th>Fail</th><th>Warning</th><th>Pass</th><th>Not passing on</th></tr>')
        foreach ($control in @($Summary.Controls)) {
            [void] $html.AppendLine(('<tr><td>{0} {1}</td><td class="{2}">{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f
                (& $h $control.Id), (& $h $control.Name), $(if ($control.Fail) { 'fail' } else { '' }), $control.Fail, $control.Warning, $control.Pass, (& $h (Format-TkFleetControlSpread -Control $control -First 12))))
        }
        [void] $html.AppendLine('</table>')
    }

    [void] $html.AppendLine(('<p class="muted">Generated by {0}.</p></main></body></html>' -f (& $h $Toolkit)))
    return $html.ToString()
}
