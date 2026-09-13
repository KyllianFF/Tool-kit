<#
    Toolkit - Features / Intervention journal and report

    What was done on this machine, written down as it happens, and a report of
    the visit to attach to the ticket.

    Every operation the toolkit already times through Start-TkOperation and
    Stop-TkOperation is recorded here too, so a tweak, an installation, a fix
    or an audit correction added later is journaled without anyone remembering
    to. One JSON line per operation, one file per day, under the data folder of
    this Windows account.

    The report is a single HTML file with its styles inline: it opens in any
    browser, prints, and can be attached to a ticket or sent to a customer.
    Every value written into it is HTML encoded, because computer names, notes
    and event text are not trusted markup.
#>

# One identifier per start of the toolkit, so "this session" can be told from
# the rest of the day. Seeded into the runspaces, which journal too.
$script:TkSessionId = [guid]::NewGuid().ToString()

# Whether an operation changed the machine or only looked at it.
$script:TkJournalKind = @{
    Tweaks      = 'Change'
    Software    = 'Change'
    Fixes       = 'Change'
    Remediation = 'Change'
    Network     = 'Change'
    SSH         = 'Change'
    Bundle      = 'Collection'
    Report      = 'Collection'
    Audit       = 'Check'
    Hunting     = 'Check'
    Integrity   = 'Check'
    Capture     = 'Check'
    Diagnostics = 'Check'
}

<#
.SYNOPSIS
    Says whether an operation category changes the machine or only reads it.

.OUTPUTS
    System.String: Change, Check, Collection or Other.
#>
function Get-TkJournalKind {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Category
    )

    if ($script:TkJournalKind.ContainsKey($Category)) {
        return $script:TkJournalKind[$Category]
    }

    return 'Other'
}

<#
.SYNOPSIS
    Returns the journal folder, creating it when needed.
#>
function Get-TkJournalFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $folder = Join-Path -Path (Get-TkContext).DataRoot -ChildPath 'journal'

    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    return $folder
}

<#
.SYNOPSIS
    Builds one journal entry.

.OUTPUTS
    PSCustomObject with Time, Session, Computer, User, Category, Kind, Name,
    Outcome, DurationMs and Detail.
#>
function New-TkJournalEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter()] [bool] $Success = $true,
        [Parameter()] [long] $DurationMs = 0,
        [Parameter()] [AllowEmptyString()] [string] $Detail = '',
        [Parameter()] [datetime] $When = (Get-Date)
    )

    return [pscustomobject] @{
        Time       = $When.ToString('o')
        Session    = $script:TkSessionId
        Computer   = $env:COMPUTERNAME
        User       = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
        Category   = $Category
        Kind       = Get-TkJournalKind -Category $Category
        Name       = $Name
        Outcome    = $(if ($Success) { 'Done' } else { 'Failed' })
        DurationMs = $DurationMs
        Detail     = $Detail
    }
}

<#
.SYNOPSIS
    Appends an entry to today's journal.

.DESCRIPTION
    Background tasks journal at the same time as the interface, so writes go
    one at a time through a named mutex. A journal that cannot be written must
    never break the operation being journaled, so every failure stays here.
#>
function Add-TkJournalEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter()] [bool] $Success = $true,
        [Parameter()] [long] $DurationMs = 0,
        [Parameter()] [AllowEmptyString()] [string] $Detail = ''
    )

    $mutex = $null

    try {
        $entry = New-TkJournalEntry -Name $Name -Category $Category -Success $Success -DurationMs $DurationMs -Detail $Detail
        $path  = Join-Path -Path (Get-TkJournalFolder) -ChildPath ('journal-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd'))
        $line  = ($entry | ConvertTo-Json -Compress) + [Environment]::NewLine

        $mutex = New-Object System.Threading.Mutex($false, 'Local\Toolkit-Journal')
        [void] $mutex.WaitOne(2000)

        [System.IO.File]::AppendAllText($path, $line, (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        $null = $_
    }
    finally {
        if ($mutex) {
            try { $mutex.ReleaseMutex() } catch { $null = $_ }
            $mutex.Dispose()
        }
    }
}

<#
.SYNOPSIS
    Reads journal entries from a moment on.

.PARAMETER Since
    The earliest entry to return.

.PARAMETER Session
    Only the entries of this session, when given.

.OUTPUTS
    PSCustomObject[], oldest first, with Time as a DateTime.
#>
function Get-TkJournalEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [datetime] $Since = (Get-Date).Date,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Session = ''
    )

    $folder  = Get-TkJournalFolder
    $entries = @()

    for ($day = $Since.Date; $day -le (Get-Date).Date; $day = $day.AddDays(1)) {

        $path = Join-Path -Path $folder -ChildPath ('journal-{0}.jsonl' -f $day.ToString('yyyyMMdd'))

        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        foreach ($line in [System.IO.File]::ReadAllLines($path)) {

            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            try {
                $entry = $line | ConvertFrom-Json -ErrorAction Stop
                $entry.Time = [datetime]::Parse([string] $entry.Time, [System.Globalization.CultureInfo]::InvariantCulture,
                                                [System.Globalization.DateTimeStyles]::RoundtripKind)

                if ($entry.Time -ge $Since -and (-not $Session -or $entry.Session -eq $Session)) {
                    $entries += $entry
                }
            }
            catch {
                # A line cut short by a crash is skipped, not fatal.
                continue
            }
        }
    }

    return @($entries | Sort-Object -Property Time)
}

<#
.SYNOPSIS
    Encodes text for HTML.
#>
function ConvertTo-TkHtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Text
    )

    return [System.Net.WebUtility]::HtmlEncode([string] $Text)
}

<#
.SYNOPSIS
    Writes the intervention report as one self-contained HTML document.

.DESCRIPTION
    Kept apart from the reading so it can be tested with a report built by
    hand. Styles are inline and there is no script, no image and no link to
    anything outside the file.

.PARAMETER Report
    Object with Computer, GeneratedAt, Technician, Ticket, Notes, Toolkit,
    Identity, OS, Tiles, Audit (Score and Findings, or null) and Entries.

.OUTPUTS
    System.String
#>
function ConvertTo-TkInterventionHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $h = { param($value) ConvertTo-TkHtmlText -Text $value }

    $badge = {
        param($severity)
        $class = switch ([string] $severity) { 'Pass' { 'pass' } 'Warning' { 'warn' } 'Fail' { 'fail' } default { 'info' } }
        '<span class="badge {0}">{1}</span>' -f $class, (& $h $severity)
    }

    $html = New-Object System.Text.StringBuilder

    [void] $html.AppendLine('<!DOCTYPE html>')
    [void] $html.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void] $html.AppendLine(('<title>Intervention report - {0}</title>' -f (& $h $Report.Computer)))
    [void] $html.AppendLine('<style>
body{font-family:"Segoe UI",Arial,sans-serif;color:#1b1f27;margin:0;background:#f3f4f7}
main{max-width:920px;margin:24px auto;background:#fff;padding:32px 40px;border:1px solid #d0d5dd;border-radius:8px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #d0d5dd;padding-bottom:6px}
.muted{color:#5c6675;font-size:13px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e6e9ee;vertical-align:top}th{background:#edeff3;font-weight:600}
.facts td:first-child{color:#5c6675;width:180px}.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}
.pass{background:#dcf1e3;color:#1a7f37}.warn{background:#f6ecd2;color:#9a6700}.fail{background:#f8dcda;color:#c0342b}.info{background:#edeff3;color:#5c6675}
.notes{white-space:pre-wrap;background:#f7f8fa;border:1px solid #e6e9ee;border-radius:6px;padding:12px;font-size:14px}
footer{margin-top:28px;color:#5c6675;font-size:12px}@media print{body{background:#fff}main{border:0;margin:0}}
</style></head><body><main>')

    # --- Header -----------------------------------------------------------
    [void] $html.AppendLine(('<h1>Intervention report</h1><div class="muted">{0} - {1}</div>' -f
        (& $h $Report.Computer), (& $h ([datetime] $Report.GeneratedAt).ToString('yyyy-MM-dd HH:mm'))))

    [void] $html.AppendLine('<h2>Intervention</h2><table class="facts">')
    [void] $html.AppendLine(('<tr><td>Ticket</td><td>{0}</td></tr>' -f $(if ($Report.Ticket) { & $h $Report.Ticket } else { '<span class="muted">None given</span>' })))
    [void] $html.AppendLine(('<tr><td>Technician</td><td>{0}</td></tr>' -f (& $h $Report.Technician)))
    [void] $html.AppendLine(('<tr><td>Period covered</td><td>{0}</td></tr>' -f (& $h $Report.Period)))
    [void] $html.AppendLine('</table>')

    # --- Machine ----------------------------------------------------------
    $identity = $Report.Identity
    $os       = $Report.OS

    [void] $html.AppendLine('<h2>Machine</h2><table class="facts">')

    # Objects rather than two element arrays: a list of inline arrays is
    # flattened into one list of strings, and each row then showed one letter.
    $facts = @(
        [pscustomobject] @{ Label = 'Computer';               Value = $Report.Computer }
        [pscustomobject] @{ Label = 'Manufacturer and model'; Value = $(if ($identity) { '{0} {1}' -f $identity.Manufacturer, $identity.Model }) }
        [pscustomobject] @{ Label = 'Serial number';          Value = $(if ($identity) { $identity.SerialNumber }) }
        [pscustomobject] @{ Label = 'Windows';                Value = $(if ($os) { '{0} {1}, build {2}' -f $os.Caption, $os.DisplayVersion, $os.Build }) }
        [pscustomobject] @{ Label = 'Uptime';                 Value = $(if ($os) { $os.UptimeText }) }
        [pscustomobject] @{ Label = 'Signed in user';         Value = $(if ($identity) { $identity.LoggedOnUser }) }
        [pscustomobject] @{ Label = 'Domain or workgroup';    Value = $(if ($identity) { $identity.Domain }) }
    )

    foreach ($fact in $facts) {
        [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $h $fact.Label),
            $(if ($fact.Value) { & $h $fact.Value } else { '<span class="muted">Not available</span>' })))
    }

    [void] $html.AppendLine('</table>')

    # --- Health -----------------------------------------------------------
    [void] $html.AppendLine('<h2>Health at the time of the report</h2>')

    if (@($Report.Tiles).Count -gt 0) {

        [void] $html.AppendLine('<table><tr><th>Check</th><th>Result</th><th>State</th><th>Detail</th></tr>')

        foreach ($tile in @($Report.Tiles)) {
            [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (& $h $tile.Title), (& $h $tile.Value), (& $badge $tile.Severity), (& $h $tile.Detail)))
        }

        [void] $html.AppendLine('</table>')
    }
    else {
        [void] $html.AppendLine('<p class="muted">The health of the machine could not be read.</p>')
    }

    # --- Security audit ---------------------------------------------------
    if ($Report.Audit) {

        $score = $Report.Audit.Score

        [void] $html.AppendLine('<h2>Security audit</h2>')
        [void] $html.AppendLine(('<p>Score <strong>{0} of 100</strong>: {1} passed, {2} failed, {3} warnings, {4} not assessed.</p>' -f
            (& $h $score.Score), (& $h $score.Passed), (& $h $score.Failed), (& $h $score.Warnings), (& $h $score.NotAssessed)))

        $open = @($Report.Audit.Findings | Where-Object { $_.Status -in @('Fail', 'Warning') })

        if ($open.Count -gt 0) {

            [void] $html.AppendLine('<table><tr><th>Control</th><th>State</th><th>Detail</th></tr>')

            foreach ($finding in $open) {
                [void] $html.AppendLine(('<tr><td>{0} {1}</td><td>{2}</td><td>{3}</td></tr>' -f
                    (& $h $finding.Id), (& $h $finding.Name), (& $badge $finding.Status), (& $h $finding.Detail)))
            }

            [void] $html.AppendLine('</table>')
        }
    }

    # --- Actions ----------------------------------------------------------
    [void] $html.AppendLine('<h2>What was done</h2>')

    $entries = @($Report.Entries | Where-Object { $_ })

    if ($entries.Count -gt 0) {

        [void] $html.AppendLine('<table><tr><th>Time</th><th>Kind</th><th>Operation</th><th>Outcome</th></tr>')

        foreach ($entry in $entries) {
            [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (& $h ([datetime] $entry.Time).ToString('yyyy-MM-dd HH:mm')), (& $h $entry.Kind), (& $h $entry.Name),
                (& $badge $(if ($entry.Outcome -eq 'Done') { 'Pass' } else { 'Fail' }))))
        }

        [void] $html.AppendLine('</table>')
    }
    else {
        [void] $html.AppendLine('<p class="muted">No operation was run through the toolkit in this period.</p>')
    }

    # --- Notes ------------------------------------------------------------
    [void] $html.AppendLine('<h2>Notes</h2>')
    [void] $html.AppendLine($(if ($Report.Notes) { '<div class="notes">{0}</div>' -f (& $h $Report.Notes) } else { '<p class="muted">No notes.</p>' }))

    [void] $html.AppendLine(('<footer>Generated by {0}. The operations listed are the ones run through the toolkit; changes made by other means do not appear.</footer>' -f (& $h $Report.Toolkit)))
    [void] $html.AppendLine('</main></body></html>')

    return $html.ToString()
}

<#
.SYNOPSIS
    Gathers what the intervention report shows.

.DESCRIPTION
    Reads the machine the way the Dashboard does, so the report and the tiles
    agree, and the journal over the period. Slow enough to run in the
    background.

.PARAMETER Since
    Start of the period covered.

.PARAMETER Session
    Only this session's operations, when given.

.OUTPUTS
    PSCustomObject for ConvertTo-TkInterventionHtml, without the fields the
    operator types.
#>
function Get-TkInterventionData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [datetime] $Since = (Get-Date).Date,
        [Parameter()] [AllowEmptyString()] [string] $Session = ''
    )

    $snapshot = Get-TkDashboardSnapshot
    $ctx      = Get-TkContext

    return [pscustomobject] @{
        Computer    = $env:COMPUTERNAME
        GeneratedAt = Get-Date
        Toolkit     = '{0} {1} ({2})' -f $ctx.AppName, $ctx.Version, $ctx.Commit
        Identity    = $snapshot.Identity
        OS          = $snapshot.OS
        Tiles       = @(ConvertTo-TkDashboardHealth -Snapshot $snapshot)
        Entries     = @(Get-TkJournalEntry -Since $Since -Session $Session)
    }
}
