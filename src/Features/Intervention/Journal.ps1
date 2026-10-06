<#
    Toolkit - Features / Intervention journal and report

    What was done on this machine, written down as it happens, and a report of
    the visit to attach to the ticket.

    Every operation the toolkit already times through Start-TkOperation and
    Stop-TkOperation is recorded here too, so a tweak, an installation, a fix
    or an audit correction added later is journaled without anyone remembering
    to. One JSON line per operation, one file per day, under the data folder of
    this Windows account.

    Each line records the SHA-256 of the line before it, across the days, so a
    line changed or removed afterwards shows (Test-TkJournalChain). That makes
    the journal tamper-evident, not tamper-proof: whoever can write the files
    can rewrite them whole, which only the head recorded in an intervention
    report that left the machine can expose.

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
    Hardening   = 'Change'
    Network     = 'Change'
    SSH         = 'Change'
    Bundle      = 'Collection'
    Report      = 'Collection'
    Triage      = 'Collection'
    Evidence    = 'Collection'
    Audit       = 'Check'
    Policy      = 'Check'
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
    Outcome, DurationMs, Detail and Previous, the SHA-256 of the line before.
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
        [Parameter()] [datetime] $When = (Get-Date),
        [Parameter()] [AllowEmptyString()] [string] $Previous = ''
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
        Previous   = $Previous
    }
}

<#
.SYNOPSIS
    Appends an entry to today's journal.

.DESCRIPTION
    Background tasks journal at the same time as the interface, so writes go
    one at a time through a named mutex, which also keeps the chain in order:
    the link to the line before is read while the mutex is held. A journal
    that cannot be written must never break the operation being journaled, so
    every failure stays here.
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
        $path  = Join-Path -Path (Get-TkJournalFolder) -ChildPath ('journal-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd'))
        $mutex = New-Object System.Threading.Mutex($false, 'Local\Toolkit-Journal')

        # A holder that died leaves the mutex abandoned, and ours all the same.
        try {
            [void] $mutex.WaitOne(2000)
        }
        catch [System.Threading.AbandonedMutexException] {
            $null = $_
        }

        $entry = New-TkJournalEntry -Name $Name -Category $Category -Success $Success -DurationMs $DurationMs -Detail $Detail -Previous (Get-TkJournalHead -Path $path)
        $line  = ($entry | ConvertTo-Json -Compress) + [Environment]::NewLine

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
    The SHA-256 of one journal line, as the line after it records it.

.PARAMETER Line
    The line as the file holds it, without its line break.

.OUTPUTS
    System.String, 64 lowercase hexadecimal characters.
#>
function Get-TkJournalLineHash {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Line
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Line))
    }
    finally {
        $sha.Dispose()
    }

    return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}

<#
.SYNOPSIS
    The journal files, one per day, oldest first.

.OUTPUTS
    System.IO.FileInfo[]
#>
function Get-TkJournalFile {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter()]
        [string] $Folder = (Get-TkJournalFolder)
    )

    return @(Get-ChildItem -LiteralPath $Folder -Filter 'journal-*.jsonl' -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match '^journal-\d{8}\.jsonl$' } | Sort-Object -Property Name)
}

<#
.SYNOPSIS
    The hash of the last line written: what the next line records.

.PARAMETER Path
    The file about to be written. Its last line, or, when it is new, the last
    line of the newest day before it, so the chain runs across the days.

.OUTPUTS
    System.String, empty for the very first line.
#>
function Get-TkJournalHead {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $name = [System.IO.Path]::GetFileName($Path)

    foreach ($file in @(Get-TkJournalFile -Folder ([System.IO.Path]::GetDirectoryName($Path)) | Where-Object { $_.Name -le $name } | Sort-Object -Property Name -Descending)) {

        $lines = @([System.IO.File]::ReadAllLines($file.FullName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        if ($lines.Count -gt 0) {
            return (Get-TkJournalLineHash -Line $lines[-1])
        }
    }

    return ''
}

<#
.SYNOPSIS
    Reads the time of a journal entry, however ConvertFrom-Json handed it over.

.DESCRIPTION
    PowerShell 7 turns an ISO 8601 string into a DateTime as it reads JSON;
    Windows PowerShell 5.1 leaves it as text.

.OUTPUTS
    System.DateTime
#>
function ConvertTo-TkJournalTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Value
    )

    if ($Value -is [datetime]) {
        return $Value
    }

    return [datetime]::Parse([string] $Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
}

<#
.SYNOPSIS
    Checks that no journal line was changed, removed or slipped in since it was written.

.DESCRIPTION
    Every line records the SHA-256 of the line before it, across the days. A
    line changed or removed makes the line after it disagree, and a day
    removed makes the next day's first line disagree. Lines written before
    the chain existed carry no link and are counted apart; one of them after
    a linked line is a break. When the oldest days were removed, as a
    clean-up does, the chain is checked from the first line kept.

    It says whether the journal is consistent as it stands. Removing the last
    lines, or rewriting every line with new hashes, leaves a consistent chain:
    the head recorded in an intervention report that left the machine is what
    shows that, since the journal would no longer lead to it.

.OUTPUTS
    PSCustomObject with Severity, Valid, Entries, Chained, Unchained,
    Trimmed, Head, First, Last and Breaks.
#>
function Test-TkJournalChain {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string] $Folder = (Get-TkJournalFolder)
    )

    $breaks    = New-Object System.Collections.Generic.List[object]
    $entries   = 0
    $chained   = 0
    $unchained = 0
    $trimmed   = $false
    $linked    = $false
    $previous  = ''
    $first     = ''
    $last      = ''

    foreach ($file in (Get-TkJournalFile -Folder $Folder)) {

        $number = 0

        foreach ($line in [System.IO.File]::ReadAllLines($file.FullName)) {

            $number++

            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $entries++
            $entry   = $null
            $problem = ''

            try {
                $entry = $line | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $entry = $null
            }

            if (-not $entry) {
                $problem = 'This line is not a journal entry: it was cut short or edited.'
            }
            elseif ($null -eq $entry.PSObject.Properties['Previous']) {
                $unchained++

                if ($linked) {
                    $problem = 'This line carries no link, after lines that do: it was added to the file.'
                }
            }
            else {
                $chained++
                $linked = $true

                if ([string] $entry.Previous -ne $previous) {

                    # The first line kept links to a line of a day since
                    # removed: the chain is checked from here.
                    if ($entries -eq 1) {
                        $trimmed = $true
                    }
                    else {
                        $problem = 'The line before this one was changed or removed, or a day before it was.'
                    }
                }
            }

            if ($entry) {
                $stamp = try { (ConvertTo-TkJournalTime -Value $entry.Time).ToString('o') } catch { '' }
                if (-not $first) { $first = $stamp }
                $last = $stamp
            }

            if ($problem -and $breaks.Count -lt 50) {
                $breaks.Add([pscustomobject] @{
                    File    = $file.Name
                    Line    = $number
                    Time    = $(if ($entry) { $stamp } else { '' })
                    Name    = $(if ($entry) { [string] $entry.Name } else { '' })
                    Problem = $problem
                })
            }

            # Each line is checked against the one before it as it now stands,
            # so every break is found, not only the first.
            $previous = Get-TkJournalLineHash -Line $line
        }
    }

    return [pscustomobject] @{
        Severity  = $(if ($breaks.Count -gt 0) { 'Fail' } elseif ($chained -gt 0) { 'Pass' } else { 'Info' })
        Valid     = ($breaks.Count -eq 0)
        Entries   = $entries
        Chained   = $chained
        Unchained = $unchained
        Trimmed   = $trimmed
        Head      = $previous
        First     = $first
        Last      = $last
        Breaks    = @($breaks.ToArray())
    }
}

<#
.SYNOPSIS
    One journal entry as a CEF event, for a SIEM.

.DESCRIPTION
    CEF:0|vendor|product|version|signature|name|severity|extension. The
    header escapes | and \, the extension escapes \ and = and writes line
    breaks as \n, as the format asks. A change that failed is the most
    severe (7), another failure 5, a change done 5, a check or a collection 3.

.PARAMETER Hash
    The SHA-256 of the entry's own line, so the event can be matched to it.

.OUTPUTS
    System.String
#>
function ConvertTo-TkCefEvent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Entry,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Hash = '',

        [Parameter()]
        [string] $Version = ([string] (Get-TkContext).Version)
    )

    $header = { param($text) ([string] $text) -replace '\\', '\\' -replace '\|', '\|' -replace '[\r\n]+', ' ' }
    $value  = { param($text) ([string] $text) -replace '\\', '\\' -replace '=', '\=' -replace "`r`n|`n|`r", '\n' }

    $failed   = [string] $Entry.Outcome -ne 'Done'
    $change   = [string] $Entry.Kind -eq 'Change'
    $severity = if ($failed -and $change) { 7 } elseif ($failed -or $change) { 5 } else { 3 }
    $time     = (ConvertTo-TkJournalTime -Value $Entry.Time).ToUniversalTime()
    $epoch    = [long] ($time - [datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).TotalMilliseconds

    $extension = @(
        'rt={0}' -f $epoch
        'shost={0}' -f (& $value $Entry.Computer)
        'suser={0}' -f (& $value $Entry.User)
        'cat={0}' -f (& $value $Entry.Category)
        'outcome={0}' -f (& $value $Entry.Outcome)
        'cn1Label=DurationMs cn1={0}' -f [long] $Entry.DurationMs
        'cs1Label=Session cs1={0}' -f (& $value $Entry.Session)
        'cs2Label=Kind cs2={0}' -f (& $value $Entry.Kind)
        'cs3Label=Detail cs3={0}' -f (& $value $Entry.Detail)
        'cs4Label=Previous cs4={0}' -f (& $value $Entry.Previous)
        'cs5Label=Hash cs5={0}' -f (& $value $Hash)
    ) -join ' '

    return ('CEF:0|Toolkit|Toolkit|{0}|{1}|{2}|{3}|{4}' -f (& $header $Version), (& $header $Entry.Category), (& $header $Entry.Name), $severity, $extension)
}

<#
.SYNOPSIS
    Writes the journal of a period to a file, as JSON Lines or CEF, for a SIEM or an archive.

.DESCRIPTION
    The JSON Lines are the lines as the journal holds them, links included,
    so the chain can be checked again elsewhere. The journal is the record
    itself: it is not pseudonymised.

.OUTPUTS
    System.Int32: how many entries were written.
#>
function Export-TkJournal {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [ValidateSet('Jsonl', 'Cef')]
        [string] $Format = 'Jsonl',

        [Parameter()]
        [datetime] $Since = (Get-Date).Date,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Session = '',

        [Parameter()]
        [string] $Folder = (Get-TkJournalFolder)
    )

    $out = New-Object System.Collections.Generic.List[string]

    foreach ($file in (Get-TkJournalFile -Folder $Folder)) {

        # A day before the period holds nothing of it.
        if ($file.Name.Substring(8, 8) -lt $Since.ToString('yyyyMMdd')) {
            continue
        }

        foreach ($line in [System.IO.File]::ReadAllLines($file.FullName)) {

            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            try {
                $entry = $line | ConvertFrom-Json -ErrorAction Stop
                $time  = ConvertTo-TkJournalTime -Value $entry.Time
            }
            catch {
                continue
            }

            if ($time -lt $Since -or ($Session -and [string] $entry.Session -ne $Session)) {
                continue
            }

            $out.Add($(if ($Format -eq 'Jsonl') { $line } else { ConvertTo-TkCefEvent -Entry $entry -Hash (Get-TkJournalLineHash -Line $line) }))
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Export the journal')) {
        return 0
    }

    [System.IO.File]::WriteAllLines($Path, $out.ToArray(), (New-Object System.Text.UTF8Encoding($false)))

    return $out.Count
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
    Identity, OS, Tiles, Audit (Score and Findings, or null), Entries and,
    when given, Journal (Test-TkJournalChain).

.OUTPUTS
    System.String
#>
function ConvertTo-TkInterventionHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report,

        # The language the report is written in. The readings it holds were
        # taken in English; their words are translated as they are written.
        [Parameter()]
        [string] $Language = (Get-TkLanguage)
    )

    $h = { param($value) ConvertTo-TkHtmlText -Text $value }

    # A label, and a sentence whose values are already HTML: the sentence is
    # encoded first, then given its values, so a value can carry markup.
    $t  = { param($text) ConvertTo-TkHtmlText -Text (Get-TkText -Text $text -Language $Language -Context 'report') }
    $tf = { param($text, [object[]] $values) (ConvertTo-TkHtmlText -Text (Get-TkText -Text $text -Language $Language -Context 'report')) -f $values }
    $l  = { param($value) ConvertTo-TkHtmlText -Text (ConvertTo-TkLocalText -Text ([string] $value) -Language $Language) }

    $badge = {
        param($severity)
        $class = switch ([string] $severity) { 'Pass' { 'pass' } 'Warning' { 'warn' } 'Fail' { 'fail' } default { 'info' } }
        '<span class="badge {0}">{1}</span>' -f $class, (& $t ([string] $severity))
    }

    $html = New-Object System.Text.StringBuilder

    [void] $html.AppendLine('<!DOCTYPE html>')
    [void] $html.AppendLine(('<html lang="{0}"><head><meta charset="utf-8">' -f $(if ($Language -eq 'fr') { 'fr' } else { 'en' })))
    [void] $html.AppendLine(('<title>{0}</title>' -f (& $tf 'Intervention report - {0}' @(& $h $Report.Computer))))
    [void] $html.AppendLine('<style>
body{font-family:"Segoe UI",Arial,sans-serif;color:#1b1f27;margin:0;background:#f3f4f7}
main{max-width:920px;margin:24px auto;background:#fff;padding:32px 40px;border:1px solid #d0d5dd;border-radius:8px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #d0d5dd;padding-bottom:6px}
.muted{color:#5c6675;font-size:13px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e6e9ee;vertical-align:top}th{background:#edeff3;font-weight:600}
.facts td:first-child{color:#5c6675;width:180px}.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}
.pass{background:#dcf1e3;color:#1a7f37}.warn{background:#f6ecd2;color:#9a6700}.fail{background:#f8dcda;color:#c0342b}.info{background:#edeff3;color:#5c6675}
.notes{white-space:pre-wrap;background:#f7f8fa;border:1px solid #e6e9ee;border-radius:6px;padding:12px;font-size:14px}
code{font-family:Consolas,"Courier New",monospace;font-size:12px;word-break:break-all}
footer{margin-top:28px;color:#5c6675;font-size:12px}@media print{body{background:#fff}main{border:0;margin:0}}
</style></head><body><main>')

    # --- Header -----------------------------------------------------------
    [void] $html.AppendLine(('<h1>{0}</h1><div class="muted">{1} - {2}</div>' -f
        (& $t 'Intervention report'), (& $h $Report.Computer), (& $h ([datetime] $Report.GeneratedAt).ToString('yyyy-MM-dd HH:mm'))))

    [void] $html.AppendLine(('<h2>{0}</h2><table class="facts">' -f (& $t 'Intervention')))
    [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $t 'Ticket'), $(if ($Report.Ticket) { & $h $Report.Ticket } else { '<span class="muted">{0}</span>' -f (& $t 'None given') })))
    [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $t 'Technician'), (& $h $Report.Technician)))
    [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $t 'Period covered'), (& $l $Report.Period)))
    [void] $html.AppendLine('</table>')

    # --- Machine ----------------------------------------------------------
    $identity = $Report.Identity
    $os       = $Report.OS

    [void] $html.AppendLine(('<h2>{0}</h2><table class="facts">' -f (& $t 'Machine')))

    # Objects rather than two element arrays: a list of inline arrays is
    # flattened into one list of strings, and each row then showed one letter.
    $facts = @(
        [pscustomobject] @{ Label = 'Computer';               Value = $Report.Computer }
        [pscustomobject] @{ Label = 'Manufacturer and model'; Value = $(if ($identity) { '{0} {1}' -f $identity.Manufacturer, $identity.Model }) }
        [pscustomobject] @{ Label = 'Serial number';          Value = $(if ($identity) { $identity.SerialNumber }) }
        [pscustomobject] @{ Label = 'Windows';                Value = $(if ($os) { Get-TkText -Text '{0} {1}, build {2}' -ArgumentList $os.Caption, $os.DisplayVersion, $os.Build -Language $Language }) }
        [pscustomobject] @{ Label = 'Uptime';                 Value = $(if ($os) { ConvertTo-TkLocalText -Text $os.UptimeText -Language $Language }) }
        [pscustomobject] @{ Label = 'Signed in user';         Value = $(if ($identity) { $identity.LoggedOnUser }) }
        [pscustomobject] @{ Label = 'Domain or workgroup';    Value = $(if ($identity) { $identity.Domain }) }
    )

    foreach ($fact in $facts) {
        [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $t $fact.Label),
            $(if ($fact.Value) { & $h $fact.Value } else { '<span class="muted">{0}</span>' -f (& $t 'Not available') })))
    }

    [void] $html.AppendLine('</table>')

    # --- Health -----------------------------------------------------------
    [void] $html.AppendLine(('<h2>{0}</h2>' -f (& $t 'Health at the time of the report')))

    if (@($Report.Tiles).Count -gt 0) {

        [void] $html.AppendLine(('<table><tr><th>{0}</th><th>{1}</th><th>{2}</th><th>{3}</th></tr>' -f (& $t 'Check'), (& $t 'Result'), (& $t 'State'), (& $t 'Detail')))

        foreach ($tile in @($Report.Tiles)) {
            [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (& $l $tile.Title), (& $l $tile.Value), (& $badge $tile.Severity), (& $l $tile.Detail)))
        }

        [void] $html.AppendLine('</table>')
    }
    else {
        [void] $html.AppendLine(('<p class="muted">{0}</p>' -f (& $t 'The health of the machine could not be read.')))
    }

    # --- Security audit ---------------------------------------------------
    if ($Report.Audit) {

        $score = $Report.Audit.Score

        [void] $html.AppendLine(('<h2>{0}</h2>' -f (& $t 'Security audit')))
        [void] $html.AppendLine(('<p><strong>{0}</strong>: {1}</p>' -f (& $tf 'Score {0} of 100' @(& $h $score.Score)),
            (& $tf '{0} passed, {1} failed, {2} warnings, {3} not assessed.' @((& $h $score.Passed), (& $h $score.Failed), (& $h $score.Warnings), (& $h $score.NotAssessed)))))

        $open = @($Report.Audit.Findings | Where-Object { $_.Status -in @('Fail', 'Warning') })

        if ($open.Count -gt 0) {

            [void] $html.AppendLine(('<table><tr><th>{0}</th><th>{1}</th><th>{2}</th></tr>' -f (& $t 'Control'), (& $t 'State'), (& $t 'Detail')))

            foreach ($finding in $open) {
                [void] $html.AppendLine(('<tr><td>{0} {1}</td><td>{2}</td><td>{3}</td></tr>' -f
                    (& $h $finding.Id), (& $h $finding.Name), (& $badge $finding.Status), (& $h $finding.Detail)))
            }

            [void] $html.AppendLine('</table>')
        }
    }

    # --- Actions ----------------------------------------------------------
    [void] $html.AppendLine(('<h2>{0}</h2>' -f (& $t 'What was done')))

    $entries = @($Report.Entries | Where-Object { $_ })

    if ($entries.Count -gt 0) {

        [void] $html.AppendLine(('<table><tr><th>{0}</th><th>{1}</th><th>{2}</th><th>{3}</th></tr>' -f (& $t 'Time'), (& $t 'Kind'), (& $t 'Operation'), (& $t 'Outcome')))

        foreach ($entry in $entries) {
            [void] $html.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                (& $h ([datetime] $entry.Time).ToString('yyyy-MM-dd HH:mm')), (& $t ([string] $entry.Kind)), (& $h $entry.Name),
                (& $badge $(if ($entry.Outcome -eq 'Done') { 'Pass' } else { 'Fail' }))))
        }

        [void] $html.AppendLine('</table>')
    }
    else {
        [void] $html.AppendLine(('<p class="muted">{0}</p>' -f (& $t 'No operation was run through the toolkit in this period.')))
    }

    # --- Journal integrity ---------------------------------------------------
    # The head of the chain, written into a report that leaves the machine: a
    # journal changed afterwards, even rewritten whole, no longer leads to it.
    if ($Report.PSObject.Properties['Journal'] -and $Report.Journal) {

        $journal = $Report.Journal

        [void] $html.AppendLine(('<h2>{0}</h2>' -f (& $t 'Journal integrity')))

        if ($journal.Valid) {
            [void] $html.AppendLine(('<p>{0} {1}{2}</p>' -f (& $badge 'Pass'),
                (& $tf '{0} entries in the journal, each linked to the one before it: none was changed or removed since it was written.' @(& $h $journal.Entries)),
                $(if ($journal.Unchained -gt 0) { ' ' + (& $tf '{0} written before the link existed are counted apart.' @(& $h $journal.Unchained)) } else { '' })))
        }
        else {
            $break = @($journal.Breaks)[0]
            [void] $html.AppendLine(('<p>{0} {1}</p>' -f (& $badge 'Fail'),
                (& $tf 'The chain is broken in {0} place(s). First: {1}, line {2}: {3}' @((& $h @($journal.Breaks).Count), (& $h $break.File), (& $h $break.Line), (& $h $break.Problem)))))
        }

        $head = if ($journal.Head) { '<code>{0}</code>' -f (& $h $journal.Head) } else { & $t 'none, the journal is empty' }
        [void] $html.AppendLine(('<p class="muted">{0}</p>' -f
            (& $tf 'Head of the journal when this report was made: {0}. Keep this report: a journal changed afterwards, even rewritten whole, no longer leads to this value.' @($head))))
    }

    # --- Notes ------------------------------------------------------------
    [void] $html.AppendLine(('<h2>{0}</h2>' -f (& $t 'Notes')))
    [void] $html.AppendLine($(if ($Report.Notes) { '<div class="notes">{0}</div>' -f (& $h $Report.Notes) } else { '<p class="muted">{0}</p>' -f (& $t 'No notes.') }))

    [void] $html.AppendLine(('<footer>{0}</footer>' -f
        (& $tf 'Generated by {0}. The operations listed are the ones run through the toolkit; changes made by other means do not appear.' @(& $h $Report.Toolkit))))
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
        Journal     = Test-TkJournalChain
    }
}
