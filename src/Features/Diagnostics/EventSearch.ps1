<#
    Toolkit - Features / Event log search

    The Tools page writes an event log query; this runs one, read only, and
    shows what it finds. The query is handed to Get-WinEvent as a
    FilterHashtable, never as text: a search word with a quote in it cannot
    break the query, and nothing typed is ever evaluated. The text search is
    applied afterwards, on the messages that came back.
#>

<#
.SYNOPSIS
    The logs offered in the log box, the ones a support call usually needs.

.DESCRIPTION
    Any other log can be typed into the box by name.

.OUTPUTS
    System.String[]
#>
function Get-TkEventLogChoice {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'System'
        'Application'
        'Security'
        'Setup'
        'Microsoft-Windows-PowerShell/Operational'
        'Microsoft-Windows-Windows Defender/Operational'
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        'Microsoft-Windows-GroupPolicy/Operational'
        'Microsoft-Windows-WLAN-AutoConfig/Operational'
        'Microsoft-Windows-Bits-Client/Operational'
        'Microsoft-Windows-PrintService/Admin'
        'Microsoft-Windows-TaskScheduler/Operational'
    )
}

<#
.SYNOPSIS
    The periods offered, as hours back from now.

.OUTPUTS
    PSCustomObject[] with Label and Hours (0 meaning no limit).
#>
function Get-TkEventPeriodChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Last hour';     Hours = 1 }
        [pscustomobject] @{ Label = 'Last 24 hours'; Hours = 24 }
        [pscustomobject] @{ Label = 'Last 7 days';   Hours = 168 }
        [pscustomobject] @{ Label = 'Last 30 days';  Hours = 720 }
        [pscustomobject] @{ Label = 'Any time';      Hours = 0 }
    )
}

<#
.SYNOPSIS
    Reads a list of event ids: single ids and ranges, separated by commas.

.DESCRIPTION
    Pure. Get-WinEvent refuses more than 23 ids in one FilterHashtable, so a
    longer list is refused here with that reason rather than failing later.

.PARAMETER Value
    For example "4624, 4625, 7000-7009".

.OUTPUTS
    PSCustomObject with Ids and Error.
#>
function ConvertFrom-TkEventIdList {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Value
    )

    $ids = New-Object System.Collections.Generic.List[int]

    foreach ($part in @(([string] $Value) -split '[,;\s]+' | Where-Object { $_ })) {

        if ($part -match '^(\d{1,5})$') {
            $ids.Add([int] $Matches[1])
            continue
        }

        if ($part -match '^(\d{1,5})-(\d{1,5})$' -and [int] $Matches[1] -lt [int] $Matches[2]) {
            $low  = [int] $Matches[1]
            $high = [int] $Matches[2]

            if ($high - $low -ge 23) {
                return [pscustomobject] @{ Ids = @(); Error = ('The range {0} holds more than the 23 ids Windows accepts in one search.' -f $part) }
            }

            foreach ($id in $low..$high) { $ids.Add($id) }
            continue
        }

        return [pscustomobject] @{ Ids = @(); Error = ('"{0}" is not an event id or a range (for example 4625 or 7000-7009).' -f $part) }
    }

    $unique = @($ids.ToArray() | Where-Object { $_ -le 65535 } | Select-Object -Unique)

    if ($unique.Count -gt 23) {
        return [pscustomobject] @{ Ids = @(); Error = 'Windows accepts at most 23 event ids in one search.' }
    }

    return [pscustomobject] @{ Ids = $unique; Error = '' }
}

<#
.SYNOPSIS
    Builds the FilterHashtable for a search.

.DESCRIPTION
    Pure. Only the keys that are set are written, and each value keeps its
    type, so nothing typed is ever read as code or as query text.

.OUTPUTS
    System.Collections.Hashtable
#>
function New-TkEventFilter {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Log,
        [Parameter()] [AllowEmptyCollection()] [int[]] $Id = @(),
        [Parameter()] [ValidateRange(0, 5)] [int] $Level = 0,
        [Parameter()] [AllowEmptyString()] [string] $Provider = '',
        [Parameter()] [int] $SinceHours = 0,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $filter = @{ LogName = $Log.Trim() }

    if (@($Id).Count -gt 0)    { $filter['Id'] = @($Id) }
    if ($Level -gt 0)          { $filter['Level'] = $Level }
    if ($Provider.Trim())      { $filter['ProviderName'] = $Provider.Trim() }
    if ($SinceHours -gt 0)     { $filter['StartTime'] = $Now.AddHours(-$SinceHours) }

    return $filter
}

<#
.SYNOPSIS
    Keeps the events whose message holds a text, and trims each to a row.

.DESCRIPTION
    Pure. The match ignores case. The message is cut to its first lines for
    the table; the whole message stays in the Message property.

.OUTPUTS
    PSCustomObject[] with Time, Level, Id, Provider, Summary and Message.
#>
function Select-TkEventRow {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Record = @(),
        [Parameter()] [AllowEmptyString()] [string] $Contains = '',
        [Parameter()] [int] $MaxEvents = 200
    )

    $needle = $Contains.Trim()
    $rows   = New-Object System.Collections.Generic.List[object]

    foreach ($entry in ($Record | Where-Object { $_ })) {

        $message = [string] $entry.Message

        if ($needle -and $message.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            continue
        }

        $summary = (($message -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ').Trim()
        if ($summary.Length -gt 240) { $summary = $summary.Substring(0, 240) + '...' }
        if (-not $summary) { $summary = '(no message text: the provider''s message file is not on this machine)' }

        $rows.Add([pscustomobject] @{
            Time     = $entry.TimeCreated
            Level    = if ($entry.LevelDisplayName) { [string] $entry.LevelDisplayName } else { [string] $entry.Level }
            Id       = [int] $entry.Id
            Provider = [string] $entry.ProviderName
            Summary  = $summary
            Message  = $message
        })

        if ($rows.Count -ge $MaxEvents) {
            break
        }
    }

    return @($rows.ToArray())
}

<#
.SYNOPSIS
    Searches an event log, read only.

.PARAMETER Log
    The log name.

.PARAMETER Id
    Event ids, any of them.

.PARAMETER Level
    1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose, 0 any.

.PARAMETER Provider
    The provider name, optional.

.PARAMETER SinceHours
    How far back, 0 for no limit.

.PARAMETER Contains
    Text the message must hold, optional.

.PARAMETER MaxEvents
    How many rows at most.

.OUTPUTS
    PSCustomObject with Log, Rows, Scanned, Truncated and Error.
#>
function Search-TkEventLog {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Log,
        [Parameter()] [AllowEmptyCollection()] [int[]] $Id = @(),
        [Parameter()] [ValidateRange(0, 5)] [int] $Level = 0,
        [Parameter()] [AllowEmptyString()] [string] $Provider = '',
        [Parameter()] [int] $SinceHours = 24,
        [Parameter()] [AllowEmptyString()] [string] $Contains = '',
        [Parameter()] [ValidateRange(1, 2000)] [int] $MaxEvents = 200
    )

    $result = { param($rows, $scanned, $truncated, $message) [pscustomobject] @{ Log = $Log; Rows = @($rows); Scanned = $scanned; Truncated = $truncated; Error = $message } }

    # Told apart by the error identifier, not the message, which Windows translates.
    $denied = { param($failure) $failure.FullyQualifiedErrorId -like 'LogInfoUnavailable*' -or $failure.Exception.InnerException -is [System.UnauthorizedAccessException] -or $failure.Exception -is [System.UnauthorizedAccessException] }

    try {
        $known = Get-WinEvent -ListLog $Log.Trim() -ErrorAction Stop
    }
    catch {
        if (& $denied $_) {
            return (& $result @() 0 $false ('Reading "{0}" needs administrator rights.' -f $Log.Trim()))
        }

        return (& $result @() 0 $false ('There is no event log named "{0}" on this machine.' -f $Log.Trim()))
    }

    $providerName = $Provider.Trim()

    if ($providerName) {

        # A wildcard would match providers the user did not mean.
        if ($providerName -match '[*?\[\]]') {
            return (& $result @() 0 $false 'Type the exact provider name: wildcards are not accepted.')
        }

        try {
            $null = Get-WinEvent -ListProvider $providerName -ErrorAction Stop
        }
        catch {
            return (& $result @() 0 $false ('No event provider is named "{0}" on this machine.' -f $providerName))
        }
    }

    if (-not $known.IsEnabled -and $known.RecordCount -eq 0) {
        return (& $result @() 0 $false ('The log "{0}" is turned off, so it holds nothing to search.' -f $known.LogName))
    }

    $filter = New-TkEventFilter -Log $known.LogName -Id $Id -Level $Level -Provider $Provider -SinceHours $SinceHours

    # With a text search, more events are read than shown, since the text is
    # matched afterwards. The bound keeps a broad search from running for ever.
    $read = if ($Contains.Trim()) { 5000 } else { $MaxEvents }

    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $read -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
            return (& $result @() 0 $false '')
        }

        if (& $denied $_) {
            return (& $result @() 0 $false ('Reading "{0}" needs administrator rights.' -f $known.LogName))
        }

        return (& $result @() 0 $false ('The search failed: {0}' -f $_.Exception.Message))
    }

    $rows = @(Select-TkEventRow -Record $events -Contains $Contains -MaxEvents $MaxEvents)

    return (& $result $rows $events.Count ($events.Count -ge $read) '')
}
