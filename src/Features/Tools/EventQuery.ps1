<#
    Toolkit - Features / Tools / Event log query builder

    Turns "what happened in the System log yesterday" into the three forms that
    actually run it: a Get-WinEvent FilterHashtable, an XPath filter for
    -FilterXPath and Event Viewer, and a wevtutil command line. Building an event
    query by hand is the kind of thing everyone looks up every time.

    Pure text work: it writes the query, it does not run it.
#>

<#
.SYNOPSIS
    The event levels, with the numeric value the log stores.

.OUTPUTS
    PSCustomObject[] with Label and Value (0 meaning any level).
#>
function Get-TkEventLevelChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Any level';    Value = 0 }
        [pscustomobject] @{ Label = 'Critical';     Value = 1 }
        [pscustomobject] @{ Label = 'Error';        Value = 2 }
        [pscustomobject] @{ Label = 'Warning';      Value = 3 }
        [pscustomobject] @{ Label = 'Information';  Value = 4 }
        [pscustomobject] @{ Label = 'Verbose';      Value = 5 }
    )
}

<#
.SYNOPSIS
    Builds an event log query in the three forms that run it.

.DESCRIPTION
    Assembles an XPath filter from the parts given, then wraps it for
    Get-WinEvent and wevtutil, and writes the FilterHashtable form as well since
    it is what most scripts use. The text search is only in the XPath forms, as
    a FilterHashtable cannot express it.

.PARAMETER Log
    The log name, such as System or Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.

.PARAMETER Id
    The event ids to match, any of them.

.PARAMETER Level
    The level to match: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose, 0 any.

.PARAMETER Provider
    The provider (source) name, optional.

.PARAMETER SinceHours
    Only events newer than this many hours, 0 for no time limit.

.PARAMETER Contains
    Text that must appear in the event data, optional.

.PARAMETER MaxEvents
    The most events to return.

.OUTPUTS
    PSCustomObject with XPath, FilterHashtable, PowerShellHashtable, PowerShellXPath and Wevtutil.
#>
function Build-TkEventQuery {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Log,

        [Parameter()]
        [int[]] $Id = @(),

        [Parameter()]
        [int] $Level = 0,

        [Parameter()]
        [string] $Provider = '',

        [Parameter()]
        [int] $SinceHours = 0,

        [Parameter()]
        [string] $Contains = '',

        [Parameter()]
        [int] $MaxEvents = 50
    )

    $log      = $Log.Trim()
    $provider = $Provider.Trim()
    $contains = $Contains.Trim()

    # --- The System[...] predicates --------------------------------------
    $system = New-Object System.Collections.Generic.List[string]

    if ($Id.Count -gt 0) {
        $system.Add('(' + ((@($Id) | ForEach-Object { 'EventID={0}' -f $_ }) -join ' or ') + ')')
    }

    if ($Level -gt 0) {
        $system.Add('Level={0}' -f $Level)
    }

    if ($provider) {
        $system.Add("Provider[@Name='{0}']" -f $provider)
    }

    if ($SinceHours -gt 0) {
        $ms = [long] $SinceHours * 3600 * 1000
        $system.Add('TimeCreated[timediff(@SystemTime) &lt;= {0}]' -f $ms)
    }

    $systemPart = if ($system.Count -gt 0) { 'System[{0}]' -f ($system -join ' and ') } else { 'System' }
    $xpath      = '*[{0}]' -f $systemPart

    if ($contains) {
        $xpath += " and *[EventData[Data[contains(.,'{0}')]]]" -f $contains
    }

    # The ampersand-escaped forms above are for the XML box in Event Viewer;
    # the command lines want the plain characters.
    $plainXpath = $xpath -replace '&lt;', '<' -replace '&gt;', '>' -replace '&quot;', '"'

    # --- FilterHashtable form --------------------------------------------
    $hashLines = New-Object System.Collections.Generic.List[string]
    $hashLines.Add("    LogName = '{0}'" -f $log)
    if ($Id.Count -gt 0)  { $hashLines.Add('    Id      = {0}' -f ((@($Id)) -join ', ')) }
    if ($Level -gt 0)     { $hashLines.Add('    Level   = {0}' -f $Level) }
    if ($provider)        { $hashLines.Add("    ProviderName = '{0}'" -f $provider) }
    if ($SinceHours -gt 0){ $hashLines.Add('    StartTime = (Get-Date).AddHours(-{0})' -f $SinceHours) }

    $hashtable = "@{`n" + ($hashLines -join "`n") + "`n}"

    $psHash = 'Get-WinEvent -FilterHashtable {0} -MaxEvents {1}' -f $hashtable, $MaxEvents
    if ($contains) {
        $psHash += " |`n    Where-Object {{ `$_.Message -like '*{0}*' }}" -f $contains
    }

    $psXpath  = "Get-WinEvent -LogName '{0}' -FilterXPath '{1}' -MaxEvents {2}" -f $log, $plainXpath, $MaxEvents
    $wevtutil = 'wevtutil qe "{0}" /q:"{1}" /f:text /c:{2} /rd:true' -f $log, $plainXpath, $MaxEvents

    return [pscustomobject] @{
        XPath               = $xpath
        PlainXPath          = $plainXpath
        FilterHashtable     = $hashtable
        PowerShellHashtable = $psHash
        PowerShellXPath     = $psXpath
        Wevtutil            = $wevtutil
    }
}

<#
.SYNOPSIS
    Lays out a built event query for the panel.

.OUTPUTS
    System.String[]
#>
function Format-TkEventQuery {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Query
    )

    return @(
        'PowerShell (FilterHashtable)'
        $Query.PowerShellHashtable
        ''
        'PowerShell (XPath)'
        $Query.PowerShellXPath
        ''
        'wevtutil'
        $Query.Wevtutil
        ''
        'XPath for Event Viewer (Filter Current Log, XML tab)'
        $Query.XPath
    )
}
