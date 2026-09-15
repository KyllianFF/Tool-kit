<#
    Toolkit - Features / Mail tools

    Reading the headers of an e-mail, and the DNS records that authenticate
    the mail of a domain.

    The header analysis is text work only: nothing is sent and no link is
    opened, so a suspicious message can be examined safely. The DNS check
    queries the resolvers this machine uses, and only when asked; its lookups
    go through a resolver passed in, which is what lets the tests run without
    a network.
#>

# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Splits pasted headers into fields, unfolding the continued lines.

.DESCRIPTION
    A header continues on the next line when that line starts with a space or
    a tab (RFC 5322 folding). Reading stops at the first empty line after the
    headers, so a pasted body is ignored. A line that is neither a field nor a
    continuation, such as a separator a mail client adds, is skipped.

.PARAMETER Text
    The headers, as copied from the mail client.

.OUTPUTS
    PSCustomObject[] with Name and Value, in the order of the message.
#>
function ConvertFrom-TkMailHeader {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $fields  = New-Object System.Collections.Generic.List[object]
    $current = $null

    foreach ($line in ($Text -split "\r?\n")) {

        if ([string]::IsNullOrWhiteSpace($line)) {

            if ($fields.Count -gt 0) {
                break
            }

            continue
        }

        if ($line -match '^[ \t]' -and $null -ne $current) {
            $current.Value = ('{0} {1}' -f $current.Value, $line.Trim()).Trim()
            continue
        }

        $field = [regex]::Match($line, '^(?<name>[!-9;-~]+):[ \t]*(?<value>.*)$')

        if ($field.Success) {
            $current = [pscustomobject] @{ Name = $field.Groups['name'].Value; Value = $field.Groups['value'].Value.Trim() }
            $fields.Add($current)
        }
    }

    return $fields.ToArray()
}

<#
.SYNOPSIS
    Reads a date as mail headers write it.

.DESCRIPTION
    Accepts the RFC 5322 form, such as Mon, 15 Sep 2026 10:11:12 +0200
    (CEST): an optional day name, a comment in parentheses, a two or four
    digit year, and a numeric zone or one of the old names (GMT, UT, EST...).

.PARAMETER Text
    The date text.

.OUTPUTS
    System.DateTimeOffset, or null when the text is not a date.
#>
function ConvertTo-TkMailDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $clean = ($Text -replace '\([^)]*\)', ' ').Trim()
    $clean = ($clean -replace '^[A-Za-z]{3},\s*', '') -replace '\s+', ' '

    $zones = @{
        'UT' = '+0000'; 'GMT' = '+0000'; 'Z' = '+0000'
        'EST' = '-0500'; 'EDT' = '-0400'; 'CST' = '-0600'; 'CDT' = '-0500'
        'MST' = '-0700'; 'MDT' = '-0600'; 'PST' = '-0800'; 'PDT' = '-0700'
    }

    $named = [regex]::Match($clean, '^(?<rest>.+?)\s+(?<zone>[A-Za-z]{1,3})$')

    if ($named.Success -and $zones.ContainsKey($named.Groups['zone'].Value.ToUpperInvariant())) {
        $clean = '{0} {1}' -f $named.Groups['rest'].Value, $zones[$named.Groups['zone'].Value.ToUpperInvariant()]
    }

    $parts = [regex]::Match($clean, '^(?<day>\d{1,2}) (?<month>[A-Za-z]{3}) (?<year>\d{2,4}) (?<hour>\d{1,2}):(?<minute>\d{2})(?::(?<second>\d{2}))? (?<sign>[+-])(?<hours>\d{2})(?<minutes>\d{2})$')

    if (-not $parts.Success) {
        return $null
    }

    $month = [array]::IndexOf(@('jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'), $parts.Groups['month'].Value.ToLowerInvariant()) + 1

    if ($month -lt 1) {
        return $null
    }

    $year = [int] $parts.Groups['year'].Value

    # The obsolete two digit years: 00 to 49 are 2000 to 2049, 50 to 99 the 1900s.
    if ($parts.Groups['year'].Value.Length -eq 2) {
        $year = if ($year -lt 50) { 2000 + $year } else { 1900 + $year }
    }

    $second = if ($parts.Groups['second'].Success) { [int] $parts.Groups['second'].Value } else { 0 }
    $offset = New-Object System.TimeSpan([int] $parts.Groups['hours'].Value, [int] $parts.Groups['minutes'].Value, 0)

    if ($parts.Groups['sign'].Value -eq '-') {
        $offset = $offset.Negate()
    }

    try {
        return New-Object System.DateTimeOffset($year, $month, [int] $parts.Groups['day'].Value,
                                                [int] $parts.Groups['hour'].Value, [int] $parts.Groups['minute'].Value, $second, $offset)
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Splits a mail address field into its display name, address and domain.

.PARAMETER Text
    The value of a From, Reply-To, Return-Path or To field.

.OUTPUTS
    PSCustomObject with Display, Address and Domain, or null without an address.
#>
function Get-TkMailAddress {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $bracketed = [regex]::Match($Text, '<(?<address>[^<>\s@]+@[^<>\s]+)>')
    $address   = ''
    $display   = ''

    if ($bracketed.Success) {
        $address = $bracketed.Groups['address'].Value
        $display = $Text.Substring(0, $bracketed.Index).Trim().Trim('"').Trim()
    }
    else {
        $bare = [regex]::Match($Text, '(?<address>[^\s<>",;]+@[^\s<>",;]+)')

        if (-not $bare.Success) {
            return $null
        }

        $address = $bare.Groups['address'].Value
    }

    return [pscustomobject] @{
        Display = $display
        Address = $address
        Domain  = ($address.Substring($address.LastIndexOf('@') + 1)).TrimEnd('.').ToLowerInvariant()
    }
}

<#
.SYNOPSIS
    Tells whether an address is private, loopback or link-local.

.OUTPUTS
    System.Boolean
#>
function Test-TkMailPrivateAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Address
    )

    $ip = $null

    if (-not [System.Net.IPAddress]::TryParse($Address, [ref] $ip)) {
        return $false
    }

    $bytes = $ip.GetAddressBytes()

    if ($bytes.Count -eq 4) {
        return ($bytes[0] -eq 10 -or $bytes[0] -eq 127 -or
                ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
                ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
                ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127))
    }

    return ($ip.IsIPv6LinkLocal -or [System.Net.IPAddress]::IsLoopback($ip) -or ($bytes[0] -band 0xFE) -eq 0xFC)
}

<#
.SYNOPSIS
    Writes a delay between two hops the way a person reads it.

.OUTPUTS
    System.String
#>
function Format-TkMailDelay {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [TimeSpan] $Span
    )

    $seconds = [math]::Round($Span.TotalSeconds)

    if ($seconds -lt 0) {
        return ('{0} s, the clocks of the two servers disagree' -f $seconds)
    }

    if ($seconds -lt 60) {
        return ('{0} s' -f $seconds)
    }

    if ($seconds -lt 3600) {
        return ('{0} min' -f [math]::Round($seconds / 60))
    }

    return ('{0} h {1} min' -f [math]::Floor($seconds / 3600), [math]::Round(($seconds % 3600) / 60))
}

<#
.SYNOPSIS
    Analyses the headers of an e-mail.

.DESCRIPTION
    Received fields are added by each server on the way, the newest at the
    top, so the route is read from the bottom up. For each hop: the server it
    came from and its address, the server that received it, and the time,
    with the delay since the previous hop.

    Authentication-Results is the verdict of the receiving system on SPF,
    DKIM and DMARC. The first one is kept: fields further down may have been
    written by the sender, and prove nothing.

    Warnings flag what phishing looks like: replies sent to another domain, a
    display name showing an address that is not the sender's, an envelope
    sender at an unrelated domain, failed authentication, and a server holding
    a message for over an hour.

.PARAMETER Text
    The headers, as copied from the mail client.

.OUTPUTS
    PSCustomObject
#>
function Get-TkMailHeaderReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $fields = @(ConvertFrom-TkMailHeader -Text $Text)

    $first = {
        param($name)
        $field = $fields | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($field) { [string] $field.Value } else { '' }
    }

    # --- Route ------------------------------------------------------------
    $received = @($fields | Where-Object { $_.Name -eq 'Received' })
    [array]::Reverse($received)

    $hops     = New-Object System.Collections.Generic.List[object]
    $previous = $null
    $number   = 0

    foreach ($field in $received) {

        $number++
        $value     = [string] $field.Value
        $separator = $value.LastIndexOf(';')
        $date      = if ($separator -ge 0) { ConvertTo-TkMailDate -Text $value.Substring($separator + 1) } else { $null }
        $route     = if ($separator -ge 0) { $value.Substring(0, $separator) } else { $value }

        $byIndex  = $route.IndexOf(' by ')
        $fromPart = if ($byIndex -ge 0) { $route.Substring(0, $byIndex) } else { $route }

        $fromHost = [regex]::Match($fromPart, '\bfrom\s+(?<host>[^\s()]+)')
        $byHost   = [regex]::Match($route, '\bby\s+(?<host>[^\s();]+)')
        $with     = [regex]::Match($route, '\bwith\s+(?<with>[^;()]+?)(?=\s+(?:id|for|via)\b|\s*\(|$)')

        # The address the receiving server saw comes last: "from [192.168.1.20]
        # (unknown [203.0.113.77])" gives the name the client announced, then
        # the address it really connected from. Exchange writes it in
        # parentheses without brackets.
        $addresses = [regex]::Matches($fromPart, '[\[(](?:IPv6:)?(?<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]+)[\])]')

        $hop = [pscustomobject] @{
            Number = $number
            From   = $(if ($fromHost.Success) { $fromHost.Groups['host'].Value } else { '' })
            FromIp = $(if ($addresses.Count -gt 0) { $addresses[$addresses.Count - 1].Groups['ip'].Value } else { '' })
            By     = $(if ($byHost.Success) { $byHost.Groups['host'].Value } else { '' })
            With   = $(if ($with.Success) { $with.Groups['with'].Value.Trim() } else { '' })
            Date   = $date
            Delay  = $(if ($null -ne $date -and $null -ne $previous -and $null -ne $previous.Date) { $date - $previous.Date } else { $null })
        }

        $hops.Add($hop)
        $previous = $hop
    }

    $dated   = @($hops | Where-Object { $null -ne $_.Date })
    $transit = if ($dated.Count -ge 2) { $dated[-1].Date - $dated[0].Date } else { $null }

    # --- Authentication ---------------------------------------------------
    $results = & $first 'Authentication-Results'

    $verdict = {
        param($pattern)
        $match = [regex]::Match($results, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) { $match.Groups[1].Value.ToLowerInvariant() } else { '' }
    }

    $authentication = [pscustomobject] @{
        Spf        = & $verdict '\bspf=(\w+)'
        Dkim       = & $verdict '\bdkim=(\w+)'
        Dmarc      = & $verdict '\bdmarc=(\w+)'
        CompAuth   = & $verdict '\bcompauth=(\w+)'
        MailFrom   = & $verdict '\bsmtp\.mailfrom=([^\s;]+)'
        DkimDomain = & $verdict '\bheader\.d=([^\s;]+)'
        HeaderFrom = & $verdict '\bheader\.from=([^\s;]+)'
    }

    # --- Addresses --------------------------------------------------------
    $from       = Get-TkMailAddress -Text (& $first 'From')
    $replyTo    = Get-TkMailAddress -Text (& $first 'Reply-To')
    $returnPath = Get-TkMailAddress -Text (& $first 'Return-Path')

    $originating = (& $first 'X-Originating-IP').Trim('[', ']', ' ')

    if (-not $originating) {
        $external = @($hops | Where-Object { $_.FromIp -and -not (Test-TkMailPrivateAddress -Address $_.FromIp) }) | Select-Object -First 1
        if ($external) { $originating = $external.FromIp }
    }

    # --- Warnings ---------------------------------------------------------
    $warnings = New-Object System.Collections.Generic.List[string]

    $related = {
        param($one, $other)
        $one -eq $other -or $one.EndsWith('.' + $other) -or $other.EndsWith('.' + $one)
    }

    if ($from -and $replyTo -and -not (& $related $from.Domain $replyTo.Domain)) {
        $warnings.Add(('Replies go to {0}, not to the domain of the sender, {1}.' -f $replyTo.Address, $from.Domain))
    }

    if ($from -and $from.Display -match '[^\s<>"]+@[^\s<>"]+' -and $Matches[0].Trim('.').ToLowerInvariant() -ne $from.Address.ToLowerInvariant()) {
        $warnings.Add(('The display name shows {0}, but the message comes from {1}.' -f $Matches[0], $from.Address))
    }

    if ($from -and $returnPath -and -not (& $related $from.Domain $returnPath.Domain)) {
        $warnings.Add(('The envelope sender (Return-Path) is at {0}, another domain than the From address: normal for a mailing service, suspicious for a colleague, a supplier or a bank.' -f $returnPath.Domain))
    }

    foreach ($check in @(
        @{ Name = 'SPF';   Value = $authentication.Spf;      Bad = @('fail', 'softfail', 'permerror') }
        @{ Name = 'DKIM';  Value = $authentication.Dkim;     Bad = @('fail', 'permerror') }
        @{ Name = 'DMARC'; Value = $authentication.Dmarc;    Bad = @('fail', 'permerror') }
        @{ Name = 'Composite authentication (compauth)'; Value = $authentication.CompAuth; Bad = @('fail') }
    )) {
        if ($check.Value -in $check.Bad) {
            $warnings.Add(('{0} gave {1} on arrival.' -f $check.Name, $check.Value))
        }
    }

    foreach ($hop in $hops) {

        if ($null -ne $hop.Delay -and $hop.Delay.TotalHours -ge 1) {
            $warnings.Add(('{0} held the message {1} before passing it on: a queue, a filter or a server that was down.' -f $(if ($hop.By) { $hop.By } else { 'Hop ' + $hop.Number }), (Format-TkMailDelay -Span $hop.Delay)))
        }
    }

    return [pscustomobject] @{
        HeaderCount    = $fields.Count
        From           = & $first 'From'
        ReplyTo        = & $first 'Reply-To'
        ReturnPath     = & $first 'Return-Path'
        To             = & $first 'To'
        Subject        = & $first 'Subject'
        Date           = ConvertTo-TkMailDate -Text (& $first 'Date')
        MessageId      = & $first 'Message-ID'
        Hops           = $hops.ToArray()
        Transit        = $transit
        Authentication = $authentication
        OriginatingIp  = $originating
        Warnings       = $warnings.ToArray()
    }
}

<#
.SYNOPSIS
    Writes a header analysis as lines of text.

.PARAMETER Report
    Output of Get-TkMailHeaderReport.

.OUTPUTS
    System.String[]
#>
function Format-TkMailHeaderReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $lines   = New-Object System.Collections.Generic.List[string]

    $lines.Add('Message')

    foreach ($row in @(
        @('From', $Report.From), @('Reply-To', $Report.ReplyTo), @('Return-Path', $Report.ReturnPath),
        @('To', $Report.To), @('Subject', $Report.Subject), @('Message-ID', $Report.MessageId)
    )) {
        if ($row[1]) {
            $lines.Add(('  {0,-12} {1}' -f $row[0], $row[1]))
        }
    }

    if ($null -ne $Report.Date) {
        $lines.Add(('  {0,-12} {1}' -f 'Date', $Report.Date.ToString('yyyy-MM-dd HH:mm:ss zzz', $culture)))
    }

    $auth = $Report.Authentication

    if ($auth.Spf -or $auth.Dkim -or $auth.Dmarc) {

        $lines.Add('')
        $lines.Add('Authentication, as the receiving system recorded it')

        foreach ($row in @(
            @('SPF', $auth.Spf, $auth.MailFrom, 'smtp.mailfrom'),
            @('DKIM', $auth.Dkim, $auth.DkimDomain, 'header.d'),
            @('DMARC', $auth.Dmarc, $auth.HeaderFrom, 'header.from'),
            @('compauth', $auth.CompAuth, '', '')
        )) {
            if ($row[1]) {
                $lines.Add(('  {0,-12} {1}{2}' -f $row[0], $row[1], $(if ($row[2]) { ' ({0}={1})' -f $row[3], $row[2] } else { '' })))
            }
        }
    }
    else {
        $lines.Add('')
        $lines.Add('No Authentication-Results field: the receiving system did not record SPF, DKIM or DMARC, or it was not pasted.')
    }

    if (@($Report.Hops).Count -gt 0) {

        $lines.Add('')
        $lines.Add(('Route, {0} hop(s), oldest first' -f @($Report.Hops).Count))

        foreach ($hop in $Report.Hops) {

            $when  = if ($null -ne $hop.Date) { $hop.Date.ToString('yyyy-MM-dd HH:mm:ss zzz', $culture) } else { 'no date' }
            $delay = if ($null -ne $hop.Delay) { '  +{0}' -f (Format-TkMailDelay -Span $hop.Delay) } else { '' }

            $lines.Add(('  {0,2}  {1}{2}' -f $hop.Number, $when, $delay))

            if ($hop.From) {
                $lines.Add(('      from {0}{1}' -f $hop.From, $(if ($hop.FromIp) { ' [{0}]' -f $hop.FromIp } else { '' })))
            }

            if ($hop.By) {
                $lines.Add(('      by   {0}{1}' -f $hop.By, $(if ($hop.With) { ' with ' + $hop.With } else { '' })))
            }
        }
    }

    if ($Report.OriginatingIp) {
        $lines.Add('')
        $lines.Add(('Sent from    {0}' -f $Report.OriginatingIp))
    }

    if ($null -ne $Report.Transit) {
        $lines.Add(('In transit   {0}' -f (Format-TkMailDelay -Span $Report.Transit)))
    }

    $lines.Add('')

    if (@($Report.Warnings).Count -gt 0) {

        $lines.Add('Warnings')

        foreach ($warning in $Report.Warnings) {
            $lines.Add(('  - {0}' -f $warning))
        }
    }
    else {
        $lines.Add('Nothing in the headers looks forged. Headers can still be sent by a genuine account that was compromised: judge the content as well.')
    }

    return $lines.ToArray()
}

# ---------------------------------------------------------------------------
# SPF, DKIM and DMARC records
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Queries MX or TXT records for the mail checker.

.DESCRIPTION
    A TXT record longer than 255 characters arrives in several strings, which
    are joined without a separator, as RFC 7208 reads an SPF record. A name
    that does not exist returns nothing rather than an error.

.OUTPUTS
    System.String[]: TXT texts, or MX records as "preference host".
#>
function Resolve-TkMailDnsRecord {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('TXT', 'MX')]
        [string] $Type
    )

    try {
        $records = @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -ErrorAction Stop)
    }
    catch {
        return @()
    }

    if ($Type -eq 'MX') {
        return @($records | Where-Object { [string] $_.Type -eq 'MX' } | Sort-Object Preference |
                 ForEach-Object { '{0} {1}' -f $_.Preference, $_.NameExchange })
    }

    return @($records | Where-Object { [string] $_.Type -eq 'TXT' } | ForEach-Object { @($_.Strings) -join '' })
}

<#
.SYNOPSIS
    Parses an SPF record.

.PARAMETER Text
    The TXT record, starting with v=spf1.

.OUTPUTS
    PSCustomObject with Valid, Terms, LocalLookups, All, Includes and Redirect.
#>
function ConvertFrom-TkSpfRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $trimmed = $Text.Trim()
    $terms   = New-Object System.Collections.Generic.List[object]

    foreach ($token in @($trimmed -split '\s+' | Select-Object -Skip 1)) {

        if (-not $token) {
            continue
        }

        $modifier  = [regex]::Match($token, '^(?<name>redirect|exp)=(?<value>.+)$', 'IgnoreCase')
        $mechanism = [regex]::Match($token, '^(?<qualifier>[+\-~?]?)(?<name>all|include|a|mx|ptr|ip4|ip6|exists)(?:[:/](?<value>.*))?$', 'IgnoreCase')

        if ($modifier.Success) {
            $terms.Add([pscustomobject] @{ Kind = 'Modifier'; Qualifier = ''; Name = $modifier.Groups['name'].Value.ToLowerInvariant(); Value = $modifier.Groups['value'].Value })
        }
        elseif ($mechanism.Success) {
            $terms.Add([pscustomobject] @{
                Kind      = 'Mechanism'
                Qualifier = $(if ($mechanism.Groups['qualifier'].Value) { $mechanism.Groups['qualifier'].Value } else { '+' })
                Name      = $mechanism.Groups['name'].Value.ToLowerInvariant()
                Value     = $mechanism.Groups['value'].Value
            })
        }
        else {
            $terms.Add([pscustomobject] @{ Kind = 'Unknown'; Qualifier = ''; Name = $token; Value = '' })
        }
    }

    $all = @($terms | Where-Object { $_.Kind -eq 'Mechanism' -and $_.Name -eq 'all' }) | Select-Object -First 1
    $redirect = @($terms | Where-Object { $_.Kind -eq 'Modifier' -and $_.Name -eq 'redirect' }) | Select-Object -First 1

    return [pscustomobject] @{
        Valid        = ($trimmed -match '^v=spf1(\s|$)')
        Terms        = $terms.ToArray()
        LocalLookups = @($terms | Where-Object { ($_.Kind -eq 'Mechanism' -and $_.Name -in @('include', 'a', 'mx', 'ptr', 'exists')) -or ($_.Kind -eq 'Modifier' -and $_.Name -eq 'redirect') }).Count
        All          = $(if ($all) { $all.Qualifier } else { '' })
        Includes     = @($terms | Where-Object { $_.Kind -eq 'Mechanism' -and $_.Name -eq 'include' } | ForEach-Object { $_.Value })
        Redirect     = $(if ($redirect) { $redirect.Value } else { '' })
    }
}

<#
.SYNOPSIS
    Counts the DNS lookups an SPF record needs, through its includes.

.DESCRIPTION
    Receivers stop at 10 lookups and treat the record as a permanent error
    (RFC 7208, section 4.6.4). include, a, mx, ptr, exists and redirect each
    cost one, and an include costs what the included record costs as well.

.PARAMETER Domain
    The domain whose SPF record is counted.

.PARAMETER Resolver
    A script block taking a name and a type (TXT) and returning texts.

.OUTPUTS
    PSCustomObject with Lookups and Errors.
#>
function Measure-TkSpfLookup {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Domain,

        [Parameter(Mandatory)]
        [scriptblock] $Resolver,

        [Parameter()]
        [int] $Depth = 0
    )

    $problems = New-Object System.Collections.Generic.List[string]
    $records  = @(& $Resolver $Domain 'TXT' | Where-Object { $_ -match '^v=spf1(\s|$)' })

    if ($records.Count -eq 0) {
        $problems.Add(('{0} has no SPF record.' -f $Domain))
        return [pscustomobject] @{ Lookups = 0; Errors = $problems.ToArray() }
    }

    if ($records.Count -gt 1) {
        $problems.Add(('{0} publishes {1} SPF records, which receivers treat as an error.' -f $Domain, $records.Count))
    }

    $record  = ConvertFrom-TkSpfRecord -Text $records[0]
    $lookups = $record.LocalLookups

    # Past ten levels the record is already broken; stopping also keeps a
    # loop of includes from running forever.
    if ($Depth -ge 10) {
        return [pscustomobject] @{ Lookups = $lookups; Errors = $problems.ToArray() }
    }

    foreach ($target in @(@($record.Includes) + @($record.Redirect) | Where-Object { $_ })) {

        $child    = Measure-TkSpfLookup -Domain $target -Resolver $Resolver -Depth ($Depth + 1)
        $lookups += $child.Lookups

        foreach ($childProblem in $child.Errors) {
            $problems.Add($childProblem)
        }
    }

    return [pscustomobject] @{ Lookups = $lookups; Errors = $problems.ToArray() }
}

<#
.SYNOPSIS
    Reads the tag=value pairs of a DMARC or DKIM record.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary with lower case tags.
#>
function ConvertFrom-TkMailTagList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $tags = [ordered] @{}

    foreach ($part in ($Text -split ';')) {

        $pair = [regex]::Match($part.Trim(), '^(?<tag>[A-Za-z]+)\s*=\s*(?<value>.*)$')

        if ($pair.Success) {
            $tags[$pair.Groups['tag'].Value.ToLowerInvariant()] = ($pair.Groups['value'].Value -replace '\s', '')
        }
    }

    return $tags
}

<#
.SYNOPSIS
    Parses a DMARC record.

.OUTPUTS
    PSCustomObject with Valid, Policy, SubdomainPolicy, Percent, Rua, Ruf,
    AlignDkim and AlignSpf.
#>
function ConvertFrom-TkDmarcRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $tags    = ConvertFrom-TkMailTagList -Text $Text
    $percent = 100

    if ($tags.Contains('pct')) {
        [void] [int]::TryParse([string] $tags['pct'], [ref] $percent)
    }

    return [pscustomobject] @{
        Valid           = ($Text.Trim() -match '^v\s*=\s*DMARC1\s*(;|$)')
        Policy          = [string] $tags['p']
        SubdomainPolicy = $(if ($tags.Contains('sp')) { [string] $tags['sp'] } else { [string] $tags['p'] })
        Percent         = $percent
        Rua             = [string] $tags['rua']
        Ruf             = [string] $tags['ruf']
        AlignDkim       = $(if ($tags.Contains('adkim')) { [string] $tags['adkim'] } else { 'r' })
        AlignSpf        = $(if ($tags.Contains('aspf')) { [string] $tags['aspf'] } else { 'r' })
    }
}

<#
.SYNOPSIS
    Parses a DKIM public key record.

.DESCRIPTION
    The key size of an RSA key is estimated from the length of its encoded
    public key, which is enough to tell a 1024-bit key from a 2048-bit one
    without a full ASN.1 reader. An empty p= tag means the key was revoked.

.OUTPUTS
    PSCustomObject with Valid, KeyType, Revoked and KeyBits.
#>
function ConvertFrom-TkDkimRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $tags    = ConvertFrom-TkMailTagList -Text $Text
    $keyType = if ($tags.Contains('k')) { ([string] $tags['k']).ToLowerInvariant() } else { 'rsa' }
    $key     = [string] $tags['p']
    $bits    = 0

    if ($key) {
        try {
            $length = ([Convert]::FromBase64String($key)).Length

            $bits = if ($keyType -eq 'ed25519') { 255 }
                    elseif ($length -lt 100) { 512 }
                    elseif ($length -lt 200) { 1024 }
                    elseif ($length -lt 330) { 2048 }
                    elseif ($length -lt 460) { 3072 }
                    else { 4096 }
        }
        catch {
            $bits = 0
        }
    }

    return [pscustomobject] @{
        Valid   = ($tags.Contains('p') -and (-not $tags.Contains('v') -or $tags['v'] -eq 'DKIM1'))
        KeyType = $keyType
        Revoked = ($tags.Contains('p') -and -not $key)
        KeyBits = $bits
    }
}

<#
.SYNOPSIS
    Checks the MX, SPF, DKIM and DMARC records of a domain.

.PARAMETER Domain
    The domain, such as contoso.com.

.PARAMETER Selector
    DKIM selectors to look up. The common ones are tried when none is given:
    selector1 and selector2 for Microsoft 365, google, k1, s1, s2, default,
    dkim and mail.

.PARAMETER Resolver
    A script block taking a name and a type (TXT or MX) and returning texts.

.OUTPUTS
    PSCustomObject with Domain, Mx, Spf, SpfLookups, Dmarc, DmarcRecord, Dkim
    and Findings, each finding a Severity (Pass, Warning, Fail, Info) and a Text.
#>
function Get-TkMailDnsReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Domain,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Selector = @(),

        [Parameter()]
        [scriptblock] $Resolver = { param($name, $type) Resolve-TkMailDnsRecord -Name $name -Type $type }
    )

    $name     = $Domain.Trim().TrimEnd('.').ToLowerInvariant()
    $findings = New-Object System.Collections.Generic.List[object]

    $finding = {
        param($severity, $text)
        $findings.Add([pscustomobject] @{ Severity = $severity; Text = $text })
    }

    if ($name -notmatch '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$') {

        & $finding 'Fail' ('"{0}" is not a domain name.' -f $Domain)

        return [pscustomobject] @{ Domain = $name; Mx = @(); Spf = ''; SpfLookups = 0; Dmarc = ''; DmarcRecord = $null; Dkim = @(); Findings = $findings.ToArray() }
    }

    # --- MX ---------------------------------------------------------------
    $mx = @(& $Resolver $name 'MX')

    if ($mx.Count -eq 0) {
        & $finding 'Info' 'No MX record: the domain receives no mail, which is right for a domain that only sends.'
    }

    # --- SPF --------------------------------------------------------------
    $spfRecords = @(& $Resolver $name 'TXT' | Where-Object { $_ -match '^v=spf1(\s|$)' })
    $spfText    = if ($spfRecords.Count -gt 0) { $spfRecords[0] } else { '' }
    $lookups    = 0

    if ($spfRecords.Count -eq 0) {
        & $finding 'Fail' 'No SPF record: receivers cannot tell which servers may send for the domain.'
    }
    else {

        if ($spfRecords.Count -gt 1) {
            & $finding 'Fail' ('{0} SPF records are published: receivers treat that as an error (permerror). Merge them into one.' -f $spfRecords.Count)
        }

        $spf = ConvertFrom-TkSpfRecord -Text $spfText

        switch ($spf.All) {
            '+'     { & $finding 'Fail'    '+all allows every server in the world to send for the domain.' }
            '?'     { & $finding 'Warning' '?all says nothing about servers that are not listed.' }
            '~'     { & $finding 'Pass'    '~all marks unlisted servers as a soft fail, which is enough once DMARC is enforced.' }
            '-'     { & $finding 'Pass'    '-all rejects servers that are not listed.' }
            default {
                if (-not $spf.Redirect) {
                    & $finding 'Warning' 'The SPF record has no all term: servers that are not listed get a neutral result.'
                }
            }
        }

        if (@($spf.Terms | Where-Object { $_.Name -eq 'ptr' }).Count -gt 0) {
            & $finding 'Warning' 'ptr is deprecated and slow: replace it with ip4, ip6 or include.'
        }

        $measure = Measure-TkSpfLookup -Domain $name -Resolver $Resolver
        $lookups = $measure.Lookups

        if ($lookups -gt 10) {
            & $finding 'Fail' ('The SPF record needs {0} DNS lookups, over the limit of 10: receivers return permerror and SPF fails for every message.' -f $lookups)
        }
        else {
            & $finding 'Pass' ('The SPF record needs {0} of the 10 DNS lookups allowed.' -f $lookups)
        }

        foreach ($lookupError in @($measure.Errors | Where-Object { $_ -notlike ('{0} *' -f $name) })) {
            & $finding 'Warning' ('Through an include: {0}' -f $lookupError)
        }
    }

    # --- DMARC ------------------------------------------------------------
    $dmarcText = @(& $Resolver ('_dmarc.{0}' -f $name) 'TXT' | Where-Object { $_ -match '^v\s*=\s*DMARC1' }) | Select-Object -First 1
    $dmarc     = if ($dmarcText) { ConvertFrom-TkDmarcRecord -Text $dmarcText } else { $null }

    if (-not $dmarc) {
        & $finding 'Fail' ('No DMARC record at _dmarc.{0}: nothing tells receivers what to do with mail spoofing the domain, and Gmail and Yahoo require one from bulk senders.' -f $name)
    }
    else {
        switch ($dmarc.Policy) {
            'reject'     { & $finding 'Pass'    'DMARC policy reject: mail failing DMARC is refused.' }
            'quarantine' { & $finding 'Pass'    'DMARC policy quarantine: mail failing DMARC goes to spam.' }
            'none'       { & $finding 'Warning' 'DMARC policy none: reports only, and spoofed mail is still delivered. Move to quarantine once the reports show only legitimate senders.' }
            default      { & $finding 'Fail'    ('DMARC record without a valid policy (p={0}).' -f $dmarc.Policy) }
        }

        if ($dmarc.Percent -lt 100) {
            & $finding 'Warning' ('The DMARC policy applies to {0}% of failing messages only.' -f $dmarc.Percent)
        }

        if (-not $dmarc.Rua) {
            & $finding 'Info' 'No aggregate report address (rua): nobody sees which servers send as the domain.'
        }
    }

    # --- DKIM -------------------------------------------------------------
    $selectors = @($Selector | ForEach-Object { ([string] $_).Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[a-z0-9][a-z0-9._-]*$' } | Select-Object -Unique)

    if ($selectors.Count -eq 0) {
        $selectors = @('selector1', 'selector2', 'google', 'k1', 's1', 's2', 'default', 'dkim', 'mail')
    }

    $dkim = New-Object System.Collections.Generic.List[object]

    foreach ($selectorName in $selectors) {

        $text = @(& $Resolver ('{0}._domainkey.{1}' -f $selectorName, $name) 'TXT' | Where-Object { $_ -match '(^|;)\s*p\s*=' }) | Select-Object -First 1

        if ($text) {
            $dkim.Add([pscustomobject] @{ Selector = $selectorName; Record = (ConvertFrom-TkDkimRecord -Text $text) })
        }
    }

    if ($dkim.Count -eq 0) {
        & $finding 'Warning' ('No DKIM key under the selectors tried ({0}). The selector a message uses is the s= of its DKIM-Signature header.' -f ($selectors -join ', '))
    }

    foreach ($key in $dkim) {

        if ($key.Record.Revoked) {
            & $finding 'Info' ('DKIM selector {0} is revoked (empty key).' -f $key.Selector)
        }
        elseif ($key.Record.KeyType -eq 'rsa' -and $key.Record.KeyBits -gt 0 -and $key.Record.KeyBits -lt 1024) {
            & $finding 'Fail' ('DKIM selector {0} has a key of about {1} bits, too short to be trusted.' -f $key.Selector, $key.Record.KeyBits)
        }
        elseif ($key.Record.KeyType -eq 'rsa' -and $key.Record.KeyBits -eq 1024) {
            & $finding 'Warning' ('DKIM selector {0} has a 1024-bit key: 2048 bits is recommended.' -f $key.Selector)
        }
        else {
            & $finding 'Pass' ('DKIM selector {0} publishes a key.' -f $key.Selector)
        }
    }

    return [pscustomobject] @{
        Domain      = $name
        Mx          = $mx
        Spf         = $spfText
        SpfLookups  = $lookups
        Dmarc       = [string] $dmarcText
        DmarcRecord = $dmarc
        Dkim        = $dkim.ToArray()
        Findings    = $findings.ToArray()
    }
}

<#
.SYNOPSIS
    Writes a mail records check as lines of text.

.PARAMETER Report
    Output of Get-TkMailDnsReport.

.OUTPUTS
    System.String[]
#>
function Format-TkMailDnsReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Domain   {0}' -f $Report.Domain))
    $lines.Add('')

    if (@($Report.Mx).Count -gt 0) {
        $lines.Add(('MX       {0}' -f (@($Report.Mx) -join ([Environment]::NewLine + '         '))))
    }

    if ($Report.Spf) {
        $lines.Add(('SPF      {0}' -f $Report.Spf))
        $lines.Add(('         {0} DNS lookup(s) of the 10 allowed' -f $Report.SpfLookups))
    }

    if ($Report.Dmarc) {

        $lines.Add(('DMARC    {0}' -f $Report.Dmarc))

        if ($Report.DmarcRecord) {
            $lines.Add(('         policy {0}, subdomains {1}, {2}%{3}' -f $Report.DmarcRecord.Policy, $Report.DmarcRecord.SubdomainPolicy, $Report.DmarcRecord.Percent,
                $(if ($Report.DmarcRecord.Rua) { ', reports to ' + $Report.DmarcRecord.Rua } else { '' })))
        }
    }

    foreach ($key in @($Report.Dkim)) {

        $description = if ($key.Record.Revoked) { 'revoked' }
                       elseif ($key.Record.KeyType -eq 'rsa' -and $key.Record.KeyBits -gt 0) { 'RSA, about {0} bits' -f $key.Record.KeyBits }
                       else { $key.Record.KeyType }

        $lines.Add(('DKIM     {0}: {1}' -f $key.Selector, $description))
    }

    $lines.Add('')
    $lines.Add('Findings')

    $labels = @{ Pass = 'OK  '; Warning = 'WARN'; Fail = 'FAIL'; Info = 'INFO' }

    foreach ($item in @($Report.Findings | Sort-Object { @{ Fail = 0; Warning = 1; Info = 2; Pass = 3 }[$_.Severity] })) {
        $lines.Add(('  [{0}] {1}' -f $labels[$item.Severity], $item.Text))
    }

    return $lines.ToArray()
}
