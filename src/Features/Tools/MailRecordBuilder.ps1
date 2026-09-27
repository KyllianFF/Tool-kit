<#
    Toolkit - Features / SPF and DMARC record builders

    The Mail DNS tool reads the records a domain publishes; these write them.
    An SPF record is one line that is easy to break: a second record, a
    forgotten ~all, or the eleventh DNS lookup, past which receivers treat the
    whole record as an error. A DMARC record is a rollout: none with reports
    first, then quarantine, then reject. Both builders check what they write
    with the same parsers the reader uses.

    Nothing is published: the record is written out for the DNS host.
#>

<#
.SYNOPSIS
    The mail services whose SPF include is well known.

.OUTPUTS
    PSCustomObject[] with Name and Include.
#>
function Get-TkSpfService {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'Microsoft 365';      Include = 'spf.protection.outlook.com' }
        [pscustomobject] @{ Name = 'Google Workspace';   Include = '_spf.google.com' }
        [pscustomobject] @{ Name = 'Amazon SES';         Include = 'amazonses.com' }
        [pscustomobject] @{ Name = 'SendGrid';           Include = 'sendgrid.net' }
        [pscustomobject] @{ Name = 'Mailchimp';          Include = 'servers.mcsv.net' }
        [pscustomobject] @{ Name = 'Mailjet';            Include = 'spf.mailjet.com' }
        [pscustomobject] @{ Name = 'Brevo (Sendinblue)'; Include = 'spf.brevo.com' }
        [pscustomobject] @{ Name = 'Salesforce';         Include = '_spf.salesforce.com' }
        [pscustomobject] @{ Name = 'Zendesk';            Include = 'mail.zendesk.com' }
        [pscustomobject] @{ Name = 'OVHcloud';           Include = 'mx.ovh.com' }
    )
}

<#
.SYNOPSIS
    Says whether a text is a domain name.

.OUTPUTS
    System.Boolean
#>
function Test-TkMailDomainName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Name
    )

    return ($Name -match '^(?=.{3,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$')
}

<#
.SYNOPSIS
    Builds an SPF record and says what is wrong with it.

.DESCRIPTION
    Pure. The record is assembled in the order receivers read it best - the
    domain's own servers, then addresses, then includes, then all - and then
    read back with ConvertFrom-TkSpfRecord.

.PARAMETER Domain
    The domain the record is published on.

.PARAMETER UseMx
    The servers named in the domain's MX records send mail.

.PARAMETER UseA
    The address of the domain itself sends mail.

.PARAMETER Address
    IPv4 and IPv6 addresses or ranges that send mail, comma or line separated.

.PARAMETER Include
    Domains whose SPF record is included, comma or line separated.

.PARAMETER All
    What happens to every other sender: -all (fail), ~all (soft fail) or ?all (neutral).

.OUTPUTS
    PSCustomObject with Name, Record, Lookups, Errors, Warnings and Notes.
#>
function New-TkSpfRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Domain = '',
        [Parameter()] [switch] $UseMx,
        [Parameter()] [switch] $UseA,
        [Parameter()] [AllowEmptyString()] [string] $Address = '',
        [Parameter()] [AllowEmptyString()] [string] $Include = '',
        [Parameter()] [ValidateSet('-all', '~all', '?all')] [string] $All = '-all'
    )

    $errors   = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $notes    = New-Object System.Collections.Generic.List[string]
    $terms    = New-Object System.Collections.Generic.List[string]

    $domain = $Domain.Trim().TrimEnd('.').ToLowerInvariant()

    if (-not $domain) {
        $errors.Add('Type the domain the record is for, such as contoso.com.')
    }
    elseif (-not (Test-TkMailDomainName -Name $domain)) {
        $errors.Add(('"{0}" is not a domain name.' -f $domain))
    }

    if ($UseMx) { $terms.Add('mx') }
    if ($UseA)  { $terms.Add('a') }

    foreach ($item in @($Address -split '[,;\s]+' | Where-Object { $_ } | Select-Object -Unique)) {

        $ip     = $null
        $parts  = $item -split '/', 2
        $prefix = if ($parts.Count -eq 2) { $parts[1] } else { '' }

        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref] $ip) -or ($parts[0] -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and -not $parts[0].Contains(':'))) {
            $errors.Add(('"{0}" is not an IP address or range.' -f $item))
            continue
        }

        $v6  = $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
        $max = if ($v6) { 128 } else { 32 }

        if ($prefix -and ($prefix -notmatch '^\d{1,3}$' -or [int] $prefix -gt $max)) {
            $errors.Add(('"{0}" has a prefix length that does not fit.' -f $item))
            continue
        }

        if ($prefix -and ((-not $v6 -and [int] $prefix -lt 16) -or ($v6 -and [int] $prefix -lt 32))) {
            $warnings.Add(('{0} lets a very large range send as this domain. Name the sending servers, not a whole network.' -f $item))
        }

        $terms.Add(('{0}:{1}' -f $(if ($v6) { 'ip6' } else { 'ip4' }), $item))
    }

    foreach ($item in @($Include -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_ -replace '^include:', '' } | Select-Object -Unique)) {
        if (-not (Test-TkMailDomainName -Name $item)) {
            $errors.Add(('"{0}" is not a domain to include.' -f $item))
            continue
        }
        $terms.Add(('include:{0}' -f $item.ToLowerInvariant()))
    }

    if ($terms.Count -eq 0) {
        $notes.Add('No sender is named: "v=spf1 -all" says this domain sends no mail at all, which is right for a domain that never sends.')
    }

    $record = ((@('v=spf1') + @($terms.ToArray()) + $All) -join ' ')
    $parsed = ConvertFrom-TkSpfRecord -Text $record

    if ($parsed.LocalLookups -gt 10) {
        $errors.Add(('The record itself needs {0} DNS lookups; receivers stop at 10 and treat the record as an error. Replace includes with the addresses they stand for, or drop unused services.' -f $parsed.LocalLookups))
    }
    elseif ($parsed.LocalLookups -gt 0) {
        $notes.Add(('{0} lookup(s) in the record itself, and each include costs what its own record costs: receivers stop at 10 in all. "Count through the includes" asks DNS for the real total.' -f $parsed.LocalLookups))
    }

    switch ($All) {
        '~all' { $notes.Add('~all marks other senders as suspicious without failing them: right while checking that every service is listed, then move to -all.') }
        '?all' { $warnings.Add('?all says nothing about other senders, so the record protects nothing. Use ~all while testing, then -all.') }
    }

    if ($record.Length -gt 255) {
        $notes.Add(('The record is {0} characters: DNS carries it as several strings of 255 at most. Most DNS hosts split it by themselves; some need it pasted as separate quoted strings.' -f $record.Length))
    }

    $notes.Add('Publish one SPF record per domain: two v=spf1 records make receivers treat both as an error. Merge this one into any record already there.')

    return [pscustomobject] @{
        Name     = $domain
        Record   = $(if ($errors.Count -eq 0) { $record } else { '' })
        Lookups  = $parsed.LocalLookups
        Includes = @($parsed.Includes)
        Errors   = @($errors.ToArray())
        Warnings = @($warnings.ToArray())
        Notes    = @($notes.ToArray())
    }
}

<#
.SYNOPSIS
    Counts the DNS lookups a draft SPF record would need, through its includes.

.DESCRIPTION
    The record is not published yet, so it cannot be looked up by name: its
    own lookups are counted from the text, and each include is measured
    through DNS with Measure-TkSpfLookup.

.PARAMETER Record
    The draft record.

.PARAMETER Resolver
    A script block taking a name and a type and returning texts.

.OUTPUTS
    PSCustomObject with Lookups, PerInclude (Name, Lookups) and Errors.
#>
function Measure-TkSpfDraftLookup {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Record,
        [Parameter(Mandatory)] [scriptblock] $Resolver
    )

    $parsed  = ConvertFrom-TkSpfRecord -Text $Record
    $total   = $parsed.LocalLookups
    $each    = New-Object System.Collections.Generic.List[object]
    $errors  = New-Object System.Collections.Generic.List[string]

    foreach ($target in @(@($parsed.Includes) + @($parsed.Redirect) | Where-Object { $_ })) {

        $child  = Measure-TkSpfLookup -Domain $target -Resolver $Resolver
        $total += $child.Lookups

        $each.Add([pscustomobject] @{ Name = $target; Lookups = 1 + $child.Lookups })
        foreach ($problem in $child.Errors) { $errors.Add($problem) }
    }

    return [pscustomobject] @{ Lookups = $total; PerInclude = @($each.ToArray()); Errors = @($errors.ToArray()) }
}

<#
.SYNOPSIS
    Builds a DMARC record and says what to watch.

.PARAMETER Domain
    The domain; the record is published on _dmarc.<domain>.

.PARAMETER Policy
    none, quarantine or reject.

.PARAMETER SubdomainPolicy
    The same as the policy when empty; otherwise none, quarantine or reject.

.PARAMETER Percent
    The share of failing mail the policy applies to, 1 to 100.

.PARAMETER AggregateReport
    Addresses for the daily aggregate reports (rua), comma separated.

.PARAMETER FailureReport
    Addresses for per-message failure reports (ruf), comma separated.

.PARAMETER StrictDkim
    DKIM alignment strict (adkim=s) rather than relaxed.

.PARAMETER StrictSpf
    SPF alignment strict (aspf=s) rather than relaxed.

.OUTPUTS
    PSCustomObject with Name, Record, Errors, Warnings and Notes.
#>
function New-TkDmarcRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Domain = '',
        [Parameter()] [ValidateSet('none', 'quarantine', 'reject')] [string] $Policy = 'none',
        [Parameter()] [ValidateSet('', 'none', 'quarantine', 'reject')] [string] $SubdomainPolicy = '',
        [Parameter()] [int] $Percent = 100,
        [Parameter()] [AllowEmptyString()] [string] $AggregateReport = '',
        [Parameter()] [AllowEmptyString()] [string] $FailureReport = '',
        [Parameter()] [switch] $StrictDkim,
        [Parameter()] [switch] $StrictSpf
    )

    $errors   = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $notes    = New-Object System.Collections.Generic.List[string]

    $domain = $Domain.Trim().TrimEnd('.').ToLowerInvariant()

    if (-not $domain) {
        $errors.Add('Type the domain the record is for, such as contoso.com.')
    }
    elseif (-not (Test-TkMailDomainName -Name $domain)) {
        $errors.Add(('"{0}" is not a domain name.' -f $domain))
    }

    if ($Percent -lt 1 -or $Percent -gt 100) {
        $errors.Add('The percentage goes from 1 to 100.')
    }

    $mailto = {
        param($text, $tag)
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($address in @($text -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_ -replace '^mailto:', '' })) {
            if ($address -notmatch '^[^@\s]+@(?<host>[^@\s]+)$' -or -not (Test-TkMailDomainName -Name $Matches['host'])) {
                $errors.Add(('"{0}" is not an e-mail address for {1}.' -f $address, $tag))
                continue
            }
            $reportDomain = $Matches['host'].ToLowerInvariant()
            if ($domain -and $reportDomain -ne $domain -and -not $reportDomain.EndsWith('.' + $domain)) {
                $notes.Add(('{0} is outside {1}: {2} must publish {1}._report._dmarc.{2} (TXT "v=DMARC1") to accept those reports, or they are not sent.' -f $address, $domain, $reportDomain))
            }
            $list.Add(('mailto:{0}' -f $address))
        }
        return , @($list.ToArray())
    }

    $rua = & $mailto $AggregateReport 'rua'
    $ruf = & $mailto $FailureReport 'ruf'

    $tags = New-Object System.Collections.Generic.List[string]
    $tags.Add('v=DMARC1')
    $tags.Add(('p={0}' -f $Policy))
    if ($SubdomainPolicy -and $SubdomainPolicy -ne $Policy) { $tags.Add(('sp={0}' -f $SubdomainPolicy)) }
    if ($Percent -lt 100 -and $Percent -ge 1) { $tags.Add(('pct={0}' -f $Percent)) }
    if ($rua.Count -gt 0) { $tags.Add(('rua={0}' -f ($rua -join ','))) }
    if ($ruf.Count -gt 0) { $tags.Add(('ruf={0}' -f ($ruf -join ','))); $tags.Add('fo=1') }
    if ($StrictDkim) { $tags.Add('adkim=s') }
    if ($StrictSpf)  { $tags.Add('aspf=s') }

    $record = $tags -join '; '
    $parsed = ConvertFrom-TkDmarcRecord -Text $record

    if (-not $parsed.Valid -or $parsed.Policy -ne $Policy) {
        $errors.Add('The record did not read back as DMARC; this is a bug in the builder.')
    }

    switch ($Policy) {
        'none' {
            if ($rua.Count -eq 0) { $warnings.Add('p=none without rua only watches, and nobody sees what it watches: add an address for the aggregate reports.') }
            else { $notes.Add('p=none is the first step: read the reports for a few weeks, fix the senders that fail, then move to quarantine.') }
        }
        'quarantine' { $notes.Add('Failing mail goes to spam. Once the reports show only legitimate mail passing, move to reject.') }
        'reject'     {
            $notes.Add('Failing mail is refused. Make sure every service that sends as this domain passes SPF or DKIM, aligned, before publishing.')
            if ($rua.Count -eq 0) { $warnings.Add('p=reject without rua: mail from a service you forgot is refused and nothing tells you. Keep an aggregate report address.') }
        }
    }

    if ($SubdomainPolicy -eq 'none' -and $Policy -ne 'none') {
        $warnings.Add('sp=none leaves every subdomain open to spoofing while the domain itself is protected.')
    }

    if ($Percent -lt 100) {
        $notes.Add(('pct={0} applies the policy to that share of failing mail only, a way to ramp up; the rest is treated one step lower.' -f $Percent))
    }

    if ($ruf.Count -gt 0) {
        $notes.Add('Failure reports (ruf) can carry parts of real messages, and most large receivers do not send them. Aggregate reports are what matter.')
    }

    return [pscustomobject] @{
        Name     = $(if ($domain) { '_dmarc.{0}' -f $domain } else { '' })
        Record   = $(if ($errors.Count -eq 0) { $record } else { '' })
        Errors   = @($errors.ToArray())
        Warnings = @($warnings.ToArray())
        Notes    = @($notes.ToArray())
    }
}

<#
.SYNOPSIS
    Lays out a built record for the panel.

.PARAMETER Built
    From New-TkSpfRecord or New-TkDmarcRecord.

.OUTPUTS
    System.String
#>
function Format-TkMailRecord {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Built
    )

    $lines = New-Object System.Collections.Generic.List[string]

    if (@($Built.Errors).Count -gt 0) {
        foreach ($problem in $Built.Errors) { $lines.Add(('Fix first: {0}' -f $problem)) }
        return ($lines -join [Environment]::NewLine)
    }

    $lines.Add('Publish as a TXT record:')
    $lines.Add(('  Name   {0}' -f $Built.Name))
    $lines.Add(('  Value  {0}' -f $Built.Record))
    $lines.Add('')

    foreach ($warning in @($Built.Warnings)) { $lines.Add(('Warning: {0}' -f $warning)) }
    foreach ($note in @($Built.Notes))       { $lines.Add(('Note: {0}' -f $note)) }

    return ($lines -join [Environment]::NewLine)
}
