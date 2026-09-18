<#
    Toolkit - Features / Tools / HTTP security headers

    Paste the response headers of a site and read what its security headers do
    and do not cover: HSTS, the content security policy, framing, sniffing,
    referrer and permissions policy, the cross-origin isolation headers, and the
    flags on its cookies. Nothing is fetched; the headers are read as pasted, the
    same as the e-mail header tool.
#>

<#
.SYNOPSIS
    Splits pasted HTTP response headers into name and value pairs.

.DESCRIPTION
    Skips the status line (HTTP/1.1 200 OK). Header names are case-insensitive,
    so they are kept as written but compared in lower case by the reader. A
    header that appears more than once, such as Set-Cookie, is kept once per
    occurrence.

.PARAMETER Text
    The headers, as copied from the browser tools or curl -I.

.OUTPUTS
    PSCustomObject[] with Name and Value.
#>
function ConvertFrom-TkHttpHeaderText {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $headers = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($rawLine in ($Text -split "`r?`n")) {

        $line = $rawLine.Trim()
        if (-not $line) { continue }

        # The status line has no colon before the first space.
        if ($line -match '^HTTP/\d') { continue }

        $split = $line.IndexOf(':')
        if ($split -lt 1) { continue }

        $name  = $line.Substring(0, $split).Trim()
        $value = $line.Substring($split + 1).Trim()

        if ($name -match '^[A-Za-z0-9-]+$') {
            $headers.Add([pscustomobject] @{ Name = $name; Value = $value })
        }
    }

    return @($headers)
}

<#
.SYNOPSIS
    Grades the security headers of a pasted response.

.DESCRIPTION
    Reads the headers, then judges the ones that matter for a browser's
    defences. A missing header is usually a warning, a present but weak one a
    warning with the weakness named, and a header that gives the server away is
    flagged as information disclosure. Each cookie is checked for its Secure,
    HttpOnly and SameSite flags.

.PARAMETER Text
    The response headers.

.OUTPUTS
    PSCustomObject with Headers, Findings and Counts.
#>
function Get-TkHttpHeaderReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $headers = @(ConvertFrom-TkHttpHeaderText -Text $Text)

    # A case-insensitive lookup of the first value of each header.
    $lookup = @{}
    foreach ($header in $headers) {
        $key = $header.Name.ToLowerInvariant()
        if (-not $lookup.ContainsKey($key)) { $lookup[$key] = $header.Value }
    }

    $findings = New-Object System.Collections.Generic.List[pscustomobject]
    $add = {
        param($severity, $header, $detail, $note)
        $findings.Add([pscustomobject] @{ Severity = $severity; Header = $header; Detail = $detail; Note = $note })
    }

    # --- Strict-Transport-Security ---------------------------------------
    if ($lookup.ContainsKey('strict-transport-security')) {
        $hsts    = $lookup['strict-transport-security']
        $maxAge  = if ($hsts -match 'max-age=(\d+)') { [long] $Matches[1] } else { 0 }
        $subDom  = $hsts -match 'includeSubDomains'
        if ($maxAge -lt 15768000) {
            & $add 'Warning' 'Strict-Transport-Security' $hsts 'HSTS is set but max-age is under six months; browsers forget it sooner than recommended.'
        }
        elseif (-not $subDom) {
            & $add 'Warning' 'Strict-Transport-Security' $hsts 'HSTS is strong but does not cover subdomains (add includeSubDomains).'
        }
        else {
            & $add 'Pass' 'Strict-Transport-Security' $hsts 'HTTPS is enforced for at least six months, subdomains included.'
        }
    }
    else {
        & $add 'Fail' 'Strict-Transport-Security' 'missing' 'No HSTS: a first request can be downgraded to HTTP and intercepted.'
    }

    # --- Content-Security-Policy -----------------------------------------
    if ($lookup.ContainsKey('content-security-policy')) {
        $csp = $lookup['content-security-policy']
        $weak = @()
        if ($csp -match "'unsafe-inline'") { $weak += "'unsafe-inline'" }
        if ($csp -match "'unsafe-eval'")   { $weak += "'unsafe-eval'" }
        if ($weak.Count -gt 0) {
            & $add 'Warning' 'Content-Security-Policy' $csp ('A policy is set but weakened by {0}, which lets injected script run.' -f ($weak -join ' and '))
        }
        else {
            & $add 'Pass' 'Content-Security-Policy' $csp 'A content security policy is set, the main defence against cross-site scripting.'
        }
    }
    else {
        & $add 'Warning' 'Content-Security-Policy' 'missing' 'No CSP: nothing restricts where script, styles and frames may load from.'
    }

    # --- X-Content-Type-Options ------------------------------------------
    if ($lookup.ContainsKey('x-content-type-options') -and $lookup['x-content-type-options'] -match 'nosniff') {
        & $add 'Pass' 'X-Content-Type-Options' $lookup['x-content-type-options'] 'The browser will not second-guess a declared content type.'
    }
    else {
        & $add 'Warning' 'X-Content-Type-Options' 'missing' 'Without nosniff the browser may treat a file as a type it was not sent as.'
    }

    # --- Framing (X-Frame-Options or CSP frame-ancestors) ----------------
    $framed = $lookup.ContainsKey('x-frame-options') -or
              ($lookup.ContainsKey('content-security-policy') -and $lookup['content-security-policy'] -match 'frame-ancestors')
    if ($framed) {
        $detail = if ($lookup.ContainsKey('x-frame-options')) { $lookup['x-frame-options'] } else { 'frame-ancestors in CSP' }
        & $add 'Pass' 'Framing' $detail 'The page cannot be framed by another site, so clickjacking is blocked.'
    }
    else {
        & $add 'Warning' 'Framing' 'missing' 'Neither X-Frame-Options nor CSP frame-ancestors: the page can be framed for clickjacking.'
    }

    # --- Referrer-Policy and Permissions-Policy --------------------------
    foreach ($optional in @(
        @{ Key = 'referrer-policy';    Name = 'Referrer-Policy';    Note = 'Controls how much of the URL is sent to other sites.' }
        @{ Key = 'permissions-policy'; Name = 'Permissions-Policy'; Note = 'Controls access to camera, microphone, geolocation and the rest.' }
    )) {
        if ($lookup.ContainsKey($optional.Key)) {
            & $add 'Pass' $optional.Name $lookup[$optional.Key] $optional.Note
        }
        else {
            & $add 'Info' $optional.Name 'missing' ('Not set. {0}' -f $optional.Note)
        }
    }

    # --- Information disclosure -------------------------------------------
    foreach ($leak in @('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version')) {
        if ($lookup.ContainsKey($leak) -and $lookup[$leak]) {
            $displayName = ($headers | Where-Object { $_.Name.ToLowerInvariant() -eq $leak } | Select-Object -First 1).Name
            & $add 'Info' $displayName $lookup[$leak] 'Names the software and often its version, which helps an attacker pick an exploit.'
        }
    }

    # --- Cookies ----------------------------------------------------------
    foreach ($cookie in @($headers | Where-Object { $_.Name.ToLowerInvariant() -eq 'set-cookie' })) {
        $cookieName = if ($cookie.Value -match '^([^=]+)=') { $Matches[1].Trim() } else { 'cookie' }
        $missing = @()
        if ($cookie.Value -notmatch '(?i)\bSecure\b')   { $missing += 'Secure' }
        if ($cookie.Value -notmatch '(?i)\bHttpOnly\b') { $missing += 'HttpOnly' }
        if ($cookie.Value -notmatch '(?i)SameSite=')    { $missing += 'SameSite' }
        if ($missing.Count -gt 0) {
            & $add 'Warning' ('Set-Cookie ({0})' -f $cookieName) $cookie.Value ('Missing {0}.' -f ($missing -join ', '))
        }
        else {
            & $add 'Pass' ('Set-Cookie ({0})' -f $cookieName) $cookie.Value 'Secure, HttpOnly and SameSite are all set.'
        }
    }

    $counts = [pscustomobject] @{
        Fail    = @($findings | Where-Object { $_.Severity -eq 'Fail' }).Count
        Warning = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count
        Pass    = @($findings | Where-Object { $_.Severity -eq 'Pass' }).Count
    }

    return [pscustomobject] @{
        Headers  = $headers
        Findings = @($findings)
        Counts   = $counts
    }
}

<#
.SYNOPSIS
    Lays out an HTTP header report for the panel.

.OUTPUTS
    System.String[]
#>
function Format-TkHttpHeaderReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $c = $Report.Counts
    $lines.Add(('{0} header(s) read: {1} good, {2} to review, {3} missing or weak.' -f @($Report.Headers).Count, $c.Pass, $c.Warning, $c.Fail))
    $lines.Add('')

    $mark = @{ Pass = '[ ok ]'; Warning = '[warn]'; Fail = '[fail]'; Info = '[info]' }

    foreach ($finding in $Report.Findings) {
        $lines.Add(('{0} {1}' -f $mark[$finding.Severity], $finding.Header))
        $lines.Add(('        {0}' -f $finding.Note))
    }

    return $lines.ToArray()
}
