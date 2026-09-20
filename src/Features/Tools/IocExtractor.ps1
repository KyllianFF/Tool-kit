<#
    Toolkit - Features / Indicator extractor and defanger

    The other half of reading a phishing e-mail or a threat report: pulling the
    indicators out of the prose around them, and making them safe to write into
    a ticket. It extracts IP addresses, domains, URLs, e-mail addresses, file
    hashes and CVE numbers from a pasted blob, refanging the defanged ones first
    so hxxp://1.2.3[.]4 is found; and it defangs a text the other way, so a live
    link is not left clickable where a colleague will open it by reflex.

    Everything is read as text on the machine. Nothing is fetched or looked up;
    for a reputation check, the indicator goes to the VirusTotal tool, which says
    when it leaves.
#>

<#
.SYNOPSIS
    Turns defanged indicators back into their real form.

.DESCRIPTION
    The notations analysts use to make an indicator unclickable, reversed so the
    extractor's patterns match: hxxp back to http, a bracketed or parenthesised
    dot back to a dot, and the spelled-out at and colon back to their character.

.OUTPUTS
    System.String
#>
function ConvertTo-TkRefanged {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    return $Text `
        -replace '(?i)h(?:xx|\[x\]|x)p', 'http' `
        -replace '(?i)\[?\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)', '.' `
        -replace '(?i)\[at\]|\(at\)|\[@\]', '@' `
        -replace '\[:\]', ':' `
        -replace '\[//\]', '//' `
        -replace '\[://\]', '://'
}

<#
.SYNOPSIS
    The known file extensions to keep out of the domain list.
#>
function Get-TkNonDomainExtension {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'js', 'jse', 'jar',
        'msi', 'scr', 'lnk', 'hta', 'doc', 'docx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx',
        'pdf', 'rtf', 'txt', 'log', 'csv', 'xml', 'json', 'html', 'htm', 'php', 'asp',
        'aspx', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'ico', 'zip', 'rar', '7z',
        'tar', 'gz', 'iso', 'img', 'md', 'ini', 'conf', 'cfg', 'yml', 'yaml', 'dat',
        'tmp', 'bak', 'dmp', 'reg', 'sh', 'py', 'pl', 'rb', 'go', 'ts', 'css', 'sql'
    )
}

<#
.SYNOPSIS
    Extracts the indicators of compromise from a text.

.PARAMETER Text
    The blob to read.

.OUTPUTS
    PSCustomObject with a sorted, de-duplicated list per indicator kind.
#>
function Get-TkIocFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $refanged = ConvertTo-TkRefanged -Text $Text

    $unique = {
        param($collection)
        @($collection | ForEach-Object { $_.Value } | Where-Object { $_ } | Sort-Object -Unique)
    }

    # URLs and e-mails first; their host is not counted again as a bare domain.
    $urlRx   = 'https?://[^\s"''<>\)\]]+'
    $emailRx = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
    $ipRx    = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    $cveRx   = '(?i)CVE-\d{4}-\d{4,7}'

    # A URL match swallows the sentence punctuation after it; trim the common
    # trailing marks back off.
    $urls   = @(& $unique ([regex]::Matches($refanged, $urlRx)) | ForEach-Object { $_.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']') } | Sort-Object -Unique)
    $emails = & $unique ([regex]::Matches($refanged, $emailRx))
    $ips    = & $unique ([regex]::Matches($refanged, $ipRx))
    $cves   = @([regex]::Matches($refanged, $cveRx) | ForEach-Object { $_.Value.ToUpperInvariant() } | Sort-Object -Unique)

    # Hashes, longest first so a SHA-256 is not also read as shorter runs.
    $sha256 = & $unique ([regex]::Matches($refanged, '\b[a-fA-F0-9]{64}\b'))
    $sha1   = & $unique ([regex]::Matches($refanged, '\b[a-fA-F0-9]{40}\b'))
    $md5    = & $unique ([regex]::Matches($refanged, '\b[a-fA-F0-9]{32}\b'))

    # Domains from what is left once URLs and e-mails are blanked out, so their
    # host is not counted a second time as a bare domain.
    $working = $refanged
    $working = [regex]::Replace($working, $urlRx,   { param($m) ' ' * $m.Value.Length })
    $working = [regex]::Replace($working, $emailRx, { param($m) ' ' * $m.Value.Length })

    $extensions = Get-TkNonDomainExtension
    $domainRx   = '\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    $domains = @([regex]::Matches($working, $domainRx) |
                 ForEach-Object { $_.Value } |
                 Where-Object { $_ -notmatch $ipRx } |
                 Where-Object { $extensions -notcontains (($_ -split '\.')[-1]).ToLowerInvariant() } |
                 Sort-Object -Unique)

    return [pscustomobject] @{
        Urls    = $urls
        Domains = $domains
        IPv4    = $ips
        Emails  = $emails
        Md5     = $md5
        Sha1    = $sha1
        Sha256  = $sha256
        Cve     = $cves
    }
}

<#
.SYNOPSIS
    Defangs the indicators in a text, so none is left clickable.

.DESCRIPTION
    Rewrites each e-mail, URL, IP address and domain in place: http becomes hxxp,
    the at sign becomes [at], and every dot becomes [.]. The prose around them is
    untouched, and a file name that only looks like a domain is left alone.

.OUTPUTS
    System.String
#>
function ConvertTo-TkDefanged {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $extensions = Get-TkNonDomainExtension

    $dotAndAt = {
        param($token)
        $token.Replace('@', '[at]').Replace('.', '[.]')
    }

    # E-mails first, then URLs, then bare IPs and domains: once a token's dots
    # are bracketed the later patterns no longer see it, so nothing is done twice.
    $result = [regex]::Replace($Text, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', { param($m) & $dotAndAt $m.Value })

    $result = [regex]::Replace($result, 'https?://[^\s"''<>\)\]]+', {
        param($m)
        ($m.Value -replace '(?i)^http', 'hxxp').Replace('.', '[.]')
    })

    $result = [regex]::Replace($result, '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', {
        param($m) $m.Value.Replace('.', '[.]')
    })

    $result = [regex]::Replace($result, '\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', {
        param($m)
        $last = (($m.Value -split '\.')[-1]).ToLowerInvariant()
        if ($extensions -contains $last) { $m.Value } else { $m.Value.Replace('.', '[.]') }
    })

    return $result
}

<#
.SYNOPSIS
    Writes the extracted indicators as lines of text.

.OUTPUTS
    System.String[]
#>
function Format-TkIocReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste an e-mail, a report or a log to pull the indicators out of it.')
    }

    $finding = Get-TkIocFinding -Text $Text
    $lines   = New-Object System.Collections.Generic.List[string]

    $section = {
        param($title, $items)
        $items = @($items | Where-Object { $_ })
        if ($items.Count -gt 0) {
            $lines.Add(('{0} ({1}):' -f $title, $items.Count))
            foreach ($item in $items) { $lines.Add('  ' + $item) }
            $lines.Add('')
        }
    }

    & $section 'URLs'          $finding.Urls
    & $section 'Domains'       $finding.Domains
    & $section 'IPv4'          $finding.IPv4
    & $section 'E-mail'        $finding.Emails
    & $section 'MD5'           $finding.Md5
    & $section 'SHA-1'         $finding.Sha1
    & $section 'SHA-256'       $finding.Sha256
    & $section 'CVE'           $finding.Cve

    if ($lines.Count -eq 0) {
        return @('No indicators found. The text holds no IP, domain, URL, e-mail, hash or CVE that could be read.')
    }

    return $lines.ToArray()
}
