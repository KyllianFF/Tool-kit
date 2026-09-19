<#
    Toolkit - Features / Connection string parser

    A database connection string is a line of key=value pairs that hides a few
    things worth seeing: which server and database it points at, whether the
    password travels in the clear, and whether the transport is encrypted and
    the server's certificate actually checked. This takes one apart, names the
    driver it is for, masks the password, and says where it is weak.

    The parsing follows the ADO.NET and ODBC rules: keys are case-insensitive,
    a value may be wrapped in single or double quotes or, for ODBC, in braces,
    and the quote or brace is doubled to include it. Nothing is connected to;
    the string is read as text.
#>

<#
.SYNOPSIS
    Splits a connection string into its key and value pairs.

.DESCRIPTION
    A single pass that respects the three ways a value may be quoted, so a
    password or a path that contains a semicolon is not cut in half. Keys keep
    their spelling; the caller lowercases them to compare.

.PARAMETER Text
    The connection string.

.OUTPUTS
    PSCustomObject[] with Key and Value.
#>
function ConvertFrom-TkConnectionString {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $pairs = New-Object System.Collections.Generic.List[pscustomobject]
    $i     = 0
    $n     = $Text.Length

    while ($i -lt $n) {

        # Skip separators and leading space.
        while ($i -lt $n -and (@(' ', ';', "`t", "`r", "`n") -contains $Text[$i])) { $i++ }
        if ($i -ge $n) { break }

        # Key runs up to the first '='.
        $keyStart = $i
        while ($i -lt $n -and $Text[$i] -ne '=') { $i++ }

        $key = $Text.Substring($keyStart, $i - $keyStart).Trim()
        if ($i -lt $n) { $i++ }   # step over '='

        while ($i -lt $n -and (@(' ', "`t") -contains $Text[$i])) { $i++ }

        $value   = New-Object System.Text.StringBuilder
        $quoted  = $false

        if ($i -lt $n -and $Text[$i] -eq '{') {

            $quoted = $true
            $i++
            while ($i -lt $n) {
                if ($Text[$i] -eq '}') {
                    if (($i + 1) -lt $n -and $Text[$i + 1] -eq '}') { [void] $value.Append('}'); $i += 2; continue }
                    $i++; break
                }
                [void] $value.Append($Text[$i]); $i++
            }
        }
        elseif ($i -lt $n -and (@('"', "'") -contains $Text[$i])) {

            $quoted = $true
            $quote  = $Text[$i]
            $i++
            while ($i -lt $n) {
                if ($Text[$i] -eq $quote) {
                    if (($i + 1) -lt $n -and $Text[$i + 1] -eq $quote) { [void] $value.Append($quote); $i += 2; continue }
                    $i++; break
                }
                [void] $value.Append($Text[$i]); $i++
            }
        }
        else {
            $valueStart = $i
            while ($i -lt $n -and $Text[$i] -ne ';') { $i++ }
            [void] $value.Append($Text.Substring($valueStart, $i - $valueStart).Trim())
        }

        # Anything after a quoted value up to the separator is ignored.
        while ($i -lt $n -and $Text[$i] -ne ';') { $i++ }
        if ($i -lt $n) { $i++ }

        if ($key) {
            $pairs.Add([pscustomobject] @{ Key = $key; Value = $value.ToString(); Quoted = $quoted })
        }
    }

    return @($pairs)
}

<#
.SYNOPSIS
    Names the kind of connection string from the keys it uses.

.OUTPUTS
    System.String
#>
function Get-TkConnectionStringKind {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Lookup
    )

    if ($Lookup.Contains('driver'))   { return 'ODBC' }
    if ($Lookup.Contains('provider')) { return 'OLE DB' }

    if ($Lookup.Contains('trustservercertificate') -or $Lookup.Contains('integrated security') -or
        $Lookup.Contains('initial catalog') -or $Lookup.Contains('multipleactiveresultsets') -or
        $Lookup.Contains('encrypt')) {
        return 'SQL Server'
    }

    if ($Lookup.Contains('host') -or $Lookup.Contains('ssl mode')) { return 'PostgreSQL' }
    if ($Lookup.Contains('sslmode') -or $Lookup.Contains('uid'))   { return 'MySQL or MariaDB' }

    return 'Generic'
}

<#
.SYNOPSIS
    Parses a connection string and judges what it exposes.

.DESCRIPTION
    Returns the kind, the pairs as written, the fields normalised to canonical
    names, and the findings: where a password rides in the clear, where the
    transport is unencrypted, and where a server certificate is trusted without
    being checked.

.PARAMETER Text
    The connection string.

.OUTPUTS
    PSCustomObject with Kind, Pairs, Field and Finding.
#>
function Get-TkConnectionStringReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $pairs  = @(ConvertFrom-TkConnectionString -Text $Text)
    $lookup = @{}
    foreach ($pair in $pairs) {
        $key = $pair.Key.ToLowerInvariant()
        if (-not $lookup.Contains($key)) { $lookup[$key] = $pair.Value }
    }

    # Canonical field to the keys that name it, richest first.
    $synonyms = [ordered] @{
        Server   = @('server', 'data source', 'datasource', 'address', 'addr', 'network address', 'host', 'hostname')
        Port     = @('port')
        Database = @('database', 'initial catalog')
        User     = @('user id', 'uid', 'user', 'username', 'user name')
        Password = @('password', 'pwd')
        Provider = @('provider')
        Driver   = @('driver')
    }

    $field = [ordered] @{}
    foreach ($name in $synonyms.Keys) {
        foreach ($key in $synonyms[$name]) {
            if ($lookup.Contains($key)) { $field[$name] = $lookup[$key]; break }
        }
    }

    $kind     = Get-TkConnectionStringKind -Lookup $lookup
    $findings = New-Object System.Collections.Generic.List[pscustomobject]

    $add = {
        param($severity, $text)
        $findings.Add([pscustomobject] @{ Severity = $severity; Text = $text })
    }

    $integrated = $false
    foreach ($key in @('integrated security', 'trusted_connection')) {
        if ($lookup.Contains($key) -and (@('true', 'sspi', 'yes') -contains ([string] $lookup[$key]).ToLowerInvariant())) {
            $integrated = $true
        }
    }

    if ($integrated) {
        & $add 'Info' 'Windows integrated authentication: the string carries no password.'
    }
    elseif ($field.Contains('Password') -and $field['Password']) {
        & $add 'Warning' 'The password is stored in clear in the string. Keep it out of source control, logs and tickets; prefer integrated authentication or a secret store.'
    }

    # Transport, per family.
    if ($kind -eq 'SQL Server') {

        if ($lookup.Contains('encrypt')) {
            $encrypt = ([string] $lookup['encrypt']).ToLowerInvariant()
            if (@('false', 'no', '0') -contains $encrypt) {
                & $add 'Warning' 'Encrypt is off: the connection, and the credentials on it, may cross the network in clear.'
            }
        }
        else {
            & $add 'Info' 'Encrypt is not set. Older drivers default it off; set Encrypt=true to be sure the connection is protected.'
        }

        if ($lookup.Contains('trustservercertificate') -and (@('true', 'yes', '1') -contains ([string] $lookup['trustservercertificate']).ToLowerInvariant())) {
            & $add 'Warning' 'TrustServerCertificate is on: encryption is used but the server certificate is not checked, so a machine in the middle can impersonate the server.'
        }
    }
    elseif ($kind -eq 'PostgreSQL' -and $lookup.Contains('ssl mode')) {

        $mode = ([string] $lookup['ssl mode']).ToLowerInvariant()
        if (@('disable', 'allow', 'prefer') -contains $mode) {
            & $add 'Warning' ('SSL Mode is "{0}": the connection may be unencrypted. Use verify-full to encrypt and check the certificate.' -f $mode)
        }
        elseif ($mode -eq 'require') {
            & $add 'Info' 'SSL Mode is "require": encrypted, but the server certificate is not verified. verify-full also checks it.'
        }
    }
    elseif ($kind -eq 'MySQL or MariaDB' -and $lookup.Contains('sslmode')) {

        $mode = ([string] $lookup['sslmode']).ToLowerInvariant()
        if (@('none', 'disabled') -contains $mode) {
            & $add 'Warning' 'SslMode is off: the connection may be unencrypted.'
        }
    }

    if ($findings.Count -eq 0 -or -not (@($findings | Where-Object { $_.Severity -eq 'Warning' }))) {
        & $add 'Pass' 'Nothing stood out. Check the transport is encrypted for anything that leaves the machine.'
    }

    return [pscustomobject] @{
        Kind    = $kind
        Pairs   = $pairs
        Field   = $field
        Finding = @($findings)
    }
}

<#
.SYNOPSIS
    Writes a connection string report as lines of text, the password masked.

.OUTPUTS
    System.String[]
#>
function Format-TkConnectionStringReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste a connection string to take it apart.')
    }

    $report = Get-TkConnectionStringReport -Text $Text

    if (@($report.Pairs).Count -eq 0) {
        return @('Nothing was recognised. A connection string is a series of key=value pairs separated by semicolons, such as Server=...;Database=...;User Id=...;Password=...')
    }

    $passwordKeys = @('password', 'pwd')
    $lines        = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Type: {0}' -f $report.Kind))
    $lines.Add('')

    foreach ($name in $report.Field.Keys) {
        $value = if ($passwordKeys -contains $name.ToLowerInvariant()) { '******** (hidden)' } else { $report.Field[$name] }
        $lines.Add(('  {0,-10} {1}' -f $name, $value))
    }

    $lines.Add('')
    $lines.Add('Parameters:')
    foreach ($pair in $report.Pairs) {
        $value = if ($passwordKeys -contains $pair.Key.ToLowerInvariant()) { '******** (hidden)' } else { $pair.Value }
        $lines.Add(('  {0} = {1}' -f $pair.Key, $value))
    }

    $lines.Add('')
    $lines.Add('Notes:')
    foreach ($finding in $report.Finding) {
        $marker = switch ($finding.Severity) { 'Warning' { '[!]' } 'Pass' { '[ok]' } default { '[i]' } }
        $lines.Add(('  {0} {1}' -f $marker, $finding.Text))
    }

    return $lines.ToArray()
}
