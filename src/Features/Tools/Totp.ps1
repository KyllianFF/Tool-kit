<#
    Toolkit - Features / TOTP authenticator

    The six-digit code an authenticator app shows, computed here from the shared
    secret so a technician can test a service account's second factor, or check
    that a seed was enrolled correctly, without reaching for a phone. It is the
    time-based one-time password of RFC 6238: an HMAC of the current thirty
    second window, truncated to a few digits.

    Everything is worked out on the machine. The secret is read, never sent
    anywhere and never echoed back; only its length is shown.
#>

<#
.SYNOPSIS
    Decodes a Base32 string (RFC 4648) into bytes.

.DESCRIPTION
    The alphabet authenticator secrets use. Spaces and the "=" padding are
    ignored and case does not matter, so a secret copied with its groups of four
    is read as is. An unexpected character is an error, not silently dropped.

.PARAMETER Text
    The Base32 text.

.OUTPUTS
    System.Byte[]
#>
function ConvertFrom-TkBase32 {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $clean    = ($Text -replace '[\s=]', '').ToUpperInvariant()

    if ([string]::IsNullOrEmpty($clean)) {
        return , ([byte[]] @())
    }

    $bytes = New-Object System.Collections.Generic.List[byte]
    $value = 0
    $bits  = 0

    foreach ($char in $clean.ToCharArray()) {

        $index = $alphabet.IndexOf($char)
        if ($index -lt 0) {
            throw [System.FormatException]::new(('"{0}" is not a Base32 character.' -f $char))
        }

        $value = ($value -shl 5) -bor $index
        $bits += 5

        if ($bits -ge 8) {
            $bits -= 8
            $bytes.Add([byte] (($value -shr $bits) -band 0xFF))
        }
    }

    return , ($bytes.ToArray())
}

<#
.SYNOPSIS
    Computes a time-based one-time password.

.DESCRIPTION
    RFC 6238: the counter is the Unix time divided by the period, HMAC'd with the
    secret, then reduced to the requested number of digits by the standard
    dynamic truncation.

.PARAMETER Secret
    The shared secret, as bytes.

.PARAMETER UnixTime
    The moment, in seconds since the epoch.

.PARAMETER Period
    The window length in seconds, usually 30.

.PARAMETER Digits
    The code length, usually 6.

.PARAMETER Algorithm
    The HMAC hash: SHA1, SHA256 or SHA512.

.OUTPUTS
    System.String
#>
function Get-TkTotpCode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Secret,

        [Parameter(Mandatory)]
        [long] $UnixTime,

        [Parameter()]
        [int] $Period = 30,

        [Parameter()]
        [ValidateRange(6, 8)]
        [int] $Digits = 6,

        [Parameter()]
        [ValidateSet('SHA1', 'SHA256', 'SHA512')]
        [string] $Algorithm = 'SHA1'
    )

    if ($Secret.Length -eq 0) {
        throw [System.ArgumentException]::new('The secret is empty.')
    }

    $counter = [long] [math]::Floor($UnixTime / $Period)

    # The counter as eight bytes, big-endian.
    $message = New-Object byte[] 8
    for ($i = 7; $i -ge 0; $i--) {
        $message[$i] = [byte] ($counter -band 0xFF)
        $counter = $counter -shr 8
    }

    $hmac = switch ($Algorithm) {
        'SHA256' { New-Object System.Security.Cryptography.HMACSHA256 }
        'SHA512' { New-Object System.Security.Cryptography.HMACSHA512 }
        default  { New-Object System.Security.Cryptography.HMACSHA1 }
    }

    $hmac.Key = $Secret
    $hash     = $hmac.ComputeHash($message)
    $hmac.Dispose()

    # Dynamic truncation: the low nibble of the last byte points at four bytes,
    # the top bit of the first cleared so the number is always positive.
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $binary = (($hash[$offset] -band 0x7F) -shl 24) -bor
              (($hash[$offset + 1] -band 0xFF) -shl 16) -bor
              (($hash[$offset + 2] -band 0xFF) -shl 8) -bor
               ($hash[$offset + 3] -band 0xFF)

    $modulo = [int] [math]::Pow(10, $Digits)
    $code   = $binary % $modulo

    return ([string] $code).PadLeft($Digits, '0')
}

<#
.SYNOPSIS
    Reads the fields of an otpauth:// URI.

.DESCRIPTION
    The URI an authenticator app imports from a QR code. The secret, issuer,
    algorithm, digit count and period are read from it, with the RFC defaults
    filled in for whatever it leaves out.

.PARAMETER Uri
    The otpauth:// text.

.OUTPUTS
    PSCustomObject, or null when it is not an otpauth URI.
#>
function ConvertFrom-TkOtpauthUri {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Uri
    )

    if ($Uri -notmatch '^otpauth://') {
        return $null
    }

    try {
        $parsed = [System.Uri] $Uri
    }
    catch {
        return $null
    }

    $query = @{}
    foreach ($part in ($parsed.Query.TrimStart('?') -split '&')) {
        if ($part -match '^(?<k>[^=]+)=(?<v>.*)$') {
            $query[$matches['k'].ToLowerInvariant()] = [System.Uri]::UnescapeDataString($matches['v'])
        }
    }

    $label   = [System.Uri]::UnescapeDataString($parsed.AbsolutePath.TrimStart('/'))
    $issuer  = if ($query.ContainsKey('issuer')) { $query['issuer'] }
               elseif ($label -match ':') { ($label -split ':', 2)[0].Trim() }
               else { '' }
    $account = if ($label -match ':') { ($label -split ':', 2)[1].Trim() } else { $label }

    return [pscustomobject] @{
        Type      = $parsed.Host
        Issuer    = $issuer
        Account   = $account
        Secret    = if ($query.ContainsKey('secret')) { $query['secret'] } else { '' }
        Algorithm = if ($query.ContainsKey('algorithm')) { $query['algorithm'].ToUpperInvariant() } else { 'SHA1' }
        Digits    = if ($query.ContainsKey('digits')) { [int] $query['digits'] } else { 6 }
        Period    = if ($query.ContainsKey('period')) { [int] $query['period'] } else { 30 }
    }
}

<#
.SYNOPSIS
    Builds the current code and its neighbours from a secret or an otpauth URI.

.PARAMETER Text
    A Base32 secret, or an otpauth:// URI.

.PARAMETER Now
    The moment to compute against. Defaults to now.

.OUTPUTS
    PSCustomObject with the code, the window, and what was read.
#>
function Get-TkTotpReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $secretText = $Text.Trim()
    $issuer     = ''
    $account    = ''
    $algorithm  = 'SHA1'
    $digits     = 6
    $period     = 30

    if ($secretText -match '^otpauth://') {

        $uri = ConvertFrom-TkOtpauthUri -Uri $secretText
        if (-not $uri -or -not $uri.Secret) {
            return [pscustomobject] @{ Error = 'The otpauth URI has no secret.' }
        }

        $secretText = $uri.Secret
        $issuer     = $uri.Issuer
        $account    = $uri.Account
        $algorithm  = $uri.Algorithm
        $digits     = $uri.Digits
        $period     = $uri.Period
    }

    if (@('SHA1', 'SHA256', 'SHA512') -notcontains $algorithm) {
        return [pscustomobject] @{ Error = ('Unsupported algorithm "{0}". Use SHA1, SHA256 or SHA512.' -f $algorithm) }
    }

    if ($digits -lt 6 -or $digits -gt 8) {
        return [pscustomobject] @{ Error = 'Only 6 to 8 digit codes are supported.' }
    }

    try {
        $secret = ConvertFrom-TkBase32 -Text $secretText
    }
    catch {
        return [pscustomobject] @{ Error = 'The secret is not valid Base32.' }
    }

    if ($secret.Length -eq 0) {
        return [pscustomobject] @{ Error = 'The secret is empty.' }
    }

    $unix      = [long] ([System.DateTimeOffset] $Now).ToUnixTimeSeconds()
    $remaining = $period - ($unix % $period)

    $common = @{ Secret = $secret; Period = $period; Digits = $digits; Algorithm = $algorithm }

    return [pscustomobject] @{
        Error            = ''
        Code             = Get-TkTotpCode @common -UnixTime $unix
        Previous         = Get-TkTotpCode @common -UnixTime ($unix - $period)
        Next             = Get-TkTotpCode @common -UnixTime ($unix + $period)
        SecondsRemaining = $remaining
        Period           = $period
        Digits           = $digits
        Algorithm        = $algorithm
        Issuer           = $issuer
        Account          = $account
        SecretByteCount  = $secret.Length
    }
}

<#
.SYNOPSIS
    Writes a TOTP report as lines of text, the secret never echoed.

.OUTPUTS
    System.String[]
#>
function Format-TkTotpReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste a Base32 secret (the key an authenticator app is set up with) or an otpauth:// URI.')
    }

    $report = Get-TkTotpReport -Text $Text -Now $Now

    if ($report.Error) {
        return @($report.Error)
    }

    # Grouped in the middle for reading aloud, as authenticator apps show it.
    $half    = [int] ($report.Digits / 2)
    $grouped = $report.Code.Substring(0, $half) + ' ' + $report.Code.Substring($half)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('Code:       {0}' -f $grouped))
    $lines.Add(('Valid for:  {0} s   (window of {1} s)' -f $report.SecondsRemaining, $report.Period))
    $lines.Add('')
    $lines.Add(('Previous:   {0}' -f $report.Previous))
    $lines.Add(('Next:       {0}' -f $report.Next))
    $lines.Add('')

    if ($report.Issuer -or $report.Account) {
        $lines.Add(('Account:    {0}{1}' -f $(if ($report.Issuer) { $report.Issuer + ' - ' } else { '' }), $report.Account))
    }

    $lines.Add(('Algorithm:  {0}   Digits: {1}   Period: {2} s' -f $report.Algorithm, $report.Digits, $report.Period))
    $lines.Add(('Secret:     read, {0} bytes (not shown)' -f $report.SecretByteCount))

    return $lines.ToArray()
}
