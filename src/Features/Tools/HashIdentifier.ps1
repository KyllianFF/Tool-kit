<#
    Toolkit - Features / Hash identifier

    A hash on its own does not say what made it: the same thirty-two hex
    characters are an MD5, an NTLM from a Windows dump, and an LM. This narrows
    a pasted hash to its likely kinds from the one thing it can be read from,
    its shape: the length, the alphabet, and the few formats that announce
    themselves with a prefix. It cannot be certain, so it lists the candidates
    rather than pretending to one answer.

    Nothing is hashed or looked up; the string is read as text on the machine.
#>

<#
.SYNOPSIS
    The hash kinds a hex string of a given length can be.

.OUTPUTS
    PSCustomObject[] with Name and Note.
#>
function Get-TkHexHashCandidate {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [int] $Length
    )

    $tool = {
        param($name, $note)
        [pscustomobject] @{ Name = $name; Note = $note }
    }

    switch ($Length) {

        8   { return @((& $tool 'CRC-32'   'A checksum, not a cryptographic hash.'),
                       (& $tool 'Adler-32' 'A checksum.')) }

        16  { return @((& $tool 'MySQL (pre-4.1)' 'The old MySQL PASSWORD() hash.')) }

        32  { return @((& $tool 'NTLM'  'A Windows account hash, as dumped from the SAM or seen in DCSync. The most likely 32-hex hash on a Windows estate.'),
                       (& $tool 'MD5'   'A general purpose digest, and the format of a WordPress or phpBB hash.'),
                       (& $tool 'MD4'   'Older, rare on its own.'),
                       (& $tool 'LM'    'A legacy Windows hash; look for it beside an NTLM in a pwdump line.'),
                       (& $tool 'RIPEMD-128' 'Uncommon.')) }

        40  { return @((& $tool 'SHA-1'       'A general purpose digest, and the basis of a Git object id.'),
                       (& $tool 'RIPEMD-160'  'Used in Bitcoin addresses.')) }

        56  { return @((& $tool 'SHA-224' ''), (& $tool 'SHA3-224' '')) }

        64  { return @((& $tool 'SHA-256'  'The current general purpose default.'),
                       (& $tool 'SHA3-256' ''),
                       (& $tool 'BLAKE2s'  ''),
                       (& $tool 'Keccak-256' 'Used by Ethereum.')) }

        96  { return @((& $tool 'SHA-384' ''), (& $tool 'SHA3-384' '')) }

        128 { return @((& $tool 'SHA-512'  ''),
                       (& $tool 'SHA3-512' ''),
                       (& $tool 'BLAKE2b'  ''),
                       (& $tool 'Whirlpool' '')) }

        default { return @() }
    }
}

<#
.SYNOPSIS
    Identifies the likely kinds of a pasted hash from its shape.

.PARAMETER Text
    The hash.

.OUTPUTS
    PSCustomObject with Input, Length, Charset and Candidate.
#>
function Get-TkHashIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $value = $Text.Trim()

    $result = {
        param($charset, $candidates)
        [pscustomobject] @{
            Input     = $value
            Length    = $value.Length
            Charset   = $charset
            Candidate = @($candidates)
        }
    }

    $one = {
        param($name, $note)
        [pscustomobject] @{ Name = $name; Note = $note }
    }

    if (-not $value) {
        return (& $result 'empty' @())
    }

    # --- Formats that name themselves with a prefix -----------------------
    if ($value -match '^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$') {
        return (& $result 'crypt' @((& $one 'bcrypt' 'A password hash with a cost factor; slow by design.')))
    }
    if ($value -match '^\$argon2(id|i|d)\$') {
        return (& $result 'crypt' @((& $one 'Argon2' 'A modern memory-hard password hash.')))
    }
    if ($value -match '^\$y\$' -or $value -match '^\$7\$') {
        return (& $result 'crypt' @((& $one 'yescrypt / scrypt' 'A memory-hard password hash used by recent Linux.')))
    }
    if ($value -match '^\$6\$')     { return (& $result 'crypt' @((& $one 'sha512crypt' 'A Linux /etc/shadow password hash.'))) }
    if ($value -match '^\$5\$')     { return (& $result 'crypt' @((& $one 'sha256crypt' 'A Linux /etc/shadow password hash.'))) }
    if ($value -match '^\$1\$')     { return (& $result 'crypt' @((& $one 'md5crypt' 'An older Unix password hash.'))) }
    if ($value -match '^\$apr1\$')  { return (& $result 'crypt' @((& $one 'Apache apr1 (MD5)' 'An Apache htpasswd hash.'))) }
    if ($value -match '^\{(SSHA|SHA|SMD5|MD5|CRYPT)\}') {
        return (& $result 'ldap' @((& $one ('LDAP {0} scheme' -f ($matches[1])) 'A directory password hash; the part after the brace is Base64.')))
    }
    if ($value -match '^\*[0-9A-Fa-f]{40}$') {
        return (& $result 'hex' @((& $one 'MySQL 4.1+' 'The SHA-1 based MySQL PASSWORD() hash, recognisable by its leading asterisk.')))
    }
    if ($value -match '^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$') {
        return (& $result 'hex' @(
            (& $one 'LM:NTLM pair' 'A pwdump line: the LM hash, a colon, then the NTLM hash. The LM half is often the empty-password value AAD3B435B51404EE.')))
    }

    # --- Pure hexadecimal --------------------------------------------------
    if ($value -match '^[0-9a-fA-F]+$') {
        return (& $result 'hexadecimal' (Get-TkHexHashCandidate -Length $value.Length))
    }

    # --- Base64, so a raw digest rather than its hex ----------------------
    if ($value -match '^[A-Za-z0-9+/]+={0,2}$' -and ($value.Length % 4) -eq 0) {
        try {
            $bytes = [Convert]::FromBase64String($value)
            $hex   = Get-TkHexHashCandidate -Length ($bytes.Length * 2)
            if (@($hex).Count -gt 0) {
                $note = @($hex | ForEach-Object { $_.Name }) -join ', '
                return (& $result 'base64' @((& $one ('Base64 of a {0}-byte digest' -f $bytes.Length) ('Decodes to {0} bytes, the size of: {1}.' -f $bytes.Length, $note))))
            }
        }
        catch {
            $null = $_
        }
    }

    return (& $result 'other' @())
}

<#
.SYNOPSIS
    Writes the hash identification as lines of text.

.OUTPUTS
    System.String[]
#>
function Format-TkHashReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste a hash to identify its likely kind.')
    }

    $identity = Get-TkHashIdentity -Text $Text
    $lines    = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Length:  {0} characters' -f $identity.Length))
    $lines.Add(('Charset: {0}' -f $identity.Charset))
    $lines.Add('')

    if (@($identity.Candidate).Count -eq 0) {
        $lines.Add('No known hash matches this shape. Check it was pasted whole, without a user name or a salt in front.')
        return $lines.ToArray()
    }

    $lines.Add('Likely kinds, most probable first:')
    foreach ($candidate in $identity.Candidate) {
        $lines.Add(('  - {0}{1}' -f $candidate.Name, $(if ($candidate.Note) { '  -  ' + $candidate.Note } else { '' })))
    }

    return $lines.ToArray()
}
