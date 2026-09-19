<#
    Toolkit - Features / Certificate tools

    Decoding certificates and certificate requests pasted or opened from a
    file: what a certificate is for, until when, with which key, and what a
    request asks a certification authority to sign.

    Certificates are read with .NET; requests with the Windows certificate
    enrolment objects (CertEnroll), because .NET Framework, which Windows
    PowerShell 5.1 runs on, has no reader for them. A private key pasted by
    mistake is recognised and never decoded.
#>

<#
.SYNOPSIS
    Finds the PEM blocks in a text.

.DESCRIPTION
    A block runs from -----BEGIN LABEL----- to the matching -----END LABEL-----.
    Several blocks may follow each other, as in a chain file.

.PARAMETER Text
    The pasted text.

.OUTPUTS
    PSCustomObject[] with Label and Bytes, Bytes null when the body is not Base64.
#>
function Split-TkPemBlock {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $blocks = foreach ($match in [regex]::Matches($Text, '-----BEGIN (?<label>[A-Z0-9 ]+)-----(?<body>[\s\S]*?)-----END \k<label>-----')) {

        $bytes = $null

        try {
            $bytes = [Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s', ''))
        }
        catch {
            $bytes = $null
        }

        [pscustomobject] @{ Label = $match.Groups['label'].Value; Bytes = $bytes }
    }

    return @($blocks)
}

<#
.SYNOPSIS
    Names the common extended key usages without depending on the language of Windows.

.OUTPUTS
    System.String
#>
function Get-TkKeyPurposeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.Oid] $Oid
    )

    $names = @{
        '1.3.6.1.5.5.7.3.1'      = 'Server authentication'
        '1.3.6.1.5.5.7.3.2'      = 'Client authentication'
        '1.3.6.1.5.5.7.3.3'      = 'Code signing'
        '1.3.6.1.5.5.7.3.4'      = 'Secure e-mail'
        '1.3.6.1.5.5.7.3.8'      = 'Time stamping'
        '1.3.6.1.5.5.7.3.9'      = 'OCSP signing'
        '1.3.6.1.4.1.311.20.2.2' = 'Smart card sign-in'
        '1.3.6.1.4.1.311.10.3.4' = 'Encrypting File System'
        '1.3.6.1.4.1.311.10.3.12' = 'Document signing'
    }

    if ($names.ContainsKey($Oid.Value)) {
        return $names[$Oid.Value]
    }

    return $(if ($Oid.FriendlyName) { '{0} ({1})' -f $Oid.FriendlyName, $Oid.Value } else { $Oid.Value })
}

<#
.SYNOPSIS
    Describes a certificate.

.PARAMETER Bytes
    The certificate, DER encoded.

.PARAMETER Now
    The moment validity is judged against.

.OUTPUTS
    PSCustomObject with Kind Certificate.
#>
function Get-TkCertificateInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $Bytes)

    # --- Names, purposes and constraints ------------------------------------
    # X509Extension.Format localises its labels ("DNS Name=" or "Nom DNS="):
    # only what follows the equals sign is kept.
    $names       = @()
    $keyUsage    = ''
    $purposes    = @()
    $isAuthority = $false
    $pathLength  = $null

    foreach ($extension in $certificate.Extensions) {

        switch ($extension.Oid.Value) {

            '2.5.29.17' {
                $names = @(foreach ($entry in ($extension.Format($false) -split ',\s*|\r?\n')) {
                    $separator = $entry.IndexOf('=')
                    $value     = if ($separator -ge 0) { $entry.Substring($separator + 1) } else { $entry }
                    if ($value.Trim()) { $value.Trim() }
                })
            }

            '2.5.29.15' {
                $keyUsage = [string] ([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] $extension).KeyUsages
            }

            '2.5.29.37' {
                $purposes = @(foreach ($oid in ([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] $extension).EnhancedKeyUsages) {
                    Get-TkKeyPurposeName -Oid $oid
                })
            }

            '2.5.29.19' {
                $constraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] $extension
                $isAuthority = $constraints.CertificateAuthority

                if ($constraints.HasPathLengthConstraint) {
                    $pathLength = $constraints.PathLengthConstraint
                }
            }
        }
    }

    # --- Key --------------------------------------------------------------
    $keyAlgorithm = [string] $certificate.PublicKey.Oid.FriendlyName
    $keySize      = 0
    $curve        = ''

    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
        if ($rsa) { $keyAlgorithm = 'RSA'; $keySize = $rsa.KeySize }
    }
    catch {
        $null = $_
    }

    if ($keySize -eq 0) {
        try {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($certificate)

            if ($ecdsa) {
                $keyAlgorithm = 'ECDSA'
                $keySize      = $ecdsa.KeySize
                $curve        = [string] $ecdsa.ExportParameters($false).Curve.Oid.FriendlyName
            }
        }
        catch {
            $null = $_
        }
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $digest = ([BitConverter]::ToString($sha256.ComputeHash($certificate.RawData))) -replace '-', ''
    $sha256.Dispose()

    # --- Validity and warnings --------------------------------------------
    $days   = [int] [math]::Floor(($certificate.NotAfter - $Now).TotalDays)
    $status = if ($Now -lt $certificate.NotBefore) { 'Not yet valid' }
              elseif ($Now -gt $certificate.NotAfter) { 'Expired' }
              elseif ($days -le 30) { 'Expires soon' }
              else { 'Valid' }

    $selfSigned = ($certificate.Subject -eq $certificate.Issuer)
    $signature  = [string] $certificate.SignatureAlgorithm.FriendlyName
    $warnings   = New-Object System.Collections.Generic.List[string]

    if ($status -eq 'Expired') {
        $warnings.Add(('Expired on {0}.' -f $certificate.NotAfter.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)))
    }

    if ($status -eq 'Not yet valid') {
        $warnings.Add('Not valid yet: check the clock of the machine using it, or the issue date.')
    }

    if ($status -eq 'Expires soon') {
        $warnings.Add(('Expires in {0} day(s): renew it before the services using it stop.' -f $days))
    }

    if ($signature -match 'sha1|md5') {
        $warnings.Add(('Signed with {0}, which browsers and Windows no longer trust for TLS.' -f $signature))
    }

    if ($keyAlgorithm -eq 'RSA' -and $keySize -gt 0 -and $keySize -lt 2048) {
        $warnings.Add(('RSA key of {0} bits: 2048 is the minimum certification authorities accept.' -f $keySize))
    }

    if (-not $isAuthority -and $names.Count -eq 0) {
        $warnings.Add('No subject alternative names: browsers ignore the common name and refuse the certificate for a website.')
    }

    if (-not $isAuthority -and -not $selfSigned -and ($certificate.NotAfter - $certificate.NotBefore).TotalDays -gt 398 -and $purposes -contains 'Server authentication') {
        $warnings.Add('Valid for more than 398 days: browsers refuse such a server certificate from a public authority, an internal PKI is not bound by it.')
    }

    return [pscustomobject] @{
        Kind                   = 'Certificate'
        Subject                = $certificate.Subject
        Issuer                 = $certificate.Issuer
        SubjectAltNames        = $names
        NotBefore              = $certificate.NotBefore
        NotAfter               = $certificate.NotAfter
        DaysRemaining          = $days
        Status                 = $status
        SerialNumber           = $certificate.SerialNumber
        Thumbprint             = $certificate.Thumbprint
        Sha256                 = $digest
        SignatureAlgorithm     = $signature
        KeyAlgorithm           = $keyAlgorithm
        KeySize                = $keySize
        Curve                  = $curve
        KeyUsage               = $keyUsage
        EnhancedKeyUsage       = $purposes
        IsCertificateAuthority = $isAuthority
        PathLength             = $pathLength
        SelfSigned             = $selfSigned
        Warnings               = $warnings.ToArray()
    }
}

<#
.SYNOPSIS
    Describes a certificate request (PKCS #10).

.DESCRIPTION
    Decoded with the Windows enrolment object CX509CertificateRequestPkcs10,
    which also reads the requested extensions. The signature of the request is
    not checked.

.PARAMETER Bytes
    The request, DER encoded.

.OUTPUTS
    PSCustomObject with Kind Request, or null when the bytes are not a request.
#>
function Get-TkCertificateRequestInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    try {
        $request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10

        # 1 is XCN_CRYPT_STRING_BASE64: the body of the PEM block without its armour.
        $request.InitializeDecode([Convert]::ToBase64String($Bytes), 1)
    }
    catch {
        return $null
    }

    $subject = ''
    $hash    = ''

    try { $subject = [string] $request.Subject.Name } catch { $subject = '' }
    try { $hash = [string] $request.HashAlgorithm.FriendlyName } catch { $hash = '' }

    $keyAlgorithm = [string] $request.PublicKey.Algorithm.FriendlyName
    $keySize      = [int] $request.PublicKey.Length

    $extensionNames = @{
        '2.5.29.14'             = 'Subject key identifier'
        '2.5.29.15'             = 'Key usage'
        '2.5.29.17'             = 'Subject alternative names'
        '2.5.29.19'             = 'Basic constraints'
        '2.5.29.37'             = 'Enhanced key usage'
        '1.3.6.1.4.1.311.20.2'  = 'Certificate template name'
        '1.3.6.1.4.1.311.21.7'  = 'Certificate template'
    }

    $names      = New-Object System.Collections.Generic.List[string]
    $extensions = New-Object System.Collections.Generic.List[string]

    foreach ($extension in $request.X509Extensions) {

        $oid = [string] $extension.ObjectId.Value
        $extensions.Add($(if ($extensionNames.ContainsKey($oid)) { $extensionNames[$oid] } else { $oid }))

        if ($oid -ne '2.5.29.17') {
            continue
        }

        try {
            $alternative = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $alternative.InitializeDecode(1, $extension.RawData(1))

            foreach ($entry in $alternative.AlternativeNames) {

                # AlternativeNameType: 2 e-mail, 3 DNS, 7 URL, 8 IP address, 11 UPN.
                $value = switch ([int] $entry.Type) {
                    8       { (New-Object System.Net.IPAddress -ArgumentList @(, [Convert]::FromBase64String($entry.RawData(1)))).ToString() }
                    default { [string] $entry.StrValue }
                }

                if ($value) {
                    $names.Add($value)
                }
            }
        }
        catch {
            $null = $_
        }
    }

    $warnings = New-Object System.Collections.Generic.List[string]

    if ($keyAlgorithm -match 'RSA' -and $keySize -gt 0 -and $keySize -lt 2048) {
        $warnings.Add(('RSA key of {0} bits: certification authorities refuse less than 2048.' -f $keySize))
    }

    if ($names.Count -eq 0) {
        $warnings.Add('No subject alternative names requested: a website certificate issued from it is refused by browsers, unless the authority adds them.')
    }

    if ($hash -match 'sha1|md5') {
        $warnings.Add(('Signed with {0}: many authorities refuse such a request.' -f $hash))
    }

    return [pscustomobject] @{
        Kind            = 'Request'
        Subject         = $subject
        KeyAlgorithm    = $keyAlgorithm
        KeySize         = $keySize
        SignatureHash   = $hash
        SubjectAltNames = $names.ToArray()
        Extensions      = $extensions.ToArray()
        Warnings        = $warnings.ToArray()
    }
}

<#
.SYNOPSIS
    Decodes one block or file into certificate, request or key items.

.OUTPUTS
    PSCustomObject[]
#>
function ConvertTo-TkCertificateItem {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [byte[]] $Bytes,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Label = '',

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    if ($Label -match 'PRIVATE KEY') {
        return @([pscustomobject] @{
            Kind     = 'PrivateKey'
            Label    = $Label
            Warnings = @('A private key was pasted. It is not decoded. Keep it out of tickets, chats and online tools, and replace the certificate if the key was shared.')
        })
    }

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return @([pscustomobject] @{ Kind = 'Unreadable'; Label = $Label; Warnings = @('The block is not valid Base64.') })
    }

    if ($Label -match 'REQUEST') {
        $request = Get-TkCertificateRequestInfo -Bytes $Bytes
        if ($request) { return @($request) }
        return @([pscustomobject] @{ Kind = 'Unreadable'; Label = $Label; Warnings = @('The request could not be decoded.') })
    }

    if ($Label -in @('', 'CERTIFICATE', 'TRUSTED CERTIFICATE', 'X509 CERTIFICATE')) {
        try {
            return @(Get-TkCertificateInfo -Bytes $Bytes -Now $Now)
        }
        catch {
            $null = $_
        }
    }

    if ($Label -in @('', 'PKCS7', 'CMS')) {
        try {
            $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $collection.Import($Bytes)

            if ($collection.Count -gt 0) {
                return @(foreach ($certificate in $collection) { Get-TkCertificateInfo -Bytes $certificate.RawData -Now $Now })
            }
        }
        catch {
            $null = $_
        }
    }

    if ($Label -eq '') {
        $request = Get-TkCertificateRequestInfo -Bytes $Bytes
        if ($request) { return @($request) }
    }

    return @([pscustomobject] @{
        Kind     = 'Unsupported'
        Label    = $Label
        Warnings = @($(if ($Label) { '{0} blocks are not decoded here.' -f $Label } else { 'Not a certificate, a certificate chain or a certificate request.' }))
    })
}

<#
.SYNOPSIS
    Decodes the certificates, requests and keys in a text or a file.

.DESCRIPTION
    A text holds PEM blocks, or the Base64 of a single certificate without its
    armour lines as some portals show it. A file holds PEM text, or DER, or a
    PKCS #7 chain (.p7b).

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkCertificateItem {
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]] $Bytes,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    if ($PSCmdlet.ParameterSetName -eq 'Bytes') {

        $asText = [System.Text.Encoding]::ASCII.GetString($Bytes)

        if ($asText -match '-----BEGIN [A-Z0-9 ]+-----') {
            return @(Get-TkCertificateItem -Text $asText -Now $Now)
        }

        return @(ConvertTo-TkCertificateItem -Bytes $Bytes -Label '' -Now $Now)
    }

    $blocks = @(Split-TkPemBlock -Text $Text)

    if ($blocks.Count -eq 0) {

        $compact = $Text -replace '\s', ''

        if ($compact.Length -ge 64 -and $compact -match '^[A-Za-z0-9+/]+={0,2}$') {

            try {
                return @(ConvertTo-TkCertificateItem -Bytes ([Convert]::FromBase64String($compact)) -Label '' -Now $Now)
            }
            catch {
                return @()
            }
        }

        return @()
    }

    return @(foreach ($block in $blocks) { ConvertTo-TkCertificateItem -Bytes $block.Bytes -Label $block.Label -Now $Now })
}

<#
    Format conversion.

    Reading a certificate is one thing; handing it back in the shape the next
    tool wants is another. A load balancer wants PEM, a Java keystore import
    wants DER, a portal shows Base64 with no armour, and a chain arrives as one
    PKCS #7 file that has to become separate PEM certificates. All of it is the
    public certificate: a private key is never read here, and a .pfx, which
    carries one, is out of scope for this reason.
#>

<#
.SYNOPSIS
    Encodes a byte string as one DER TLV: a tag, a length, and the content.

.DESCRIPTION
    The short form of the length is a single byte under 128; the long form is a
    lead byte counting the length's own bytes, then the length big-endian. Enough
    of ASN.1 to reassemble a public key, which .NET Framework cannot export on
    its own.

.OUTPUTS
    System.Byte[]
#>
function New-TkDerTlv {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte] $Tag,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Content
    )

    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add($Tag)

    if ($Content.Length -lt 0x80) {
        $out.Add([byte] $Content.Length)
    }
    else {
        $length = New-Object System.Collections.Generic.List[byte]
        $value  = $Content.Length

        while ($value -gt 0) {
            $length.Insert(0, [byte] ($value -band 0xFF))
            $value = $value -shr 8
        }

        $out.Add([byte] (0x80 -bor $length.Count))
        $out.AddRange($length)
    }

    $out.AddRange($Content)

    return , $out.ToArray()
}

<#
.SYNOPSIS
    Encodes an object identifier as a DER OBJECT IDENTIFIER.

.DESCRIPTION
    The first two arcs share a byte as 40*first + second; every arc after is
    base 128, big-endian, with the high bit set on all but its last byte.

.OUTPUTS
    System.Byte[]
#>
function ConvertTo-TkDerOid {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Oid
    )

    $arcs = @($Oid -split '\.' | ForEach-Object { [int] $_ })
    $body = New-Object System.Collections.Generic.List[byte]
    $body.Add([byte] (40 * $arcs[0] + $arcs[1]))

    for ($i = 2; $i -lt $arcs.Count; $i++) {

        $arc   = $arcs[$i]
        $group = New-Object System.Collections.Generic.List[byte]

        $group.Add([byte] ($arc -band 0x7F))
        $arc = $arc -shr 7

        while ($arc -gt 0) {
            $group.Insert(0, [byte] (($arc -band 0x7F) -bor 0x80))
            $arc = $arc -shr 7
        }

        $body.AddRange($group)
    }

    return New-TkDerTlv -Tag 0x06 -Content $body.ToArray()
}

<#
.SYNOPSIS
    Builds the SubjectPublicKeyInfo of a certificate as DER.

.DESCRIPTION
    The public key in the standard SEQUENCE { AlgorithmIdentifier, BIT STRING }
    form, from the pieces a certificate exposes on every runtime: the algorithm
    OID, its parameters already encoded, and the raw key value. Rebuilt by hand
    because .NET Framework, which Windows PowerShell runs on, has no method that
    exports it.

.OUTPUTS
    System.Byte[]
#>
function Get-TkSubjectPublicKeyInfo {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $key = $Certificate.PublicKey

    # Built through a byte list rather than array concatenation: New-TkDerTlv
    # returns its bytes as one protected array, which @( ) would keep whole
    # instead of unrolling, nesting a byte[] where a byte is expected.
    $algorithmContent = New-Object System.Collections.Generic.List[byte]
    $algorithmContent.AddRange([byte[]] (ConvertTo-TkDerOid -Oid $key.Oid.Value))
    $algorithmContent.AddRange([byte[]] $key.EncodedParameters.RawData)
    $algorithm = New-TkDerTlv -Tag 0x30 -Content $algorithmContent.ToArray()

    $bitStringContent = New-Object System.Collections.Generic.List[byte]
    $bitStringContent.Add([byte] 0x00)
    $bitStringContent.AddRange([byte[]] $key.EncodedKeyValue.RawData)
    $bitString = New-TkDerTlv -Tag 0x03 -Content $bitStringContent.ToArray()

    $spki = New-Object System.Collections.Generic.List[byte]
    $spki.AddRange([byte[]] $algorithm)
    $spki.AddRange([byte[]] $bitString)

    return New-TkDerTlv -Tag 0x30 -Content $spki.ToArray()
}

<#
.SYNOPSIS
    Wraps DER bytes in a PEM block, the Base64 folded at 64 characters.

.OUTPUTS
    System.String
#>
function ConvertTo-TkPemBlock {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter()]
        [string] $Label = 'CERTIFICATE'
    )

    $base64 = [Convert]::ToBase64String($Bytes)

    $folded = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $base64.Length; $i += 64) {
        [void] $folded.AppendLine($base64.Substring($i, [math]::Min(64, $base64.Length - $i)))
    }

    return "-----BEGIN {0}-----`n{1}-----END {0}-----" -f $Label, ($folded.ToString() -replace "`r", '')
}

<#
.SYNOPSIS
    Extracts the public certificates from pasted text or a file's bytes.

.DESCRIPTION
    Reads PEM (one certificate or a chain), a single DER certificate, a PKCS #7
    chain, or Base64 with no armour, and returns each certificate as an object.
    Certificate blocks only: a private key in the text is ignored, not exported.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2[]
#>
function Get-TkCertificateChain {
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]] $Bytes
    )

    $certificateLabels = @('CERTIFICATE', 'TRUSTED CERTIFICATE', 'X509 CERTIFICATE')

    if ($PSCmdlet.ParameterSetName -eq 'Bytes') {

        $asText = [System.Text.Encoding]::ASCII.GetString($Bytes)

        if ($asText -match '-----BEGIN [A-Z0-9 ]+-----') {
            return @(Get-TkCertificateChain -Text $asText)
        }

        # DER, a single certificate or a PKCS #7 chain: the collection reads both.
        try {
            $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $collection.Import($Bytes)
            return @($collection)
        }
        catch {
            return @()
        }
    }

    $blocks = @(Split-TkPemBlock -Text $Text | Where-Object { $_.Label -in $certificateLabels -and $_.Bytes })

    if ($blocks.Count -gt 0) {
        return @(foreach ($block in $blocks) {
            try { New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $block.Bytes) } catch { $null = $_ }
        })
    }

    # Base64 with no armour, as some portals present a certificate.
    $compact = $Text -replace '\s', ''

    if ($compact.Length -ge 64 -and $compact -match '^[A-Za-z0-9+/]+={0,2}$') {
        try {
            return @(Get-TkCertificateChain -Bytes ([Convert]::FromBase64String($compact)))
        }
        catch {
            return @()
        }
    }

    return @()
}

<#
.SYNOPSIS
    Converts certificates to PEM, to one-line Base64 DER, or to their public key.

.PARAMETER Certificate
    The certificates from Get-TkCertificateChain.

.PARAMETER Format
    Pem for armoured certificates, DerBase64 for the raw certificate as one
    Base64 line, PublicKey for the SubjectPublicKeyInfo as a PEM public key.

.OUTPUTS
    System.String
#>
function ConvertTo-TkCertificateFormat {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $Certificate,

        [Parameter(Mandatory)]
        [ValidateSet('Pem', 'DerBase64', 'PublicKey')]
        [string] $Format
    )

    # Not named $certificate: PowerShell variable names are case insensitive, so
    # that would be the $Certificate parameter itself, and the loop would read
    # the whole array where one certificate is meant.
    $parts = foreach ($entry in $Certificate) {

        switch ($Format) {
            'Pem'       { ConvertTo-TkPemBlock -Bytes $entry.RawData -Label 'CERTIFICATE' }
            'DerBase64' { [Convert]::ToBase64String($entry.RawData) }
            'PublicKey' { ConvertTo-TkPemBlock -Bytes (Get-TkSubjectPublicKeyInfo -Certificate $entry) -Label 'PUBLIC KEY' }
        }
    }

    return (@($parts) -join "`n`n")
}

<#
.SYNOPSIS
    Writes decoded certificates, requests and keys as lines of text.

.PARAMETER Item
    Output of Get-TkCertificateItem.

.OUTPUTS
    System.String[]
#>
function Format-TkCertificateItem {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Item
    )

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $lines   = New-Object System.Collections.Generic.List[string]
    $number  = 0

    foreach ($entry in $Item) {

        $number++

        if ($lines.Count -gt 0) {
            $lines.Add('')
        }

        switch ($entry.Kind) {

            'Certificate' {
                $lines.Add(('Certificate {0}{1}' -f $number, $(if ($entry.IsCertificateAuthority) { ', a certification authority' } elseif ($entry.SelfSigned) { ', self-signed' } else { '' })))
                $lines.Add(('  Subject      {0}' -f $entry.Subject))
                $lines.Add(('  Issuer       {0}' -f $entry.Issuer))

                if (@($entry.SubjectAltNames).Count -gt 0) {
                    $lines.Add(('  Names        {0}' -f (@($entry.SubjectAltNames) -join ', ')))
                }

                $lines.Add(('  Valid        {0} to {1}, {2}' -f $entry.NotBefore.ToString('yyyy-MM-dd', $culture), $entry.NotAfter.ToString('yyyy-MM-dd', $culture),
                    $(switch ($entry.Status) { 'Expired' { 'expired' } 'Not yet valid' { 'not valid yet' } default { '{0} day(s) left' -f $entry.DaysRemaining } })))
                $lines.Add(('  Key          {0}{1}{2}' -f $entry.KeyAlgorithm, $(if ($entry.KeySize) { ' {0} bits' -f $entry.KeySize } else { '' }), $(if ($entry.Curve) { ', ' + $entry.Curve } else { '' })))
                $lines.Add(('  Signature    {0}' -f $entry.SignatureAlgorithm))

                if ($entry.KeyUsage) {
                    $lines.Add(('  Key usage    {0}' -f $entry.KeyUsage))
                }

                if (@($entry.EnhancedKeyUsage).Count -gt 0) {
                    $lines.Add(('  Purposes     {0}' -f (@($entry.EnhancedKeyUsage) -join ', ')))
                }

                if ($entry.IsCertificateAuthority -and $null -ne $entry.PathLength) {
                    $lines.Add(('  Path length  {0}' -f $entry.PathLength))
                }

                $lines.Add(('  Serial       {0}' -f $entry.SerialNumber))
                $lines.Add(('  SHA-1        {0}' -f $entry.Thumbprint))
                $lines.Add(('  SHA-256      {0}' -f $entry.Sha256))
            }

            'Request' {
                $lines.Add(('Certificate request {0}' -f $number))
                $lines.Add(('  Subject      {0}' -f $(if ($entry.Subject) { $entry.Subject } else { '(empty)' })))

                if (@($entry.SubjectAltNames).Count -gt 0) {
                    $lines.Add(('  Names        {0}' -f (@($entry.SubjectAltNames) -join ', ')))
                }

                $lines.Add(('  Key          {0} {1} bits' -f $entry.KeyAlgorithm, $entry.KeySize))

                if ($entry.SignatureHash) {
                    $lines.Add(('  Signed with  {0}' -f $entry.SignatureHash))
                }

                if (@($entry.Extensions).Count -gt 0) {
                    $lines.Add(('  Extensions   {0}' -f (@($entry.Extensions) -join ', ')))
                }
            }

            'PrivateKey' {
                $lines.Add(('Private key {0} ({1})' -f $number, $entry.Label))
            }

            default {
                $lines.Add(('Block {0}{1}' -f $number, $(if ($entry.Label) { ' ({0})' -f $entry.Label } else { '' })))
            }
        }

        foreach ($warning in @($entry.Warnings)) {
            $lines.Add(('  Warning      {0}' -f $warning))
        }
    }

    return $lines.ToArray()
}
