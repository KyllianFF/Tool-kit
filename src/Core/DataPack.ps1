<#
    Toolkit - Core / Signed data packs

    A data pack is a .psd1 file an organisation publishes for the toolkit to
    read: its policy, for one. It is data and nothing else, and it is read
    only once it is trusted:

    - trusted means signed with Authenticode by a certificate whose
      thumbprint is pinned here, with a chain Windows trusts; or its SHA-256
      pinned here, which needs no certificate at all;
    - the bytes are read once. The data is parsed from them, and the
      signature is checked on a private copy of them, locked against writing
      and compared with them first, so the file cannot change between the
      check and the parse;
    - the text is parsed, never run: the one hashtable it holds is evaluated
      the way Import-PowerShellDataFile evaluates it, which accepts constants,
      arrays and hashtables and refuses anything that would run code.

    A pack that fails any of this is not half read: nothing of it is used,
    and the reason is given.
#>

<#
.SYNOPSIS
    Sorts pinned values into certificate thumbprints and SHA-256 hashes.

.DESCRIPTION
    Pure. A thumbprint is 40 hexadecimal characters, a SHA-256 is 64. The
    values may be separated by commas, semicolons or lines, and written with
    spaces or colons between the bytes, as certificate dialogs show them.
    Anything else is kept apart, so a typing mistake is reported rather than
    silently trusting less than was meant.

.OUTPUTS
    PSCustomObject with Thumbprints, Hashes and Invalid, each a string array.
#>
function ConvertTo-TkTrustAnchor {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $Value = @()
    )

    $thumbprints = New-Object System.Collections.Generic.List[string]
    $hashes      = New-Object System.Collections.Generic.List[string]
    $invalid     = New-Object System.Collections.Generic.List[string]

    foreach ($item in @($Value | ForEach-Object { [string] $_ -split '[,;\r\n]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {

        $clean = ($item -replace '[\s:]', '').ToUpperInvariant()

        if ($clean -match '^[0-9A-F]{40}$') {
            if (-not $thumbprints.Contains($clean)) { $thumbprints.Add($clean) }
        }
        elseif ($clean -match '^[0-9A-F]{64}$') {
            if (-not $hashes.Contains($clean)) { $hashes.Add($clean) }
        }
        else {
            $invalid.Add($item)
        }
    }

    return [pscustomobject] @{
        Thumbprints = [string[]] $thumbprints.ToArray()
        Hashes      = [string[]] $hashes.ToArray()
        Invalid     = [string[]] $invalid.ToArray()
    }
}

<#
.SYNOPSIS
    The SHA-256 of some bytes, in upper case hexadecimal.
#>
function Get-TkBytesSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '')
    }
    finally {
        $sha.Dispose()
    }
}

<#
.SYNOPSIS
    Reads a data pack's bytes from a file, a share or an https:// address.

.DESCRIPTION
    An address is downloaded to a temporary file, read and deleted. Plain
    http:// is refused: the pack would be verified all the same, but a
    policy has no reason to travel in clear. A pack larger than MaxBytes is
    refused before it is read: a policy is a few kilobytes.

.PARAMETER Download
    Fetches an address into a file. Replaced in the tests.

.OUTPUTS
    System.Byte[]
#>
function Get-TkDataPackBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter()]
        [int] $MaxBytes = 1048576,

        [Parameter()]
        [scriptblock] $Download = {
            param($uri, $path)
            Invoke-WebRequest -Uri $uri -OutFile $path -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 3 -ErrorAction Stop
        }
    )

    $tooLarge = 'It is larger than {0} KB, which no data pack should be.' -f [math]::Ceiling($MaxBytes / 1024)

    if ($Source -match '^(?i)http://') {
        throw 'Use an https:// address: a data pack has no reason to travel in clear.'
    }

    if ($Source -match '^(?i)https://') {

        $temporary = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('tk-pack-{0}.tmp' -f [guid]::NewGuid().ToString('N'))

        try {
            try {
                & $Download $Source $temporary
            }
            catch {
                throw ('{0} could not be downloaded: {1}' -f $Source, $_.Exception.Message)
            }

            if (-not (Test-Path -LiteralPath $temporary -PathType Leaf)) {
                throw ('{0} returned nothing.' -f $Source)
            }

            if ((Get-Item -LiteralPath $temporary).Length -gt $MaxBytes) {
                throw $tooLarge
            }

            return , [System.IO.File]::ReadAllBytes($temporary)
        }
        finally {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw ('{0} does not exist, or cannot be reached from here.' -f $Source)
    }

    $file = Get-Item -LiteralPath $Source

    if ($file.Length -gt $MaxBytes) {
        throw $tooLarge
    }

    return , [System.IO.File]::ReadAllBytes($file.FullName)
}

<#
.SYNOPSIS
    Turns a data pack's text into the hashtable it holds, without running it.

.DESCRIPTION
    Pure. The text must be one hashtable and nothing else: no statement
    before or after it, no param block, no #requires. The hashtable is then
    evaluated with SafeGetValue, as Import-PowerShellDataFile does, which
    accepts constants, arrays and hashtables, and $true, $false and $null,
    and throws on a command, a variable or an expression. Comments,
    including the signature block, are ignored.

.OUTPUTS
    System.Collections.Hashtable
#>
function ConvertFrom-TkDataPackText {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $tokens = $null
    $errors = $null
    $ast    = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref] $tokens, [ref] $errors)

    if (@($errors).Count -gt 0) {
        throw ('It does not parse: {0} (line {1}).' -f $errors[0].Message, $errors[0].Extent.StartLineNumber)
    }

    $onlyData = 'It must hold one hashtable, @{ ... }, and nothing else.'

    if ($ast.ParamBlock -or $ast.BeginBlock -or $ast.ProcessBlock -or $ast.DynamicParamBlock -or $ast.ScriptRequirements -or -not $ast.EndBlock) {
        throw $onlyData
    }

    $statements = @($ast.EndBlock.Statements)

    # Traps is null rather than empty without one, and @($null) counts one.
    if ($statements.Count -ne 1 -or ($ast.EndBlock.Traps -and $ast.EndBlock.Traps.Count -gt 0)) {
        throw $onlyData
    }

    $pipeline = $statements[0]

    $isHashtable = ($pipeline -is [System.Management.Automation.Language.PipelineAst]) -and
                   (@($pipeline.PipelineElements).Count -eq 1) -and
                   ($pipeline.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) -and
                   (-not $pipeline.PipelineElements[0].Redirections -or @($pipeline.PipelineElements[0].Redirections).Count -eq 0) -and
                   ($pipeline.PipelineElements[0].Expression -is [System.Management.Automation.Language.HashtableAst])

    if (-not $isHashtable) {
        throw $onlyData
    }

    try {
        $value = $pipeline.PipelineElements[0].Expression.SafeGetValue()
    }
    catch {
        throw 'It holds a command, a variable or an expression where only values are allowed: constants, @( ) arrays and @{ } hashtables.'
    }

    return $value
}

<#
.SYNOPSIS
    Decodes a data pack's bytes into text, by its byte order mark.

.DESCRIPTION
    Pure. A signed PowerShell file is often UTF-16 or UTF-8 with a byte order
    mark; without one, UTF-8 is assumed.

.OUTPUTS
    System.String
#>
function ConvertFrom-TkDataPackBytes {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    $stream = New-Object System.IO.MemoryStream(, $Bytes)
    $reader = New-Object System.IO.StreamReader($stream, (New-Object System.Text.UTF8Encoding($false)), $true)

    try {
        return $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

<#
.SYNOPSIS
    Reads the Authenticode signature of some bytes, through a locked copy.

.DESCRIPTION
    Get-AuthenticodeSignature -Content would read the bytes directly, but
    Windows PowerShell 5.1 reports some signed UTF-8 files NotSigned that
    way, while it reads the same file by its path correctly. So the bytes are
    written to a private temporary file, which is then held open for reading
    and shared for reading only: nothing can change it while the signature is
    read, and it is compared with the bytes before.

.OUTPUTS
    System.Management.Automation.Signature
#>
function Get-TkBytesSignature {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Signature])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes,

        [Parameter()]
        [ValidatePattern('^\.[A-Za-z0-9]{1,8}$')]
        [string] $Extension = '.psd1'
    )

    $folder = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('tk-pack-{0}' -f [guid]::NewGuid().ToString('N'))
    $path   = Join-Path -Path $folder -ChildPath ('pack{0}' -f $Extension)
    $lock   = $null

    try {
        [void] [System.IO.Directory]::CreateDirectory($folder)
        [System.IO.File]::WriteAllBytes($path, $Bytes)

        $lock = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $copy = New-Object byte[] $lock.Length
        $read = 0
        while ($read -lt $copy.Length) {
            $count = $lock.Read($copy, $read, $copy.Length - $read)
            if ($count -le 0) { break }
            $read += $count
        }

        if ((Get-TkBytesSha256 -Bytes $copy) -ne (Get-TkBytesSha256 -Bytes $Bytes)) {
            throw 'The copy changed before its signature could be read.'
        }

        return (Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop)
    }
    finally {
        if ($lock) { $lock.Dispose() }
        Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
    Says whether a data pack's bytes are trusted, and by what.

.DESCRIPTION
    Pure but for the signature reader, which the tests replace. A pinned
    SHA-256 trusts exactly these bytes. A pinned thumbprint trusts a
    signature by that certificate, and only when Windows reports the
    signature Valid: the content unchanged since it was signed, and a
    certificate chain it trusts. A self-signed certificate that is not in the
    trusted roots does not qualify; its file can still be pinned by SHA-256.

.PARAMETER Anchor
    As returned by ConvertTo-TkTrustAnchor.

.PARAMETER Signature
    Reads the Authenticode signature of the bytes.

.OUTPUTS
    PSCustomObject with Verified, By (Signature or Hash), Sha256, Signer,
    Thumbprint, SignatureStatus and Reason.
#>
function Test-TkDataPackTrust {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [pscustomobject] $Anchor,

        [Parameter()]
        [string] $Extension = '.psd1',

        [Parameter()]
        [scriptblock] $Signature = {
            param($bytes, $extension)
            Get-TkBytesSignature -Bytes $bytes -Extension $extension
        }
    )

    $sha    = Get-TkBytesSha256 -Bytes $Bytes
    $signed = try { & $Signature $Bytes $Extension } catch { $null }

    $status     = if ($signed) { [string] $signed.Status } else { 'Unreadable' }
    $thumbprint = if ($signed -and $signed.SignerCertificate) { ([string] $signed.SignerCertificate.Thumbprint).ToUpperInvariant() } else { '' }
    $signer     = if ($signed -and $signed.SignerCertificate) { [string] $signed.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1' } else { '' }

    $result = [pscustomobject] @{
        Verified        = $false
        By              = ''
        Sha256          = $sha
        Signer          = $signer
        Thumbprint      = $thumbprint
        SignatureStatus = $status
        Reason          = ''
    }

    if (@($Anchor.Hashes) -contains $sha) {
        $result.Verified = $true
        $result.By       = 'Hash'
        return $result
    }

    if ($status -eq 'Valid' -and $thumbprint -and @($Anchor.Thumbprints) -contains $thumbprint) {
        $result.Verified = $true
        $result.By       = 'Signature'
        return $result
    }

    $pinned = @($Anchor.Hashes).Count + @($Anchor.Thumbprints).Count

    $result.Reason = if ($pinned -eq 0) {
        'Nothing is trusted yet: pin the thumbprint of the certificate that signs it, or its SHA-256. Its SHA-256 is {0}{1}.' -f $sha, $(if ($thumbprint) { ', and it is signed by {0} (certificate {1})' -f $signer, $thumbprint } else { '' })
    }
    elseif ($status -eq 'Valid') {
        'It is signed by {0} (certificate {1}), which is not a trusted signer here, and its SHA-256 {2} is not a trusted hash.' -f $signer, $thumbprint, $sha
    }
    elseif ($status -eq 'HashMismatch') {
        'It was changed after it was signed: its signature no longer matches its content.'
    }
    elseif ($status -eq 'NotSigned') {
        'It is not signed, and its SHA-256 {0} is not a trusted hash.' -f $sha
    }
    elseif ($thumbprint) {
        'Its signature by {0} (certificate {1}) is not valid for Windows ({2}): the certificate chain is not trusted here. Install the certificate in Trusted Root and Trusted Publishers, or pin the SHA-256 of the file, {3}.' -f $signer, $thumbprint, $status, $sha
    }
    else {
        'Its signature could not be read ({0}), and its SHA-256 {1} is not a trusted hash.' -f $status, $sha
    }

    return $result
}

<#
.SYNOPSIS
    Reads a signed data pack: its bytes, their trust, then their data.

.DESCRIPTION
    Never throws: what went wrong is in Reason, and Data is set only when the
    pack is trusted and parses. The SHA-256 and the signer are reported even
    for a pack that is refused, so the one who publishes it can pin them.

.PARAMETER Source
    A file, a share or an https:// address.

.PARAMETER Trust
    Pinned certificate thumbprints and SHA-256 hashes.

.OUTPUTS
    PSCustomObject with Source, Accepted, VerifiedBy, Sha256, Signer,
    Thumbprint, SignatureStatus, Reason and Data.
#>
function Read-TkSignedDataPack {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $Trust = @(),

        [Parameter()]
        [int] $MaxBytes = 1048576,

        [Parameter()]
        [scriptblock] $Signature,

        [Parameter()]
        [scriptblock] $Download
    )

    $result = [pscustomobject] @{
        Source          = $Source
        Accepted        = $false
        VerifiedBy      = ''
        Sha256          = ''
        Signer          = ''
        Thumbprint      = ''
        SignatureStatus = ''
        Reason          = ''
        Data            = $null
    }

    $anchor = ConvertTo-TkTrustAnchor -Value $Trust

    if (@($anchor.Invalid).Count -gt 0) {
        $result.Reason = '"{0}" is neither a certificate thumbprint (40 hexadecimal characters) nor a SHA-256 (64).' -f $anchor.Invalid[0]
        return $result
    }

    $read = @{ Source = $Source; MaxBytes = $MaxBytes }
    if ($Download) { $read['Download'] = $Download }

    try {
        $bytes = Get-TkDataPackBytes @read
    }
    catch {
        $result.Reason = $_.Exception.Message
        return $result
    }

    $check = @{ Bytes = $bytes; Anchor = $anchor; Extension = '.psd1' }
    if ($Signature) { $check['Signature'] = $Signature }

    $trusted = Test-TkDataPackTrust @check

    $result.VerifiedBy      = $trusted.By
    $result.Sha256          = $trusted.Sha256
    $result.Signer          = $trusted.Signer
    $result.Thumbprint      = $trusted.Thumbprint
    $result.SignatureStatus = $trusted.SignatureStatus

    if (-not $trusted.Verified) {
        $result.Reason = $trusted.Reason
        return $result
    }

    try {
        $result.Data = ConvertFrom-TkDataPackText -Text (ConvertFrom-TkDataPackBytes -Bytes $bytes)
    }
    catch {
        $result.Reason = 'It is trusted, but it is not a data file: {0}' -f $_.Exception.Message
        return $result
    }

    $result.Accepted = $true
    return $result
}
