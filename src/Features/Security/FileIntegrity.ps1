<#
    Toolkit - Features / File integrity

    Hashing, hash comparison and Authenticode signature inspection.

    These three answer the question a technician actually has about a
    downloaded file: is it the file the publisher produced. A hash proves the
    bytes match a reference; a signature proves who produced them. Neither
    alone is enough, which is why both live in the same module.
#>

<#
.SYNOPSIS
    Computes one or more hashes for a file.

.DESCRIPTION
    Reads the file once per algorithm through the .NET providers. MD5 and
    SHA1 are offered because vendors still publish them, and are labelled as
    unsuitable for integrity decisions in the returned object.

.PARAMETER Path
    File to hash.

.PARAMETER Algorithm
    One or more of MD5, SHA1, SHA256, SHA384, SHA512.

.OUTPUTS
    PSCustomObject
#>
function Get-TkFileHashReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string[]] $Algorithm = @('SHA256')
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {

        Write-TkLog -Level Error -Category 'Integrity' -Message ('File not found: {0}' -f $Path)
        return $null
    }

    $file   = Get-Item -LiteralPath $Path
    $hashes = [ordered]@{}

    $stopwatch = Start-TkOperation -Name ('Hash {0}' -f $file.Name) -Category 'Integrity'

    foreach ($name in $Algorithm) {

        try {
            $hashes[$name] = (Get-FileHash -LiteralPath $Path -Algorithm $name -ErrorAction Stop).Hash
        }
        catch {
            Write-TkLog -Level Error -Category 'Integrity' -Message (
                '{0} hashing failed: {1}' -f $name, $_.Exception.Message
            )

            $hashes[$name] = ''
        }
    }

    Stop-TkOperation -Name ('Hash {0}' -f $file.Name) -Stopwatch $stopwatch -Category 'Integrity'

    $weak = @($Algorithm | Where-Object { $_ -in @('MD5', 'SHA1') })

    return [pscustomobject]@{
        Path        = $file.FullName
        Name        = $file.Name
        Size        = Format-TkBytes -Bytes $file.Length
        SizeBytes   = $file.Length
        Modified    = $file.LastWriteTime
        Hashes      = $hashes
        Signature   = Get-TkFileSignature -Path $file.FullName
        WeakWarning = if ($weak.Count -gt 0) {
                          ('{0} is broken for integrity purposes: a match proves nothing against a deliberate forgery.' -f ($weak -join ' and '))
                      }
                      else { '' }
    }
}

<#
.SYNOPSIS
    Compares a file against an expected hash.

.DESCRIPTION
    The comparison is case insensitive and tolerant of the separators vendors
    put in published hashes. The algorithm is inferred from the length of the
    expected value, which removes the most common source of false mismatches.

.PARAMETER Path
    File to verify.

.PARAMETER ExpectedHash
    Reference hash as published by the vendor.

.OUTPUTS
    PSCustomObject with Match, Algorithm, Expected and Actual.
#>
function Test-TkFileHash {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $ExpectedHash
    )

    $normalised = ($ExpectedHash -replace '[\s:-]', '').Trim().ToUpperInvariant()

    $algorithm = switch ($normalised.Length) {
        32  { 'MD5'    ; break }
        40  { 'SHA1'   ; break }
        64  { 'SHA256' ; break }
        96  { 'SHA384' ; break }
        128 { 'SHA512' ; break }
        default { $null }
    }

    if (-not $algorithm) {

        Write-TkLog -Level Error -Category 'Integrity' -Message (
            'Cannot infer an algorithm from a {0} character hash.' -f $normalised.Length
        )

        return [pscustomobject]@{
            Match     = $false
            Algorithm = 'Unknown'
            Expected  = $normalised
            Actual    = ''
            Message   = 'The expected hash has an unexpected length.'
        }
    }

    if ($normalised -notmatch '^[0-9A-F]+$') {

        return [pscustomobject]@{
            Match     = $false
            Algorithm = $algorithm
            Expected  = $normalised
            Actual    = ''
            Message   = 'The expected hash contains non hexadecimal characters.'
        }
    }

    try {
        $actual = (Get-FileHash -LiteralPath $Path -Algorithm $algorithm -ErrorAction Stop).Hash.ToUpperInvariant()
    }
    catch {
        return [pscustomobject]@{
            Match     = $false
            Algorithm = $algorithm
            Expected  = $normalised
            Actual    = ''
            Message   = $_.Exception.Message
        }
    }

    $match = ($actual -eq $normalised)

    Write-TkLog -Level $(if ($match) { 'Information' } else { 'Warning' }) -Category 'Integrity' -Message (
        '{0} verification of {1}: {2}' -f $algorithm, (Split-Path $Path -Leaf), $(if ($match) { 'MATCH' } else { 'MISMATCH' })
    )

    return [pscustomobject]@{
        Match     = $match
        Algorithm = $algorithm
        Expected  = $normalised
        Actual    = $actual
        Message   = if ($match) { 'The file matches the published hash.' }
                    else { 'The file does NOT match. Do not run it.' }
    }
}

<#
.SYNOPSIS
    Inspects the Authenticode signature of a file.

.DESCRIPTION
    Reports the signer, the timestamp and the chain status. A valid signature
    on an expired certificate is still trustworthy when the file carries a
    countersignature timestamp, and that distinction is made explicit here
    because it is the one people get wrong.

.OUTPUTS
    PSCustomObject
#>
function Get-TkFileSignature {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Status     = 'Unavailable'
            Signer     = ''
            Issuer     = ''
            ValidFrom  = $null
            ValidTo    = $null
            TimeStamp  = $null
            IsTrusted  = $false
            Message    = $_.Exception.Message
        }
    }

    $signer = $signature.SignerCertificate

    $message = switch ([string] $signature.Status) {
        'Valid'              { 'Signed and trusted.' ; break }
        'NotSigned'          { 'The file carries no digital signature.' ; break }
        'HashMismatch'       { 'The file was modified after it was signed. Treat it as hostile.' ; break }
        'NotTrusted'         { 'Signed, but the issuing authority is not trusted on this machine.' ; break }
        'UnknownError'       { 'The signature could not be evaluated.' ; break }
        default              { [string] $signature.Status }
    }

    return [pscustomobject]@{
        Status     = [string] $signature.Status
        Signer     = if ($signer) { $signer.Subject } else { '' }
        Issuer     = if ($signer) { $signer.Issuer } else { '' }
        ValidFrom  = if ($signer) { $signer.NotBefore } else { $null }
        ValidTo    = if ($signer) { $signer.NotAfter } else { $null }
        TimeStamp  = $signature.TimeStamperCertificate.NotBefore
        IsTrusted  = ($signature.Status -eq 'Valid')
        Message    = $message
    }
}

<#
.SYNOPSIS
    Hashes every file in a folder and writes a manifest.

.DESCRIPTION
    The baseline half of change detection: take a manifest now, compare it
    later with Compare-TkDirectoryManifest to see what moved.

.PARAMETER Path
    Folder to inventory.

.PARAMETER ManifestPath
    Destination JSON file.

.OUTPUTS
    System.String - the manifest path.
#>
function New-TkDirectoryManifest {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $ManifestPath,

        [Parameter()]
        [ValidateSet('SHA256', 'SHA512')]
        [string] $Algorithm = 'SHA256'
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Write-TkLog -Level Error -Category 'Integrity' -Message ('Folder not found: {0}' -f $Path)
        return $null
    }

    if (-not $PSCmdlet.ShouldProcess($ManifestPath, 'Write manifest')) {
        return $null
    }

    $entries = @()
    $files   = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {

        try {
            $entries += [pscustomobject]@{
                RelativePath = $file.FullName.Substring($Path.Length).TrimStart('\')
                Size         = $file.Length
                Modified     = $file.LastWriteTimeUtc.ToString('o')
                Hash         = (Get-FileHash -LiteralPath $file.FullName -Algorithm $Algorithm -ErrorAction Stop).Hash
            }
        }
        catch {
            Write-TkLog -Level Warning -Category 'Integrity' -Message (
                'Skipped {0}: {1}' -f $file.FullName, $_.Exception.Message
            )
        }
    }

    $manifest = [pscustomobject]@{
        Root      = (Resolve-Path -LiteralPath $Path).Path
        Algorithm = $Algorithm
        Created   = (Get-Date).ToString('o')
        FileCount = $entries.Count
        Files     = $entries
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

    Write-TkLog -Level Information -Category 'Integrity' -Message (
        'Manifest written: {0} files.' -f $entries.Count
    )

    return $ManifestPath
}

<#
.SYNOPSIS
    Compares a folder against a previously written manifest.

.OUTPUTS
    PSCustomObject with Added, Removed, Modified and Unchanged counts.
#>
function Compare-TkDirectoryManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ManifestPath,

        [Parameter()]
        [string] $Path
    )

    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-TkLog -Level Error -Category 'Integrity' -Message (
            'Unreadable manifest: {0}' -f $_.Exception.Message
        )

        return $null
    }

    if (-not $Path) {
        $Path = $manifest.Root
    }

    $baseline = @{}

    foreach ($entry in $manifest.Files) {
        $baseline[$entry.RelativePath] = $entry.Hash
    }

    $added    = @()
    $modified = @()
    $seen     = @{}

    foreach ($file in (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue)) {

        $relative     = $file.FullName.Substring($Path.Length).TrimStart('\')
        $seen[$relative] = $true

        try {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm $manifest.Algorithm -ErrorAction Stop).Hash
        }
        catch {
            continue
        }

        if (-not $baseline.ContainsKey($relative)) {
            $added += $relative
        }
        elseif ($baseline[$relative] -ne $hash) {
            $modified += $relative
        }
    }

    $removed = @($baseline.Keys | Where-Object { -not $seen.ContainsKey($_) })

    Write-TkLog -Level Information -Category 'Integrity' -Message (
        'Comparison: {0} added, {1} modified, {2} removed.' -f $added.Count, $modified.Count, $removed.Count
    )

    return [pscustomobject]@{
        Added     = $added
        Modified  = $modified
        Removed   = $removed
        Unchanged = ($baseline.Count - $modified.Count - $removed.Count)
    }
}
