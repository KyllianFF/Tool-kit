<#
.SYNOPSIS
    Authenticode-signs the toolkit script with a timestamp.

.DESCRIPTION
    Signs one or more files with a code-signing certificate, given either by
    thumbprint (a certificate already in a certificate store) or by a .pfx file
    and its password. The signature is timestamped, so it stays valid after the
    certificate itself expires - without a timestamp, every signature dies with
    the certificate.

    This is the plain Authenticode path and nothing more: no packing, no
    conversion to an executable, no obfuscation. It adds a signature block to
    the end of a readable script and leaves the rest of the file as it was.

.PARAMETER Path
    One or more files to sign. Typically dist\toolkit.ps1 or a portable
    Toolkit.ps1.

.PARAMETER Thumbprint
    Thumbprint of a certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My.

.PARAMETER PfxPath
    A .pfx holding the signing certificate and its private key.

.PARAMETER Password
    Password for the .pfx. Prompted for if -PfxPath is given without it.

.PARAMETER TimestampServer
    RFC 3161 timestamp server. Defaults to DigiCert's.

.PARAMETER HashAlgorithm
    Signature hash algorithm. Defaults to SHA256.

.OUTPUTS
    System.Management.Automation.Signature[]

.EXAMPLE
    .\build\Sign-Toolkit.ps1 -Path .\dist\toolkit.ps1 -Thumbprint 1A2B3C...

.EXAMPLE
    $pw = Read-Host -AsSecureString 'PFX password'
    .\build\Sign-Toolkit.ps1 -Path .\dist\toolkit.ps1 -PfxPath .\dist\signing\toolkit.pfx -Password $pw
#>
[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
[OutputType([System.Management.Automation.Signature[]])]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]] $Path,

    [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
    [string] $Thumbprint,

    [Parameter(Mandatory, ParameterSetName = 'Pfx')]
    [string] $PfxPath,

    [Parameter(ParameterSetName = 'Pfx')]
    [System.Security.SecureString] $Password,

    [Parameter()]
    [string] $TimestampServer = 'http://timestamp.digicert.com',

    [Parameter()]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string] $HashAlgorithm = 'SHA256'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve the signing certificate
# ---------------------------------------------------------------------------

$certificate = $null

if ($PSCmdlet.ParameterSetName -eq 'Pfx') {

    if (-not (Test-Path -LiteralPath $PfxPath)) {
        throw ('PFX not found: {0}' -f $PfxPath)
    }

    if (-not $Password) {
        $Password = Read-Host -AsSecureString -Prompt ('Password for {0}' -f (Split-Path $PfxPath -Leaf))
    }

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path -LiteralPath $PfxPath).Path,
        $Password,
        'DefaultKeySet'
    )
}
else {

    # A certificate can live in the user or the machine store; check both.
    foreach ($storePath in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {

        $found = Get-ChildItem -Path $storePath -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $Thumbprint }

        if ($found) {
            $certificate = $found | Select-Object -First 1
            break
        }
    }

    if (-not $certificate) {
        throw ('No code-signing certificate with thumbprint {0} was found in the current user or local machine store.' -f $Thumbprint)
    }
}

if (-not $certificate.HasPrivateKey) {
    throw 'The certificate has no private key, so it cannot sign. Use the .pfx that holds the private key, or a thumbprint from a store that has it.'
}

Write-Host 'Signing with' -ForegroundColor Cyan
Write-Host ('  Subject    : {0}' -f $certificate.Subject)
Write-Host ('  Thumbprint : {0}' -f $certificate.Thumbprint)
Write-Host ('  Not after  : {0:yyyy-MM-dd}' -f $certificate.NotAfter)
Write-Host ('  Timestamp  : {0}' -f $TimestampServer)
Write-Host ''

# ---------------------------------------------------------------------------
# Sign each file
# ---------------------------------------------------------------------------

$signatures = @()

foreach ($item in $Path) {

    if (-not (Test-Path -LiteralPath $item)) {
        throw ('File not found: {0}' -f $item)
    }

    $full = (Resolve-Path -LiteralPath $item).Path

    $signature = Set-AuthenticodeSignature `
        -FilePath $full `
        -Certificate $certificate `
        -HashAlgorithm $HashAlgorithm `
        -TimestampServer $TimestampServer `
        -IncludeChain All

    $colour = if ($signature.Status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host ('  {0,-6} {1}' -f $signature.Status, $full) -ForegroundColor $colour

    if ($signature.Status -ne 'Valid') {
        Write-Host ('         {0}' -f $signature.StatusMessage) -ForegroundColor Red
    }

    $signatures += $signature
}

Write-Host ''

$invalid = @($signatures | Where-Object { $_.Status -ne 'Valid' })

if ($invalid.Count -gt 0) {
    throw ('{0} of {1} file(s) did not sign to a valid state.' -f $invalid.Count, $signatures.Count)
}

Write-Host ('Signed {0} file(s).' -f $signatures.Count) -ForegroundColor Green
Write-Host 'A machine trusts this signature once the signing certificate is in its Trusted Publishers store.'

return $signatures
