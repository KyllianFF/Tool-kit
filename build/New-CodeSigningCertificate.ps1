<#
.SYNOPSIS
    Creates a self-signed code-signing certificate for the portable build.

.DESCRIPTION
    Code signing is the honest way to get an administration tool past an
    endpoint product: sign the script, then let the security team allow it by
    publisher. A publisher rule survives a rebuild, where a hash rule does not.

    This makes a self-signed certificate suitable for signing, exports it as a
    password-protected .pfx (the private key, kept for signing) and a .cer (the
    public certificate, shared so machines can trust it), and can install the
    public certificate into the current user's Trusted Publishers and Trusted
    Root so a signature made with it validates on this machine.

    Self-signed is fine for a lab, a personal machine or an internal fleet you
    control. It is trusted only where its .cer has been deployed - typically
    pushed to Trusted Publishers by group policy on managed machines. For a tool
    that leaves your control, a certificate from a public authority is the right
    choice instead; Sign-Toolkit.ps1 takes either.

.PARAMETER Subject
    The certificate subject. Shown as the publisher on the signature.

.PARAMETER OutputFolder
    Where the .pfx and .cer are written. Defaults to dist\signing.

.PARAMETER Password
    Password protecting the exported .pfx. Prompted for if not supplied.

.PARAMETER YearsValid
    How long the certificate stays valid. Defaults to 3 years.

.PARAMETER Install
    Also installs the public certificate into the current user's Trusted
    Publishers and Trusted Root, so a signature made with it validates here.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2

.EXAMPLE
    .\build\New-CodeSigningCertificate.ps1 -Install

.EXAMPLE
    $pw = Read-Host -AsSecureString 'PFX password'
    .\build\New-CodeSigningCertificate.ps1 -Subject 'CN=Contoso IT Toolkit' -Password $pw
#>
[CmdletBinding()]
[OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
param(
    [Parameter()]
    [string] $Subject = 'CN=Toolkit Code Signing',

    [Parameter()]
    [string] $OutputFolder,

    [Parameter()]
    [System.Security.SecureString] $Password,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int] $YearsValid = 3,

    [Parameter()]
    [switch] $Install
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command -Name 'New-SelfSignedCertificate' -ErrorAction SilentlyContinue)) {
    throw 'New-SelfSignedCertificate is not available. Run this on Windows in Windows PowerShell 5.1 or PowerShell 7.'
}

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent

if (-not $OutputFolder) {
    $OutputFolder = Join-Path -Path $repositoryRoot -ChildPath 'dist\signing'
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

if (-not $Password) {
    $Password = Read-Host -AsSecureString -Prompt 'Choose a password to protect the exported .pfx'
}

if ($Password.Length -eq 0) {
    throw 'A .pfx must be protected by a password. None was given.'
}

Write-Host 'Creating a self-signed code-signing certificate' -ForegroundColor Cyan
Write-Host ('  Subject : {0}' -f $Subject)
Write-Host ('  Valid   : {0} year(s)' -f $YearsValid)
Write-Host ('  Output  : {0}' -f $OutputFolder)
Write-Host ''

# CodeSigningCert sets the Code Signing enhanced key usage; without it a
# certificate cannot sign a script. It is created in the current user store so
# no administrator rights are needed.
$certificate = New-SelfSignedCertificate `
    -Subject $Subject `
    -Type CodeSigningCert `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears($YearsValid)

# A file name that stays stable across runs of the same subject.
$safeName = ($Subject -replace '^CN=', '' -replace '[^A-Za-z0-9._-]+', '-').Trim('-')

if (-not $safeName) {
    $safeName = 'toolkit-signing'
}

$pfxPath = Join-Path -Path $OutputFolder -ChildPath ('{0}.pfx' -f $safeName)
$cerPath = Join-Path -Path $OutputFolder -ChildPath ('{0}.cer' -f $safeName)

Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $Password | Out-Null
Export-Certificate    -Cert $certificate -FilePath $cerPath -Type CERT          | Out-Null

Write-Host 'Certificate created.' -ForegroundColor Green
Write-Host ('  Thumbprint : {0}' -f $certificate.Thumbprint)
Write-Host ('  PFX        : {0}  (private key - keep this secret)' -f $pfxPath)
Write-Host ('  CER        : {0}  (public - share this to be trusted)' -f $cerPath)
Write-Host ''

if ($Install) {

    # Trusted Publisher lets a signature by this certificate be accepted;
    # Root lets the self-signed chain validate. Current user only, so this
    # trusts the certificate for this account without touching the machine.
    foreach ($storeName in @('TrustedPublisher', 'Root')) {

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'CurrentUser')
        $store.Open('ReadWrite')
        $store.Add($certificate)
        $store.Close()
    }

    Write-Host 'Installed into the current user Trusted Publishers and Trusted Root.' -ForegroundColor Green
    Write-Host 'Signatures made with this certificate now validate for this account.'
    Write-Host ''
}

Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host ('  Sign a build : .\build\Sign-Toolkit.ps1 -Path <file> -Thumbprint {0}' -f $certificate.Thumbprint)
Write-Host  '  Trust a fleet: deploy the .cer to Trusted Publishers by group policy.'

return $certificate
