<#
.SYNOPSIS
    Builds the offline, portable editions of the toolkit.

.DESCRIPTION
    Produces two things a machine can run without the network, and without
    looking like something an antivirus should quarantine:

      1. A de-blobbed folder (and its .zip). The script is readable PowerShell
         with no embedded base64; the catalogs and the interface sit beside it
         as plain files. This is the shape least likely to trip a scanner,
         because there is nothing packed to trip it.

      2. A single-file build. The same self-contained script the online
         one-liner serves, copied into dist under a versioned name so it can be
         signed and shipped as one file.

    Both can be Authenticode-signed in the same run when a signing certificate
    is supplied - the honest way past an endpoint product, paired with the
    allowlisting guidance in the folder's README. Nothing here packs, obfuscates
    or converts the script to an executable.

.PARAMETER Version
    Version stamped into the builds and used in the file names. Defaults to the
    value in Config.ps1.

.PARAMETER OutputFolder
    Where the .zip and the single-file build are written. Defaults to dist.

.PARAMETER Thumbprint
    Sign both builds with the certificate of this thumbprint (see Sign-Toolkit).

.PARAMETER PfxPath
    Sign both builds with the certificate in this .pfx.

.PARAMETER Password
    Password for the .pfx.

.PARAMETER TimestampServer
    Timestamp server passed through to the signing step.

.PARAMETER SkipSingleFile
    Build only the portable folder and its zip, not the single-file copy.

.EXAMPLE
    .\build\New-PortablePackage.ps1

.EXAMPLE
    .\build\New-PortablePackage.ps1 -Thumbprint 1A2B3C4D...
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $Version,

    [Parameter()]
    [string] $OutputFolder,

    [Parameter()]
    [string] $Thumbprint,

    [Parameter()]
    [string] $PfxPath,

    [Parameter()]
    [System.Security.SecureString] $Password,

    [Parameter()]
    [string] $TimestampServer = 'http://timestamp.digicert.com',

    [Parameter()]
    [switch] $SkipSingleFile
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$buildScript    = Join-Path -Path $PSScriptRoot   -ChildPath 'Build-Toolkit.ps1'
$signScript     = Join-Path -Path $PSScriptRoot   -ChildPath 'Sign-Toolkit.ps1'
$templateFolder = Join-Path -Path $PSScriptRoot   -ChildPath 'portable'
$dataFolder     = Join-Path -Path $repositoryRoot -ChildPath 'data'
$xamlFile       = Join-Path -Path $repositoryRoot -ChildPath 'src\UI\MainWindow.xaml'

if (-not $OutputFolder) {
    $OutputFolder = Join-Path -Path $repositoryRoot -ChildPath 'dist'
}

# ---------------------------------------------------------------------------
# 1. Resolve version and commit (the same way the build does)
# ---------------------------------------------------------------------------

if (-not $Version) {

    $configText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src\Core\Config.ps1') -Raw

    if ($configText -match "TkAppVersion\s*=\s*'(?<version>[^']+)'") {
        $Version = $Matches['version']
    }
    else {
        $Version = '0.0.0'
    }
}

$commit = 'local'

try {
    Push-Location $repositoryRoot
    $described = git rev-parse --short HEAD 2>$null

    if ($LASTEXITCODE -eq 0 -and $described) {
        $commit = $described.Trim()
    }
}
catch {
    # git is not available, or this is not a checkout; keep the default.
    $null = $_
}
finally {
    Pop-Location
    $global:LASTEXITCODE = 0
}

# Whether the caller asked for a signature at all.
$signing = [bool] ($Thumbprint -or $PfxPath)

# Arguments handed to Sign-Toolkit.ps1, built once and reused.
$signArgs = @{ TimestampServer = $TimestampServer }

if ($Thumbprint) { $signArgs['Thumbprint'] = $Thumbprint }
if ($PfxPath)    { $signArgs['PfxPath']    = $PfxPath }
if ($Password)   { $signArgs['Password']   = $Password }

Write-Host 'Building the portable editions' -ForegroundColor Cyan
Write-Host ('  Version : {0} ({1})' -f $Version, $commit)
Write-Host ('  Output  : {0}' -f $OutputFolder)
Write-Host ('  Signing : {0}' -f $(if ($signing) { 'yes' } else { 'no (unsigned build)' }))
Write-Host ''

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

# ---------------------------------------------------------------------------
# 2. The de-blobbed folder
# ---------------------------------------------------------------------------

$folderName  = 'Toolkit-Portable-{0}' -f $Version
$stageFolder = Join-Path -Path $OutputFolder -ChildPath $folderName

if (Test-Path -LiteralPath $stageFolder) {
    Remove-Item -LiteralPath $stageFolder -Recurse -Force
}

New-Item -Path $stageFolder -ItemType Directory -Force | Out-Null

Write-Host ('  Assembling {0}' -f $folderName) -ForegroundColor Cyan

# The readable script, with the embeds left empty so its loaders fall through
# to the files placed beside it below.
$portableScript = Join-Path -Path $stageFolder -ChildPath 'Toolkit.ps1'
& $buildScript -NoEmbed -Version $Version -OutputPath $portableScript | Out-Null

# The build writes a .sha256 sidecar next to its output; the package carries a
# single SHA256SUMS.txt instead, so remove the stray one.
Remove-Item -LiteralPath ($portableScript + '.sha256') -Force -ErrorAction SilentlyContinue

# The data and the interface the script reads from disk.
Copy-Item -LiteralPath $dataFolder -Destination (Join-Path $stageFolder 'data') -Recurse -Force
Copy-Item -LiteralPath $xamlFile   -Destination (Join-Path $stageFolder 'MainWindow.xaml') -Force

# The launcher, verbatim.
Copy-Item -LiteralPath (Join-Path $templateFolder 'Start-Toolkit.cmd') -Destination (Join-Path $stageFolder 'Start-Toolkit.cmd') -Force

# The README, with its version tokens filled in.
$readme = Get-Content -LiteralPath (Join-Path $templateFolder 'README.txt') -Raw
$readme = $readme.
    Replace('{{VERSION}}', $Version).
    Replace('{{COMMIT}}',  $commit).
    Replace('{{DATE}}',    (Get-Date -Format 'yyyy-MM-dd'))
Set-Content -LiteralPath (Join-Path $stageFolder 'README.txt') -Value $readme -Encoding UTF8

# Sign the readable script before the checksums are taken, so the checksum
# covers the signed bytes.
if ($signing) {
    Write-Host ''
    & $signScript -Path $portableScript @signArgs | Out-Null
    Write-Host ''
}

# ---------------------------------------------------------------------------
# 3. Checksums for every file in the folder
# ---------------------------------------------------------------------------

$sumsPath = Join-Path -Path $stageFolder -ChildPath 'SHA256SUMS.txt'
$sumLines = New-Object System.Collections.Generic.List[string]

# Relative paths are resolved from inside the folder, so an 8.3 short path in
# $stageFolder cannot throw the offset off the way a raw substring would.
Push-Location -LiteralPath $stageFolder

try {
    Get-ChildItem -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            $relative = (Resolve-Path -LiteralPath $_.FullName -Relative) -replace '^\.[\\/]', '' -replace '\\', '/'
            $hash     = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            $sumLines.Add(('{0}  {1}' -f $hash, $relative))
        }
}
finally {
    Pop-Location
}

Set-Content -LiteralPath $sumsPath -Value $sumLines -Encoding ASCII

# ---------------------------------------------------------------------------
# 4. Zip the folder
# ---------------------------------------------------------------------------

$zipPath = Join-Path -Path $OutputFolder -ChildPath ('{0}.zip' -f $folderName)

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Compress-Archive -Path (Join-Path $stageFolder '*') -DestinationPath $zipPath -CompressionLevel Optimal

$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash

Write-Host ('  Folder : {0}' -f $stageFolder) -ForegroundColor Green
Write-Host ('  Zip    : {0}' -f $zipPath) -ForegroundColor Green
Write-Host ('  SHA256 : {0}' -f $zipHash)

# ---------------------------------------------------------------------------
# 5. The single-file build
# ---------------------------------------------------------------------------

if (-not $SkipSingleFile) {

    Write-Host ''
    Write-Host '  Building the single-file edition' -ForegroundColor Cyan

    $singleFile = Join-Path -Path $OutputFolder -ChildPath ('Toolkit-{0}.ps1' -f $Version)
    & $buildScript -Version $Version -OutputPath $singleFile | Out-Null

    if ($signing) {
        Write-Host ''
        & $signScript -Path $singleFile @signArgs | Out-Null
    }

    # The build wrote a sidecar for the file before signing; refresh it so it
    # matches the signed bytes.
    $singleHash = (Get-FileHash -LiteralPath $singleFile -Algorithm SHA256).Hash
    Set-Content -LiteralPath ($singleFile + '.sha256') -Value ('{0}  {1}' -f $singleHash, (Split-Path $singleFile -Leaf)) -Encoding ASCII

    Write-Host ''
    Write-Host ('  Single : {0}' -f $singleFile) -ForegroundColor Green
    Write-Host ('  SHA256 : {0}' -f $singleHash)
}

Write-Host ''
Write-Host 'Portable build complete.' -ForegroundColor Green

if (-not $signing) {
    Write-Host ''
    Write-Host 'This build is unsigned. To sign it, create a certificate with' -ForegroundColor Yellow
    Write-Host '  .\build\New-CodeSigningCertificate.ps1' -ForegroundColor Yellow
    Write-Host 'then run this again with -Thumbprint <thumbprint> (or -PfxPath).' -ForegroundColor Yellow
}
