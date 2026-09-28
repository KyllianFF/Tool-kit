<#
.SYNOPSIS
    Writes the notes of a release: its SHA-256 and its verified launch command.

.DESCRIPTION
    Run once the build of the release is merged and tagged. The notes carry
    the SHA-256 of dist/toolkit.ps1 at that tag and the verified launch
    command pinned to it: the command downloads the build of the tag, checks
    its SHA-256 and runs it only if it matches, in memory. The command is
    produced by New-TkLaunchCommand, the same function the toolkit uses for
    its own elevation, so both always agree.

    Publish the notes with the release, for example:

        .\build\New-ReleaseNotes.ps1 -Tag v1.0.0 -OutFile notes.md
        gh release create v1.0.0 --title "Toolkit 1.0.0" --notes-file notes.md

.PARAMETER Tag
    The release tag, v followed by the version.

.PARAMETER OutFile
    Writes the notes to this file instead of the output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^v\d+\.\d+\.\d+$')]
    [string] $Tag,

    [Parameter()]
    [string] $OutFile
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent

# The generator the toolkit itself uses.
. (Join-Path -Path $repositoryRoot -ChildPath 'src\Core\Launch.ps1')

$manifestPath = Join-Path -Path $repositoryRoot -ChildPath 'dist\toolkit.ps1.version.json'
$manifest     = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version      = [string] $manifest.version
$sha256       = ([string] $manifest.sha256).ToUpperInvariant()

if ($Tag -ne ('v{0}' -f $version)) {
    throw ('The tag {0} does not match the version of the build, {1}.' -f $Tag, $version)
}

# The file at the tag must be the one the manifest describes.
$actual = (Get-FileHash -LiteralPath (Join-Path -Path $repositoryRoot -ChildPath 'dist\toolkit.ps1') -Algorithm SHA256).Hash
if ($actual -ne $sha256) {
    throw 'dist\toolkit.ps1 does not match its manifest: build again before writing the notes.'
}

$uri     = 'https://raw.githubusercontent.com/KyllianFF/Tool-kit/{0}/dist/toolkit.ps1' -f $Tag
$command = New-TkLaunchCommand -SourceUri $uri -Sha256 $sha256
$fence   = '```'

$notes = @"
## Toolkit $version

SHA-256 of ``dist/toolkit.ps1`` at this tag:

    $sha256

### Verified launch, pinned to this release

The command downloads the build of this release, checks its SHA-256, and runs it only if it matches. Nothing is written to disk. **Restart as administrator** and every UAC prompt download the same address again and run it only if the hash still matches, so the elevated process is always this build.

${fence}powershell
$command
$fence

The plain one-liner, ``irm $uri | iex``, runs the same build without checking it.

### Download, check, then run

${fence}powershell
`$out = "`$env:TEMP\toolkit-$version.ps1"
Invoke-WebRequest -Uri '$uri' -OutFile `$out -UseBasicParsing
if ((Get-FileHash -Path `$out -Algorithm SHA256).Hash -ne '$sha256') { throw 'SHA-256 mismatch' }
powershell -NoProfile -ExecutionPolicy Bypass -STA -File `$out
$fence
"@

if ($OutFile) {
    [System.IO.File]::WriteAllText($OutFile, $notes, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ('Release notes written to {0}' -f $OutFile)
}
else {
    $notes
}
