<#
.SYNOPSIS
    Compiles the toolkit sources into a single self contained script.

.DESCRIPTION
    Produces dist/toolkit.ps1: every source file, the XAML and every data
    catalog concatenated into one script with no external dependency. That
    file is what a one liner downloads and runs.

    Why compile at all, rather than publishing the sources: a script piped
    into Invoke-Expression has no $PSScriptRoot and no working directory it
    can trust, so it cannot load a second file. Everything it needs has to be
    inside it.

    Catalogs and XAML are embedded as base64 rather than as here-strings.
    A here-string breaks the moment a catalog contains its own terminator,
    and base64 cannot collide with the surrounding syntax.

.PARAMETER OutputPath
    Destination of the compiled script.

.PARAMETER Version
    Version stamped into the build. Defaults to the value in Config.ps1.

.PARAMETER SkipAnalysis
    Skips the PSScriptAnalyzer pass.

.EXAMPLE
    .\build\Build-Toolkit.ps1

.EXAMPLE
    .\build\Build-Toolkit.ps1 -Version 1.1.0
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath,

    [Parameter()]
    [string] $Version,

    [Parameter()]
    [switch] $SkipAnalysis
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$orderFile      = Join-Path -Path $PSScriptRoot     -ChildPath 'source-order.txt'
$xamlFile       = Join-Path -Path $repositoryRoot   -ChildPath 'src\UI\MainWindow.xaml'
$dataFolder     = Join-Path -Path $repositoryRoot   -ChildPath 'data'

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $repositoryRoot -ChildPath 'dist\toolkit.ps1'
}

Write-Host 'Building the toolkit' -ForegroundColor Cyan
Write-Host ('  Repository : {0}' -f $repositoryRoot)
Write-Host ('  Output     : {0}' -f $OutputPath)

# ---------------------------------------------------------------------------
# 1. Resolve the build metadata
# ---------------------------------------------------------------------------

$configPath = Join-Path -Path $repositoryRoot -ChildPath 'src\Core\Config.ps1'
$configText = Get-Content -LiteralPath $configPath -Raw

if (-not $Version) {

    if ($configText -match "TkAppVersion\s*=\s*'(?<version>[^']+)'") {
        $Version = $Matches['version']
    }
    else {
        $Version = '0.0.0'
    }
}

# The commit is informational: a build made outside a checkout still works.
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
}
finally {
    Pop-Location

    # A failed git call leaves a non zero exit code behind, which would become
    # the exit code of this build and fail a CI step that actually succeeded.
    $global:LASTEXITCODE = 0
}

Write-Host ('  Version    : {0} ({1})' -f $Version, $commit)

# ---------------------------------------------------------------------------
# 2. Read the sources in order
# ---------------------------------------------------------------------------

$sourceFiles = @()

foreach ($line in (Get-Content -LiteralPath $orderFile)) {

    $trimmed = $line.Trim()

    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
        continue
    }

    $path = Join-Path -Path $repositoryRoot -ChildPath ($trimmed -replace '/', '\')

    if (-not (Test-Path -LiteralPath $path)) {
        throw ('Missing source file: {0}' -f $path)
    }

    $sourceFiles += $path
}

Write-Host ('  Sources    : {0} files' -f $sourceFiles.Count)

# ---------------------------------------------------------------------------
# 3. Static analysis
# ---------------------------------------------------------------------------

if (-not $SkipAnalysis) {

    if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {

        Write-Host '  Analysing...' -NoNewline

        Import-Module PSScriptAnalyzer -ErrorAction Stop

        $findings = @()

        foreach ($file in $sourceFiles) {

            # Excluded rules, each for a stated reason:
            #  - WriteHost      : this is an interactive tool, not a pipeline
            #                     component; console output is the point.
            #  - ShouldProcess  : already implemented where it matters; the
            #                     rule also fires on read only helpers whose
            #                     verb merely looks state changing.
            #  - InvokeExpression: not used in the sources; the rule fires on
            #                     the documented iex one liner in comments.
            #  - SingularNouns  : Settings, Bytes and Catalogs are correct
            #                     English plurals for what those functions
            #                     return.
            #  - UnusedParameter: fires on every parameter captured by a
            #                     GetNewClosure or used inside a dispatcher
            #                     script block, which the analyser cannot see
            #                     into. Too noisy to be useful here.
            $findings += Invoke-ScriptAnalyzer -Path $file -Severity @('Error', 'Warning') `
                                               -ExcludeRule @(
                                                   'PSAvoidUsingWriteHost',
                                                   'PSUseShouldProcessForStateChangingFunctions',
                                                   'PSAvoidUsingInvokeExpression',
                                                   'PSUseSingularNouns',
                                                   'PSReviewUnusedParameter'
                                               )
        }

        $errors = @($findings | Where-Object { $_.Severity -eq 'Error' })

        Write-Host (' {0} finding(s), {1} error(s)' -f $findings.Count, $errors.Count)

        foreach ($finding in $findings) {

            $colour = if ($finding.Severity -eq 'Error') { 'Red' } else { 'Yellow' }

            Write-Host ('    [{0}] {1}:{2} {3}' -f
                $finding.Severity, (Split-Path $finding.ScriptName -Leaf),
                $finding.Line, $finding.RuleName) -ForegroundColor $colour
        }

        if ($errors.Count -gt 0) {
            throw 'The analyser reported errors. Fix them before building.'
        }
    }
    else {
        Write-Host '  PSScriptAnalyzer is not installed; analysis skipped.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 4. Embed the XAML and the catalogs
# ---------------------------------------------------------------------------

function ConvertTo-EmbeddedString {
    <#
    .SYNOPSIS
        Encodes text as base64 so it can be embedded without escaping.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
}

$xamlBase64 = ConvertTo-EmbeddedString -Text (Get-Content -LiteralPath $xamlFile -Raw -Encoding UTF8)

$catalogLines = @()

foreach ($catalog in (Get-ChildItem -LiteralPath $dataFolder -Filter '*.json' -File)) {

    $json = Get-Content -LiteralPath $catalog.FullName -Raw -Encoding UTF8

    # Fail early on a malformed catalog rather than shipping a build whose
    # pages silently come up empty.
    try {
        $json | ConvertFrom-Json -ErrorAction Stop | Out-Null
    }
    catch {
        throw ('{0} is not valid JSON: {1}' -f $catalog.Name, $_.Exception.Message)
    }

    $name = [IO.Path]::GetFileNameWithoutExtension($catalog.Name)

    $catalogLines += "    '{0}' = '{1}'" -f $name, (ConvertTo-EmbeddedString -Text $json)
}

Write-Host ('  Catalogs   : {0} embedded' -f $catalogLines.Count)

# ---------------------------------------------------------------------------
# 5. Assemble
# ---------------------------------------------------------------------------

$builder = New-Object System.Text.StringBuilder

[void] $builder.AppendLine(@"
<#
    Toolkit $Version ($commit)

    Generated by build/Build-Toolkit.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').
    Do not edit this file: change the sources under src/ and build again.

    Sources: https://github.com/KyllianFF/Tool-kit
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] `$SourceUri,

    [Parameter()]
    [switch] `$NoGui
)

`$ErrorActionPreference = 'Stop'

"@)

# --- Sources ---------------------------------------------------------------
foreach ($file in $sourceFiles) {

    $relative = $file.Substring($repositoryRoot.Length).TrimStart('\')

    [void] $builder.AppendLine('# ' + ('=' * 74))
    [void] $builder.AppendLine('# Source: ' + ($relative -replace '\\', '/'))
    [void] $builder.AppendLine('# ' + ('=' * 74))
    [void] $builder.AppendLine('')
    [void] $builder.AppendLine((Get-Content -LiteralPath $file -Raw -Encoding UTF8))
    [void] $builder.AppendLine('')
}

# --- Embedded resources ----------------------------------------------------
[void] $builder.AppendLine(@"
# ==========================================================================
# Embedded resources
# ==========================================================================

# Build metadata, overriding the development defaults declared in Config.ps1.
`$script:TkAppVersion = '$Version'
`$script:TkAppCommit  = '$commit'

# Interface markup, base64 encoded so no quoting can collide with the XAML.
`$script:TkEmbeddedXaml = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('$xamlBase64')
)

# Data catalogs, keyed by name and decoded on first use.
`$script:TkEmbeddedCatalogsRaw = @{
$($catalogLines -join "`r`n")
}

`$script:TkEmbeddedCatalogs = @{}

foreach (`$catalogName in `$script:TkEmbeddedCatalogsRaw.Keys) {

    `$script:TkEmbeddedCatalogs[`$catalogName] = [System.Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String(`$script:TkEmbeddedCatalogsRaw[`$catalogName])
    )
}

# ==========================================================================
# Entry point
# ==========================================================================

# The file the operator ran, used by an elevation restart. Empty when this
# script was piped straight into the shell, in which case the source URL is
# replayed instead.
`$script:TkEntryScript = `$PSCommandPath

if (`$NoGui) {
    Start-Toolkit -NoGui -SourceUri `$SourceUri
}
else {
    Start-Toolkit -SourceUri `$SourceUri
}
"@)

# ---------------------------------------------------------------------------
# 6. Write and verify
# ---------------------------------------------------------------------------

$outputFolder = Split-Path -Path $OutputPath -Parent

if (-not (Test-Path -LiteralPath $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

# Line endings are normalised to LF before writing. StringBuilder.AppendLine
# uses Environment.NewLine, so a build on Windows and a build on a Linux
# runner would otherwise produce different bytes, different hashes, and a
# published SHA256 that only matches on one of them.
$content = $builder.ToString() -replace "`r`n", "`n"

# UTF-8 without a byte order mark: a BOM in the middle of a piped download
# is parsed as content and breaks the one liner.
$encoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $content, $encoding)

# Parse the result. A build that produces a syntactically invalid script must
# fail here, not on a user machine.
$parseErrors = $null
$tokens      = $null

[System.Management.Automation.Language.Parser]::ParseFile($OutputPath, [ref] $tokens, [ref] $parseErrors) | Out-Null

if ($parseErrors -and $parseErrors.Count -gt 0) {

    foreach ($parseError in $parseErrors) {
        Write-Host ('    {0} at line {1}' -f $parseError.Message, $parseError.Extent.StartLineNumber) -ForegroundColor Red
    }

    throw 'The compiled script does not parse. The build is not usable.'
}

$sizeKb = [math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1KB, 1)
$sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash

Write-Host ''
Write-Host 'Build succeeded.' -ForegroundColor Green
Write-Host ('  File   : {0}' -f $OutputPath)
Write-Host ('  Size   : {0} KB' -f $sizeKb)
Write-Host ('  SHA256 : {0}' -f $sha256)
Write-Host ''
Write-Host 'Publish the SHA256 alongside the release so users can verify what they run.' -ForegroundColor Cyan

# Written next to the build so a release workflow can attach it.
Set-Content -LiteralPath ($OutputPath + '.sha256') -Value ('{0}  {1}' -f $sha256, (Split-Path $OutputPath -Leaf)) -Encoding ASCII
