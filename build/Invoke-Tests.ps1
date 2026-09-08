<#
.SYNOPSIS
    Runs the toolkit test suite.

.DESCRIPTION
    One entry point used by both a developer and the CI workflow, so that a
    green run locally means the same thing as a green run on a runner.

    It also installs Pester when it is missing. That matters more than it
    looks: Windows PowerShell and PowerShell 7 read modules from different
    per-user paths, so a suite that must run on both cannot rely on a single
    install step performed by whichever host happened to run first.

.PARAMETER ResultPath
    Optional NUnit XML result file, for a CI test report.

.PARAMETER SkipInstall
    Does not attempt to install Pester. Use when the module is already
    present and the machine has no gallery access.

.EXAMPLE
    .\build\Invoke-Tests.ps1

.EXAMPLE
    powershell -NoProfile -File .\build\Invoke-Tests.ps1 -ResultPath results.xml
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $ResultPath,

    [Parameter()]
    [switch] $SkipInstall
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$testPath       = Join-Path -Path $repositoryRoot -ChildPath 'tests'

Write-Host ('Host      : PowerShell {0} ({1})' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
Write-Host ('Tests     : {0}' -f $testPath)

# --- Pester ----------------------------------------------------------------
$pester = Get-Module -ListAvailable -Name Pester |
          Where-Object { $_.Version -ge [version] '5.0.0' } |
          Sort-Object -Property Version -Descending |
          Select-Object -First 1

if (-not $pester -and -not $SkipInstall) {

    Write-Host 'Pester 5 is not available for this host; installing it.'

    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

    Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser `
                   -Force -SkipPublisherCheck -ErrorAction Stop

    $pester = Get-Module -ListAvailable -Name Pester |
              Where-Object { $_.Version -ge [version] '5.0.0' } |
              Sort-Object -Property Version -Descending |
              Select-Object -First 1
}

if (-not $pester) {
    throw 'Pester 5.0.0 or later is required and could not be installed.'
}

Import-Module -Name Pester -MinimumVersion 5.0.0 -Force

Write-Host ('Pester    : {0}' -f (Get-Module Pester).Version)
Write-Host ''

# --- Run -------------------------------------------------------------------
$configuration = New-PesterConfiguration

$configuration.Run.Path         = $testPath
$configuration.Run.PassThru     = $true
$configuration.Output.Verbosity = 'Detailed'

if ($ResultPath) {
    $configuration.TestResult.Enabled      = $true
    $configuration.TestResult.OutputPath   = $ResultPath
    $configuration.TestResult.OutputFormat = 'NUnitXml'
}

$result = Invoke-Pester -Configuration $configuration

Write-Host ''
Write-Host ('Passed {0}, failed {1}, skipped {2}, in {3:N1}s' -f
    $result.PassedCount, $result.FailedCount, $result.SkippedCount,
    $result.Duration.TotalSeconds)

# Explicit exit code rather than Run.Exit, so this script can also be dot
# sourced or called from another script without terminating the session.
if ($result.FailedCount -gt 0) {
    exit 1
}

exit 0
