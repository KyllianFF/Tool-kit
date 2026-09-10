<#
.SYNOPSIS
    Checks that every application in the catalog still resolves in winget.

.DESCRIPTION
    The catalog is data, and a package identifier is only correct until the
    publisher renames it or the manifest is withdrawn. A dead identifier
    produces the worst possible failure mode: the install appears to run,
    winget returns a large negative number, and nothing says which of the two
    hundred entries was wrong.

    This asks winget to resolve each one and reports the ones that do not.
    It is deliberately not part of the normal build: it needs the network,
    it takes several minutes, and a transient source outage would otherwise
    fail a build that is perfectly good.

    Store product identifiers are resolved against msstore, everything else
    against winget, matching what the installer does.

.PARAMETER Path
    Application catalog. Defaults to data/applications.json.

.PARAMETER TimeoutSeconds
    Per package timeout.

.PARAMETER PassThru
    Returns the result objects as well as printing the summary.

.EXAMPLE
    .\build\Test-TkPackage.ps1

.EXAMPLE
    .\build\Test-TkPackage.ps1 -PassThru | Where-Object { -not $_.Resolves }
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $Path,

    [Parameter()]
    [ValidateRange(5, 120)]
    [int] $TimeoutSeconds = 25,

    [Parameter()]
    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent

if (-not $Path) {
    $Path = Join-Path -Path $repositoryRoot -ChildPath 'data\applications.json'
}

if (-not (Get-Command -Name 'winget' -ErrorAction SilentlyContinue)) {
    throw 'winget is not available on this machine, so the catalog cannot be checked.'
}

$catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json

Write-Host ('Checking {0} package identifiers against winget.' -f @($catalog.applications).Count) -ForegroundColor Cyan
Write-Host 'This needs the network and takes a few minutes.'
Write-Host ''

# A Store product identifier only exists in msstore; everything else is in
# the winget source. Resolving against the wrong one always fails.
$storePattern = '^[9X][A-Z0-9]{11}$'

$results = @()
$index   = 0

foreach ($application in $catalog.applications) {

    $index++

    $source = if ($application.packageId -cmatch $storePattern) { 'msstore' } else { 'winget' }

    $arguments = @(
        'show',
        '--id', $application.packageId,
        '--exact',
        '--source', $source,
        '--disable-interactivity',
        '--accept-source-agreements'
    )

    $process = New-Object System.Diagnostics.ProcessStartInfo
    $process.FileName               = 'winget'
    $process.RedirectStandardOutput = $true
    $process.RedirectStandardError  = $true
    $process.UseShellExecute        = $false
    $process.CreateNoWindow         = $true
    $process.Arguments              = ($arguments -join ' ')

    $runner = New-Object System.Diagnostics.Process
    $runner.StartInfo = $process

    $resolves = $false
    $detail   = ''

    try {
        [void] $runner.Start()

        $output = $runner.StandardOutput.ReadToEndAsync()
        $null   = $runner.StandardError.ReadToEndAsync()

        if ($runner.WaitForExit($TimeoutSeconds * 1000)) {
            $resolves = ($runner.ExitCode -eq 0)
            $detail   = if ($resolves) { '' } else { 'exit code {0}' -f $runner.ExitCode }
        }
        else {
            try { $runner.Kill() } catch { $null = $_ }
            $detail = 'timed out'
        }

        $null = $output.GetAwaiter().GetResult()
    }
    catch {
        $detail = $_.Exception.Message
    }
    finally {
        $runner.Dispose()
    }

    $results += [pscustomobject]@{
        Name      = $application.name
        PackageId = $application.packageId
        Category  = $application.category
        Source    = $source
        Resolves  = $resolves
        Detail    = $detail
    }

    $marker = if ($resolves) { 'ok  ' } else { 'MISS' }
    $colour = if ($resolves) { 'DarkGray' } else { 'Red' }

    Write-Host ('  [{0,3}/{1}] {2} {3,-40} {4}' -f
        $index, @($catalog.applications).Count, $marker, $application.packageId, $detail) -ForegroundColor $colour
}

$failed = @($results | Where-Object { -not $_.Resolves })

Write-Host ''
Write-Host ('{0} of {1} identifiers resolve.' -f ($results.Count - $failed.Count), $results.Count) -ForegroundColor Cyan

if ($failed.Count -gt 0) {

    Write-Host ''
    Write-Host 'These do not resolve and would fail at install time:' -ForegroundColor Red

    foreach ($entry in $failed) {
        Write-Host ('  {0,-28} {1,-40} {2} ({3})' -f $entry.Name, $entry.PackageId, $entry.Detail, $entry.Source) -ForegroundColor Red
    }

    Write-Host ''
    Write-Host 'Search for the current identifier with: winget search "<name>"' -ForegroundColor Yellow
}

if ($PassThru) {
    return $results
}

exit $(if ($failed.Count -gt 0) { 1 } else { 0 })
