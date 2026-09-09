<#
.SYNOPSIS
    Development launcher for the toolkit.

.DESCRIPTION
    Loads every source file in the order declared by build/source-order.txt
    and starts the application. Use this while working on the code; the
    single file build in dist/ is what end users run.

    Dot sourcing keeps every function in this script scope, which is exactly
    what the compiled build produces, so the two behave identically.

.PARAMETER NoGui
    Loads the functions without showing a window. Handy for trying a function
    in the console, and used by the test suite.

.PARAMETER Elevated
    Restarts the launcher elevated before loading anything.

.EXAMPLE
    .\toolkit.ps1

.EXAMPLE
    .\toolkit.ps1 -NoGui
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch] $NoGui,

    [Parameter()]
    [switch] $Elevated
)

# Strict mode is deliberately not enabled. The catalogs are JSON documents in
# which most fields are optional, and under Set-StrictMode reading an absent
# property throws instead of returning $null. That would turn every optional
# catalog field into a required one, which is the opposite of the point.
$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$orderFile      = Join-Path -Path $repositoryRoot -ChildPath 'build\source-order.txt'

if (-not (Test-Path -LiteralPath $orderFile)) {
    throw ('The load order file is missing: {0}' -f $orderFile)
}

# --- Load the sources ------------------------------------------------------
$loaded = 0

foreach ($line in (Get-Content -LiteralPath $orderFile)) {

    $trimmed = $line.Trim()

    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
        continue
    }

    $path = Join-Path -Path $repositoryRoot -ChildPath ($trimmed -replace '/', '\')

    if (-not (Test-Path -LiteralPath $path)) {
        throw ('Source file listed in the load order is missing: {0}' -f $path)
    }

    . $path
    $loaded++
}

Write-Verbose ('{0} source files loaded.' -f $loaded)

# Record the script the operator ran, so an elevation restart re-runs this
# launcher rather than whichever source file declared the elevation function.
$script:TkEntryScript = $PSCommandPath

# --- Optional elevation ----------------------------------------------------
if ($Elevated -and -not (Test-TkIsElevated)) {

    Initialize-TkContext | Out-Null

    if (Invoke-TkElevation -Confirm:$false) {
        return
    }
}

# --- Start -----------------------------------------------------------------
if ($NoGui) {
    Start-Toolkit -NoGui
}
else {
    Start-Toolkit
}
