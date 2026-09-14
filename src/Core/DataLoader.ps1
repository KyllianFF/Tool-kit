<#
    Toolkit - Core / Data loader

    Every list the user sees (applications, tweaks, fixes, network notes,
    vendor commands) is data, not code. Adding an application must never mean
    editing a function.

    Two sources are supported and tried in this order:

      1. Catalogs embedded at build time, used by the single file release.
      2. The data folder next to the sources, used during development.

    The embedded copy wins so that a released build is self contained and
    cannot be influenced by stray JSON left in the working directory.
#>

# Filled by build/Build-Toolkit.ps1. Key = catalog name, value = JSON text.
$script:TkEmbeddedCatalogs = @{}

# Filled by build/Build-Toolkit.ps1. Key = resource name, such as
# mac-vendors.tsv, value = base64 of the gzip compressed file.
$script:TkEmbeddedResources = @{}

# Decompressed resources, so each is inflated once per session.
$script:TkDataResourceCache = @{}

<#
.SYNOPSIS
    Loads one catalog by name.

.DESCRIPTION
    Returns the parsed JSON. Results are cached in the context so a page
    switch does not re-read the disk. A missing catalog is a warning, not a
    fatal error: the matching page simply renders empty.

.PARAMETER Name
    Catalog file name without the .json extension, for example 'applications'.

.PARAMETER Force
    Bypasses the cache and re-reads the source.

.OUTPUTS
    PSCustomObject, or $null when the catalog cannot be loaded.
#>
function Import-TkCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [switch] $Force
    )

    $ctx = Get-TkContext

    if (-not $Force -and $ctx.Catalogs.ContainsKey($Name)) {
        return $ctx.Catalogs[$Name]
    }

    $json = $null

    # --- Source 1: embedded in a compiled build ---------------------------
    if ($script:TkEmbeddedCatalogs.ContainsKey($Name)) {
        $json = $script:TkEmbeddedCatalogs[$Name]
    }

    # --- Source 2: data folder during development -------------------------
    if ($null -eq $json) {

        $path = Get-TkCatalogPath -Name $Name

        if ($path) {

            try {
                $json = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
            }
            catch {
                Write-TkLog -Level Error -Category 'Data' -Message (
                    'Could not read catalog "{0}": {1}' -f $Name, $_.Exception.Message
                )
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($json)) {

        Write-TkLog -Level Warning -Category 'Data' -Message (
            'Catalog "{0}" was not found. The matching page will be empty.' -f $Name
        )

        return $null
    }

    try {
        $parsed = $json | ConvertFrom-Json -ErrorAction Stop
        $ctx.Catalogs[$Name] = $parsed

        Write-TkLog -Level Debug -Category 'Data' -Message ('Catalog "{0}" loaded.' -f $Name)

        return $parsed
    }
    catch {
        Write-TkLog -Level Error -Category 'Data' -Message (
            'Catalog "{0}" is not valid JSON: {1}' -f $Name, $_.Exception.Message
        )

        return $null
    }
}

<#
.SYNOPSIS
    Resolves a catalog file path in the development tree.

.PARAMETER Extension
    The extension of the file: .json for a catalog, .gz for a compressed
    resource.

.OUTPUTS
    System.String, or $null when nothing matched.
#>
function Get-TkCatalogPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [string] $Extension = '.json'
    )

    $fileName = '{0}{1}' -f $Name, $Extension

    # $PSScriptRoot is empty when the code was pasted or piped into a shell,
    # which is exactly the case a released build covers with embedding.
    $roots = @()

    if ($PSScriptRoot) {
        $roots += (Join-Path -Path $PSScriptRoot -ChildPath '..\..\data')
        $roots += (Join-Path -Path $PSScriptRoot -ChildPath '..\data')
        $roots += (Join-Path -Path $PSScriptRoot -ChildPath 'data')
    }

    $roots += (Join-Path -Path (Get-Location).Path -ChildPath 'data')

    foreach ($root in $roots) {

        $candidate = Join-Path -Path $root -ChildPath $fileName

        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return $null
}

<#
.SYNOPSIS
    Reads a compressed data resource as text.

.DESCRIPTION
    A resource is a gzip file in the data folder, embedded as bytes in a
    compiled build: data too large to ship as JSON, such as the MAC vendor
    registry. It is decompressed on the first read and kept for the session.

.PARAMETER Name
    The file name without .gz, for example mac-vendors.tsv.

.OUTPUTS
    System.String, or $null when the resource cannot be read.
#>
function Get-TkDataResource {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    # A background worker has the embedded resources but not the cache.
    if ($null -eq $script:TkDataResourceCache) {
        $script:TkDataResourceCache = @{}
    }

    if ($script:TkDataResourceCache.ContainsKey($Name)) {
        return $script:TkDataResourceCache[$Name]
    }

    $bytes = $null

    if ($script:TkEmbeddedResources -and $script:TkEmbeddedResources.ContainsKey($Name)) {
        $bytes = [Convert]::FromBase64String($script:TkEmbeddedResources[$Name])
    }
    else {
        $path = Get-TkCatalogPath -Name $Name -Extension '.gz'

        if ($path) {
            $bytes = [IO.File]::ReadAllBytes($path)
        }
    }

    if ($null -eq $bytes) {
        Write-TkLog -Level Warning -Category 'Data' -Message ('Resource "{0}" was not found.' -f $Name)
        return $null
    }

    $memory = New-Object System.IO.MemoryStream(, $bytes)
    $gzip   = $null
    $reader = $null

    try {
        $gzip   = New-Object System.IO.Compression.GZipStream($memory, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object System.IO.StreamReader($gzip, (New-Object System.Text.UTF8Encoding($false)))
        $text   = $reader.ReadToEnd()
    }
    catch {
        Write-TkLog -Level Error -Category 'Data' -Message ('Resource "{0}" could not be decompressed: {1}' -f $Name, $_.Exception.Message)
        return $null
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($gzip) { $gzip.Dispose() }
        $memory.Dispose()
    }

    $script:TkDataResourceCache[$Name] = $text

    return $text
}

<#
.SYNOPSIS
    Loads every catalog the interface needs.

.DESCRIPTION
    Called once during start-up so that a broken data file is reported before
    the window appears rather than when the user clicks a tab.
#>
function Import-TkAllCatalogs {
    [CmdletBinding()]
    param()

    $names = @(
        'applications',
        'app-icons',
        'tweaks',
        'fixes',
        'network-knowledge',
        'vendor-commands',
        'vendor-support',
        'bug-checks',
        'bug-check-names',
        'device-problems'
    )

    foreach ($name in $names) {
        Import-TkCatalog -Name $name | Out-Null
    }
}
