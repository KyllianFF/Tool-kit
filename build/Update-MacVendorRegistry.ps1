<#
.SYNOPSIS
    Rebuilds data/mac-vendors.tsv.gz from the IEEE registration authority.

.DESCRIPTION
    The MAC vendor lookup of the Network page reads a compressed copy of the
    three public IEEE registries, so it answers offline and nothing about a
    device leaves the machine:

      - MA-L, the 24 bit blocks most manufacturers hold (oui.csv);
      - MA-M, the 28 bit blocks (mam.csv);
      - MA-S, the 36 bit blocks (oui36.csv).

    Each line of the result is a prefix of 6, 7 or 9 hexadecimal digits, a
    tab and the organisation, with its legal suffix taken off: "Cisco
    Systems" reads better in a neighbour table than "Cisco Systems, Inc". The
    lines are sorted and the file is gzip compressed; the build embeds it as
    bytes and the toolkit decompresses it on the first lookup.

    Run it now and then: the IEEE adds a few hundred blocks a month.

.PARAMETER SourceFolder
    A folder that already holds oui.csv, mam.csv and oui36.csv. Without it,
    the three files are downloaded from standards-oui.ieee.org.

.PARAMETER OutputPath
    Where to write the compressed registry.

.EXAMPLE
    .\build\Update-MacVendorRegistry.ps1
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $SourceFolder = '',

    [Parameter()]
    [string] $OutputPath = ''
)

$ErrorActionPreference = 'Stop'

# Worked out here rather than as the default value: Windows PowerShell 5.1
# leaves $PSScriptRoot empty while it binds the parameters.
if (-not $OutputPath) {
    $OutputPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'data\mac-vendors.tsv.gz'
}

$registries = @(
    [pscustomobject] @{ Name = 'MA-L'; File = 'oui.csv';   Uri = 'https://standards-oui.ieee.org/oui/oui.csv';     Digits = 6 }
    [pscustomobject] @{ Name = 'MA-M'; File = 'mam.csv';   Uri = 'https://standards-oui.ieee.org/oui28/mam.csv';   Digits = 7 }
    [pscustomobject] @{ Name = 'MA-S'; File = 'oui36.csv'; Uri = 'https://standards-oui.ieee.org/oui36/oui36.csv'; Digits = 9 }
)

$folder = $SourceFolder

if (-not $folder) {

    $folder = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ('ieee-registries-{0}' -f [guid]::NewGuid().ToString('N'))
    New-Item -Path $folder -ItemType Directory -Force | Out-Null

    foreach ($registry in $registries) {
        Write-Host ('  Downloading {0}' -f $registry.Uri)
        # The IEEE server refuses requests without a browser user agent.
        Invoke-WebRequest -Uri $registry.Uri -OutFile (Join-Path $folder $registry.File) -UseBasicParsing `
            -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' -TimeoutSec 300
    }
}

# Legal forms at the end of a name, taken off one after the other so
# "Example Technology Co., Ltd." ends as "Example Technology".
$suffix = '[\s,]+(Inc|Incorporated|Corporation|Corp|Co\.?,?\s*Ltd|Company\s+Limited|Co\.?,?\s*Limited|Ltd|Limited|LLC|L\.L\.C|GmbH(\s*&\s*Co\.?\s*KG)?|KG|S\.?A\.?S|S\.?A|S\.?L|S\.?p\.?A|S\.?r\.?l|AG|B\.?V|N\.?V|Pty\.?(\s*Ltd)?|K\.?K|Oy|AB|A/S|AS|ApS|s\.r\.o|Sp\.\s*z\s*o\.?o|Co|PLC|Pvt\.?(\s*Ltd)?|Private)\.?$'

$entries = New-Object System.Collections.Generic.List[string]
$counts  = [ordered] @{}

foreach ($registry in $registries) {

    $path  = Join-Path -Path $folder -ChildPath $registry.File
    $count = 0

    foreach ($row in (Import-Csv -LiteralPath $path)) {

        $prefix = ([string] $row.Assignment).Trim().ToUpperInvariant()

        if ($prefix -notmatch ('^[0-9A-F]{{{0}}}$' -f $registry.Digits)) {
            continue
        }

        $name = (([string] $row.'Organization Name') -replace '\s+', ' ').Trim()

        do {
            $previous = $name
            $name     = ($name -replace $suffix, '').Trim(' ', ',')
        }
        while ($name -ne $previous -and $name)

        if (-not $name) {
            $name = ([string] $row.'Organization Name').Trim()
        }

        $entries.Add(('{0}{1}{2}' -f $prefix, "`t", $name))
        $count++
    }

    $counts[$registry.Name] = $count
}

$sorted = $entries.ToArray()
[Array]::Sort($sorted, [StringComparer]::Ordinal)

$header = @(
    '# MAC address vendors from the IEEE registration authority: MA-L, MA-M and MA-S.'
    ('# Retrieved {0}. Rebuild with build/Update-MacVendorRegistry.ps1.' -f (Get-Date -Format 'yyyy-MM-dd'))
)

$text  = (@($header) + @($sorted)) -join "`n"
$bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($text + "`n")

$memory = New-Object System.IO.MemoryStream

$gzip = New-Object System.IO.Compression.GZipStream($memory, [System.IO.Compression.CompressionLevel]::Optimal, $true)
$gzip.Write($bytes, 0, $bytes.Length)
$gzip.Dispose()

[IO.File]::WriteAllBytes($OutputPath, $memory.ToArray())

Write-Host ('  {0}' -f (($counts.Keys | ForEach-Object { '{0}: {1}' -f $_, $counts[$_] }) -join ', '))
Write-Host ('  {0} prefixes, {1:N0} bytes of text, {2:N0} bytes compressed' -f $sorted.Count, $bytes.Length, $memory.Length)
Write-Host ('  Written to {0}' -f $OutputPath)
