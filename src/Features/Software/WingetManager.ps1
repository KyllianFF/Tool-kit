<#
    Toolkit - Features / Software management

    Thin, defensive wrapper around winget.

    Two rules govern this module:

      1. Package identifiers are validated before they reach a command line.
         The catalog is data, and data can be edited; a package id that can
         contain a space or a quote is an argument injection waiting to
         happen.
      2. Only the Microsoft "winget" source is used by default. A package
         resolved from an unexpected source is a supply chain problem, not a
         convenience.
#>

# A winget identifier is a dotted name. Anything outside this set is rejected
# before the value is used to build a command line.
$script:TkPackageIdPattern = '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}(\.[A-Za-z0-9._+-]{1,128})*$'

# A Microsoft Store product identifier: twelve characters starting with 9 or X.
# These exist only in the msstore source, so pinning every install to the
# winget source made them fail with "no applicable installer found".
$script:TkStoreIdPattern = '^[9X][A-Z0-9]{11}$'

<#
.SYNOPSIS
    Tells whether winget is available and usable.

.OUTPUTS
    PSCustomObject with Available and Version.
#>
function Get-TkWingetStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if (-not (Test-TkCommand -Name 'winget')) {

        return [pscustomobject]@{
            Available = $false
            Version   = $null
            Message   = 'winget is not installed. Install the App Installer package from the Microsoft Store.'
        }
    }

    $result = Invoke-TkProcess -FilePath 'winget' -ArgumentList @('--version') -TimeoutSeconds 30

    if ($result.ExitCode -ne 0) {

        return [pscustomobject]@{
            Available = $false
            Version   = $null
            Message   = 'winget is present but did not respond correctly.'
        }
    }

    return [pscustomobject]@{
        Available = $true
        Version   = $result.StandardOutput.Trim()
        Message   = 'Ready.'
    }
}

<#
.SYNOPSIS
    Validates a winget package identifier.

.DESCRIPTION
    Central gate: every function in this module that builds a winget command
    line calls it first. Keeping the check in one place is what makes the
    guarantee auditable.

.OUTPUTS
    System.Boolean
#>
function Test-TkPackageId {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $PackageId
    )

    if ([string]::IsNullOrWhiteSpace($PackageId)) {
        return $false
    }

    if ($PackageId -notmatch $script:TkPackageIdPattern) {

        Write-TkLog -Level Error -Category 'Software' -Message (
            'Rejected package identifier "{0}": it does not match the expected format.' -f $PackageId
        )

        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Installs a package with winget.

.DESCRIPTION
    Runs a non interactive install pinned to the winget source, accepting the
    package and source agreements because there is no console to accept them
    on. Exit code 0 and the "no applicable upgrade" codes are treated as
    success, which is what makes a re-run of a batch install idempotent.

.PARAMETER PackageId
    Validated winget identifier.

.PARAMETER Scope
    Machine or User. Machine installs require elevation.

.OUTPUTS
    System.Boolean
#>
function Install-TkWingetPackage {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $PackageId,

        [Parameter()]
        [ValidateSet('Machine', 'User', 'Any')]
        [string] $Scope = 'Any'
    )

    if (-not (Test-TkPackageId -PackageId $PackageId)) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($PackageId, 'winget install')) {
        return $false
    }

    # The source is chosen from the shape of the identifier rather than being
    # fixed. Pinning a source is what keeps an install from being resolved
    # somewhere unexpected, but a Store product id only exists in msstore and
    # pinning winget for it guarantees failure.
    $source = if ($PackageId -cmatch $script:TkStoreIdPattern) { 'msstore' } else { 'winget' }

    $arguments = @(
        'install',
        '--id', $PackageId,
        '--exact',
        '--source', $source,
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--disable-interactivity',
        '--silent'
    )

    if ($Scope -ne 'Any') {
        $arguments += @('--scope', $Scope.ToLower())
    }

    $stopwatch = Start-TkOperation -Name ('Install {0}' -f $PackageId) -Category 'Software'
    $result    = Invoke-TkProcess -FilePath 'winget' -ArgumentList $arguments -TimeoutSeconds 1800

    # 0                 success
    # -1978335189       no applicable update found (already current)
    # -1978335135       package already installed
    # -1978334956       already installed, nothing to do
    $acceptable = @(0, -1978335189, -1978335135, -1978334956)
    $success    = $acceptable -contains $result.ExitCode

    if (-not $success) {

        # winget reports failures as a large negative number and nothing else
        # useful on stderr, so the common ones are translated here.
        $reason = switch ($result.ExitCode) {
            -1978335212 { 'no applicable installer for this machine, or the package is not in the {0} source' -f $source ; break }
            -1978335216 { 'no package matched that identifier in the {0} source' -f $source ; break }
            -1978335215 { 'more than one package matched' ; break }
            -1978335231 { 'the installer failed' ; break }
            -1978334967 { 'the machine must be restarted to finish' ; break }
            default     { Get-TkFirstLine -Text ($result.StandardError + $result.StandardOutput) }
        }

        Write-TkLog -Level Error -Category 'Software' -Message (
            'winget install {0} failed ({1}): {2}' -f $PackageId, $result.ExitCode, $reason
        )
    }

    Stop-TkOperation -Name ('Install {0}' -f $PackageId) -Stopwatch $stopwatch `
                     -Category 'Software' -Success $success

    return $success
}

<#
.SYNOPSIS
    Removes a package with winget.

.OUTPUTS
    System.Boolean
#>
function Uninstall-TkWingetPackage {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $PackageId
    )

    if (-not (Test-TkPackageId -PackageId $PackageId)) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($PackageId, 'winget uninstall')) {
        return $false
    }

    $arguments = @(
        'uninstall',
        '--id', $PackageId,
        '--exact',
        '--accept-source-agreements',
        '--disable-interactivity',
        '--silent'
    )

    $stopwatch = Start-TkOperation -Name ('Uninstall {0}' -f $PackageId) -Category 'Software'
    $result    = Invoke-TkProcess -FilePath 'winget' -ArgumentList $arguments -TimeoutSeconds 900

    $success = ($result.ExitCode -eq 0)

    if (-not $success) {
        Write-TkLog -Level Error -Category 'Software' -Message (
            'winget uninstall {0} failed with exit code {1}.' -f $PackageId, $result.ExitCode
        )
    }

    Stop-TkOperation -Name ('Uninstall {0}' -f $PackageId) -Stopwatch $stopwatch `
                     -Category 'Software' -Success $success

    return $success
}

<#
.SYNOPSIS
    Installs several packages in sequence and reports per package results.

.DESCRIPTION
    Sequential on purpose. Parallel winget installs contend for the same
    installer mutex and produce failures that look like package problems.

.PARAMETER PackageId
    Identifiers to install.

.OUTPUTS
    PSCustomObject[] with PackageId and Success.
#>
function Install-TkPackageBatch {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string[]] $PackageId
    )

    $results = @()
    $index   = 0

    foreach ($id in $PackageId) {

        $index++

        Write-TkLog -Level Information -Category 'Software' -Message (
            '[{0}/{1}] {2}' -f $index, $PackageId.Count, $id
        )

        $results += [pscustomobject]@{
            PackageId = $id
            Success   = (Install-TkWingetPackage -PackageId $id)
        }
    }

    $failed = @($results | Where-Object { -not $_.Success })

    Write-TkLog -Level Information -Category 'Software' -Message (
        'Batch finished: {0} succeeded, {1} failed.' -f ($results.Count - $failed.Count), $failed.Count
    )

    return $results
}

<#
.SYNOPSIS
    Lists packages that have an update available.

.DESCRIPTION
    Parses the fixed width table winget prints. The parser locates the column
    offsets from the header rather than splitting on whitespace, because
    application names legitimately contain spaces.

.OUTPUTS
    PSCustomObject[] with Name, Id, Current and Available.
#>
function Get-TkUpgradablePackage {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $arguments = @('upgrade', '--include-unknown', '--accept-source-agreements')
    $result    = Invoke-TkProcess -FilePath 'winget' -ArgumentList $arguments -TimeoutSeconds 180

    if ($result.ExitCode -ne 0 -and [string]::IsNullOrWhiteSpace($result.StandardOutput)) {

        Write-TkLog -Level Warning -Category 'Software' -Message 'winget upgrade returned no usable output.'
        return @()
    }

    return (ConvertFrom-TkWingetTable -Text $result.StandardOutput)
}

<#
.SYNOPSIS
    Searches the winget catalog.

.PARAMETER Query
    Free text search term.

.OUTPUTS
    PSCustomObject[]
#>
function Search-TkWingetPackage {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Query
    )

    # The query is passed as its own argument, never concatenated, so quotes
    # and spaces inside it cannot alter the command line.
    $arguments = @('search', '--query', $Query, '--source', 'winget', '--accept-source-agreements')
    $result    = Invoke-TkProcess -FilePath 'winget' -ArgumentList $arguments -TimeoutSeconds 120

    return (ConvertFrom-TkWingetTable -Text $result.StandardOutput)
}

<#
.SYNOPSIS
    Returns the identifiers of every package winget knows to be installed.

.DESCRIPTION
    Used to show the installed state next to each catalog entry. Returned as
    a HashSet so the UI can test membership for hundreds of rows cheaply.

.OUTPUTS
    System.Collections.Generic.HashSet[string]
#>
function Get-TkInstalledPackageId {
    [CmdletBinding()]
    param()

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    $arguments = @('list', '--accept-source-agreements')
    $result    = Invoke-TkProcess -FilePath 'winget' -ArgumentList $arguments -TimeoutSeconds 180

    foreach ($row in (ConvertFrom-TkWingetTable -Text $result.StandardOutput)) {

        if ($row.Id) {
            [void] $set.Add($row.Id)
        }
    }

    Write-TkLog -Level Debug -Category 'Software' -Message (
        '{0} installed packages reported by winget.' -f $set.Count
    )

    return $set
}

<#
.SYNOPSIS
    Parses the fixed width table produced by winget list, search and upgrade.

.DESCRIPTION
    winget aligns its output in columns whose positions are given by the
    header row. Splitting on whitespace breaks on any name containing a
    space, so the header offsets are used instead. Progress spinner
    characters emitted before the table are stripped first.

.OUTPUTS
    PSCustomObject[]
#>
function ConvertFrom-TkWingetTable {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $lines = $Text -split "`r?`n"

    # Locate the header. It is the line that names the Id column and is
    # immediately followed by a rule of dashes.
    $headerIndex = -1

    for ($i = 0; $i -lt $lines.Count; $i++) {

        if ($lines[$i] -match '^\s*Name\s+Id\s+Version' -or $lines[$i] -match '^\s*Nom\s+ID\s+Version') {
            $headerIndex = $i
            break
        }
    }

    if ($headerIndex -lt 0) {
        return @()
    }

    $header = $lines[$headerIndex]

    # Column starts, derived from the header text itself so the parser works
    # whatever the console width or the display language.
    $columns = @()

    foreach ($match in [regex]::Matches($header, '\S+(\s\S+)*?(?=\s{2,}|$)')) {
        $columns += [pscustomobject]@{ Name = $match.Value.Trim(); Start = $match.Index }
    }

    if ($columns.Count -lt 2) {
        return @()
    }

    $rows = @()

    # Skip the header and the dashed rule underneath it.
    for ($i = $headerIndex + 2; $i -lt $lines.Count; $i++) {

        $line = $lines[$i]

        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        # Trailing summary lines such as "3 upgrades available."
        if ($line -match '^\s*\d+\s+\S+\s+(available|upgrades)') {
            continue
        }

        $values = @{}

        for ($c = 0; $c -lt $columns.Count; $c++) {

            $start = $columns[$c].Start

            if ($start -ge $line.Length) {
                $values[$columns[$c].Name] = ''
                continue
            }

            if ($c -lt ($columns.Count - 1)) {
                $end    = [Math]::Min($columns[$c + 1].Start, $line.Length)
                $length = $end - $start
            }
            else {
                $length = $line.Length - $start
            }

            $values[$columns[$c].Name] = $line.Substring($start, $length).Trim()
        }

        $id = $values['Id']

        if (-not $id) {
            $id = $values['ID']
        }

        $name = $values['Name']

        if (-not $name) {
            $name = $values['Nom']
        }

        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        $rows += [pscustomobject]@{
            Name      = $name
            Id        = $id
            Version   = $values['Version']
            Available = $values['Available']
            Source    = $values['Source']
        }
    }

    return $rows
}

<#
.SYNOPSIS
    Returns the first non empty line of a text block.

.DESCRIPTION
    Used to keep error logs readable: winget failures print a paragraph, but
    only the first line identifies the problem.

.OUTPUTS
    System.String
#>
function Get-TkFirstLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    foreach ($line in ($Text -split "`r?`n")) {

        if (-not [string]::IsNullOrWhiteSpace($line)) {
            return $line.Trim()
        }
    }

    return ''
}
