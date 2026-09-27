<#
    Toolkit - Features / Update check

    The one-liner always runs the build published on GitHub, but a copy kept
    on a USB key or in the portable folder grows old without saying so. This
    tells the user when a newer build is published, and nothing more.

    It is off until the user turns it on in Settings, and it makes a single
    small request: the build manifest the build script writes next to
    dist/toolkit.ps1 (version, commit, SHA256, date). Nothing is downloaded or
    replaced on its own. A signed portable copy would lose its signature, and
    a toolkit that rewrites itself from the network is exactly the behaviour a
    security product is right to distrust. The user is pointed at the
    published file and its SHA256 instead.
#>

<#
.SYNOPSIS
    Where the published build and its manifest live.

.OUTPUTS
    PSCustomObject with ManifestUri and DownloadPage.
#>
function Get-TkUpdateSource {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject] @{
        ManifestUri  = 'https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1.version.json'
        DownloadPage = 'https://github.com/KyllianFF/Tool-kit/tree/main/dist'
    }
}

<#
.SYNOPSIS
    Checks a build manifest and keeps only well formed values.

.DESCRIPTION
    Pure. The manifest comes from the network, so every field is checked
    against the form the build script writes before it is shown or compared.

.PARAMETER Manifest
    The parsed JSON: version, commit, sha256 and published.

.OUTPUTS
    PSCustomObject with Version, Commit, Sha256 and Published, or $null.
#>
function ConvertFrom-TkBuildManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Manifest
    )

    if ($null -eq $Manifest) {
        return $null
    }

    $value = { param($name) $property = $Manifest.PSObject.Properties[$name]; if ($property) { [string] $property.Value } else { '' } }

    $version   = & $value 'version'
    $commit    = & $value 'commit'
    $sha256    = & $value 'sha256'
    $published = & $value 'published'

    if ($version -notmatch '^\d{1,5}(\.\d{1,5}){1,3}$' -or $commit -notmatch '^[0-9a-f]{7,40}$' -or $sha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        return $null
    }

    if ($published -notmatch '^\d{4}-\d{2}-\d{2}$') {
        $published = ''
    }

    return [pscustomobject] @{ Version = $version; Commit = $commit; Sha256 = $sha256.ToUpperInvariant(); Published = $published }
}

<#
.SYNOPSIS
    Compares the running build with the published one.

.DESCRIPTION
    Pure. The commit identifies a build: the published one is by definition
    the latest, so a different commit means a newer build, unless its version
    number is lower (a copy built ahead of the published one). A development
    copy has no commit to compare.

.PARAMETER RunningVersion
    The version of this copy.

.PARAMETER RunningCommit
    The commit this copy was built from; dev or local for a development copy.

.PARAMETER Published
    From ConvertFrom-TkBuildManifest, or $null when it could not be read.

.PARAMETER Reason
    Why the published build could not be read, when it could not.

.OUTPUTS
    PSCustomObject with Status (UpToDate, UpdateAvailable, Newer, Development
    or Unknown), Text and Published.
#>
function Compare-TkToolkitBuild {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $RunningVersion,
        [Parameter(Mandatory)] [string] $RunningCommit,
        [Parameter()] [AllowNull()] [pscustomobject] $Published,
        [Parameter()] [AllowEmptyString()] [string] $Reason = ''
    )

    $result = { param($status, $text) [pscustomobject] @{ Status = $status; Text = $text; Published = $Published } }

    if ($RunningCommit -notmatch '^[0-9a-f]{7,40}$') {
        return (& $result 'Development' 'This is a development copy, run from the sources: there is no published build to compare it with.')
    }

    if (-not $Published) {
        $why = if ($Reason) { $Reason } else { 'the published build information could not be read' }
        return (& $result 'Unknown' ('The check did not complete: {0}.' -f $why.TrimEnd('.')))
    }

    $date = if ($Published.Published) { ' on {0}' -f $Published.Published } else { '' }

    if ($Published.Commit.StartsWith($RunningCommit) -or $RunningCommit.StartsWith($Published.Commit)) {
        return (& $result 'UpToDate' ('This copy is the build published{0} (version {1}, commit {2}).' -f $date, $Published.Version, $Published.Commit))
    }

    $running = $null
    $latest  = $null

    if ([version]::TryParse($RunningVersion, [ref] $running) -and [version]::TryParse($Published.Version, [ref] $latest) -and $running -gt $latest) {
        return (& $result 'Newer' ('This copy (version {0}) is ahead of the published build (version {1}, commit {2}).' -f $RunningVersion, $Published.Version, $Published.Commit))
    }

    return (& $result 'UpdateAvailable' ('A newer build was published{0}: version {1}, commit {2}. This copy is commit {3}.' -f $date, $Published.Version, $Published.Commit, $RunningCommit))
}

<#
.SYNOPSIS
    Checks whether a newer build of the toolkit is published.

.DESCRIPTION
    One request for the manifest, with a short time-out so an offline machine
    answers at once. Nothing else is fetched.

.PARAMETER TimeoutSeconds
    How long to wait for GitHub.

.OUTPUTS
    PSCustomObject as returned by Compare-TkToolkitBuild.
#>
function Test-TkToolkitUpdate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 60)]
        [int] $TimeoutSeconds = 8
    )

    $ctx       = Get-TkContext
    $source    = Get-TkUpdateSource
    $published = $null
    $reason    = ''

    try {
        $manifest  = Invoke-RestMethod -Uri $source.ManifestUri -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop `
                                       -Headers @{ 'Cache-Control' = 'no-cache' }
        $published = ConvertFrom-TkBuildManifest -Manifest $manifest

        if (-not $published) {
            $reason = 'the published build information is not in the expected form'
        }
    }
    catch {
        # A 404 is an answer, not a network failure: nothing is published there.
        $code = $null
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
            $code = [int] $_.Exception.Response.StatusCode
        }

        $reason = if ($code -eq 404) { 'no build information is published on GitHub yet' }
                  else { 'GitHub could not be reached ({0})' -f $_.Exception.Message.Trim().TrimEnd('.') }
    }

    $comparison = Compare-TkToolkitBuild -RunningVersion ([string] $ctx.Version) -RunningCommit ([string] $ctx.Commit) `
                                         -Published $published -Reason $reason

    Write-TkLog -Level Information -Category 'Updates' -Message $comparison.Text

    return $comparison
}
