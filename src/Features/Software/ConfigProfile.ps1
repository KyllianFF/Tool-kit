<#
    Toolkit - Features / Configuration profiles

    The applications and tweaks one technician ticks for a new workstation are
    the same the next time, and the time after. A profile keeps that choice in
    a small JSON file, to tick it again on another machine.

    A profile holds catalogue identifiers and nothing else: no package name,
    no registry path, no command. Every identifier is looked up again in the
    catalogues of the toolkit that reads it, and one it does not know is
    reported and left out, so a profile edited by hand, or written by a newer
    toolkit, can never make this one run something its catalogues do not
    describe. Loading a profile only ticks the boxes: installing and applying
    stay on their own buttons, with their confirmation and their elevation.
#>

<#
.SYNOPSIS
    Builds a profile from the ticked applications and tweaks.

.PARAMETER Name
    What the profile is for, for example "Accounting workstation".

.PARAMETER ApplicationId
    Catalogue identifiers of the applications.

.PARAMETER TweakId
    Catalogue identifiers of the tweaks.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary, ready for ConvertTo-Json.
#>
function New-TkConfigProfile {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Name = '',
        [Parameter()] [AllowEmptyCollection()] [string[]] $ApplicationId = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $TweakId = @()
    )

    $ctx = Get-TkContext

    return [ordered] @{
        schema        = 'toolkit-config-profile'
        schemaVersion = 1
        name          = $Name.Trim()
        created       = (Get-Date).ToString('yyyy-MM-dd')
        toolkit       = ('{0} ({1})' -f $ctx.Version, $ctx.Commit)
        applications  = @($ApplicationId | Where-Object { $_ } | Select-Object -Unique)
        tweaks        = @($TweakId | Where-Object { $_ } | Select-Object -Unique)
    }
}

<#
.SYNOPSIS
    Reads a profile and keeps only what the catalogues know.

.DESCRIPTION
    Pure. The text is bounded, parsed, checked to be a toolkit profile, and
    each identifier is matched against the catalogue identifiers passed in.
    Identifiers are compared exactly: a profile cannot reach an entry through
    a pattern or a different case.

.PARAMETER Json
    The file content.

.PARAMETER KnownApplication
    The application identifiers of the catalogue.

.PARAMETER KnownTweak
    The tweak identifiers of the catalogue.

.OUTPUTS
    PSCustomObject with Name, Applications, Tweaks, Unknown (identifiers left
    out, each with its kind) and Error.
#>
function Read-TkConfigProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Json,
        [Parameter()] [AllowEmptyCollection()] [string[]] $KnownApplication = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $KnownTweak = @()
    )

    $failed = { param($message) [pscustomobject] @{ Name = ''; Applications = @(); Tweaks = @(); Unknown = @(); Error = $message } }

    if ($Json.Length -gt 256KB) {
        return (& $failed 'The file is too large to be a toolkit profile.')
    }

    try {
        $data = $Json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return (& $failed 'The file is not valid JSON.')
    }

    if ($null -eq $data -or $data -is [System.Array] -or -not $data.PSObject.Properties['schema'] -or [string] $data.schema -ne 'toolkit-config-profile') {
        return (& $failed 'The file is not a toolkit configuration profile.')
    }

    if ($data.PSObject.Properties['schemaVersion'] -and [int] $data.schemaVersion -gt 1) {
        return (& $failed 'The profile was written by a newer toolkit, in a form this one does not read.')
    }

    $unknown = New-Object System.Collections.Generic.List[string]

    $pick = {
        param($values, [string[]] $known, $kind)

        $kept = New-Object System.Collections.Generic.List[string]

        foreach ($value in @($values)) {

            $id = [string] $value

            if (-not $id) {
                continue
            }

            if ($id -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$' -and $known -ccontains $id) {
                if (-not $kept.Contains($id)) { $kept.Add($id) }
            }
            else {
                $unknown.Add(('{0} "{1}"' -f $kind, $(if ($id.Length -gt 40) { $id.Substring(0, 40) + '...' } else { $id })))
            }
        }

        return , @($kept.ToArray())
    }

    $applications = if ($data.PSObject.Properties['applications']) { & $pick $data.applications $KnownApplication 'application' } else { @() }
    $tweaks       = if ($data.PSObject.Properties['tweaks'])       { & $pick $data.tweaks $KnownTweak 'tweak' } else { @() }

    $name = if ($data.PSObject.Properties['name']) { ([string] $data.name).Trim() } else { '' }
    if ($name.Length -gt 80) { $name = $name.Substring(0, 80) }

    return [pscustomobject] @{
        Name         = $name
        Applications = @($applications)
        Tweaks       = @($tweaks)
        Unknown      = @($unknown.ToArray())
        Error        = ''
    }
}

<#
.SYNOPSIS
    Ticks the applications and tweaks of a profile, and unticks the rest.

.PARAMETER ConfigProfile
    From Read-TkConfigProfile.

.PARAMETER ApplicationItem
    The items of the Software list.

.PARAMETER TweakItem
    The items of the Tweaks list.

.OUTPUTS
    PSCustomObject with Applications and Tweaks, the number ticked.
#>
function Set-TkConfigProfileSelection {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $ConfigProfile,
        [Parameter()] [AllowEmptyCollection()] [object[]] $ApplicationItem = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $TweakItem = @()
    )

    if (-not $PSCmdlet.ShouldProcess('the Software and Tweaks lists', 'Tick the profile')) {
        return [pscustomobject] @{ Applications = 0; Tweaks = 0 }
    }

    $apps   = 0
    $tweaks = 0

    foreach ($item in ($ApplicationItem | Where-Object { $_ })) {
        $item.IsSelected = (@($ConfigProfile.Applications) -ccontains [string] $item.Id)
        if ($item.IsSelected) { $apps++ }
    }

    foreach ($item in ($TweakItem | Where-Object { $_ })) {
        $item.IsSelected = (@($ConfigProfile.Tweaks) -ccontains [string] $item.Id)
        if ($item.IsSelected) { $tweaks++ }
    }

    return [pscustomobject] @{ Applications = $apps; Tweaks = $tweaks }
}
