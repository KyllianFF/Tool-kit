<#
    Toolkit - Features / Store apps

    Windows ships with a row of Store apps most people never open: tips,
    feedback, news, sponsored games. This offers to remove them, and only
    them.

    A machine holds far more Store packages than that, and many of them must
    stay: the codecs that play video, the language pack the interface is
    displayed in, the winget sources, the companion apps of printer and audio
    drivers, the frameworks other apps are built on, the Store itself. So
    nothing is offered by looking at what is removable: only the apps named in
    data/store-apps.json are ever listed, and the removal refuses any other
    name, and any protected component, whatever it is handed. That check runs
    again in the elevated process, which is the one that removes.

    A removal is for every account and for the accounts created later, since
    the package is also taken out of the Windows image. An app removed by
    mistake comes back from the Microsoft Store.
#>

<#
.SYNOPSIS
    The components never removed, whatever list asks for them.

.DESCRIPTION
    A second line behind the catalogue: even an entry added to it by mistake
    cannot take one of these away. Patterns, matched against the package name.

.OUTPUTS
    System.String[]
#>
function Get-TkProtectedStoreAppPattern {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        '^Microsoft\.WindowsStore$', '^Microsoft\.StorePurchaseApp$', '^Microsoft\.DesktopAppInstaller$',
        '^Microsoft\.Winget\.', '^Microsoft\.SecHealthUI$', '^Microsoft\.Windows\.SecHealthUI$',
        '^Microsoft\.WindowsTerminal', '^Microsoft\.WindowsNotepad$', '^Microsoft\.WindowsCalculator$',
        '^Microsoft\.Paint$', '^Microsoft\.ScreenSketch$', '^Microsoft\.Windows\.Photos$',
        '^Microsoft\.Xbox\.TCUI$', '^Microsoft\.XboxIdentityProvider$', '^Microsoft\.XboxSpeechToTextOverlay$',
        '^Microsoft\.GamingServices$', '^Microsoft\.LanguageExperiencePack', '^Microsoft\.Ink\.',
        'VideoExtension', 'ImageExtension', '^Microsoft\.WebMediaExtensions$',
        '^Microsoft\.VCLibs', '^Microsoft\.NET\.', '^Microsoft\.UI\.Xaml', '^Microsoft\.WindowsAppRuntime',
        '^Microsoft\.WinAppRuntime', '^Microsoft\.Services\.Store', '^MicrosoftWindows\.',
        '^Microsoft\.Windows\.(ShellExperienceHost|StartMenuExperienceHost|Search|CloudExperienceHost)'
    )
}

<#
.SYNOPSIS
    Says whether a package name may be removed: listed in the catalogue, well formed, not protected.

.PARAMETER Name
    The package name, for example Microsoft.BingNews.

.PARAMETER Catalog
    The catalogue entries. Read from data/store-apps.json when not given.

.OUTPUTS
    System.Boolean
#>
function Test-TkStoreAppRemovable {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Name,

        [Parameter()]
        [object[]] $Catalog
    )

    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-]{2,}$') {
        return $false
    }

    foreach ($pattern in (Get-TkProtectedStoreAppPattern)) {
        if ($Name -match $pattern) {
            return $false
        }
    }

    if ($null -eq $Catalog) {
        $Catalog = @((Import-TkCatalog -Name 'store-apps').apps)
    }

    return [bool] (@($Catalog | Where-Object { $_.name -eq $Name }).Count -gt 0)
}

<#
.SYNOPSIS
    Matches the installed packages against the catalogue.

.DESCRIPTION
    Pure. A package that is not in the catalogue is left out, whatever it is.

.PARAMETER Package
    Objects with Name and Version, as Get-AppxPackage returns them.

.PARAMETER Catalog
    The catalogue entries.

.OUTPUTS
    PSCustomObject[] with Name, Label, Category, Description and Version,
    rarely used ones first.
#>
function ConvertTo-TkStoreAppItem {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Package = @(),
        [Parameter(Mandatory)] [object[]] $Catalog
    )

    $installed = @{}

    foreach ($item in $Package) {
        if ($item -and $item.Name -and -not $installed.ContainsKey([string] $item.Name)) {
            $installed[[string] $item.Name] = [string] $item.Version
        }
    }

    $items = foreach ($entry in $Catalog) {

        if (-not $installed.ContainsKey([string] $entry.name)) {
            continue
        }

        if (-not (Test-TkStoreAppRemovable -Name $entry.name -Catalog $Catalog)) {
            continue
        }

        [pscustomobject] @{
            Name        = [string] $entry.name
            Label       = [string] $entry.label
            Category    = [string] $entry.category
            Description = [string] $entry.description
            Version     = $installed[[string] $entry.name]
        }
    }

    return @($items | Sort-Object @{ Expression = { if ($_.Category -eq 'bloat') { 0 } else { 1 } } }, Label)
}

<#
.SYNOPSIS
    Lists the catalogue apps installed for this account.

.OUTPUTS
    PSCustomObject with Available, Reason and Apps.
#>
function Get-TkStoreApp {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $catalog = @((Import-TkCatalog -Name 'store-apps').apps)

    try {
        $packages = @(Get-AppxPackage -ErrorAction Stop | Select-Object Name, Version)
    }
    catch {
        return [pscustomobject] @{ Available = $false; Reason = ('The Store apps could not be read: {0}' -f $_.Exception.Message); Apps = @() }
    }

    return [pscustomobject] @{
        Available = $true
        Reason    = ''
        Apps      = @(ConvertTo-TkStoreAppItem -Package $packages -Catalog $catalog)
    }
}

<#
.SYNOPSIS
    Removes catalogue apps for every account and from the Windows image.

.DESCRIPTION
    Needs administrator rights: it runs in the elevated worker. Every name is
    checked again here, so a name that is not in the catalogue, or a protected
    component, is refused even if the list handed over was tampered with.
    Each removal is timed, logged and written to the intervention journal.

.PARAMETER Name
    The package names.

.OUTPUTS
    PSCustomObject[] with Name, Ok and Message.
#>
function Remove-TkStoreApp {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Name
    )

    $catalog = @((Import-TkCatalog -Name 'store-apps').apps)
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($app in $Name) {

        if (-not (Test-TkStoreAppRemovable -Name $app -Catalog $catalog)) {
            $results.Add([pscustomobject] @{ Name = $app; Ok = $false; Message = 'Refused: not an app this toolkit removes.' })
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($app, 'Remove the Store app for every account')) {
            continue
        }

        $label     = (@($catalog | Where-Object { $_.name -eq $app }) | Select-Object -First 1).label
        $stopwatch = Start-TkOperation -Name ('Remove Store app: {0}' -f $label) -Category 'Software'
        $ok        = $true
        $message   = ''

        try {
            foreach ($package in @(Get-AppxPackage -AllUsers -Name $app -ErrorAction Stop)) {
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
            }

            # Out of the image too, or Windows installs it again for the next new account.
            foreach ($provisioned in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { $_.DisplayName -eq $app })) {
                Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction Stop | Out-Null
            }

            $message = ('{0} removed.' -f $label)
        }
        catch {
            $ok      = $false
            $message = ('{0} could not be removed: {1}' -f $label, $_.Exception.Message)
        }

        Stop-TkOperation -Name ('Remove Store app: {0}' -f $label) -Stopwatch $stopwatch -Category 'Software' -Success $ok
        $results.Add([pscustomobject] @{ Name = $app; Ok = $ok; Message = $message })
    }

    return @($results.ToArray())
}
