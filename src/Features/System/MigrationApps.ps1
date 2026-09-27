<#
    Toolkit - Features / Migration: the applications

    The configuration profile only knows the applications of the toolkit
    catalogue. A machine holds far more: every program in the uninstall keys,
    the Store apps, and whatever winget installed. This lists all of them and
    says how each one comes back on the new machine: through winget, from the
    Microsoft Store, or by hand with its installer and its licence, which is
    the list a technician needs before wiping the old disk.

    The export writes the whole list as a CSV and a winget export file; the
    import can reinstall what winget knows with winget import, run as the
    signed-in user as every winget call in the toolkit is.
#>

<#
.SYNOPSIS
    The Store apps this account can see in the Start menu.

.DESCRIPTION
    Frameworks, system parts and apps that cannot be removed are left out:
    they come with Windows. The name is the one the Start menu shows.

.OUTPUTS
    PSCustomObject[] with Name, Version, Publisher and Family.
#>
function Get-TkStoreApplication {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $names = @{}
    try {
        foreach ($app in @(Get-StartApps -ErrorAction Stop)) {
            $family = ([string] $app.AppID -split '!')[0]
            if ($family -and -not $names.ContainsKey($family)) { $names[$family] = [string] $app.Name }
        }
    }
    catch {
        $null = $_
    }

    $packages = @(try { Get-AppxPackage -ErrorAction Stop } catch { @() })

    return @(foreach ($package in $packages) {
        if ($package.IsFramework -or $package.NonRemovable -or [string] $package.SignatureKind -ne 'Store') { continue }
        if (-not $names.ContainsKey([string] $package.PackageFamilyName)) { continue }

        [pscustomobject] @{
            Name      = $names[[string] $package.PackageFamilyName]
            Version   = [string] $package.Version
            Publisher = ([string] $package.Publisher -replace '^CN=([^,]+).*$', '$1')
            Family    = [string] $package.PackageFamilyName
            Package   = [string] $package.Name
            Inbox     = (Test-TkInboxStoreApp -Name ([string] $package.Name))
        }
    })
}

<#
.SYNOPSIS
    Says whether a Store app comes with Windows.

.DESCRIPTION
    Pure. The protected components and the preinstalled apps of the Store
    apps catalogue are on every new Windows: nothing to reinstall.

.OUTPUTS
    System.Boolean
#>
function Test-TkInboxStoreApp {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [Parameter()] [string[]] $Catalog = @(@((Import-TkCatalog -Name 'store-apps').apps) | ForEach-Object { [string] $_.name })
    )

    if (-not $Name) { return $false }

    foreach ($pattern in (Get-TkProtectedStoreAppPattern)) {
        if ($Name -match $pattern) { return $true }
    }

    return ($Catalog -contains $Name -or $Name -match '^(Microsoft\.(Windows|ZuneMusic|ZuneVideo|MicrosoftEdge|Getstarted|People|Todos|OutlookForWindows|BingWeather|WindowsAlarms|WindowsCamera|WindowsSoundRecorder|WindowsFeedbackHub|GetHelp|YourPhone|PowerAutomateDesktop|Copilot|MicrosoftStickyNotes|WindowsMaps|MicrosoftSolitaireCollection|Clipchamp)|Clipchamp\.|MicrosoftCorporationII\.|MicrosoftWindows\.)')
}

<#
.SYNOPSIS
    Puts the programs, the Store apps and what winget knows into one list.

.DESCRIPTION
    Pure. winget names a program the way its uninstall entry does, so a
    program is matched to winget by its exact name. A winget row with a
    source (winget or msstore) can be reinstalled by winget import; a Store
    app winget does not list comes back from the Store; anything else is
    reinstalled by hand. A package winget installed that is neither in the
    uninstall keys nor in the Store list (a portable tool) is kept too.

.PARAMETER Program
    Name, Version, Publisher, from Get-TkInstalledProgram.

.PARAMETER StoreApp
    Name, Version, Publisher, from Get-TkStoreApplication.

.PARAMETER WingetRow
    Name, Id, Version, Source, from winget list.

.PARAMETER Catalog
    Name and PackageId of the toolkit catalogue. winget list does not always
    connect an installed program to its source (a per-user install often
    shows as ARP\User\... with no source), so a program still without a way
    back is matched to the catalogue by its name: the same name, or the name
    followed by a version or an architecture.

.OUTPUTS
    PSCustomObject[] with Name, Version, Publisher, Kind, Reinstall and
    WingetId, sorted by name.
#>
function ConvertTo-TkApplicationInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Program = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $StoreApp = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $WingetRow = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Catalog = @()
    )

    $available = @{}
    foreach ($row in ($WingetRow | Where-Object { $_ -and $_.Name -and $_.PSObject.Properties['Source'] -and $_.Source })) {
        $key = ([string] $row.Name).Trim().ToLowerInvariant()
        if (-not $available.ContainsKey($key)) { $available[$key] = $row }
    }

    $used = @{}
    $rows = New-Object System.Collections.Generic.List[object]

    $add = {
        param($name, $version, $publisher, $kind, $fallback)
        $key   = ([string] $name).Trim().ToLowerInvariant()
        $match = if ($available.ContainsKey($key)) { $available[$key] } else { $null }
        if ($match) { $used[$key] = $true }

        $reinstall = if (-not $match) { $fallback }
                     elseif ([string] $match.Source -eq 'msstore') { 'Microsoft Store (winget)' }
                     else { 'winget' }
        $wingetId  = if ($match) { [string] $match.Id } else { '' }

        if (-not $match -and $kind -eq 'Program') {
            $known = @($Catalog | Where-Object {
                $catalogName = ([string] $_.Name).Trim()
                $catalogName -and ($key -eq $catalogName.ToLowerInvariant() -or
                                   $key.StartsWith($catalogName.ToLowerInvariant() + ' '))
            } | Sort-Object { ([string] $_.Name).Length } -Descending) | Select-Object -First 1

            if ($known) {
                $reinstall = 'winget (catalogue)'
                $wingetId  = [string] $known.PackageId
            }
        }

        $rows.Add([pscustomobject] @{
            Name      = ([string] $name).Trim()
            Version   = [string] $version
            Publisher = [string] $publisher
            Kind      = $kind
            Reinstall = $reinstall
            WingetId  = $wingetId
        })
    }

    $seen = @{}
    foreach ($item in ($Program | Where-Object { $_ -and $_.Name })) {
        $key = ([string] $item.Name).Trim().ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        & $add $item.Name $item.Version $item.Publisher 'Program' 'By hand'
    }

    foreach ($item in ($StoreApp | Where-Object { $_ -and $_.Name })) {
        $key = ([string] $item.Name).Trim().ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $fallback = if ($item.PSObject.Properties['Inbox'] -and $item.Inbox) { 'Comes with Windows' } else { 'Microsoft Store' }
        & $add $item.Name $item.Version $item.Publisher 'Store app' $fallback
    }

    foreach ($key in @($available.Keys)) {
        if ($used.ContainsKey($key) -or $seen.ContainsKey($key)) { continue }
        $row = $available[$key]
        $rows.Add([pscustomobject] @{
            Name = [string] $row.Name; Version = [string] $row.Version; Publisher = ''
            Kind = 'winget package'; Reinstall = $(if ([string] $row.Source -eq 'msstore') { 'Microsoft Store (winget)' } else { 'winget' }); WingetId = [string] $row.Id
        })
    }

    return @($rows.ToArray() | Sort-Object Name)
}

<#
.SYNOPSIS
    Lists every application of this machine and how each comes back.

.OUTPUTS
    PSCustomObject with Applications, WingetAvailable.
#>
function Get-TkApplicationInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $wingetRows = @()
    $winget     = [bool] (Get-Command -Name 'winget' -ErrorAction SilentlyContinue)

    if ($winget) {
        $run = Invoke-TkProcess -FilePath 'winget' -ArgumentList @('list', '--accept-source-agreements', '--disable-interactivity') -TimeoutSeconds 180
        $wingetRows = @(ConvertFrom-TkWingetTable -Text ([string] $run.StandardOutput))
    }

    $catalog = @(@((Import-TkCatalog -Name 'applications').applications) | ForEach-Object { [pscustomobject] @{ Name = [string] $_.name; PackageId = [string] $_.packageId } })

    return [pscustomobject] @{
        Applications    = @(ConvertTo-TkApplicationInventory -Program @(Get-TkInstalledProgram) -StoreApp @(Get-TkStoreApplication) -WingetRow $wingetRows -Catalog $catalog)
        WingetAvailable = $winget
    }
}

<#
.SYNOPSIS
    Counts the applications by the way they come back.

.OUTPUTS
    PSCustomObject with Total, Winget, Store, Manual and Inbox.
#>
function Measure-TkApplicationInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Application = @()
    )

    $all = @($Application | Where-Object { $_ })

    return [pscustomobject] @{
        Total  = $all.Count
        Winget = @($all | Where-Object { $_.Reinstall -like '*winget*' }).Count
        Store  = @($all | Where-Object { $_.Reinstall -eq 'Microsoft Store' }).Count
        Manual = @($all | Where-Object { $_.Reinstall -eq 'By hand' }).Count
        Inbox  = @($all | Where-Object { $_.Reinstall -eq 'Comes with Windows' }).Count
    }
}

<#
.SYNOPSIS
    Adds package ids to the winget source of a winget export file.

.DESCRIPTION
    For the programs winget list did not connect to a source but the
    catalogue knows: winget import then reinstalls them too. An id already in
    the file is not added twice.

.OUTPUTS
    System.Int32, the number of ids added.
#>
function Add-TkWingetExportPackage {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Id = @()
    )

    $wanted = @($Id | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._+-]{1,127}$' } | Select-Object -Unique)
    if ($wanted.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($Path, 'Add catalogue packages')) { return 0 }

    $data = if (Test-Path -LiteralPath $Path) { [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json } else { $null }
    if (-not $data) {
        $data = [pscustomobject] @{ '$schema' = 'https://aka.ms/winget-packages.schema.2.0.json'; CreationDate = (Get-Date).ToString('o'); Sources = @(); WinGetVersion = '' }
    }

    $sources = @($data.Sources)
    $source  = @($sources | Where-Object { $_.SourceDetails.Name -eq 'winget' }) | Select-Object -First 1

    if (-not $source) {
        $source = [pscustomobject] @{
            Packages      = @()
            SourceDetails = [pscustomobject] @{
                Argument   = 'https://cdn.winget.microsoft.com/cache'
                Identifier = 'Microsoft.Winget.Source_8wekyb3d8bbwe'
                Name       = 'winget'
                Type       = 'Microsoft.PreIndexed.Package'
            }
        }
        $sources += $source
    }

    $present = @(@($sources | ForEach-Object { $_.Packages }) | ForEach-Object { [string] $_.PackageIdentifier })
    $added   = @($wanted | Where-Object { $present -notcontains $_ })

    $source.Packages = @(@($source.Packages) + @($added | ForEach-Object { [pscustomobject] @{ PackageIdentifier = $_ } }))
    $data.Sources    = @($sources)

    [System.IO.File]::WriteAllText($Path, ($data | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))

    return $added.Count
}

<#
.SYNOPSIS
    Writes the application list and the winget export into the package.

.DESCRIPTION
    apps\applications.csv holds every application with the way it comes
    back; apps\winget.json is winget export, for winget import on the new
    machine.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary, the manifest section.
#>
function Export-TkMigrationApplication {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Root
    )

    $folder = [System.IO.Path]::Combine($Root, 'apps')

    if (-not $PSCmdlet.ShouldProcess($folder, 'Write the application list')) {
        return [ordered] @{}
    }

    New-Item -ItemType Directory -Path $folder -Force | Out-Null

    $inventory = Get-TkApplicationInventory
    $count     = Measure-TkApplicationInventory -Application $inventory.Applications

    $inventory.Applications | Select-Object Name, Version, Publisher, Kind, Reinstall, WingetId |
        Export-Csv -LiteralPath ([System.IO.Path]::Combine($folder, 'applications.csv')) -NoTypeInformation -Encoding UTF8

    $wingetFile = ''
    if ($inventory.WingetAvailable) {
        $target = [System.IO.Path]::Combine($folder, 'winget.json')
        $run    = Invoke-TkProcess -FilePath 'winget' -ArgumentList @('export', '-o', $target, '--accept-source-agreements', '--disable-interactivity') -TimeoutSeconds 300
        # winget export can end with a non-zero code when a package is not in any
        # source, and still write the file: the file is what counts.
        $null = $run
        if (Test-Path -LiteralPath $target) { $wingetFile = 'apps\winget.json' }

        $fromCatalogue = @($inventory.Applications | Where-Object { $_.Reinstall -eq 'winget (catalogue)' } | ForEach-Object { $_.WingetId })
        if ($fromCatalogue.Count -gt 0) {
            [void] (Add-TkWingetExportPackage -Path $target -Id $fromCatalogue -Confirm:$false)
            $wingetFile = 'apps\winget.json'
        }
    }

    return [ordered] @{
        total      = $count.Total
        winget     = $count.Winget
        store      = $count.Store
        manual     = $count.Manual
        list       = 'apps\applications.csv'
        wingetFile = $wingetFile
    }
}

<#
.SYNOPSIS
    Reads the application part of a package, from its fixed file names.

.DESCRIPTION
    The file names are fixed, never taken from the manifest, so a package
    cannot point the import at a file outside itself.

.OUTPUTS
    PSCustomObject with List, Winget, Applications and WingetCount, or $null.
#>
function Read-TkMigrationApplication {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Root
    )

    $list   = [System.IO.Path]::Combine($Root, 'apps\applications.csv')
    $winget = [System.IO.Path]::Combine($Root, 'apps\winget.json')

    if (-not (Test-Path -LiteralPath $list -PathType Leaf)) {
        return $null
    }

    $applications = @(try { Import-Csv -LiteralPath $list -ErrorAction Stop } catch { @() })

    $wingetCount = 0
    if (Test-Path -LiteralPath $winget -PathType Leaf) {
        try {
            $data = [System.IO.File]::ReadAllText($winget) | ConvertFrom-Json -ErrorAction Stop
            $wingetCount = @($data.Sources | ForEach-Object { $_.Packages }).Count
        }
        catch {
            $winget = ''
        }
    }
    else {
        $winget = ''
    }

    return [pscustomobject] @{ List = $list; Winget = $winget; Applications = $applications; WingetCount = $wingetCount }
}

<#
.SYNOPSIS
    Reinstalls on this machine what winget knows from the package.

.DESCRIPTION
    winget import, as the signed-in user: an elevated winget reads its
    sources from the wrong profile. Packages no longer available are skipped,
    and the latest version is installed rather than the old one.

.OUTPUTS
    PSCustomObject with Ok, ExitCode and Text.
#>
function Invoke-TkWingetImport {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or [System.IO.Path]::GetFileName($Path) -ne 'winget.json') {
        return [pscustomobject] @{ Ok = $false; ExitCode = -1; Text = 'The package has no winget.json.' }
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'winget import')) {
        return [pscustomobject] @{ Ok = $false; ExitCode = -1; Text = 'Cancelled.' }
    }

    $stopwatch = Start-TkOperation -Name 'Reinstall applications (winget import)' -Category 'Migration'

    $run = Invoke-TkProcess -FilePath 'winget' -TimeoutSeconds 0 -ArgumentList @(
        'import', '-i', $Path, '--ignore-unavailable', '--ignore-versions',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'
    )

    $ok = ($run.ExitCode -eq 0)
    Stop-TkOperation -Name 'Reinstall applications (winget import)' -Stopwatch $stopwatch -Category 'Migration' -Success $ok

    $text = if ($ok) { 'winget reinstalled the applications it knows.' }
            else { 'winget finished with code {0}: some applications may not have been installed. {1}' -f $run.ExitCode, (Get-TkWingetErrorText -ExitCode $run.ExitCode) }

    return [pscustomobject] @{ Ok = $ok; ExitCode = $run.ExitCode; Text = $text.Trim() }
}
