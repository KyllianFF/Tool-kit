<#
    Toolkit - Features / Installed apps

    Every application installed on the machine in one list, whatever put it
    there: winget and the Microsoft Store, the programs of the uninstall keys
    (the local PC), the games of Steam, Epic Games, Battle.net, Rockstar,
    Ubisoft Connect, EA app and GOG, and the packages of pip, npm,
    Chocolatey, Scoop, the PowerShell Gallery, .NET tools and Cargo. Each row
    says where it comes from and whether an update is known, and the ticked
    rows can be updated or uninstalled.

    An operation is always built from the row's own manager: winget for what
    winget lists (it knows the silent switches of each installer), the
    launcher for a game (a launcher owns its games: its own window opens),
    the package manager for a package. Automatic runs silently; Manual shows
    the installer's or the command's own window. What needs administrator
    rights (Chocolatey, modules installed for all users, the preinstalled
    Windows apps removed for every account) goes through one UAC prompt.

    Nothing here is guessed from a name typed by the user: every id and name
    comes from the manager that listed it, and is checked again before it is
    handed to a command.
#>

<#
.SYNOPSIS
    Reads the uninstall entries of the machine and of this account, with their key names.

.OUTPUTS
    PSCustomObject[] with KeyName, Scope (Machine, User), View (X64, X86),
    DisplayName, DisplayVersion, Publisher, UninstallString,
    QuietUninstallString, InstallLocation, WindowsInstaller, SystemComponent,
    ParentKeyName and ReleaseType.
#>
function Get-TkUninstallEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $sources = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Scope = 'Machine'; View = 'X64' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine'; View = 'X86' }
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Scope = 'User';    View = 'X64' }
    )

    return @(foreach ($source in $sources) {
        try { $key = Get-Item -LiteralPath $source.Path -ErrorAction Stop } catch { continue }

        foreach ($subKeyName in $key.GetSubKeyNames()) {
            try {
                $subKey = $key.OpenSubKey($subKeyName)
                if (-not $subKey) { continue }
                [pscustomobject] @{
                    KeyName              = $subKeyName
                    Scope                = $source.Scope
                    View                 = $source.View
                    DisplayName          = [string] $subKey.GetValue('DisplayName')
                    DisplayVersion       = [string] $subKey.GetValue('DisplayVersion')
                    Publisher            = [string] $subKey.GetValue('Publisher')
                    UninstallString      = [string] $subKey.GetValue('UninstallString')
                    QuietUninstallString = [string] $subKey.GetValue('QuietUninstallString')
                    InstallLocation      = [string] $subKey.GetValue('InstallLocation')
                    WindowsInstaller     = ([string] $subKey.GetValue('WindowsInstaller') -eq '1')
                    SystemComponent      = ([string] $subKey.GetValue('SystemComponent') -eq '1')
                    ParentKeyName        = [string] $subKey.GetValue('ParentKeyName')
                    ReleaseType          = [string] $subKey.GetValue('ReleaseType')
                }
                $subKey.Close()
            }
            catch {
                # One unreadable entry must not hide the others.
                $null = $_
            }
        }
        $key.Close()
    })
}

<#
.SYNOPSIS
    Says which game launcher owns an uninstall entry, if one does.

.DESCRIPTION
    Pure. A launcher registers its games with an uninstall entry that hands
    the uninstall back to it (steam://uninstall, uplay://uninstall, the
    Battle.net or Rockstar launcher). The launchers themselves are programs
    like any other and are not matched.

.OUTPUTS
    PSCustomObject with Source and LauncherId, or $null.
#>
function Resolve-TkLauncherSource {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowNull()] [object] $Entry
    )

    if (-not $Entry) { return $null }

    $key       = [string] $Entry.KeyName
    $name      = [string] $Entry.DisplayName
    $publisher = [string] $Entry.Publisher
    $uninstall = [string] $Entry.UninstallString
    $location  = [string] $Entry.InstallLocation
    $found     = { param($source, $id) [pscustomobject] @{ Source = $source; LauncherId = [string] $id } }

    if ($key -match '^Steam App (\d+)$') { return (& $found 'Steam' $Matches[1]) }
    if ($uninstall -match 'steam://uninstall/(\d+)') { return (& $found 'Steam' $Matches[1]) }
    if ($key -match '^Uplay Install (\d+)$') { return (& $found 'Ubisoft Connect' $Matches[1]) }
    if ($uninstall -match 'uplay://uninstall/(\d+)') { return (& $found 'Ubisoft Connect' $Matches[1]) }
    if ($uninstall -match 'Battle\.net' -and $publisher -match 'Blizzard' -and $name -notmatch '^Battle\.net$') { return (& $found 'Battle.net' '') }
    if ($publisher -match '^Rockstar Games' -and $name -notmatch 'Launcher') { return (& $found 'Rockstar Games' '') }
    if ($publisher -match 'Electronic Arts' -and $uninstall -match 'EAInstaller|EA Desktop|Origin' -and $name -notmatch '^(EA app|EA|Origin)$') { return (& $found 'EA app' '') }
    if (($uninstall -match 'EpicGamesLauncher|com\.epicgames' -or $location -match '\\Epic Games\\') -and $name -notmatch 'Epic Games Launcher|Epic Online Services') { return (& $found 'Epic Games' '') }
    if (($publisher -match 'GOG\.com' -or $location -match 'GOG Galaxy\\Games') -and $name -notmatch 'GOG GALAXY') { return (& $found 'GOG' '') }

    return $null
}

<#
.SYNOPSIS
    Reads the games the Epic Games Launcher installed.

.DESCRIPTION
    Epic keeps its games out of the uninstall keys: each has a manifest in
    the launcher's data folder instead.

.OUTPUTS
    PSCustomObject[] with Name, AppName and Version.
#>
function Get-TkEpicGame {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [string] $ManifestFolder = ([System.IO.Path]::Combine($env:ProgramData, 'Epic\EpicGamesLauncher\Data\Manifests'))
    )

    if (-not [System.IO.Directory]::Exists($ManifestFolder)) { return @() }

    return @(foreach ($file in @(Get-ChildItem -LiteralPath $ManifestFolder -Filter '*.item' -File -ErrorAction SilentlyContinue)) {
        try {
            $item = [System.IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
            if ($item.DisplayName -and $item.AppName) {
                [pscustomobject] @{ Name = [string] $item.DisplayName; AppName = [string] $item.AppName; Version = [string] $item.AppVersionString }
            }
        }
        catch {
            $null = $_
        }
    })
}

<#
.SYNOPSIS
    Builds one row of the installed apps list.

.OUTPUTS
    PSCustomObject
#>
function New-TkInstalledApp {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Id,
        [Parameter()] [AllowEmptyString()] [string] $Version = '',
        [Parameter()] [AllowEmptyString()] [string] $Available = '',
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Manager,
        [Parameter()] [switch] $Preinstalled,
        [Parameter()] [switch] $Elevated,
        [Parameter()] [AllowNull()] [object] $Entry = $null,
        [Parameter()] [AllowEmptyString()] [string] $PackageName = '',
        [Parameter()] [AllowEmptyString()] [string] $LauncherId = ''
    )

    $cleanVersion = if ($Version -match '^(Unknown|Inconnu|Unbekannt|Desconocido|Sconosciuto)$') { '' } else { $Version.Trim() }

    return [pscustomobject] @{
        IsSelected   = $false
        Name         = $Name.Trim()
        Id           = $Id.Trim()
        Version      = $cleanVersion
        Available    = $Available.Trim()
        Source       = $Source
        Manager      = $Manager
        Preinstalled = [bool] $Preinstalled
        Elevated     = [bool] $Elevated
        Entry        = $Entry
        PackageName  = $PackageName
        LauncherId   = $LauncherId
        StateText    = ''
        StateFailed  = $false
    }
}

<#
.SYNOPSIS
    Puts what winget, the uninstall keys, the Store and the launchers know into one list.

.DESCRIPTION
    Pure. With winget, its list is the base: it covers the winget and Store
    packages and every uninstall entry (ARP\...) and Store app (MSIX\...) it
    can act on, and it knows the updates. Each ARP row is matched to its
    uninstall entry by key, to find the games of a launcher. Without winget,
    the uninstall entries and the Store apps are listed directly. Epic games
    and the packages of the other managers are added after.

.PARAMETER Preinstalled
    Package names of the preinstalled Windows apps (data/store-apps.json):
    these are marked, and uninstalled for every account.

.OUTPUTS
    PSCustomObject[] sorted by name.
#>
function ConvertTo-TkInstalledApp {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $WingetRow = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Entry = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $StoreApp = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $EpicGame = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Extra = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Preinstalled = @()
    )

    $byKey = @{}
    foreach ($item in ($Entry | Where-Object { $_ })) {
        $scopeKey = if ($item.Scope -eq 'User') { 'User' } else { 'Machine\{0}' -f $item.View }
        $byKey[('{0}\{1}' -f $scopeKey, $item.KeyName).ToLowerInvariant()] = $item
    }

    $rows = New-Object System.Collections.Generic.List[object]

    if (@($WingetRow | Where-Object { $_ }).Count -gt 0) {

        foreach ($row in ($WingetRow | Where-Object { $_ -and $_.Id })) {
            $id        = [string] $row.Id
            $available = if ($row.PSObject.Properties['Available']) { [string] $row.Available } else { '' }

            if ($id -match '^ARP\\(Machine|User)\\(X64|X86|Arm64)\\(.+)$') {
                $scopeKey = if ($Matches[1] -eq 'User') { 'User' } else { 'Machine\{0}' -f $Matches[2] }
                $found    = $byKey[('{0}\{1}' -f $scopeKey, $Matches[3]).ToLowerInvariant()]
                if (-not $found -and $Matches[1] -eq 'Machine') { $found = $byKey[('Machine\X64\{0}' -f $Matches[3]).ToLowerInvariant()] }
                $launcher = Resolve-TkLauncherSource -Entry $found
                if ($launcher) {
                    $rows.Add((New-TkInstalledApp -Name $row.Name -Id $id -Version $row.Version -Source $launcher.Source -Manager 'launcher' -Entry $found -LauncherId $launcher.LauncherId))
                }
                else {
                    $rows.Add((New-TkInstalledApp -Name $row.Name -Id $id -Version $row.Version -Available $available -Source 'Local PC' -Manager 'winget' -Entry $found))
                }
            }
            elseif ($id -match '^MSIX\\([^_]+)_') {
                $package = $Matches[1]
                $rows.Add((New-TkInstalledApp -Name $row.Name -Id $id -Version $row.Version -Available $available -Source 'Microsoft Store' -Manager 'winget' `
                                              -PackageName $package -Preinstalled:($Preinstalled -contains $package) -Elevated:($Preinstalled -contains $package)))
            }
            else {
                $source = if ([string] $row.Source -eq 'msstore') { 'Microsoft Store' } else { 'WinGet' }
                $rows.Add((New-TkInstalledApp -Name $row.Name -Id $id -Version $row.Version -Available $available -Source $source -Manager 'winget'))
            }
        }
    }
    else {
        $seen = @{}
        foreach ($item in ($Entry | Where-Object { $_ -and $_.DisplayName })) {
            if ($item.SystemComponent -or $item.ParentKeyName -or $item.ReleaseType -match 'Update|Hotfix') { continue }
            $key = '{0}|{1}' -f $item.DisplayName.Trim().ToLowerInvariant(), $item.DisplayVersion
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $launcher = Resolve-TkLauncherSource -Entry $item
            if ($launcher) {
                $rows.Add((New-TkInstalledApp -Name $item.DisplayName -Id $item.KeyName -Version $item.DisplayVersion -Source $launcher.Source -Manager 'launcher' -Entry $item -LauncherId $launcher.LauncherId))
            }
            else {
                $rows.Add((New-TkInstalledApp -Name $item.DisplayName -Id $item.KeyName -Version $item.DisplayVersion -Source 'Local PC' -Manager 'registry' -Entry $item))
            }
        }

        foreach ($app in ($StoreApp | Where-Object { $_ -and $_.Name })) {
            $package = [string] $app.Package
            $rows.Add((New-TkInstalledApp -Name $app.Name -Id ([string] $app.Family) -Version $app.Version -Source 'Microsoft Store' -Manager 'appx' `
                                          -PackageName $package -Preinstalled:($Preinstalled -contains $package) -Elevated:($Preinstalled -contains $package)))
        }
    }

    $names = @{}
    foreach ($row in $rows) { $names[$row.Name.ToLowerInvariant()] = $true }
    foreach ($game in ($EpicGame | Where-Object { $_ -and $_.Name })) {
        if ($names.ContainsKey(([string] $game.Name).Trim().ToLowerInvariant())) { continue }
        $rows.Add((New-TkInstalledApp -Name $game.Name -Id $game.AppName -Version $game.Version -Source 'Epic Games' -Manager 'launcher' -LauncherId $game.AppName))
    }

    foreach ($item in ($Extra | Where-Object { $_ })) { $rows.Add($item) }

    return @($rows.ToArray() | Sort-Object -Property @{ Expression = { $_.Name } }, Source)
}

# ---------------------------------------------------------------------------
# The package managers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads pip list --format=json, with the outdated list if there is one.

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkPipList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Json = '',
        [Parameter()] [AllowEmptyString()] [string] $OutdatedJson = ''
    )

    $parse = { param($text) if ($text -and $text.TrimStart().StartsWith('[')) { @($text | ConvertFrom-Json) } else { @() } }
    $latest = @{}
    foreach ($item in (& $parse $OutdatedJson)) { $latest[[string] $item.name] = [string] $item.latest_version }

    return @(foreach ($item in (& $parse $Json)) {
        New-TkInstalledApp -Name ([string] $item.name) -Id ([string] $item.name) -Version ([string] $item.version) -Available ([string] $latest[[string] $item.name]) -Source 'pip' -Manager 'pip'
    })
}

<#
.SYNOPSIS
    Reads npm ls -g --json and npm outdated -g --json.

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkNpmList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Json = '',
        [Parameter()] [AllowEmptyString()] [string] $OutdatedJson = ''
    )

    $data     = try { if ($Json.Trim()) { $Json | ConvertFrom-Json } else { $null } } catch { $null }
    $outdated = try { if ($OutdatedJson.Trim()) { $OutdatedJson | ConvertFrom-Json } else { $null } } catch { $null }
    if (-not $data -or -not $data.PSObject.Properties['dependencies'] -or -not $data.dependencies) { return @() }

    return @(foreach ($property in $data.dependencies.PSObject.Properties) {
        $newer = if ($outdated -and $outdated.PSObject.Properties[$property.Name]) { [string] $outdated.($property.Name).latest } else { '' }
        $newer = if ($newer -and $newer -ne [string] $property.Value.version) { $newer } else { '' }
        New-TkInstalledApp -Name $property.Name -Id $property.Name -Version ([string] $property.Value.version) -Available $newer -Source 'npm' -Manager 'npm'
    })
}

<#
.SYNOPSIS
    Reads choco list -r and choco outdated -r (name|version, name|current|available|pinned).

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkChocoList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Text = '',
        [Parameter()] [AllowEmptyString()] [string] $Outdated = ''
    )

    $latest = @{}
    foreach ($line in ($Outdated -split "`r?`n")) {
        $parts = $line.Trim() -split '\|'
        if ($parts.Count -ge 3 -and $parts[0] -and $parts[2]) { $latest[$parts[0]] = $parts[2] }
    }

    return @(foreach ($line in ($Text -split "`r?`n")) {
        $parts = $line.Trim() -split '\|'
        if ($parts.Count -lt 2 -or -not $parts[0] -or $parts[0] -match '\s') { continue }
        New-TkInstalledApp -Name $parts[0] -Id $parts[0] -Version $parts[1] -Available ([string] $latest[$parts[0]]) -Source 'Chocolatey' -Manager 'choco' -Elevated
    })
}

<#
.SYNOPSIS
    Reads scoop export.

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkScoopExport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Json = ''
    )

    $data = try { if ($Json.Trim()) { $Json | ConvertFrom-Json } else { $null } } catch { $null }
    if (-not $data -or -not $data.PSObject.Properties['apps']) { return @() }

    return @(foreach ($app in @($data.apps)) {
        if (-not $app.Name) { continue }
        New-TkInstalledApp -Name ([string] $app.Name) -Id ([string] $app.Name) -Version ([string] $app.Version) -Source 'Scoop' -Manager 'scoop'
    })
}

<#
.SYNOPSIS
    Reads dotnet tool list -g: the table under its dashed rule.

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkDotnetToolList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Text = ''
    )

    $lines = @($Text -split "`r?`n")
    $rule  = [array]::FindIndex([string[]] $lines, [Predicate[string]] { param($line) $line -match '^-{5,}' })
    if ($rule -lt 0) { return @() }

    return @(foreach ($line in ($lines | Select-Object -Skip ($rule + 1))) {
        $parts = @($line.Trim() -split '\s+')
        if ($parts.Count -lt 2 -or -not $parts[0]) { continue }
        New-TkInstalledApp -Name $parts[0] -Id $parts[0] -Version $parts[1] -Source '.NET tool' -Manager 'dotnet'
    })
}

<#
.SYNOPSIS
    Reads cargo install --list.

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkCargoList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Text = ''
    )

    return @(foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^(\S+) v(\S+?)(\s.*)?:$') {
            New-TkInstalledApp -Name $Matches[1] -Id $Matches[1] -Version $Matches[2] -Source 'Cargo' -Manager 'cargo'
        }
    })
}

<#
.SYNOPSIS
    Reads the modules list a PowerShell edition wrote as JSON.

.OUTPUTS
    PSCustomObject[] rows.
#>
function ConvertFrom-TkPowerShellModuleList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Json = '',
        [Parameter(Mandatory)] [ValidateSet('5', '7')] [string] $Edition
    )

    $data = try { if ($Json.Trim()) { @($Json | ConvertFrom-Json) } else { @() } } catch { @() }

    return @(foreach ($module in $data) {
        if (-not $module -or -not $module.Name) { continue }
        New-TkInstalledApp -Name ([string] $module.Name) -Id ([string] $module.Name) -Version ([string] $module.Version) -Available ([string] $module.Available) `
                           -Source ('PowerShell {0}' -f $Edition) -Manager ('powershell{0}' -f $Edition) -Elevated:([bool] $module.AllUsers)
    })
}

<#
.SYNOPSIS
    Finds the package managers of this machine.

.DESCRIPTION
    The Microsoft Store's python.exe alias is not Python: it opens the Store.
    npm and scoop are called through their .cmd shims.

.OUTPUTS
    Hashtable of name to path, for the managers found.
#>
function Get-TkPackageTool {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $tools = @{}
    $find  = { param($name) (Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source }

    foreach ($name in @('winget', 'choco', 'dotnet', 'cargo', 'pwsh')) {
        $path = & $find $name
        if ($path) { $tools[$name] = $path }
    }

    $py = & $find 'py'
    if ($py) { $tools['python'] = $py; $tools['pythonLauncher'] = $true }
    else {
        $python = & $find 'python'
        if ($python -and $python -notmatch '\\WindowsApps\\') { $tools['python'] = $python }
    }

    foreach ($name in @('npm', 'scoop')) {
        $path = & $find ('{0}.cmd' -f $name)
        if ($path) { $tools[$name] = $path }
    }

    $tools['powershell'] = [System.IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\powershell.exe')
    return $tools
}

<#
.SYNOPSIS
    The script a PowerShell edition runs to list its Gallery modules and their updates.

.OUTPUTS
    System.String
#>
function Get-TkModuleListScript {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
$ProgressPreference = 'SilentlyContinue'
$modules = @(Get-InstalledModule -ErrorAction SilentlyContinue)
$latest = @{}
if ($modules.Count -gt 0) { foreach ($found in @(Find-Module -Name @($modules.Name) -ErrorAction SilentlyContinue)) { $latest[$found.Name] = [string] $found.Version } }
$rows = foreach ($module in $modules) {
    $newer = ''
    try { if ($latest[$module.Name] -and [version] $latest[$module.Name] -gt [version] [string] $module.Version) { $newer = $latest[$module.Name] } } catch { $newer = '' }
    [pscustomobject] @{ Name = $module.Name; Version = [string] $module.Version; Available = $newer; AllUsers = ([string] $module.InstalledLocation).StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) }
}
ConvertTo-Json -InputObject @($rows) -Compress
'@
}

<#
.SYNOPSIS
    Lists every installed application, and what each manager knows of its updates.

.OUTPUTS
    PSCustomObject with Items and Notes (a line per source that could not be read).
#>
function Get-TkInstalledApplication {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [hashtable] $Tool = (Get-TkPackageTool)
    )

    $notes  = New-Object System.Collections.Generic.List[string]
    $extra  = New-Object System.Collections.Generic.List[object]
    # winget, pip, npm, Scoop, .NET and Cargo write UTF-8 whatever the console code page.
    $utf8   = New-Object System.Text.UTF8Encoding($false)
    $run    = {
        param($file, $arguments, $timeout)
        $wide = $file -match '(winget|py|python|npm|scoop|dotnet|cargo)(\.exe|\.cmd)?$'
        if ($wide) { Invoke-TkProcess -FilePath $file -ArgumentList $arguments -TimeoutSeconds $timeout -OutputEncoding $utf8 }
        else { Invoke-TkProcess -FilePath $file -ArgumentList $arguments -TimeoutSeconds $timeout }
    }
    $catalog = @(@((Import-TkCatalog -Name 'store-apps').apps) | ForEach-Object { [string] $_.name })

    $wingetRows = @()
    if ($Tool['winget']) {
        $list = & $run $Tool['winget'] @('list', '--accept-source-agreements', '--disable-interactivity') 240
        $wingetRows = @(ConvertFrom-TkWingetTable -Text ([string] $list.StandardOutput))
        if ($wingetRows.Count -eq 0) { $notes.Add('winget listed nothing: the uninstall keys and the Store are read instead.') }
    }
    else {
        $notes.Add('winget is not installed: the uninstall keys and the Store are read instead, without updates.')
    }

    $storeApps = if ($wingetRows.Count -eq 0) { @(Get-TkStoreApplication) } else { @() }

    if ($Tool['python']) {
        $prefix = @('-m', 'pip')
        $list   = & $run $Tool['python'] ($prefix + @('list', '--format=json', '--disable-pip-version-check')) 120
        $old    = & $run $Tool['python'] ($prefix + @('list', '--outdated', '--format=json', '--disable-pip-version-check')) 180
        foreach ($row in @(ConvertFrom-TkPipList -Json ([string] $list.StandardOutput) -OutdatedJson ([string] $old.StandardOutput))) { $extra.Add($row) }
    }
    if ($Tool['npm']) {
        $list = & $run $Tool['npm'] @('ls', '-g', '--depth=0', '--json') 120
        $old  = & $run $Tool['npm'] @('outdated', '-g', '--json') 180
        $rows = @(ConvertFrom-TkNpmList -Json ([string] $list.StandardOutput) -OutdatedJson ([string] $old.StandardOutput))
        foreach ($row in $rows) { $extra.Add($row) }
        # ENOENT on the global folder only means nothing was ever installed globally.
        if ($rows.Count -eq 0 -and $list.ExitCode -ne 0 -and ('{0}{1}' -f $list.StandardOutput, $list.StandardError) -notmatch 'ENOENT') {
            $notes.Add('npm could not list its global packages.')
        }
    }
    if ($Tool['choco']) {
        $version = [string] (& $run $Tool['choco'] @('--version') 60).StandardOutput
        $local   = if ($version -match '^\s*[01]\.') { @('list', '--local-only', '-r') } else { @('list', '-r') }
        $list    = & $run $Tool['choco'] $local 120
        $old     = & $run $Tool['choco'] @('outdated', '-r', '--ignore-unfound') 240
        foreach ($row in @(ConvertFrom-TkChocoList -Text ([string] $list.StandardOutput) -Outdated ([string] $old.StandardOutput))) { $extra.Add($row) }
    }
    if ($Tool['scoop']) {
        foreach ($row in @(ConvertFrom-TkScoopExport -Json ([string] (& $run $Tool['scoop'] @('export') 120).StandardOutput))) { $extra.Add($row) }
    }
    if ($Tool['dotnet']) {
        foreach ($row in @(ConvertFrom-TkDotnetToolList -Text ([string] (& $run $Tool['dotnet'] @('tool', 'list', '-g') 120).StandardOutput))) { $extra.Add($row) }
    }
    if ($Tool['cargo']) {
        foreach ($row in @(ConvertFrom-TkCargoList -Text ([string] (& $run $Tool['cargo'] @('install', '--list') 120).StandardOutput))) { $extra.Add($row) }
    }

    $script = Get-TkModuleListScript
    foreach ($edition in @(@{ Name = '5'; Path = $Tool['powershell'] }, @{ Name = '7'; Path = $Tool['pwsh'] })) {
        if (-not $edition.Path -or -not [System.IO.File]::Exists($edition.Path)) { continue }
        $list = & $run $edition.Path @('-NoProfile', '-NonInteractive', '-Command', $script) 240
        foreach ($row in @(ConvertFrom-TkPowerShellModuleList -Json ([string] $list.StandardOutput) -Edition $edition.Name)) { $extra.Add($row) }
    }

    $items = ConvertTo-TkInstalledApp -WingetRow $wingetRows -Entry @(Get-TkUninstallEntry) -StoreApp $storeApps -EpicGame @(Get-TkEpicGame) `
                                      -Extra @($extra.ToArray()) -Preinstalled $catalog

    return [pscustomobject] @{ Items = @($items); Notes = @($notes.ToArray()) }
}

# ---------------------------------------------------------------------------
# Updating and uninstalling
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Splits a command line from the registry into the program and its arguments.

.DESCRIPTION
    Pure. The program is quoted, or runs up to .exe, or is the first word.

.OUTPUTS
    PSCustomObject with FilePath and Arguments (one string), or $null.
#>
function Split-TkCommandLine {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $CommandLine = ''
    )

    $text = $CommandLine.Trim()
    if (-not $text) { return $null }

    if ($text -match '^"([^"]+)"\s*(.*)$') { return [pscustomobject] @{ FilePath = $Matches[1]; Arguments = $Matches[2].Trim() } }
    if ($text -match '^(.+?\.exe)(\s+.*)?$') { return [pscustomobject] @{ FilePath = $Matches[1]; Arguments = ([string] $Matches[2]).Trim() } }

    $parts = $text -split '\s+', 2
    return [pscustomobject] @{ FilePath = $parts[0]; Arguments = $(if ($parts.Count -gt 1) { $parts[1] } else { '' }) }
}

<#
.SYNOPSIS
    Says whether a package id or name may be handed to its manager.

.OUTPUTS
    System.Boolean
#>
function Test-TkInstalledAppId {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Id = '',
        [Parameter(Mandatory)] [string] $Manager
    )

    if (-not $Id -or $Id.Length -gt 256 -or $Id -match '["\r\n\t`]' -or $Id -match '[\x00-\x1f]') { return $false }
    if ($Manager -eq 'winget') { return $true }
    return ($Id -match '^[A-Za-z0-9@][A-Za-z0-9._+/@-]*$')
}

<#
.SYNOPSIS
    Works out how to update or uninstall one row, without running anything.

.DESCRIPTION
    Pure. Kind is Run (a hidden process, output read), Shell (a program the
    user sees and may have to confirm, UAC included), Console (a command in
    a window the user sees), Open (a launcher link), Appx (the Store app of
    this account), Elevated (through the one UAC prompt of the batch) or
    None (with the reason in Note).

.OUTPUTS
    PSCustomObject with Kind, FilePath, Arguments (string[] for Run and
    Console, one string for Shell), Name (for Appx and Elevated) and Note.
#>
function Get-TkInstalledAppCommand {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Item,
        [Parameter(Mandatory)] [ValidateSet('Update', 'Uninstall')] [string] $Operation,
        [Parameter()] [ValidateSet('Silent', 'Interactive')] [string] $Mode = 'Silent',
        [Parameter()] [hashtable] $Tool = @{}
    )

    $plan   = { param($kind, $file, $arguments, $note) [pscustomobject] @{ Kind = $kind; FilePath = [string] $file; Arguments = $arguments; Name = ''; Note = [string] $note } }
    $none   = { param($note) & $plan 'None' '' @() $note }
    $silent = $Mode -eq 'Silent'
    $id     = [string] $Item.Id

    if ($Item.Manager -ne 'launcher' -and $Item.Manager -ne 'registry' -and $Item.Manager -ne 'appx' -and -not (Test-TkInstalledAppId -Id $id -Manager $Item.Manager)) {
        return (& $none 'its id cannot be handed to a command safely')
    }

    # The preinstalled Windows apps go for every account, as the old Store apps tab did.
    if ($Item.Preinstalled -and $Operation -eq 'Uninstall') {
        $elevated = & $plan 'Elevated' '' @() 'removed for every account, and from the Windows image'
        $elevated.Name = [string] $Item.PackageName
        return $elevated
    }

    switch ($Item.Manager) {

        'winget' {
            if (-not $Tool['winget']) { return (& $none 'winget is not installed') }
            if ($Operation -eq 'Update') {
                if (-not $Item.Available -or $id -match '^(ARP|MSIX)\\') { return (& $none 'no update that winget can install') }
                $arguments = @('upgrade', '--id', $id, '--exact', '--accept-source-agreements', '--accept-package-agreements')
            }
            else {
                $arguments = @('uninstall', '--id', $id, '--exact', '--accept-source-agreements')
            }
            $arguments += if ($silent) { @('--silent', '--disable-interactivity') } else { @('--interactive') }
            return (& $plan 'Run' $Tool['winget'] $arguments '')
        }

        'launcher' {
            if ($Operation -eq 'Update') { return (& $none ('{0} updates its games itself' -f $Item.Source)) }
            if ($Item.Source -eq 'Epic Games') { return (& $plan 'Open' 'com.epicgames.launcher://store' @() 'uninstall it from the Epic Games Launcher library') }
            $command = Split-TkCommandLine -CommandLine ([string] $Item.Entry.UninstallString)
            if (-not $command) { return (& $none ('{0} has no uninstaller registered: use {1}' -f $Item.Name, $Item.Source)) }
            return (& $plan 'Shell' $command.FilePath $command.Arguments ('{0} opens its own uninstall' -f $Item.Source))
        }

        'registry' {
            if ($Operation -eq 'Update') { return (& $none 'update it from the application or its publisher') }
            $entry = $Item.Entry
            if ($entry.WindowsInstaller -and $entry.KeyName -match '^\{[0-9A-Fa-f-]{36}\}$') {
                $msi = @('/x', $entry.KeyName) + $(if ($silent) { @('/qn', '/norestart') } else { @() })
                return (& $plan 'Shell' 'msiexec.exe' ($msi -join ' ') '')
            }
            $line = if ($silent -and $entry.QuietUninstallString) { $entry.QuietUninstallString } else { $entry.UninstallString }
            $command = Split-TkCommandLine -CommandLine ([string] $line)
            if (-not $command) { return (& $none 'no uninstaller is registered') }
            $note = if ($silent -and -not $entry.QuietUninstallString) { 'no silent uninstaller is registered: its own window opens' } else { '' }
            return (& $plan 'Shell' $command.FilePath $command.Arguments $note)
        }

        'appx' {
            if ($Operation -eq 'Update') { return (& $none 'the Microsoft Store updates it') }
            $appx = & $plan 'Appx' '' @() ''
            $appx.Name = [string] $Item.PackageName
            return $appx
        }

        'pip' {
            if (-not $Tool['python']) { return (& $none 'Python is not found') }
            $arguments = if ($Operation -eq 'Update') { @('-m', 'pip', 'install', '--upgrade', $id, '--disable-pip-version-check') }
                         else { @('-m', 'pip', 'uninstall', $id) + $(if ($silent) { @('-y') } else { @() }) }
            return (& $plan $(if ($silent) { 'Run' } else { 'Console' }) $Tool['python'] $arguments '')
        }

        'npm' {
            if (-not $Tool['npm']) { return (& $none 'npm is not found') }
            $arguments = if ($Operation -eq 'Update') { @('install', '-g', ('{0}@latest' -f $id)) } else { @('uninstall', '-g', $id) }
            return (& $plan $(if ($silent) { 'Run' } else { 'Console' }) $Tool['npm'] $arguments '')
        }

        'scoop' {
            if (-not $Tool['scoop']) { return (& $none 'Scoop is not found') }
            $arguments = if ($Operation -eq 'Update') { @('update', $id) } else { @('uninstall', $id) }
            return (& $plan $(if ($silent) { 'Run' } else { 'Console' }) $Tool['scoop'] $arguments '')
        }

        'dotnet' {
            if (-not $Tool['dotnet']) { return (& $none '.NET is not found') }
            $arguments = if ($Operation -eq 'Update') { @('tool', 'update', '-g', $id) } else { @('tool', 'uninstall', '-g', $id) }
            return (& $plan $(if ($silent) { 'Run' } else { 'Console' }) $Tool['dotnet'] $arguments '')
        }

        'cargo' {
            if (-not $Tool['cargo']) { return (& $none 'Cargo is not found') }
            $arguments = if ($Operation -eq 'Update') { @('install', $id) } else { @('uninstall', $id) }
            return (& $plan $(if ($silent) { 'Run' } else { 'Console' }) $Tool['cargo'] $arguments '')
        }

        { $_ -in @('choco', 'powershell5', 'powershell7') } {
            if ($Item.Elevated) {
                $elevated = & $plan 'Elevated' '' @() $(if ($Item.Manager -eq 'choco') { 'Chocolatey needs administrator rights' } else { 'installed for every account' })
                $elevated.Name = $id
                return $elevated
            }
            $shell = if ($Item.Manager -eq 'powershell5') { $Tool['powershell'] } else { $Tool['pwsh'] }
            $verb  = if ($Operation -eq 'Update') { "Update-Module -Name '{0}' -Force" -f $id } else { "Uninstall-Module -Name '{0}' -AllVersions -Force" -f $id }
            return (& $plan $(if ($silent) { 'Run' } else { 'Console' }) $shell @('-NoProfile', '-NonInteractive', '-Command', $verb) '')
        }
    }

    return (& $none 'not supported')
}

<#
.SYNOPSIS
    Runs one planned operation that needs no elevation.

.OUTPUTS
    PSCustomObject with Ok and Text.
#>
function Invoke-TkInstalledAppCommand {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Plan
    )

    $done = { param($ok, $text) [pscustomobject] @{ Ok = [bool] $ok; Text = [string] $text } }
    if (-not $PSCmdlet.ShouldProcess($Plan.FilePath, $Plan.Kind)) { return (& $done $false 'Cancelled.') }

    try {
        switch ($Plan.Kind) {
            'Run' {
                $result = Invoke-TkProcess -FilePath $Plan.FilePath -ArgumentList @($Plan.Arguments) -TimeoutSeconds 1800
                if ($result.ExitCode -eq 0) { return (& $done $true 'done') }
                $why = Get-TkFirstLine -Text $(if ($result.StandardError) { [string] $result.StandardError } else { [string] $result.StandardOutput })
                return (& $done $false ('failed (code {0}) {1}' -f $result.ExitCode, $why).Trim())
            }
            'Console' {
                $process = Start-Process -FilePath $Plan.FilePath -ArgumentList @($Plan.Arguments | ForEach-Object { ConvertTo-TkProcessArgument -Value $_ }) -Wait -PassThru
                return (& $done ($process.ExitCode -eq 0) $(if ($process.ExitCode -eq 0) { 'done' } else { 'ended with code {0}' -f $process.ExitCode }))
            }
            'Shell' {
                $start = @{ FilePath = $Plan.FilePath; Wait = $true; PassThru = $true }
                if ([string] $Plan.Arguments) { $start['ArgumentList'] = [string] $Plan.Arguments }
                $process = Start-Process @start
                $ok = @(0, 1641, 3010) -contains $process.ExitCode
                return (& $done $ok $(if ($ok) { 'done' } else { 'ended with code {0}' -f $process.ExitCode }))
            }
            'Open' {
                Start-Process -FilePath $Plan.FilePath
                return (& $done $true 'opened')
            }
            'Appx' {
                $packages = @(Get-AppxPackage -Name $Plan.Name -ErrorAction Stop)
                if ($packages.Count -eq 0) { return (& $done $false 'not installed for this account') }
                foreach ($package in $packages) { Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop }
                return (& $done $true 'removed for this account')
            }
        }
    }
    catch {
        return (& $done $false $_.Exception.Message)
    }

    return (& $done $false 'not run')
}

<#
.SYNOPSIS
    Updates or uninstalls the ticked rows that need no elevation, one after the other.

.DESCRIPTION
    Sequential on purpose: installers share one Windows Installer mutex.
    The rows that need administrator rights are returned for one elevated
    batch instead of being run here.

.OUTPUTS
    PSCustomObject with Results (Name, Source, Ok, Text) and Elevated
    (Manager, Operation, Name, Label).
#>
function Invoke-TkInstalledAppAction {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Item,
        [Parameter(Mandatory)] [ValidateSet('Update', 'Uninstall')] [string] $Operation,
        [Parameter()] [ValidateSet('Silent', 'Interactive')] [string] $Mode = 'Silent',
        [Parameter()] [hashtable] $Tool = (Get-TkPackageTool)
    )

    $results  = New-Object System.Collections.Generic.List[object]
    $elevated = New-Object System.Collections.Generic.List[object]

    foreach ($row in ($Item | Where-Object { $_ })) {

        $plan = Get-TkInstalledAppCommand -Item $row -Operation $Operation -Mode $Mode -Tool $Tool

        if ($plan.Kind -eq 'Elevated') {
            $manager = if ($row.Preinstalled) { 'appx' } else { [string] $row.Manager }
            $elevated.Add([pscustomobject] @{ Manager = $manager; Operation = $Operation; Name = $plan.Name; Label = $row.Name })
            continue
        }
        if ($plan.Kind -eq 'None') {
            $results.Add([pscustomobject] @{ Name = $row.Name; Source = $row.Source; Ok = $false; Text = $plan.Note })
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($row.Name, $Operation)) { continue }

        $done = Invoke-TkInstalledAppCommand -Plan $plan -Confirm:$false
        $text = if ($plan.Note) { '{0}; {1}' -f $done.Text, $plan.Note } else { $done.Text }
        $results.Add([pscustomobject] @{ Name = $row.Name; Source = $row.Source; Ok = $done.Ok; Text = $text })
    }

    if ($results.Count -gt 0) {
        Add-TkJournalEntry -Name ('Installed apps: {0}' -f $Operation.ToLowerInvariant()) -Category 'Software' -Detail (
            (@($results | ForEach-Object { '{0} ({1}): {2}' -f $_.Name, $_.Source, $_.Text })) -join '; '
        )
    }

    return [pscustomobject] @{ Results = @($results.ToArray()); Elevated = @($elevated.ToArray()) }
}

<#
.SYNOPSIS
    Runs the operations that need administrator rights, in the elevated worker.

.DESCRIPTION
    Each item is checked again here: a Chocolatey or module name must pass
    the id check, and a Store app must be one of the preinstalled apps the
    toolkit removes (Remove-TkStoreApp refuses anything else).

.OUTPUTS
    PSCustomObject[] with Name, Source, Ok and Text.
#>
function Invoke-TkElevatedPackageAction {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Item,
        [Parameter()] [hashtable] $Tool = (Get-TkPackageTool)
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($entry in ($Item | Where-Object { $_ })) {

        $manager   = [string] $entry.Manager
        $operation = [string] $entry.Operation
        $name      = [string] $entry.Name
        $label     = if ($entry.Label) { [string] $entry.Label } else { $name }
        $add       = { param($ok, $text, $source) $results.Add([pscustomobject] @{ Name = $label; Source = $source; Ok = [bool] $ok; Text = [string] $text }) }

        if ($operation -notin @('Update', 'Uninstall') -or -not (Test-TkInstalledAppId -Id $name -Manager 'choco')) {
            & $add $false 'refused: not a package name' $manager
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($name, $operation)) { continue }

        switch ($manager) {
            'appx' {
                if ($operation -ne 'Uninstall') { & $add $false 'refused' 'Microsoft Store'; break }
                foreach ($removed in @(Remove-TkStoreApp -Name @($name) -Confirm:$false)) { & $add $removed.Ok $removed.Message 'Microsoft Store' }
            }
            'choco' {
                if (-not $Tool['choco']) { & $add $false 'Chocolatey is not found' 'Chocolatey'; break }
                $verb = if ($operation -eq 'Update') { 'upgrade' } else { 'uninstall' }
                $run  = Invoke-TkProcess -FilePath $Tool['choco'] -ArgumentList @($verb, $name, '-y', '--no-progress') -TimeoutSeconds 1800
                & $add ($run.ExitCode -eq 0 -or $run.ExitCode -eq 3010) $(if ($run.ExitCode -eq 0) { 'done' } else { 'ended with code {0}' -f $run.ExitCode }) 'Chocolatey'
            }
            { $_ -in @('powershell5', 'powershell7') } {
                $shell = if ($manager -eq 'powershell5') { $Tool['powershell'] } else { $Tool['pwsh'] }
                $verb  = if ($operation -eq 'Update') { "Update-Module -Name '{0}' -Force" -f $name } else { "Uninstall-Module -Name '{0}' -AllVersions -Force" -f $name }
                $run   = Invoke-TkProcess -FilePath $shell -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $verb) -TimeoutSeconds 900
                & $add ($run.ExitCode -eq 0) $(if ($run.ExitCode -eq 0) { 'done' } else { Get-TkFirstLine -Text ([string] $run.StandardError) }) ('PowerShell {0}' -f $manager.Substring(10))
            }
            default { & $add $false 'refused: not a manager that needs elevation' $manager }
        }
    }

    Add-TkJournalEntry -Name 'Installed apps: elevated operations' -Category 'Software' -Detail (
        (@($results | ForEach-Object { '{0} ({1}): {2}' -f $_.Name, $_.Source, $_.Text })) -join '; '
    )

    return @($results.ToArray())
}
