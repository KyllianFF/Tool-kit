<#
    Toolkit - Features / Software lifecycle

    Whether Windows and the installed programs still receive security fixes.
    A program past its end of support is not broken, which is why it stays
    installed for years: it simply never gets a fix again, for any
    vulnerability found after that date.

    The dates come from data/software-lifecycle.json, written from what each
    vendor publishes, so the report works offline and says when the catalog
    was reviewed. Two rules keep it honest:

      - a program the catalog does not list is not judged at all, and a
        version of a listed product that no cycle matches is reported as not
        in the catalog, never guessed;
      - the judgement follows the risk of the product. An unsupported browser
        plugin or database is a failure; an old Visual C++ runtime, which only
        runs inside the programs built with it, is information.
#>

<#
.SYNOPSIS
    Reads a field of a catalog object, or $null when it is absent.

.PARAMETER Object
    An object read from JSON.

.PARAMETER Name
    The field.
#>
function Get-TkCatalogField {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] $Object,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]

    if ($property) {
        return $property.Value
    }

    return $null
}

<#
.SYNOPSIS
    Reads a catalog date.

.DESCRIPTION
    Written as yyyy-MM-dd. PowerShell 7 already turns such a string into a
    DateTime while reading the JSON, and Windows PowerShell 5.1 does not, so
    both are accepted.

.PARAMETER Value
    The date as read, or $null for no date.

.OUTPUTS
    System.DateTime, or $null.
#>
function ConvertTo-TkLifecycleDate {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or ($Value -is [string] -and -not $Value)) {
        return $null
    }

    if ($Value -is [datetime]) {
        return $Value.Date
    }

    return [datetime]::ParseExact([string] $Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

<#
.SYNOPSIS
    Judges an end of support date against today.

.PARAMETER End
    The last day of support, or $null when none is announced.

.PARAMETER Risk
    High for what handles untrusted content or data, such as Windows, Office,
    a browser plugin or a database; Medium for runtimes; Low for components
    that only run inside other programs.

.PARAMETER Now
    Today.

.PARAMETER WarningDays
    How close an end has to be to warn.

.OUTPUTS
    PSCustomObject with Status (Supported, Ending, Ended), Severity, Ends and
    DaysLeft.
#>
function Get-TkLifecycleState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowNull()] $End,
        [Parameter()] [ValidateSet('High', 'Medium', 'Low')] [string] $Risk = 'High',
        [Parameter()] [datetime] $Now = (Get-Date),
        [Parameter()] [ValidateRange(1, 3650)] [int] $WarningDays = 180
    )

    $endDate = ConvertTo-TkLifecycleDate -Value $End

    if ($null -eq $endDate) {
        return [pscustomobject] @{ Status = 'Supported'; Severity = 'Pass'; Ends = ''; DaysLeft = $null }
    }

    $days = [int] ($endDate - $Now.Date).TotalDays
    $ends = $endDate.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)

    if ($days -lt 0) {

        $severity = switch ($Risk) {
            'High'   { 'Fail' }
            'Medium' { 'Warning' }
            default  { 'Info' }
        }

        return [pscustomobject] @{ Status = 'Ended'; Severity = $severity; Ends = $ends; DaysLeft = $days }
    }

    if ($days -le $WarningDays) {

        $severity = if ($Risk -eq 'Low') { 'Info' } else { 'Warning' }

        return [pscustomobject] @{ Status = 'Ending'; Severity = $severity; Ends = $ends; DaysLeft = $days }
    }

    return [pscustomobject] @{ Status = 'Supported'; Severity = 'Pass'; Ends = $ends; DaysLeft = $days }
}

<#
.SYNOPSIS
    The state of a version the catalog does not know.
#>
function New-TkUnknownLifecycleState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject] @{ Status = 'Unknown'; Severity = 'Info'; Ends = ''; DaysLeft = $null }
}

<#
.SYNOPSIS
    Builds one row of the report, the same shape for Windows and a program.
#>
function New-TkLifecycleRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $ProductId,
        [Parameter(Mandatory)] [string] $Product,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Cycle,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Title,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Installed = @(),
        [Parameter()] [AllowEmptyString()] [string] $Version = '',
        [Parameter(Mandatory)] [pscustomobject] $State,
        [Parameter()] [AllowEmptyString()] [string] $Risk = 'High',
        [Parameter()] [AllowEmptyString()] [string] $Note = '',
        [Parameter()] [AllowEmptyString()] [string] $Replacement = '',
        [Parameter()] [AllowEmptyString()] [string] $Reference = ''
    )

    return [pscustomobject] @{
        ProductId   = $ProductId
        Product     = $Product
        Cycle       = $Cycle
        Title       = $Title
        Installed   = @($Installed)
        Version     = $Version
        Ends        = $State.Ends
        DaysLeft    = $State.DaysLeft
        Status      = $State.Status
        Severity    = $State.Severity
        Risk        = $Risk
        Note        = $Note
        Replacement = $Replacement
        Reference   = $Reference
    }
}

<#
.SYNOPSIS
    Says in a few words where a row stands.

.PARAMETER Row
    A row of the report.

.OUTPUTS
    System.String
#>
function Format-TkLifecycleDetail {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Row
    )

    switch ($Row.Status) {

        'Ended' { return ('ended {0}' -f $Row.Ends) }

        'Ending' {
            if ($Row.DaysLeft -eq 0) { return 'ends today' }
            return ('ends {0}, in {1} days' -f $Row.Ends, $Row.DaysLeft)
        }

        'Supported' {
            if ($Row.Ends) { return ('supported until {0}' -f $Row.Ends) }
            return 'no end date announced'
        }

        'Outdated' { return 'not kept up to date' }
    }

    return 'not in the catalog'
}

# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads what decides the support of this Windows installation.

.DESCRIPTION
    The edition identifier rather than the caption, which Windows translates
    ("Professionnel", "Professionell").

.OUTPUTS
    PSCustomObject with Caption, EditionId, InstallationType, DisplayVersion
    and Build.
#>
function Get-TkWindowsVersionFact {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $path  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = 0

    [void] [int]::TryParse([string] (Get-TkRegistryValue -Path $path -Name 'CurrentBuild'), [ref] $build)

    $os      = Get-TkCimInstanceSafe -ClassName 'Win32_OperatingSystem'
    $caption = if ($os -and $os.Caption) { [string] $os.Caption } else { [string] (Get-TkRegistryValue -Path $path -Name 'ProductName') }

    return [pscustomobject] @{
        Caption          = $caption.Trim()
        EditionId        = [string] (Get-TkRegistryValue -Path $path -Name 'EditionID')
        InstallationType = [string] (Get-TkRegistryValue -Path $path -Name 'InstallationType')
        DisplayVersion   = [string] (Get-TkRegistryValue -Path $path -Name 'DisplayVersion')
        Build            = $build
    }
}

<#
.SYNOPSIS
    Tells which support calendar an edition follows.

.DESCRIPTION
    Home, Pro, Pro Education and Pro for Workstations get 24 months per
    Windows 11 feature update; Enterprise, Education and IoT Enterprise get
    36. The LTSC editions and Windows Server have calendars of their own.

.PARAMETER EditionId
    EditionID from the registry, such as Professional, Enterprise or
    EnterpriseS.

.PARAMETER InstallationType
    InstallationType from the registry: Client, Server or Server Core.

.OUTPUTS
    PSCustomObject with Channel (Client, Ltsc, Server), Audience (Consumer,
    Enterprise, Ltsc, IotLtsc, Server) and Label.
#>
function Get-TkWindowsAudience {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $EditionId = '',
        [Parameter()] [AllowEmptyString()] [string] $InstallationType = ''
    )

    $audience = {
        param($channel, $name, $label)
        [pscustomobject] @{ Channel = $channel; Audience = $name; Label = $label }
    }

    if ($InstallationType -like 'Server*' -or $EditionId -like 'Server*') {
        return (& $audience 'Server' 'Server' 'Server')
    }

    if ($EditionId -like 'IoTEnterpriseS*') {
        return (& $audience 'Ltsc' 'IotLtsc' 'IoT Enterprise LTSC')
    }

    if ($EditionId -like 'EnterpriseS*') {
        return (& $audience 'Ltsc' 'Ltsc' 'Enterprise LTSC')
    }

    if ($EditionId -match '^(Enterprise|Education|IoTEnterprise)') {
        return (& $audience 'Client' 'Enterprise' 'Enterprise and Education')
    }

    return (& $audience 'Client' 'Consumer' 'Home and Pro')
}

<#
.SYNOPSIS
    Judges the support of a Windows installation.

.PARAMETER Fact
    What Get-TkWindowsVersionFact returns.

.PARAMETER Catalog
    The software-lifecycle catalog.

.PARAMETER Now
    Today.

.OUTPUTS
    PSCustomObject as built by New-TkLifecycleRow.
#>
function Resolve-TkWindowsLifecycle {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Fact,
        [Parameter(Mandatory)] $Catalog,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $audience = Get-TkWindowsAudience -EditionId ([string] $Fact.EditionId) -InstallationType ([string] $Fact.InstallationType)
    $build    = [int] $Fact.Build
    $entries  = @($Catalog.windows | Where-Object { $_ -and $_.channel -eq $audience.Channel })

    $entry = $entries | Where-Object { (Get-TkCatalogField -Object $_ -Name 'build') -eq $build } | Select-Object -First 1

    if (-not $entry) {

        $entry = $entries | Where-Object {
            $from  = Get-TkCatalogField -Object $_ -Name 'buildFrom'
            $below = Get-TkCatalogField -Object $_ -Name 'buildBelow'
            $null -ne $from -and $null -ne $below -and $build -ge $from -and $build -lt $below
        } | Select-Object -First 1
    }

    $version     = if ($Fact.DisplayVersion) { '{0}, build {1}' -f $Fact.DisplayVersion, $build } else { 'build {0}' -f $build }
    $replacement = [string] (Get-TkCatalogField -Object (Get-TkCatalogField -Object $Catalog -Name 'windowsReplacement') -Name $audience.Channel)
    $reference   = [string] (Get-TkCatalogField -Object (Get-TkCatalogField -Object $Catalog -Name 'windowsReference') -Name $audience.Channel)
    $installed   = @($Fact.Caption | Where-Object { $_ })
    $end         = if ($entry) { Get-TkCatalogField -Object $entry.ends -Name $audience.Audience } else { $null }

    if (-not $entry -or $null -eq $end) {

        $known  = @($entries | ForEach-Object { Get-TkCatalogField -Object $_ -Name 'build' } | Where-Object { $null -ne $_ })
        $newest = ($known | Measure-Object -Maximum).Maximum

        $note = if ($newest -and $build -gt $newest) {
                    'This build is newer than every release in the catalog, reviewed in {0}: it is most likely supported. The Windows release information says until when.' -f $Catalog.reviewed
                }
                else {
                    'This build and edition are not in the catalog reviewed in {0}.' -f $Catalog.reviewed
                }

        $name = if ($entry) { [string] $entry.name } else { 'Windows build {0}' -f $build }

        return New-TkLifecycleRow -ProductId 'windows' -Product $name -Cycle $audience.Label `
            -Title ('{0}, {1}' -f $name, $audience.Label) -Installed $installed -Version $version `
            -State (New-TkUnknownLifecycleState) -Note $note -Reference $reference
    }

    $state = Get-TkLifecycleState -End $end -Risk 'High' -Now $Now

    return New-TkLifecycleRow -ProductId 'windows' -Product ([string] $entry.name) -Cycle $audience.Label `
        -Title ('{0}, {1}' -f $entry.name, $audience.Label) -Installed $installed -Version $version `
        -State $state -Note ([string] (Get-TkCatalogField -Object $entry -Name 'note')) `
        -Replacement $replacement -Reference $reference
}

# ---------------------------------------------------------------------------
# Installed programs
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Keeps the uninstall entries that Installed apps would show.

.DESCRIPTION
    Leaves out components hidden from the list (SystemComponent), updates
    attached to another product (ParentKeyName, or a release type of update
    or hotfix), entries without a name, and the second copy of a program
    registered in both the 64-bit and 32-bit views.

.PARAMETER Entry
    Dictionaries with the registry values DisplayName, DisplayVersion,
    Publisher, SystemComponent, ParentKeyName and ReleaseType, plus Scope and
    Architecture.

.OUTPUTS
    PSCustomObject[] with Name, Version, Publisher, Scope and Architecture.
#>
function Select-TkInstalledProgram {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Entry
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    $rows = foreach ($item in $Entry) {

        if (-not $item) { continue }

        $name = ([string] $item.DisplayName).Trim()

        if (-not $name) { continue }
        if ([string] $item.SystemComponent -eq '1') { continue }
        if ($item.ParentKeyName) { continue }
        if ([string] $item.ReleaseType -match 'Update|Hotfix') { continue }
        if ($name -match '^(Security Update|Update|Hotfix) for ') { continue }

        $version = ([string] $item.DisplayVersion).Trim()

        if (-not $seen.Add(('{0}|{1}' -f $name, $version))) { continue }

        [pscustomobject] @{
            Name         = $name
            Version      = $version
            Publisher    = ([string] $item.Publisher).Trim()
            Scope        = [string] $item.Scope
            Architecture = [string] $item.Architecture
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Lists the programs installed for the machine and for the current user.

.OUTPUTS
    PSCustomObject[] as Select-TkInstalledProgram returns them.
#>
function Get-TkInstalledProgram {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $sources = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Scope = 'Machine'; Architecture = '64-bit' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine'; Architecture = '32-bit' }
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Scope = 'User';    Architecture = '' }
    )

    $entries = foreach ($source in $sources) {

        try {
            $key = Get-Item -LiteralPath $source.Path -ErrorAction Stop
        }
        catch {
            continue
        }

        foreach ($subKeyName in $key.GetSubKeyNames()) {

            try {
                $subKey = $key.OpenSubKey($subKeyName)

                if (-not $subKey) { continue }

                @{
                    DisplayName     = $subKey.GetValue('DisplayName')
                    DisplayVersion  = $subKey.GetValue('DisplayVersion')
                    Publisher       = $subKey.GetValue('Publisher')
                    SystemComponent = $subKey.GetValue('SystemComponent')
                    ParentKeyName   = $subKey.GetValue('ParentKeyName')
                    ReleaseType     = $subKey.GetValue('ReleaseType')
                    Scope           = $source.Scope
                    Architecture    = $source.Architecture
                }

                $subKey.Close()
            }
            catch {
                # One unreadable entry must not hide the others.
                $null = $_
            }
        }

        $key.Close()
    }

    return (Select-TkInstalledProgram -Entry @($entries))
}

<#
.SYNOPSIS
    Matches installed programs to the catalog and judges each release found.

.DESCRIPTION
    A program goes to the first product whose pattern names it, and to the
    first cycle of that product whose name and version patterns both fit.
    The x86 and x64 copies of one release come out as one row listing both.

.PARAMETER Program
    Rows with Name and Version.

.PARAMETER Catalog
    The software-lifecycle catalog.

.PARAMETER Now
    Today.

.OUTPUTS
    PSCustomObject[] as built by New-TkLifecycleRow, the worst first.
#>
function Resolve-TkProgramLifecycle {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Program,
        [Parameter(Mandatory)] $Catalog,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $groups  = [ordered] @{}
    $claimed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($product in @($Catalog.products)) {

        $pattern = [string] $product.match
        $exclude = [string] (Get-TkCatalogField -Object $product -Name 'exclude')

        foreach ($item in $Program) {

            if (-not $item -or -not $item.Name) { continue }

            $name    = [string] $item.Name
            $version = [string] $item.Version
            $id      = '{0}|{1}' -f $name, $version

            if ($claimed.Contains($id)) { continue }
            if ($name -notmatch $pattern) { continue }
            if ($exclude -and $name -match $exclude) { continue }

            [void] $claimed.Add($id)

            $cycle = $null

            foreach ($candidate in @($product.cycles)) {

                $namePattern    = [string] (Get-TkCatalogField -Object $candidate -Name 'name')
                $versionPattern = [string] (Get-TkCatalogField -Object $candidate -Name 'version')

                if ($namePattern -and $name -notmatch $namePattern) { continue }
                if ($versionPattern -and $version -notmatch $versionPattern) { continue }

                $cycle = $candidate
                break
            }

            $label = if ($cycle) { [string] $cycle.cycle } else { 'version not in the catalog' }
            $key   = '{0}|{1}' -f $product.id, $label

            if (-not $groups.Contains($key)) {
                $groups[$key] = [pscustomobject] @{
                    Product  = $product
                    Cycle    = $cycle
                    Label    = $label
                    Names    = New-Object System.Collections.Generic.List[string]
                    Versions = New-Object System.Collections.Generic.List[string]
                }
            }

            $group = $groups[$key]

            if (-not $group.Names.Contains($name)) { $group.Names.Add($name) }
            if ($version -and -not $group.Versions.Contains($version)) { $group.Versions.Add($version) }
        }
    }

    $rows = foreach ($group in $groups.Values) {

        $product = $group.Product
        $risk    = [string] $product.risk
        $note    = ''

        if ($group.Cycle) {

            $state = Get-TkLifecycleState -End (Get-TkCatalogField -Object $group.Cycle -Name 'end') -Risk $risk -Now $Now
            $note  = [string] (Get-TkCatalogField -Object $group.Cycle -Name 'note')

            # A continuous track numbered by year, such as Acrobat 20.x for
            # 2020, is only supported on its latest release.
            if ($state.Status -eq 'Supported' -and (Get-TkCatalogField -Object $group.Cycle -Name 'yearFromMajor')) {

                $years  = @($group.Versions | ForEach-Object { if ($_ -match '^(\d{2})\.') { 2000 + [int] $Matches[1] } })
                $oldest = ($years | Measure-Object -Minimum).Minimum

                if ($oldest -and ($Now.Year - $oldest) -ge 2) {

                    $state = [pscustomobject] @{
                        Status   = 'Outdated'
                        Severity = $(if ($risk -eq 'Low') { 'Info' } else { 'Warning' })
                        Ends     = ''
                        DaysLeft = $null
                    }

                    $note = 'The continuous track only receives fixes on its latest release, and this one dates from {0}. Update it.' -f $oldest
                }
            }

            $productNote = [string] (Get-TkCatalogField -Object $product -Name 'note')

            if ($productNote -and $state.Status -in @('Ended', 'Ending')) {
                $note = (@($note, $productNote) | Where-Object { $_ }) -join ' '
            }
        }
        else {
            $state = New-TkUnknownLifecycleState
            $note  = 'This version is not in the catalog reviewed in {0}: it may be newer than the catalog, or a release it does not list.' -f $Catalog.reviewed
        }

        $title = if ($group.Cycle) { '{0} {1}' -f $product.name, $group.Label } else { [string] $product.name }

        New-TkLifecycleRow -ProductId ([string] $product.id) -Product ([string] $product.name) -Cycle $group.Label `
            -Title $title -Installed $group.Names.ToArray() -Version ($group.Versions -join ', ') `
            -State $state -Risk $risk -Note $note `
            -Replacement ([string] $product.replacement) -Reference ([string] $product.reference)
    }

    $rank = @{ Fail = 3; Warning = 2; Info = 1; Pass = 0 }

    return @($rows | Sort-Object -Property @{ Expression = { $rank[$_.Severity] }; Descending = $true },
                                            @{ Expression = { if ($_.Ends) { $_.Ends } else { '9999' } } },
                                            @{ Expression = { $_.Title } })
}

<#
.SYNOPSIS
    Collects the software support report of this machine.

.PARAMETER Now
    Today.

.OUTPUTS
    PSCustomObject with Reviewed, Windows, Programs and InstalledCount.
#>
function Get-TkSoftwareLifecycleReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $catalog = Import-TkCatalog -Name 'software-lifecycle'

    if (-not $catalog) {
        throw 'The software lifecycle catalog could not be loaded.'
    }

    $programs = @(Get-TkInstalledProgram)

    return [pscustomobject] @{
        Reviewed       = [string] $catalog.reviewed
        Windows        = Resolve-TkWindowsLifecycle -Fact (Get-TkWindowsVersionFact) -Catalog $catalog -Now $Now
        Programs       = @(Resolve-TkProgramLifecycle -Program $programs -Catalog $catalog -Now $Now)
        InstalledCount = $programs.Count
    }
}
