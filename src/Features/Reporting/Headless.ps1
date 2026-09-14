<#
    Toolkit - Features / Headless reports

    The reports of the interface, collected without a window and written as
    JSON, for a script, a remote session or an RMM agent:

        & ([scriptblock]::Create((irm <published url>))) -Report Audit, Storage -OutFile C:\Temp\report.json

    The plain irm | iex launch passes no argument and still opens the window.
    Running the downloaded text as a script block is what lets it take
    parameters, with still nothing written to disk but the report asked for.

    Three rules shape this file. The reports are a table, so the help, the
    error message and the tests read the same names. A report that needs
    administrator rights is skipped with the reason rather than run half
    blind. And the output goes through ConvertTo-TkPlainData before JSON, so
    Windows PowerShell 5.1 and PowerShell 7 write the same document: dates as
    ISO 8601, enumerations as names, CIM objects as their properties.
#>

<#
.SYNOPSIS
    Lists the reports a headless run can collect.

.DESCRIPTION
    Each collector receives the options of the run and returns one object, or
    one array wrapped so a single row still comes out as an array.

.OUTPUTS
    PSCustomObject[] with Name, Elevated, Description and Collect.
#>
function Get-TkHeadlessReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $row = {
        param($name, $elevated, $description, $collect)
        [pscustomobject] @{ Name = $name; Elevated = $elevated; Description = $description; Collect = $collect }
    }

    return @(
        (& $row 'Dashboard' $false 'Computer, network and health tiles, as on the Dashboard.' {
            param($Options)
            $null = $Options
            Get-TkDashboardSnapshot
        })

        (& $row 'Inventory' $false 'Identity, operating system, hardware, volumes, platform security and activation.' {
            param($Options)
            $null = $Options
            [pscustomobject] @{
                Identity   = Get-TkMachineIdentity
                System     = Get-TkOperatingSystemInfo
                Hardware   = Get-TkHardwareInfo
                Volumes    = @(Get-TkVolumeUsage)
                Security   = Get-TkPlatformSecurityInfo
                Activation = Get-TkActivationStatus
            }
        })

        (& $row 'Network' $false 'Network adapters, connected or not.' {
            param($Options)
            $null = $Options
            , @(Get-TkNetworkAdapterInfo -IncludeDisconnected)
        })

        (& $row 'Reboot' $false 'Whether a restart is pending, and why.' {
            param($Options)
            $null = $Options
            Get-TkPendingRebootStatus
        })

        (& $row 'Storage' $false 'Disk reliability, free space and SSD wear.' {
            param($Options)
            $null = $Options
            , @(Get-TkStorageHealth)
        })

        (& $row 'Performance' $false 'Usage now by application, startup programs, and start up time when elevated.' {
            param($Options)
            $null = $Options
            $snapshot = Get-TkPerformanceSnapshot
            $startup  = @(Get-TkStartupProgram)
            $boot     = Get-TkBootPerformance -Days 30

            [pscustomobject] @{
                Findings = @(Get-TkPerformanceFinding -Snapshot $snapshot -Startup $startup -Boot $boot)
                Snapshot = $snapshot
                Startup  = $startup
                Boot     = $boot
            }
        })

        (& $row 'Devices' $false 'Devices Device Manager flags, with their problem code explained.' {
            param($Options)
            $null = $Options
            , @(Get-TkDeviceProblem)
        })

        (& $row 'Crashes' $false 'Blue screens of the last 30 days and stability events of the last 14.' {
            param($Options)
            $null = $Options
            [pscustomobject] @{
                Crashes   = @(Get-TkCrashHistory -Days 30)
                Stability = @(Get-TkStabilityReport -Days 14)
            }
        })

        (& $row 'Wifi' $false 'Wi-Fi signal, band, rate, security and drops of the last week.' {
            param($Options)
            $null = $Options
            $status = Get-TkWifiStatus -Days 7

            [pscustomobject] @{
                Findings = @(Get-TkWifiFinding -Status $status)
                Status   = $status
            }
        })

        (& $row 'Proxy' $false 'The three proxy settings, and whether each proxy answers.' {
            param($Options)
            $null = $Options
            $setting = Get-TkProxySetting
            $probe   = Invoke-TkProxyProbe -Setting $setting

            [pscustomobject] @{
                Findings = @(Get-TkProxyFinding -Setting $setting -Probe $probe)
                Setting  = $setting
                Probe    = $probe
            }
        })

        (& $row 'Identity' $false 'Join type, single sign-on, domain controller, clock and MDM.' {
            param($Options)
            $null = $Options
            , @(Get-TkIdentityHealth)
        })

        (& $row 'Updates' $false 'The last 30 updates, drivers and feature updates included.' {
            param($Options)
            $null = $Options
            , @(Get-TkUpdateHistory -Count 30)
        })

        (& $row 'Printing' $false 'Spooler, printers, ports, drivers and queues.' {
            param($Options)
            $null = $Options
            , @(Get-TkPrintingReport)
        })

        (& $row 'Profiles' $false 'Profile sizes, mapped drives and logon timing.' {
            param($Options)
            $null = $Options
            , @(Get-TkUserContextReport)
        })

        (& $row 'Audit' $true 'The security audit with its score, at the level asked for.' {
            param($Options)

            # The accounts excluded in the interface apply here too, and are
            # named in the output as they are in the report.
            $excluded = @()

            if (Get-Command -Name 'Get-TkAuditExclusion' -ErrorAction SilentlyContinue) {
                $excluded = @(Get-TkAuditExclusion)
            }

            $findings = @(Invoke-TkSecurityAudit -Level $Options.AuditLevel -ExcludedAccount $excluded)

            [pscustomobject] @{
                Level           = $Options.AuditLevel
                ExcludedAccount = $excluded
                Score           = Get-TkAuditScore -Finding $findings
                Findings        = $findings
            }
        })
    )
}

<#
.SYNOPSIS
    Turns the report names given on the command line into table names.

.DESCRIPTION
    Accepts an array or one comma separated string, in any case. All means
    every report. An unknown name stops the run and lists the known ones,
    rather than producing a document that silently lacks it.

.PARAMETER Name
    The names given.

.OUTPUTS
    System.String[], in the order given, without duplicates.
#>
function Resolve-TkHeadlessReportName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Name
    )

    $table  = @(Get-TkHeadlessReport)
    $wanted = @($Name | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ })

    if (@($wanted | Where-Object { $_ -eq 'All' }).Count -gt 0) {
        return @($table | ForEach-Object { $_.Name })
    }

    $resolved = foreach ($item in $wanted) {

        $match = $table | Where-Object { $_.Name -eq $item } | Select-Object -First 1

        if (-not $match) {
            throw ('Unknown report "{0}". Available: {1}, or All.' -f $item, ((@($table | ForEach-Object { $_.Name })) -join ', '))
        }

        $match.Name
    }

    return @($resolved | Select-Object -Unique)
}

<#
.SYNOPSIS
    Converts collected objects into data JSON writes the same way everywhere.

.DESCRIPTION
    ConvertTo-Json on raw objects differs between Windows PowerShell 5.1 and
    PowerShell 7: dates come out as \/Date(...)\/ in one and ISO text in the
    other, enumerations as numbers, and a CIM object or a TimeSpan as a pile of
    internal properties. This keeps the meaning and drops the rest.

.PARAMETER InputObject
    Anything a collector returned.

.PARAMETER Depth
    How deep to follow nested objects before writing the value as text.

.OUTPUTS
    Strings, numbers, booleans, $null, ordered dictionaries and arrays.
#>
function ConvertTo-TkPlainData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [ValidateRange(0, 32)]
        [int] $Depth = 12
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $base = $InputObject.PSObject.BaseObject

    if ($base -is [string] -or $base -is [char]) {
        return [string] $base
    }

    if ($base -is [bool]) {
        return $base
    }

    if ($base -is [double] -or $base -is [single]) {

        # JSON has no NaN or infinity.
        if ([double]::IsNaN($base) -or [double]::IsInfinity($base)) {
            return $null
        }

        # A rounded value such as 12 is written 12 by Windows PowerShell 5.1
        # and 12.0 by PowerShell 7, which a reader then types differently. A
        # whole number goes out as an integer from both.
        if ([math]::Floor($base) -eq $base -and [math]::Abs($base) -lt 9007199254740992) {
            return [long] $base
        }

        return $base
    }

    if ($base -is [byte] -or $base -is [sbyte] -or $base -is [int16] -or $base -is [uint16] -or
        $base -is [int] -or $base -is [uint32] -or $base -is [long] -or $base -is [uint64] -or $base -is [decimal]) {
        return $base
    }

    if ($base -is [datetime] -or $base -is [datetimeoffset]) {
        return $base.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }

    if ($base -is [timespan]) {
        return $base.ToString('c', [Globalization.CultureInfo]::InvariantCulture)
    }

    if ($base -is [guid] -or $base -is [enum] -or $base -is [version] -or $base -is [uri] -or $base -is [type]) {
        return [string] $base
    }

    if ($base -is [scriptblock]) {
        return $null
    }

    if ($base -is [byte[]]) {
        return [Convert]::ToBase64String($base)
    }

    if ($Depth -le 0) {
        return [string] $base
    }

    if ($base -is [System.Collections.IDictionary]) {

        $map = [ordered] @{}

        foreach ($key in @($base.Keys)) {
            $map[[string] $key] = ConvertTo-TkPlainData -InputObject $base[$key] -Depth ($Depth - 1)
        }

        return $map
    }

    if ($base -is [System.Collections.IEnumerable]) {

        $items = New-Object System.Collections.Generic.List[object]

        foreach ($item in $base) {
            $items.Add((ConvertTo-TkPlainData -InputObject $item -Depth ($Depth - 1)))
        }

        return , $items.ToArray()
    }

    # A CIM instance: its class properties, not the provider plumbing.
    if ($base.GetType().FullName -eq 'Microsoft.Management.Infrastructure.CimInstance') {

        $map = [ordered] @{}

        foreach ($property in $base.CimInstanceProperties) {
            $map[$property.Name] = ConvertTo-TkPlainData -InputObject $property.Value -Depth ($Depth - 1)
        }

        return $map
    }

    # A PSCustomObject, or any other object: its properties.
    $map        = [ordered] @{}
    $memberKind = if ($base -is [System.Management.Automation.PSCustomObject]) { '*' } else { 'Property' }

    foreach ($property in @($InputObject.PSObject.Properties | Where-Object { $memberKind -eq '*' -or $_.MemberType -eq 'Property' })) {

        try {
            $value = $property.Value
        }
        catch {
            $value = $null
        }

        $map[$property.Name] = ConvertTo-TkPlainData -InputObject $value -Depth ($Depth - 1)
    }

    return $map
}

<#
.SYNOPSIS
    Finds the worst judgement anywhere in a report.

.DESCRIPTION
    Every judged row of the toolkit carries a Severity or a Status of Fail,
    Warning, Pass or Info. The worst one is what a monitoring rule needs to
    read without knowing the shape of each report.

.PARAMETER Data
    A report after ConvertTo-TkPlainData.

.OUTPUTS
    System.String: Fail, Warning, Pass, or '' when nothing in it is judged.
#>
function Get-TkWorstSeverity {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Data
    )

    $rank = @{ 'Fail' = 3; 'Warning' = 2; 'Pass' = 1; 'Info' = 1 }
    $best = 0

    $pending = New-Object System.Collections.Generic.Stack[object]
    $pending.Push($Data)

    while ($pending.Count -gt 0) {

        $node = $pending.Pop()

        if ($node -is [System.Collections.IDictionary]) {

            foreach ($key in @($node.Keys)) {

                $value = $node[$key]

                if ([string] $key -in @('Severity', 'Status') -and $value -is [string] -and $rank.ContainsKey($value) -and $rank[$value] -gt $best) {
                    $best = $rank[$value]
                }

                if ($value -is [System.Collections.IDictionary] -or ($value -is [array])) {
                    $pending.Push($value)
                }
            }
        }
        elseif ($node -is [array]) {

            foreach ($item in $node) {
                if ($item -is [System.Collections.IDictionary] -or $item -is [array]) {
                    $pending.Push($item)
                }
            }
        }
    }

    switch ($best) {
        3       { return 'Fail' }
        2       { return 'Warning' }
        1       { return 'Pass' }
        default { return '' }
    }
}

<#
.SYNOPSIS
    Runs one report of a headless run.

.PARAMETER Entry
    A row of Get-TkHeadlessReport.

.PARAMETER Elevated
    Whether this session has administrator rights.

.PARAMETER Options
    The options of the run, handed to the collector.

.OUTPUTS
    Ordered dictionary with Status (Ok, Skipped or Failed), Reason,
    DurationMs, Worst and Data.
#>
function Invoke-TkHeadlessCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Entry,

        [Parameter()]
        [bool] $Elevated = $false,

        [Parameter()]
        [hashtable] $Options = @{}
    )

    $timer  = [System.Diagnostics.Stopwatch]::StartNew()
    $result = [ordered] @{ Status = 'Ok'; Reason = ''; DurationMs = 0; Worst = ''; Data = $null }

    if ($Entry.Elevated -and -not $Elevated) {
        $result.Status = 'Skipped'
        $result.Reason = 'Needs administrator rights: run the command from an elevated PowerShell.'
    }
    else {
        try {
            $data = & $Entry.Collect $Options

            $result.Data  = ConvertTo-TkPlainData -InputObject $data
            $result.Worst = Get-TkWorstSeverity -Data $result.Data
        }
        catch {
            $result.Status = 'Failed'
            $result.Reason = $_.Exception.Message

            Write-TkLog -Level Warning -Category 'Headless' -Message (
                '{0} could not be collected: {1}' -f $Entry.Name, $_.Exception.Message
            )
        }
    }

    $result.DurationMs = $timer.ElapsedMilliseconds

    return $result
}

<#
.SYNOPSIS
    Collects reports without a window and returns them as JSON.

.PARAMETER Report
    Report names, All, or List for the available reports.

.PARAMETER OutFile
    Where to write the JSON. Without it the JSON is returned.

.PARAMETER AuditLevel
    Essential or Full, for the Audit report.

.OUTPUTS
    System.String: the JSON, or the full path of the file written.
#>
function Invoke-TkHeadlessReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Report,

        [Parameter()]
        [AllowEmptyString()]
        [string] $OutFile = '',

        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $AuditLevel = 'Essential'
    )

    $table = @(Get-TkHeadlessReport)

    if (@($Report | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ -eq 'List' }).Count -gt 0) {

        $document = ConvertTo-TkPlainData -InputObject @($table | Select-Object -Property Name, Elevated, Description)
    }
    else {

        $names    = @(Resolve-TkHeadlessReportName -Name $Report)
        $elevated = [bool] (Test-TkIsElevated)
        $options  = @{ AuditLevel = $AuditLevel }
        $context  = Get-TkContext

        $stopwatch = Start-TkOperation -Name ('Headless report: {0}' -f ($names -join ', ')) -Category 'Headless'

        $reports = [ordered] @{}
        $worst   = [ordered] @{}

        foreach ($name in $names) {

            $entry  = $table | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            $result = Invoke-TkHeadlessCollector -Entry $entry -Elevated $elevated -Options $options

            $reports[$name] = $result

            if ($result.Worst) {
                $worst[$name] = $result.Worst
            }
        }

        $overall = Get-TkWorstSeverity -Data ([ordered] @{ Rows = @($worst.Values | ForEach-Object { [ordered] @{ Severity = $_ } }) })

        $document = [ordered] @{
            Computer    = $env:COMPUTERNAME
            User        = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
            GeneratedAt = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            Toolkit     = [ordered] @{ Version = [string] $context.Version; Commit = [string] $context.Commit }
            Elevated    = $elevated
            Summary     = [ordered] @{ Worst = $overall; Reports = $worst }
            Reports     = $reports
        }

        Stop-TkOperation -Name ('Headless report: {0}' -f ($names -join ', ')) -Stopwatch $stopwatch -Category 'Headless' `
                         -Success (@($reports.Values | Where-Object { $_.Status -eq 'Failed' }).Count -eq 0)
    }

    $json = ConvertTo-Json -InputObject $document -Depth 40

    if (-not $OutFile) {
        return $json
    }

    # Relative to the PowerShell location, which is not always the process
    # directory [IO.Path] would use.
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)

    # UTF-8 without a byte order mark, which every JSON reader accepts.
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))

    Write-TkLog -Level Information -Category 'Headless' -Message ('Report written to {0}' -f $path)

    return $path
}
