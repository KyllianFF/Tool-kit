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

    The document is a contract with whatever reads it: docs/REPORT-FORMAT.md
    describes it, docs/report.schema.json lets a validator check it, and the
    tests hold the code to both.
#>

<#
.SYNOPSIS
    The name and version of the report document format.

.DESCRIPTION
    The minor version rises when fields are added, the major one when a field
    of the envelope is removed or renamed, or changes type or meaning. Each
    report carries a version of its own for its Data (Get-TkHeadlessReport).

.OUTPUTS
    PSCustomObject with Name and Version.
#>
function Get-TkReportSchema {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject] @{ Name = 'toolkit-report'; Version = '1.0' }
}

<#
.SYNOPSIS
    A stable identifier for this machine that names nothing.

.DESCRIPTION
    A salted SHA-256 of the MachineGuid Windows writes at setup, cut to 32
    hexadecimal characters: the same after a rename and in a pseudonymised
    document, so a fleet view tells machines apart, and no way back to the
    MachineGuid. Read from the 64-bit registry view, where the value lives,
    so a 32-bit PowerShell (as some RMM agents run) gets the same one.

.OUTPUTS
    System.String, empty when the MachineGuid cannot be read.
#>
function Get-TkMachineId {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $guid = ''

    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        try {
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
            if ($key) { $guid = [string] $key.GetValue('MachineGuid'); $key.Dispose() }
        }
        finally {
            $base.Dispose()
        }
    }
    catch {
        return ''
    }

    if (-not $guid.Trim()) { return '' }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('toolkit-report|' + $guid.Trim().ToLowerInvariant()))
    }
    finally {
        $sha.Dispose()
    }

    return ([BitConverter]::ToString($hash, 0, 16) -replace '-', '').ToLowerInvariant()
}

<#
.SYNOPSIS
    Lists the reports a headless run can collect.

.DESCRIPTION
    Each collector receives the options of the run and returns one object, or
    one array wrapped so a single row still comes out as an array.

    Version is the version of the report's Data. Raise it when a field of it
    is removed or renamed, or changes type or meaning, and change
    docs/REPORT-FORMAT.md with it; a field can be added without it.

.OUTPUTS
    PSCustomObject[] with Name, Version, Elevated, Description and Collect.
#>
function Get-TkHeadlessReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $row = {
        param($name, $version, $elevated, $description, $collect)
        [pscustomobject] @{ Name = $name; Version = [int] $version; Elevated = $elevated; Description = $description; Collect = $collect }
    }

    return @(
        (& $row 'Dashboard' 1 $false 'Computer, network and health tiles, as on the Dashboard.' {
            param($Options)
            $null = $Options
            Get-TkDashboardSnapshot
        })

        (& $row 'Inventory' 1 $false 'Identity, operating system, hardware, volumes, platform security and activation.' {
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

        (& $row 'Network' 1 $false 'Network adapters, connected or not.' {
            param($Options)
            $null = $Options
            , @(Get-TkNetworkAdapterInfo -IncludeDisconnected)
        })

        (& $row 'Reboot' 1 $false 'Whether a restart is pending, and why.' {
            param($Options)
            $null = $Options
            Get-TkPendingRebootStatus
        })

        (& $row 'Storage' 1 $false 'Disk reliability, free space and SSD wear.' {
            param($Options)
            $null = $Options
            , @(Get-TkStorageHealth)
        })

        (& $row 'Performance' 1 $false 'Usage now by application, startup programs, and start up time when elevated.' {
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

        (& $row 'Devices' 1 $false 'Devices Device Manager flags, with their problem code explained.' {
            param($Options)
            $null = $Options
            , @(Get-TkDeviceProblem)
        })

        (& $row 'Crashes' 1 $false 'Blue screens of the last 30 days and stability events of the last 14.' {
            param($Options)
            $null = $Options
            [pscustomobject] @{
                Crashes   = @(Get-TkCrashHistory -Days 30)
                Stability = @(Get-TkStabilityReport -Days 14)
            }
        })

        (& $row 'Duplicates' 1 $false 'Files that exist more than once in the account''s own folders, and the space the copies take.' {
            param($Options)
            $null = $Options
            Get-TkDuplicateFileReport
        })

        (& $row 'Path' 1 $false 'The system and user PATH, each entry judged, and the commands two folders provide.' {
            param($Options)
            $null = $Options
            Get-TkPathAudit
        })

        (& $row 'Restarts' 1 $false 'Every start of the last 30 days, how the session before it ended and who asked.' {
            param($Options)
            $null = $Options
            Get-TkBootHistory -Days 30
        })

        (& $row 'Timeline' 1 $false 'What changed in the last 14 days: programs, updates, drivers, services, starts and crashes, threats, firewall rules.' {
            param($Options)
            $null = $Options
            Get-TkTimeline -Days 14
        })

        (& $row 'Wifi' 1 $false 'Wi-Fi signal, band, rate, security and drops of the last week.' {
            param($Options)
            $null = $Options
            $status = Get-TkWifiStatus -Days 7

            [pscustomobject] @{
                Findings = @(Get-TkWifiFinding -Status $status)
                Status   = $status
            }
        })

        (& $row 'Proxy' 1 $false 'The three proxy settings, and whether each proxy answers.' {
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

        (& $row 'Identity' 1 $false 'Join type, single sign-on, domain controller, clock and MDM.' {
            param($Options)
            $null = $Options
            , @(Get-TkIdentityHealth)
        })

        (& $row 'Updates' 1 $false 'The last 30 updates, drivers and feature updates included.' {
            param($Options)
            $null = $Options
            , @(Get-TkUpdateHistory -Count 30)
        })

        (& $row 'Printing' 1 $false 'Spooler, printers, ports, drivers and queues.' {
            param($Options)
            $null = $Options
            , @(Get-TkPrintingReport)
        })

        (& $row 'Profiles' 1 $false 'Profile sizes, mapped drives and logon timing.' {
            param($Options)
            $null = $Options
            , @(Get-TkUserContextReport)
        })

        (& $row 'Lifecycle' 1 $false 'Whether Windows and the installed programs still receive security fixes.' {
            param($Options)
            $null = $Options
            Get-TkSoftwareLifecycleReport
        })

        (& $row 'Readiness' 1 $false 'Whether the machine can run Windows 11, and whether to keep, upgrade or replace it.' {
            param($Options)
            $null = $Options
            Get-TkHardwareReadinessReport
        })

        (& $row 'Journal' 1 $false 'Whether the intervention journal is intact, each line linked to the one before it.' {
            param($Options)
            $null = $Options
            Test-TkJournalChain
        })

        (& $row 'Impact' 1 $false 'What the audit modes recorded before hardening: NTLM, SMBv1, LSA protection and PowerShell 2.0.' {
            param($Options)
            $null = $Options
            [pscustomobject] @{ Probes = @(Get-TkImpactReport) }
        })

        (& $row 'Audit' 1 $true 'The security audit with its score, at the level asked for, and its compliance with the organisation policy when one is set.' {
            param($Options)

            # The accounts excluded in the interface apply here too, and are
            # named in the output as they are in the report.
            $excluded = @()

            if (Get-Command -Name 'Get-TkAuditExclusion' -ErrorAction SilentlyContinue) {
                $excluded = @(Get-TkAuditExclusion)
            }

            # The policy given on the command line, or else the one set in
            # Settings for this account.
            $source = [string] $Options['Policy']
            $trust  = @($Options['PolicyTrust'] | Where-Object { $_ })

            if (-not $source) {
                $setting = Get-TkPolicySetting
                $source  = $setting.Source
                $trust   = @($setting.Trust)
            }

            $audit = Invoke-TkPolicyAudit -Level $Options.AuditLevel -ExcludedAccount $excluded -PolicySource $source -PolicyTrust $trust

            $data = [ordered] @{
                Level           = $audit.Level
                ExcludedAccount = @($audit.ExcludedAccount)
                Score           = $audit.Score
                Findings        = @($audit.Findings)
            }

            # Only with a policy, so a document without one reads as before.
            if ($audit.Compliance) {
                $data['Compliance'] = $audit.Compliance
            }

            [pscustomobject] $data
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
    Ordered dictionary with Version, Status (Ok, Skipped or Failed), Reason,
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
    $result = [ordered] @{ Version = [int] $Entry.Version; Status = 'Ok'; Reason = ''; DurationMs = 0; Worst = ''; Data = $null }

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
    Collects reports into a report document, ready to be written as JSON.

.DESCRIPTION
    The document docs/REPORT-FORMAT.md describes: what it is and in which
    version first, then the machine, the run and its privacy level, the
    summary a monitoring rule reads, and each report with its own version.
    The collection is timed and journaled as one operation.

.PARAMETER Name
    The reports to collect, as Resolve-TkHeadlessReportName returns them.

.PARAMETER Table
    The reports the names are looked up in: Get-TkHeadlessReport, unless given.

.PARAMETER Options
    The options of the run, handed to each collector.

.PARAMETER Privacy
    The level the document is about to be pseudonymised at, recorded in it.

.OUTPUTS
    Ordered dictionary.
#>
function New-TkReportDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Name,

        [Parameter()]
        [AllowNull()]
        [object[]] $Table = $null,

        [Parameter()]
        [hashtable] $Options = @{ AuditLevel = 'Essential' },

        [Parameter()]
        [ValidateSet('None', 'Personal', 'Strict')]
        [string] $Privacy = 'None'
    )

    if (-not $Table) {
        $Table = @(Get-TkHeadlessReport)
    }

    $elevated  = [bool] (Test-TkIsElevated)
    $context   = Get-TkContext
    $schema    = Get-TkReportSchema
    $operation = 'Headless report: {0}' -f ($Name -join ', ')
    $stopwatch = Start-TkOperation -Name $operation -Category 'Headless'

    $reports = [ordered] @{}
    $worst   = [ordered] @{}

    foreach ($item in $Name) {

        $entry  = $Table | Where-Object { $_.Name -eq $item } | Select-Object -First 1
        $result = Invoke-TkHeadlessCollector -Entry $entry -Elevated $elevated -Options $Options

        $reports[$item] = $result

        if ($result.Worst) {
            $worst[$item] = $result.Worst
        }
    }

    $overall = Get-TkWorstSeverity -Data ([ordered] @{ Rows = @($worst.Values | ForEach-Object { [ordered] @{ Severity = $_ } }) })

    Stop-TkOperation -Name $operation -Stopwatch $stopwatch -Category 'Headless' `
                     -Success (@($reports.Values | Where-Object { $_.Status -eq 'Failed' }).Count -eq 0)

    return [ordered] @{
        Schema        = $schema.Name
        SchemaVersion = $schema.Version
        Computer      = $env:COMPUTERNAME
        MachineId     = Get-TkMachineId
        User          = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        GeneratedAt   = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        Toolkit       = [ordered] @{ Version = [string] $context.Version; Commit = [string] $context.Commit }
        Elevated      = $elevated
        Privacy       = $Privacy
        Summary       = [ordered] @{ Worst = $overall; Reports = $worst }
        Reports       = $reports
    }
}

<#
.SYNOPSIS
    Collects reports without a window and returns them as JSON.

.PARAMETER Report
    Report names, All, or List for the available reports.

.PARAMETER CompareWith
    A report document saved earlier. Its reports are collected again when
    Report is not given, and what changed since is added to the output.

.PARAMETER OutFile
    Where to write the JSON. Without it the JSON is returned.

.PARAMETER AuditLevel
    Essential or Full, for the Audit report.

.PARAMETER Policy
    The organisation policy the Audit report is judged against: a file, a
    share or an https:// address. Without it, the one set in Settings.

.PARAMETER PolicyTrust
    The certificate thumbprints and SHA-256 hashes that make the policy
    trusted.

.OUTPUTS
    System.String: the JSON, or the full path of the file written.
#>
function Invoke-TkHeadlessReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Report = @(),

        [Parameter()]
        [AllowEmptyString()]
        [string] $CompareWith = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $OutFile = '',

        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $AuditLevel = 'Essential',

        # Pseudonymises the document once collected and compared: a
        # comparison needs the real values, a document sent away does not.
        [Parameter()]
        [ValidateSet('None', 'Personal', 'Strict')]
        [string] $Redact = 'None',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Policy = '',

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $PolicyTrust = @()
    )

    $table     = @(Get-TkHeadlessReport)
    $reference = $null

    if (@($Report | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ -eq 'List' }).Count -gt 0) {

        $document = ConvertTo-TkPlainData -InputObject @($table | Select-Object -Property Name, Version, Elevated, Description)
    }
    else {

        # Read before anything is collected, so a wrong file fails at once
        # rather than after half a minute of collection.
        if ($CompareWith) {

            $reference = Read-TkReportDocument -Path $CompareWith

            # Its aliases would each read as a change against the real values.
            if ([string] $reference['Privacy'] -in @('Personal', 'Strict')) {
                throw ('{0} was pseudonymised ({1}): its names and addresses are aliases, and each would read as a change. Compare with a document saved without -Redact.' -f $CompareWith, $reference['Privacy'])
            }

            if (@($Report | Where-Object { $_ }).Count -eq 0) {
                $Report = @($reference.Reports.Keys)
            }
        }

        if (@($Report | Where-Object { $_ }).Count -eq 0) {
            throw 'Name the reports to collect with -Report, or give -CompareWith a report document to collect again.'
        }

        $names    = @(Resolve-TkHeadlessReportName -Name $Report)
        $document = New-TkReportDocument -Name $names -Table $table -Options @{ AuditLevel = $AuditLevel; Policy = $Policy; PolicyTrust = @($PolicyTrust | Where-Object { $_ }) } -Privacy $Redact

        if ($reference) {
            $document['Comparison'] = ConvertTo-TkPlainData -InputObject (Compare-TkReportDocument -Reference $reference -Difference $document)
        }
    }

    $json = ConvertTo-Json -InputObject $document -Depth 40

    if ($Redact -ne 'None') {
        $safe = Protect-TkExportText -Text $json -Level $Redact -Label 'headless-report'
        $json = $safe.Text
        Write-TkLog -Level Information -Category 'Headless' -Message (
            'Pseudonymised ({0}): {1} value(s) replaced; the table is kept at {2}.' -f $Redact, $safe.Replaced, $(if ($safe.MapPath) { $safe.MapPath } else { '(nothing replaced)' }))
    }

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
