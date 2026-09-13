<#
    Toolkit - Features / Performance

    "The machine is slow" split into the questions that have an answer: what is
    using the processor, the memory and the disks right now, which programs
    start with Windows, and how long start up takes and what slows it.

    The snapshot and the start up programs are read as a standard user, from
    the performance classes, whose names do not change with the display
    language the way counter paths do. How long Windows takes to start comes
    from the Diagnostics-Performance log, which Windows only opens to an
    administrator; without elevation the report says so rather than guessing.

    The judgement is kept in Get-TkPerformanceFinding, apart from the reading,
    so its thresholds are tested without a machine under load.
#>

<#
.SYNOPSIS
    Groups per process usage by application.

.DESCRIPTION
    The performance classes list every process instance, brave, brave#1 up to
    brave#13, and the processor time of each summed over every logical
    processor. A browser with fourteen processes is one application to the
    person asking, and 3200 % on 32 logical processors is a full machine.

.PARAMETER Process
    Rows with Name, PercentProcessorTime, WorkingSetPrivate and IODataBytesPersec.

.PARAMETER LogicalProcessors
    The number of logical processors.

.OUTPUTS
    PSCustomObject[] with Name, Instances, CpuPercent, MemoryMB and IoKBps.
#>
function Group-TkProcessUsage {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Process,

        [Parameter()]
        [ValidateRange(1, 4096)]
        [int] $LogicalProcessors = [Environment]::ProcessorCount
    )

    $rows = foreach ($group in (@($Process | Where-Object { $_ -and $_.Name -notin @('_Total', 'Idle') }) |
                                Group-Object -Property { [string] $_.Name -replace '#\d+$', '' })) {

        [pscustomobject] @{
            Name       = $group.Name
            Instances  = $group.Count
            CpuPercent = [math]::Round((($group.Group | Measure-Object -Property PercentProcessorTime -Sum).Sum / $LogicalProcessors), 1)
            MemoryMB   = [math]::Round((($group.Group | Measure-Object -Property WorkingSetPrivate -Sum).Sum / 1MB))
            IoKBps     = [math]::Round((($group.Group | Measure-Object -Property IODataBytesPersec -Sum).Sum / 1KB))
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Reads what the machine is doing right now.

.OUTPUTS
    PSCustomObject with CpuPercent, MemoryUsedPercent, MemoryTotalGB,
    MemoryFreeGB, CommitPercent, Applications, Disks, LogicalProcessors and
    Uptime.
#>
function Get-TkPerformanceSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # The first query of a performance class starts its provider and can take
    # a couple of seconds; the value that matters is read after it.
    $null = Get-TkCimInstanceSafe -ClassName 'Win32_PerfFormattedData_PerfOS_Processor' -Filter "Name = '_Total'"
    Start-Sleep -Milliseconds 500

    $processor = Get-TkCimInstanceSafe -ClassName 'Win32_PerfFormattedData_PerfOS_Processor' -Filter "Name = '_Total'"
    $processes = Get-TkCimInstanceSafe -ClassName 'Win32_PerfFormattedData_PerfProc_Process' -All
    $disks     = Get-TkCimInstanceSafe -ClassName 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' -All
    $os        = Get-TkCimInstanceSafe -ClassName 'Win32_OperatingSystem'

    $cores = [Environment]::ProcessorCount

    $totalKB = if ($os) { [double] $os.TotalVisibleMemorySize } else { 0 }
    $freeKB  = if ($os) { [double] $os.FreePhysicalMemory } else { 0 }
    $virtual = if ($os) { [double] $os.TotalVirtualMemorySize } else { 0 }

    return [pscustomobject] @{
        CpuPercent        = $(if ($processor) { [int] $processor.PercentProcessorTime } else { $null })
        MemoryUsedPercent = $(if ($totalKB -gt 0) { [math]::Round((($totalKB - $freeKB) / $totalKB) * 100) } else { $null })
        MemoryTotalGB     = [math]::Round($totalKB / 1MB, 1)
        MemoryFreeGB      = [math]::Round($freeKB / 1MB, 1)
        CommitPercent     = $(if ($virtual -gt 0) { [math]::Round((($virtual - [double] $os.FreeVirtualMemory) / $virtual) * 100) } else { $null })
        Applications      = @(Group-TkProcessUsage -Process @($processes) -LogicalProcessors $cores)
        Disks             = @($disks | Where-Object { $_ -and $_.Name -ne '_Total' } | ForEach-Object {
                                [pscustomobject] @{
                                    Name        = [string] $_.Name
                                    BusyPercent = [int] [math]::Min(100, [double] $_.PercentDiskTime)
                                    Queue       = [double] $_.AvgDiskQueueLength
                                    ReadKBps    = [math]::Round([double] $_.DiskReadBytesPersec / 1KB)
                                    WriteKBps   = [math]::Round([double] $_.DiskWriteBytesPersec / 1KB)
                                }
                            })
        LogicalProcessors = $cores
        Uptime            = $(if ($os -and $os.LastBootUpTime) { (Get-Date) - [datetime] $os.LastBootUpTime } else { $null })
    }
}

<#
.SYNOPSIS
    Returns the StartupApproved key that says whether a startup entry runs.

.DESCRIPTION
    Task Manager records the choice to disable a startup program under
    Explorer\StartupApproved, in a key that depends on where the program was
    registered: the user or the machine Run key, the 32-bit Run key, or a
    Startup folder.

.PARAMETER Location
    The Location of a Win32_StartupCommand row.

.OUTPUTS
    System.String, a registry path, or '' when the location has no such key.
#>
function Get-TkStartupApprovalKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Location
    )

    $base = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'

    switch -Regex ($Location) {
        '^Startup$'                          { return "HKCU:\$base\StartupFolder" }
        '^Common Startup$'                   { return "HKLM:\$base\StartupFolder" }
        '^HKU\\[^\\]+\\.*\\Run$'             { return "HKCU:\$base\Run" }
        '^HKLM\\SOFTWARE\\Wow6432Node\\.*\\Run$' { return "HKLM:\$base\Run32" }
        '^HKLM\\.*\\Run$'                    { return "HKLM:\$base\Run" }
    }

    return ''
}

<#
.SYNOPSIS
    Says whether a StartupApproved value leaves the program enabled.

.DESCRIPTION
    The first byte is 2 or 6 when the program runs and 3 or 7 when it was
    disabled: the lowest bit is the switch. No value at all means nobody
    disabled it.

.PARAMETER Value
    The binary value, or $null when there is none.
#>
function Test-TkStartupApproved {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [byte[]] $Value
    )

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return $true
    }

    return (($Value[0] -band 1) -eq 0)
}

<#
.SYNOPSIS
    Lists the programs registered to start with Windows, and whether they run.

.OUTPUTS
    PSCustomObject[] with Name, Command, Scope and Enabled.
#>
function Get-TkStartupProgram {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $rows = foreach ($entry in @(Get-TkCimInstanceSafe -ClassName 'Win32_StartupCommand' -All | Where-Object { $_ })) {

        $key   = Get-TkStartupApprovalKey -Location ([string] $entry.Location)
        $value = $null

        if ($key) {

            try {
                $item = Get-Item -LiteralPath $key -ErrorAction Stop

                # A Startup folder entry is recorded with its file extension.
                $valueName = @($item.GetValueNames()) |
                             Where-Object { $_ -eq $entry.Name -or [System.IO.Path]::GetFileNameWithoutExtension($_) -eq $entry.Name } |
                             Select-Object -First 1

                if ($valueName) {
                    $value = [byte[]] $item.GetValue($valueName)
                }
            }
            catch {
                $value = $null
            }
        }

        [pscustomobject] @{
            Name    = [string] $entry.Name
            Command = [string] $entry.Command
            Scope   = $(if ([string] $entry.Location -match '^HKLM|^Common') { 'All users' } else { 'This user' })
            Enabled = Test-TkStartupApproved -Value $value
        }
    }

    return @($rows | Sort-Object -Property @{ Expression = 'Enabled'; Descending = $true }, Name)
}

<#
.SYNOPSIS
    Turns one Diagnostics-Performance event into a record.

.DESCRIPTION
    Event 100 is one start up, with its durations in milliseconds. Events 101,
    102, 103 and 109 each name an application, a driver, a service or a device
    that made a start up slower than usual, with how much time it added.

.PARAMETER Id
    The event identifier.

.PARAMETER Data
    The event data as a hashtable of name to text.

.PARAMETER When
    When the event was written.

.OUTPUTS
    PSCustomObject, or $null for an identifier this does not read.
#>
function ConvertFrom-TkBootEvent {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [int] $Id,
        [Parameter(Mandatory)] [hashtable] $Data,
        [Parameter()] [datetime] $When = (Get-Date)
    )

    $number = {
        param($name)
        $parsed = 0L
        if ([long]::TryParse([string] $Data[$name], [ref] $parsed)) { $parsed } else { $null }
    }

    if ($Id -eq 100) {
        return [pscustomobject] @{
            When        = $When
            BootMs      = & $number 'BootTime'
            MainPathMs  = & $number 'MainPathBootTime'
            PostBootMs  = & $number 'BootPostBootTime'
            Degraded    = ([string] $Data['BootIsDegradation'] -match '^(true|1)$')
        }
    }

    $kind = switch ($Id) { 101 { 'Application' } 102 { 'Driver' } 103 { 'Service' } 109 { 'Device' } default { '' } }

    if (-not $kind) {
        return $null
    }

    $name = @([string] $Data['FriendlyName'], [string] $Data['Name']) | Where-Object { $_ } | Select-Object -First 1

    return [pscustomobject] @{
        When          = $When
        Kind          = $kind
        Name          = $name
        TotalMs       = & $number 'TotalTime'
        DegradationMs = & $number 'DegradationTime'
    }
}

<#
.SYNOPSIS
    Reads how long Windows took to start, and what slowed it.

.PARAMETER Days
    How far back to look.

.OUTPUTS
    PSCustomObject with Available, Boots (most recent first) and Slowdowns
    (grouped by kind and name, the worst first).
#>
function Get-TkBootPerformance {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 180)]
        [int] $Days = 30
    )

    if (-not (Test-TkIsElevated)) {
        return [pscustomobject] @{ Available = $false; Boots = @(); Slowdowns = @() }
    }

    $events = @()

    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Diagnostics-Performance/Operational'
            Id        = 100, 101, 102, 103, 109
            StartTime = (Get-Date).AddDays(-$Days)
        } -MaxEvents 500 -ErrorAction Stop)
    }
    catch {
        $events = @()
    }

    $records = foreach ($record in $events) {

        $data = @{}

        try {
            foreach ($item in ([xml] $record.ToXml()).Event.EventData.Data) {
                $data[[string] $item.Name] = [string] $item.'#text'
            }
        }
        catch {
            continue
        }

        ConvertFrom-TkBootEvent -Id $record.Id -Data $data -When $record.TimeCreated
    }

    $boots     = @($records | Where-Object { $_ -and $_.PSObject.Properties['BootMs'] } | Sort-Object -Property When -Descending)
    $slowdowns = foreach ($group in (@($records | Where-Object { $_ -and $_.PSObject.Properties['Kind'] }) | Group-Object -Property Kind, Name)) {

        $first = $group.Group[0]

        [pscustomobject] @{
            Kind          = $first.Kind
            Name          = $first.Name
            Count         = $group.Count
            AddedMs       = [math]::Round(($group.Group | Measure-Object -Property DegradationMs -Average).Average)
        }
    }

    return [pscustomobject] @{
        Available = $true
        Boots     = $boots
        Slowdowns = @($slowdowns | Sort-Object -Property AddedMs -Descending)
    }
}

<#
.SYNOPSIS
    Judges the performance readings.

.PARAMETER Snapshot
    Output of Get-TkPerformanceSnapshot.

.PARAMETER Startup
    Output of Get-TkStartupProgram.

.PARAMETER Boot
    Output of Get-TkBootPerformance, or $null.

.OUTPUTS
    PSCustomObject[] with Severity, Heading, Detail and Note.
#>
function Get-TkPerformanceFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] $Snapshot,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Startup = @(),
        [Parameter()] $Boot
    )

    # Numbers go through [string] before -f: the format operator writes
    # decimals in the display language, 2,3 % on a French Windows beside sizes
    # printed as 1.99 TB, while a string conversion always uses a point.
    $findings = @()
    $finding  = { param($severity, $heading, $detail, $note) [pscustomobject] @{ Severity = $severity; Heading = $heading; Detail = $detail; Note = $note } }

    if ($Snapshot) {

        $apps = @($Snapshot.Applications)

        # --- Processor ----------------------------------------------------
        if ($null -ne $Snapshot.CpuPercent) {

            $top = @($apps | Sort-Object -Property CpuPercent -Descending | Select-Object -First 3 | Where-Object { $_.CpuPercent -ge 1 })

            $findings += & $finding $(if ($Snapshot.CpuPercent -ge 85) { 'Warning' } else { 'Pass' }) `
                ('Processor {0}% busy' -f $Snapshot.CpuPercent) `
                $(if ($top) { (@($top | ForEach-Object { '{0} {1}%' -f $_.Name, [string] $_.CpuPercent })) -join ', ' } else { 'Nothing stands out' }) `
                $(if ($Snapshot.CpuPercent -ge 85) { 'A processor this busy makes everything feel slow. Close or update the application at the top of the list, and check it is not stuck in a loop.' } else { 'Measured over about a second.' })
        }

        # --- Memory -------------------------------------------------------
        if ($null -ne $Snapshot.MemoryUsedPercent) {

            $top = @($apps | Sort-Object -Property MemoryMB -Descending | Select-Object -First 3)

            $severity = if ($Snapshot.MemoryUsedPercent -ge 97) { 'Fail' } elseif ($Snapshot.MemoryUsedPercent -ge 90 -or $Snapshot.CommitPercent -ge 90) { 'Warning' } else { 'Pass' }

            $findings += & $finding $severity `
                ('Memory {0}% used' -f $Snapshot.MemoryUsedPercent) `
                ('{0} GB free of {1} GB; {2}' -f [string] $Snapshot.MemoryFreeGB, [string] $Snapshot.MemoryTotalGB, ((@($top | ForEach-Object { '{0} {1} MB' -f $_.Name, [string] $_.MemoryMB })) -join ', ')) `
                $(if ($severity -ne 'Pass') { 'When memory runs out Windows pages to disk and everything slows down. Close what is not needed; if this is the normal load, the machine needs more memory.' } else { 'Commit charge {0}% of what memory and the page file can hold.' -f $Snapshot.CommitPercent })
        }

        # --- Disks --------------------------------------------------------
        foreach ($disk in @($Snapshot.Disks | Where-Object { $_.BusyPercent -ge 80 -or $_.Queue -ge 2 })) {

            $findings += & $finding 'Warning' ('Disk {0} busy {1}%' -f $disk.Name, $disk.BusyPercent) `
                ('Queue {0}, reading {1} KB/s, writing {2} KB/s' -f [string] $disk.Queue, [string] $disk.ReadKBps, [string] $disk.WriteKBps) `
                'A disk that stays this busy makes every program wait for it. Look at what reads or writes the most, and at the disk health in Storage health.'
        }
    }

    # --- Programs that start with Windows -------------------------------------
    $enabled = @($Startup | Where-Object { $_ -and $_.Enabled })

    if (@($Startup).Count -gt 0) {

        $findings += & $finding $(if ($enabled.Count -gt 15) { 'Warning' } else { 'Info' }) `
            ('{0} program(s) start with Windows' -f $enabled.Count) `
            ('{0} more registered and disabled' -f (@($Startup).Count - $enabled.Count)) `
            'Each one adds to the time before the desktop is usable. Disable the ones not needed at every start in Task Manager, Startup apps.'
    }

    # --- Start up ---------------------------------------------------------------
    if ($Boot -and -not $Boot.Available) {
        $findings += & $finding 'Info' 'Start up time not read' 'Needs administrator rights' `
            'Windows records how long each start up takes in a log it only opens to an administrator. Restart the toolkit elevated to include it.'
    }
    elseif ($Boot -and @($Boot.Boots).Count -gt 0) {

        $recent  = @($Boot.Boots | Select-Object -First 5)
        $average = [math]::Round((($recent | Measure-Object -Property MainPathMs -Average).Average) / 1000)
        $last    = $recent[0]

        $findings += & $finding $(if ($average -gt 120) { 'Fail' } elseif ($average -gt 60) { 'Warning' } else { 'Pass' }) `
            ('Start up to the desktop: {0} s on average' -f $average) `
            ('Last: {0} s, then {1} s until the machine settled, on {2}' -f [math]::Round($last.MainPathMs / 1000), [math]::Round($last.PostBootMs / 1000), ([datetime] $last.When).ToString('yyyy-MM-dd HH:mm')) `
            'Over the last five start ups Windows recorded. What made them slower is listed below.'

        foreach ($slow in @($Boot.Slowdowns | Select-Object -First 8)) {

            $findings += & $finding 'Warning' ('{0}: {1}' -f $slow.Kind, $slow.Name) `
                ('Added {0} s, {1} time(s)' -f [string] [math]::Round($slow.AddedMs / 1000, 1), $slow.Count) `
                'Windows measured this slowing a start up down. Update it, delay it or remove it from start up.'
        }
    }
    elseif ($Boot) {
        $findings += & $finding 'Info' 'No start up recorded in the last 30 days' '' 'Windows records a start up in the Diagnostics-Performance log once the machine has settled after it.'
    }

    return $findings
}
