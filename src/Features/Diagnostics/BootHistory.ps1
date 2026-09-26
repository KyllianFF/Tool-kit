<#
    Toolkit - Features / Restarts and shutdowns

    "Why did my PC restart?" The System log already knows. Every start is
    logged by the kernel with its exact time, every clean stop too, and before
    a restart or a shutdown User32 records which program asked for it, for
    which account and with what reason. When the session instead ended with no
    shutdown at all, the kernel says so at the next start.

    This lines those events up into one timeline: for each start, how the
    session before it ended and who asked. Blue screens themselves are read in
    detail by the crash report, and start up time by the performance report;
    this one answers when and why.

    Everything is read from structured event fields, never from the message
    text, which Windows translates: the same code reads a French or an English
    log. For the same reason a restart is told from a shutdown by the time the
    machine stayed off, not by the translated word User32 writes.
#>

<#
.SYNOPSIS
    Names the program that asked for a restart or a shutdown.

.DESCRIPTION
    User32 records the full path of the program with the computer name after
    it. The path says little to a user, so the programs that usually ask are
    named for what they are: Windows Update, the Start menu, a command.

.PARAMETER Process
    The first field of a User32 1074 event, for example
    "C:\Windows\servicing\TrustedInstaller.exe (PC-01)".

.OUTPUTS
    PSCustomObject with Name (for display) and File (the program file name).
#>
function ConvertFrom-TkShutdownInitiator {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Process
    )

    # Drop the "(COMPUTER)" User32 appends, then keep the file name.
    $path = ($Process -replace '\s*\([^)]*\)\s*$', '').Trim()
    $file = if ($path) { Split-Path -Path $path -Leaf } else { '' }

    $name = switch -Regex ($file.ToLowerInvariant()) {
        '^(trustedinstaller|mousocoreworker|usoclient|wuauclt|musnotification|musnotificationux)\.exe$' { 'Windows Update'; break }
        '^(startmenuexperiencehost|explorer|shellexperiencehost|shellhost)\.exe$'                     { 'Start menu (the user)'; break }
        '^winlogon\.exe$'                   { 'Windows (power button, sign-in or lock screen)'; break }
        '^(wininit|csrss|services)\.exe$'   { 'Windows'; break }
        '^shutdown\.exe$'                   { 'The shutdown command'; break }
        '^(powershell|pwsh)\.exe$'          { 'PowerShell (Restart-Computer or Stop-Computer)'; break }
        '^msiexec\.exe$'                    { 'An installer (msiexec)'; break }
        '^svchost\.exe$'                    { 'A Windows service (svchost)'; break }
        '^$'                                { 'Unknown'; break }
        default                             { $file }
    }

    return [pscustomobject] @{ Name = $name; File = $file }
}

<#
.SYNOPSIS
    Names the kind of start from the Kernel-Boot boot type.

.DESCRIPTION
    0 is a full start. 1 is Fast Startup: a "shut down" that hibernated the
    kernel, so Windows resumed rather than started, and its uptime kept
    counting. 2 is a resume from hibernation.

.OUTPUTS
    System.String
#>
function Get-TkBootTypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $BootType
    )

    switch ([string] $BootType) {
        '0'     { return 'Full start' }
        '1'     { return 'Fast startup' }
        '2'     { return 'Resume from hibernation' }
        default { return 'Unknown' }
    }
}

<#
.SYNOPSIS
    Lines up start, stop and initiator events into one timeline.

.DESCRIPTION
    Pure: it takes the events already read, so it can be tested with made up
    ones. For each start, the events between the start before it and this
    one say how that earlier session ended:

      - an unexpected-end event logged just after this start: the session
        ended with no shutdown (a stop code means a blue screen);
      - otherwise a clean stop, and the time the machine then stayed off:
        up to RestartGapMinutes is a restart, longer a shutdown;
      - neither: unknown, typically because the log rolled over.

    The program that asked is the last User32 request before the stop.

.PARAMETER Boot
    Starts: objects with When.

.PARAMETER Stop
    Clean stops: objects with When.

.PARAMETER Initiator
    User32 requests: objects with When, Process, User, Reason and ReasonCode.

.PARAMETER Unexpected
    Unexpected ends, logged at the next start: objects with When and
    BugcheckCode.

.PARAMETER BootType
    Kernel-Boot records: objects with When and Type.

.PARAMETER RestartGapMinutes
    The longest time off that still counts as a restart.

.OUTPUTS
    PSCustomObject[] newest first, with Started, StartType, PreviousEnd,
    Severity, By, ByFile, User, Reason, ReasonCode, SessionLength, OffFor.
#>
function ConvertTo-TkBootTimeline {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Boot       = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Stop       = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Initiator  = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $Unexpected = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $BootType   = @(),

        [Parameter()]
        [ValidateRange(1, 60)]
        [int] $RestartGapMinutes = 5
    )

    $boots   = @($Boot | Where-Object { $_ } | Sort-Object { [datetime] $_.When })
    $rows    = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $boots.Count; $i++) {

        $start     = [datetime] $boots[$i].When
        $prevStart = if ($i -gt 0) { [datetime] $boots[$i - 1].When } else { [datetime]::MinValue }

        # What happened between the start before this one and this one.
        $stopEvent = @($Stop | Where-Object { $_ -and ([datetime] $_.When) -gt $prevStart -and ([datetime] $_.When) -le $start } |
                  Sort-Object { [datetime] $_.When }) | Select-Object -Last 1

        $until = if ($stopEvent) { [datetime] $stopEvent.When } else { $start }

        $asked = @($Initiator | Where-Object { $_ -and ([datetime] $_.When) -gt $prevStart -and ([datetime] $_.When) -le $until } |
                   Sort-Object { [datetime] $_.When }) | Select-Object -Last 1

        # The kernel logs an unexpected end a few seconds after the next start.
        # The closest one: two resets ten minutes apart must not trade events.
        $crash = @($Unexpected | Where-Object {
                     $_ -and ([datetime] $_.When) -ge $start.AddMinutes(-1) -and ([datetime] $_.When) -le $start.AddMinutes(10)
                 } | Sort-Object { [math]::Abs((([datetime] $_.When) - $start).TotalSeconds) }) | Select-Object -First 1

        $type = @($BootType | Where-Object {
                    $_ -and [math]::Abs((([datetime] $_.When) - $start).TotalMinutes) -le 2
                }) | Select-Object -First 1

        $offFor = $null

        if ($crash) {
            $code = 0L
            [void] [long]::TryParse([string] $crash.BugcheckCode, [ref] $code)

            $previousEnd = if ($code -ne 0) { 'Blue screen' } else { 'Unexpected' }
            $severity    = if ($code -ne 0) { 'Fail' } else { 'Warning' }
        }
        elseif ($stopEvent) {
            $offFor      = $start - [datetime] $stopEvent.When
            $previousEnd = if ($offFor.TotalMinutes -le $RestartGapMinutes) { 'Restart' } else { 'Shut down' }
            $severity    = 'Pass'
        }
        else {
            $previousEnd = 'Unknown'
            $severity    = 'Info'
        }

        # Only a clean stop dates the end of the session before.
        $sessionLength = if ($i -gt 0 -and $stopEvent -and -not $crash) { ([datetime] $stopEvent.When) - $prevStart } else { $null }

        $by = if ($asked -and -not $crash) { ConvertFrom-TkShutdownInitiator -Process ([string] $asked.Process) } else { $null }

        $rows.Add([pscustomobject] @{
            Started       = $start
            StartType     = Get-TkBootTypeName -BootType $(if ($type) { $type.Type } else { $null })
            PreviousEnd   = $previousEnd
            Severity      = $severity
            By            = if ($by) { $by.Name } else { '' }
            ByFile        = if ($by) { $by.File } else { '' }
            User          = if ($asked -and -not $crash) { [string] $asked.User } else { '' }
            Reason        = if ($asked -and -not $crash) { [string] $asked.Reason } else { '' }
            ReasonCode    = if ($asked -and -not $crash) { [string] $asked.ReasonCode } else { '' }
            SessionLength = $sessionLength
            OffFor        = $offFor
        })
    }

    $ordered = @($rows.ToArray())
    [array]::Reverse($ordered)

    return $ordered
}

<#
.SYNOPSIS
    Counts the timeline: starts, restarts, shutdowns, unexpected ends, and who asked.

.OUTPUTS
    PSCustomObject with Starts, Restarts, Shutdowns, Unexpected, BlueScreens,
    FastStartups and Initiators (Name, Count, Last), most frequent first.
#>
function Get-TkBootHistorySummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Timeline = @()
    )

    $rows = @($Timeline | Where-Object { $_ })

    $initiators = @($rows | Where-Object { $_.By } | Group-Object By | ForEach-Object {
        [pscustomobject] @{
            Name  = $_.Name
            Count = $_.Count
            Last  = (@($_.Group | Sort-Object Started -Descending) | Select-Object -First 1).Started
        }
    } | Sort-Object @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Last'; Descending = $true })

    return [pscustomobject] @{
        Starts       = $rows.Count
        Restarts     = @($rows | Where-Object { $_.PreviousEnd -eq 'Restart' }).Count
        Shutdowns    = @($rows | Where-Object { $_.PreviousEnd -eq 'Shut down' }).Count
        Unexpected   = @($rows | Where-Object { $_.PreviousEnd -in @('Unexpected', 'Blue screen') }).Count
        BlueScreens  = @($rows | Where-Object { $_.PreviousEnd -eq 'Blue screen' }).Count
        FastStartups = @($rows | Where-Object { $_.StartType -eq 'Fast startup' }).Count
        Initiators   = $initiators
    }
}

<#
.SYNOPSIS
    Reads the named fields of an event.

.OUTPUTS
    System.Collections.Hashtable, empty when the event cannot be read.
#>
function Get-TkEventData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        $Record
    )

    $data = @{}

    try {
        foreach ($item in @(([xml] $Record.ToXml()).Event.EventData.Data)) {
            if ($item.Name) { $data[[string] $item.Name] = [string] $item.'#text' }
        }
    }
    catch {
        $null = $_
    }

    return $data
}

<#
.SYNOPSIS
    Reads one provider's events from the System log, none being a normal answer.
#>
function Read-TkSystemEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Provider,
        [Parameter(Mandatory)] [int[]]    $Id,
        [Parameter(Mandatory)] [datetime] $Since
    )

    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $Provider; Id = $Id; StartTime = $Since } -MaxEvents 2000 -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Write-TkLog -Level Debug -Category 'Diagnostics' -Message (
                'Could not read {0} event(s) {1}: {2}' -f $Provider, ($Id -join ','), $_.Exception.Message
            )
        }

        return @()
    }
}

<#
.SYNOPSIS
    Reads the restarts and shutdowns of the last days from the System log.

.DESCRIPTION
    Readable by a standard user. Starts come from Kernel-General 12 and clean
    stops from Kernel-General 13, both with their exact time; requests from
    User32 1074; unexpected ends from Kernel-Power 41; the kind of start from
    Kernel-Boot 27; wakes from sleep from Power-Troubleshooter 1.

.PARAMETER Days
    How far back to look.

.OUTPUTS
    PSCustomObject with Days, Current, Timeline, Summary and Wakes.
#>
function Get-TkBootHistory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int] $Days = 30
    )

    # A little before the window, so the stop that preceded its first start
    # is there to explain it.
    $since = (Get-Date).AddDays(-$Days)
    $read  = $since.AddDays(-1)

    $utcField = {
        param($data, $name, $fallback)
        $parsed = [datetime]::MinValue
        if ($data[$name] -and [datetime]::TryParse($data[$name], [System.Globalization.CultureInfo]::InvariantCulture,
                                                     [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $parsed)) {
            return $parsed.ToLocalTime()
        }
        return $fallback
    }

    $boots = @(Read-TkSystemEvent -Provider 'Microsoft-Windows-Kernel-General' -Id 12 -Since $read | ForEach-Object {
        [pscustomobject] @{ When = & $utcField (Get-TkEventData -Record $_) 'StartTime' $_.TimeCreated }
    })

    $stops = @(Read-TkSystemEvent -Provider 'Microsoft-Windows-Kernel-General' -Id 13 -Since $read | ForEach-Object {
        [pscustomobject] @{ When = & $utcField (Get-TkEventData -Record $_) 'StopTime' $_.TimeCreated }
    })

    $initiators = @(Read-TkSystemEvent -Provider 'User32' -Id 1074 -Since $read | ForEach-Object {
        $data = Get-TkEventData -Record $_
        [pscustomobject] @{
            When       = $_.TimeCreated
            Process    = $data['param1']
            Reason     = $data['param3']
            ReasonCode = $data['param4']
            User       = $data['param7']
        }
    })

    $unexpected = @(Read-TkSystemEvent -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Since $read | ForEach-Object {
        [pscustomobject] @{ When = $_.TimeCreated; BugcheckCode = (Get-TkEventData -Record $_)['BugcheckCode'] }
    })

    $bootTypes = @(Read-TkSystemEvent -Provider 'Microsoft-Windows-Kernel-Boot' -Id 27 -Since $read | ForEach-Object {
        [pscustomobject] @{ When = $_.TimeCreated; Type = (Get-TkEventData -Record $_)['BootType'] }
    })

    $wakes = @(Read-TkSystemEvent -Provider 'Microsoft-Windows-Power-Troubleshooter' -Id 1 -Since $since)

    $timeline = @(ConvertTo-TkBootTimeline -Boot $boots -Stop $stops -Initiator $initiators `
                                           -Unexpected $unexpected -BootType $bootTypes |
                  Where-Object { $_.Started -ge $since })

    $latest = $timeline | Select-Object -First 1

    return [pscustomobject] @{
        Days     = $Days
        Current  = if ($latest) {
            [pscustomobject] @{ Since = $latest.Started; Uptime = (Get-Date) - $latest.Started; StartType = $latest.StartType }
        } else { $null }
        Timeline = $timeline
        Summary  = Get-TkBootHistorySummary -Timeline $timeline
        Wakes    = $wakes.Count
    }
}
