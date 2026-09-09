<#
    Toolkit - Features / Workstation diagnostics

    The questions a technician answers on a support call, in the order they
    usually come up: is it waiting for a reboot, is the disk failing or just
    full, why did it crash, what happened at the last update, why will it not
    print, and whose profile is this.

    Every function here is read only. A support call starts by finding out
    what is true, and a tool that changes things while you are still looking
    destroys the evidence.
#>

# ---------------------------------------------------------------------------
# Reboot state
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reports whether the machine is waiting for a restart, and why.

.DESCRIPTION
    Windows records a pending reboot in several unrelated places, and no
    single one of them is authoritative. A machine can be waiting on a
    servicing operation with none of the usual prompts showing, which is why
    "have you restarted it" so often produces "yes" and no improvement.

.OUTPUTS
    PSCustomObject with Pending and Reasons.
#>
function Get-TkPendingRebootStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $reasons = @()

    $keys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
           Why  = 'Component servicing has staged changes that only apply at boot.' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
           Why  = 'Windows Update installed something that needs a restart.' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'
           Why  = 'A servicing operation is part way through.' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
           Why  = 'Packages are staged and waiting.' }
    )

    foreach ($key in $keys) {

        if (Test-Path -LiteralPath $key.Path -ErrorAction Ignore) {
            $reasons += $key.Why
        }
    }

    # A rename queued for the next boot is the classic invisible pending
    # reboot: no prompt anywhere, but an installer will refuse to proceed.
    $renames = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                                   -Name 'PendingFileRenameOperations'

    if ($renames) {
        $reasons += 'File renames are queued for the next boot ({0} entries).' -f @($renames).Count
    }

    # A computer rename that has not taken effect yet.
    $active = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName'
    $target = Get-TkRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName'

    if ($active -and $target -and $active -ne $target) {
        $reasons += 'The computer was renamed to "{0}" and is still running as "{1}".' -f $target, $active
    }

    # Configuration Manager, where present, keeps its own flag.
    try {
        $ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' `
                                -MethodName 'DetermineIfRebootPending' -ErrorAction Stop

        if ($ccm.RebootPending -or $ccm.IsHardRebootPending) {
            $reasons += 'The Configuration Manager client reports a pending reboot.'
        }
    }
    catch {
        # No SCCM client on this machine, which is the common case.
        $null = $_
    }

    return [pscustomobject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = $reasons
        Uptime  = Format-TkTimeSpan -Value ((Get-Date) - (Get-TkCimInstanceSafe -ClassName Win32_OperatingSystem).LastBootUpTime)
    }
}

# ---------------------------------------------------------------------------
# Storage health
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reports disk health and the volumes that are running out of room.

.DESCRIPTION
    Joins the SMART style reliability counters to the free space figures,
    because "the machine is slow" is answered by one or the other far more
    often than by anything else.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkStorageHealth {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $results = @()

    foreach ($disk in (Get-TkCimInstanceSafe -ClassName 'MSFT_PhysicalDisk' -Namespace 'Root\Microsoft\Windows\Storage' -All)) {

        $wearPercent   = $null
        $temperature   = $null
        $readErrors    = $null
        $powerOnHours  = $null

        try {
            $reliability = Get-CimInstance -Namespace 'Root\Microsoft\Windows\Storage' `
                                           -ClassName 'MSFT_StorageReliabilityCounter' `
                                           -ErrorAction Stop |
                           Where-Object { $_.DeviceId -eq $disk.DeviceId } |
                           Select-Object -First 1

            if ($reliability) {
                $wearPercent  = $reliability.Wear
                $temperature  = $reliability.Temperature
                $readErrors   = $reliability.ReadErrorsTotal
                $powerOnHours = $reliability.PowerOnHours
            }
        }
        catch {
            $null = $_
        }

        $severity = 'Pass'
        $notes    = @()

        if ([int] $disk.HealthStatus -ne 0) {
            $severity = 'Fail'
            $notes += 'the drive reports itself as unhealthy'
        }

        # An SSD reports how much of its rated write endurance is used.
        if ($null -ne $wearPercent -and $wearPercent -gt 80) {
            $severity = 'Warning'
            $notes += 'write endurance is {0} percent used' -f $wearPercent
        }

        if ($null -ne $temperature -and $temperature -gt 60) {
            $severity = 'Warning'
            $notes += 'running at {0} degrees' -f $temperature
        }

        $results += [pscustomobject]@{
            Severity     = $severity
            Kind         = 'Disk'
            Name         = Format-TkValue $disk.FriendlyName
            Size         = Format-TkBytes -Bytes $disk.Size
            MediaType    = ConvertFrom-TkMediaType -Code $disk.MediaType
            BusType      = ConvertFrom-TkBusType -Code $disk.BusType
            Health       = switch ([int] $disk.HealthStatus) { 0 { 'Healthy' } 1 { 'Warning' } 2 { 'Unhealthy' } default { 'Unknown' } }
            WearPercent  = $wearPercent
            TemperatureC = $temperature
            PowerOnHours = $powerOnHours
            ReadErrors   = $readErrors
            Notes        = ($notes -join '; ')
        }
    }

    foreach ($volume in (Get-TkCimInstanceSafe -ClassName 'Win32_LogicalDisk' -Filter 'DriveType=3' -All)) {

        $freePercent = 0

        if ($volume.Size -gt 0) {
            $freePercent = [math]::Round(($volume.FreeSpace / $volume.Size) * 100, 1)
        }

        $severity = 'Pass'
        $notes    = ''

        # Below ten percent Windows starts to struggle: no room for updates,
        # no room for the page file to grow, no room for a restore point.
        if ($freePercent -lt 5) {
            $severity = 'Fail'
            $notes    = 'Critically full. Updates and restore points will fail.'
        }
        elseif ($freePercent -lt 12) {
            $severity = 'Warning'
            $notes    = 'Low. Windows needs headroom for servicing.'
        }

        $results += [pscustomobject]@{
            Severity     = $severity
            Kind         = 'Volume'
            Name         = '{0} {1}' -f $volume.DeviceID, (Format-TkValue $volume.VolumeName -Placeholder '')
            Size         = Format-TkBytes -Bytes $volume.Size
            MediaType    = $volume.FileSystem
            BusType      = ''
            Health       = '{0} percent free' -f $freePercent
            WearPercent  = $null
            TemperatureC = $null
            PowerOnHours = $null
            ReadErrors   = $null
            Notes        = $notes
        }
    }

    return $results
}

# ---------------------------------------------------------------------------
# Stability
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Summarises crashes, bug checks and unexpected shutdowns.

.DESCRIPTION
    The three questions behind "it keeps crashing": did Windows itself stop,
    did an application stop, or did the machine simply lose power. Each has a
    different event and a completely different cause.

.PARAMETER Days
    How far back to look.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkStabilityReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 90)]
        [int] $Days = 14
    )

    $since   = (Get-Date).AddDays(-$Days)
    $results = @()

    # --- Bug checks, which is to say blue screens -------------------------
    $bugChecks = Get-TkWinEvent -LogName 'System' -Id 1001 -Since $since -MaxEvents 100 |
                 Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting' }

    foreach ($record in @($bugChecks | Select-Object -First 10)) {

        $results += [pscustomobject]@{
            Severity = 'Fail'
            Kind     = 'Bug check'
            When     = $record.TimeCreated
            Source   = 'Windows kernel'
            Detail   = ($record.Message -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1)
        }
    }

    # --- Unexpected shutdowns --------------------------------------------
    $unexpected = Get-TkWinEvent -LogName 'System' -Id 6008 -Since $since -MaxEvents 50

    foreach ($record in @($unexpected | Select-Object -First 10)) {

        $results += [pscustomobject]@{
            Severity = 'Warning'
            Kind     = 'Unexpected shutdown'
            When     = $record.TimeCreated
            Source   = 'Power or bug check'
            Detail   = 'The machine stopped without shutting down cleanly.'
        }
    }

    # --- Application crashes ---------------------------------------------
    $crashes = Get-TkWinEvent -LogName 'Application' -Id 1000 -Since $since -MaxEvents 500

    $byApplication = $crashes |
        ForEach-Object { $_.Properties[0].Value } |
        Where-Object { $_ } |
        Group-Object |
        Sort-Object -Property Count -Descending |
        Select-Object -First 8

    foreach ($group in $byApplication) {

        $results += [pscustomobject]@{
            Severity = $(if ($group.Count -ge 10) { 'Warning' } else { 'Info' })
            Kind     = 'Application crash'
            When     = $null
            Source   = $group.Name
            Detail   = '{0} crash(es) in the last {1} days.' -f $group.Count, $Days
        }
    }

    # --- Disk errors ------------------------------------------------------
    $diskErrors = Get-TkWinEvent -LogName 'System' -Id 7 -Since $since -MaxEvents 50

    if ($diskErrors.Count -gt 0) {

        $results += [pscustomobject]@{
            Severity = 'Fail'
            Kind     = 'Disk error'
            When     = $diskErrors[0].TimeCreated
            Source   = 'disk'
            Detail   = '{0} bad block event(s). Back the machine up before anything else.' -f $diskErrors.Count
        }
    }

    if ($results.Count -eq 0) {

        $results += [pscustomobject]@{
            Severity = 'Pass'
            Kind     = 'Stability'
            When     = $null
            Source   = ''
            Detail   = 'No bug check, unexpected shutdown, disk error or repeated application crash in the last {0} days.' -f $Days
        }
    }

    return $results
}

# ---------------------------------------------------------------------------
# Servicing
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the recent Windows Update history.

.DESCRIPTION
    Read through the update session COM interface rather than Get-HotFix,
    because Get-HotFix only reports servicing packages and misses driver and
    feature updates entirely, which are exactly the ones that break things.

.PARAMETER Count
    How many entries to return.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkUpdateHistory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 200)]
        [int] $Count = 30
    )

    $results = @()

    try {
        $session  = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $total    = $searcher.GetTotalHistoryCount()

        if ($total -le 0) {
            return $results
        }

        foreach ($entry in $searcher.QueryHistory(0, [Math]::Min($Count, $total))) {

            # 1 installed, 2 succeeded with errors, 3 failed, 4 aborted.
            $outcome = switch ($entry.ResultCode) {
                1 { 'In progress' ; break }
                2 { 'Installed'   ; break }
                3 { 'Installed with errors' ; break }
                4 { 'Failed'      ; break }
                5 { 'Cancelled'   ; break }
                default { 'Unknown' }
            }

            $results += [pscustomobject]@{
                Severity = switch ($entry.ResultCode) { 2 { 'Pass' } 4 { 'Fail' } 3 { 'Warning' } default { 'Info' } }
                When     = $entry.Date
                Title    = $entry.Title
                Outcome  = $outcome
                Code     = '0x{0:X8}' -f $entry.HResult
            }
        }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Diagnostics' -Message (
            'The update history could not be read: {0}' -f $_.Exception.Message
        )
    }

    return $results
}

# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reports the printing subsystem: printers, ports, drivers and the queue.

.DESCRIPTION
    "It will not print" is one call in five, and the answer is nearly always
    one of four things: the printer is offline, the queue is jammed, the port
    points somewhere unreachable, or the spooler has stopped.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkPrintingReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $results = @()

    $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue

    $results += [pscustomobject]@{
        Severity = $(if ($spooler -and $spooler.Status -eq 'Running') { 'Pass' } else { 'Fail' })
        Kind     = 'Spooler'
        Name     = 'Print Spooler service'
        Status   = $(if ($spooler) { [string] $spooler.Status } else { 'not present' })
        Detail   = $(if ($spooler -and $spooler.Status -eq 'Running') { 'Running.' }
                     else { 'Stopped. Nothing will print until it is started.' })
    }

    try {
        $printers = Get-Printer -ErrorAction Stop

        foreach ($printer in $printers) {

            $queued = 0

            try {
                $queued = @(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop).Count
            }
            catch {
                $null = $_
            }

            $severity = 'Pass'
            $notes    = @()

            if ($printer.PrinterStatus -notin @('Normal', 'Idle')) {
                $severity = 'Warning'
                $notes += 'status is {0}' -f $printer.PrinterStatus
            }

            if ($queued -gt 5) {
                $severity = 'Warning'
                $notes += '{0} jobs queued' -f $queued
            }

            $results += [pscustomobject]@{
                Severity = $severity
                Kind     = $(if ($printer.Shared) { 'Shared printer' } else { 'Printer' })
                Name     = $printer.Name
                Status   = '{0} on {1}' -f $printer.PrinterStatus, $printer.PortName
                Detail   = '{0}{1}' -f $printer.DriverName, $(if ($notes) { ' - ' + ($notes -join ', ') } else { '' })
            }
        }

        if ($printers.Count -eq 0) {

            $results += [pscustomobject]@{
                Severity = 'Info'; Kind = 'Printer'; Name = 'None installed'
                Status = ''; Detail = 'No printer is installed on this machine.'
            }
        }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Diagnostics' -Message (
            'Printers could not be enumerated: {0}' -f $_.Exception.Message
        )
    }

    return $results
}

# ---------------------------------------------------------------------------
# Sessions, profiles and policy
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reports user profiles, sessions, mapped drives and applied policy.

.DESCRIPTION
    The context of a support call: who is signed in, how large their profile
    is, what is mapped, and which policies actually applied. A roaming
    profile of twelve gigabytes explains a slow logon better than any amount
    of network testing.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkUserContextReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $results = @()

    # --- Profiles ---------------------------------------------------------
    foreach ($userProfile in (Get-TkCimInstanceSafe -ClassName 'Win32_UserProfile' -All)) {

        if ($userProfile.Special) {
            continue
        }

        $size = $null
        $name = $userProfile.LocalPath

        if ($userProfile.LocalPath -and (Test-Path -LiteralPath $userProfile.LocalPath -ErrorAction Ignore)) {

            $name = Split-Path -Path $userProfile.LocalPath -Leaf

            try {
                $measured = Get-ChildItem -LiteralPath $userProfile.LocalPath -Recurse -File -Force -ErrorAction Ignore |
                            Measure-Object -Property Length -Sum

                $size = $measured.Sum
            }
            catch {
                $null = $_
            }
        }

        $severity = 'Info'
        $detail   = 'Roaming: {0}. Last used: {1}.' -f $userProfile.RoamingConfigured,
                        $(if ($userProfile.LastUseTime) { ([datetime] $userProfile.LastUseTime).ToString('yyyy-MM-dd') } else { 'unknown' })

        if ($size -and $size -gt 10GB) {
            $severity = 'Warning'
            $detail  += ' A profile this large makes every logon and logoff slow.'
        }

        $results += [pscustomobject]@{
            Severity = $severity
            Kind     = 'Profile'
            Name     = $name
            Value    = Format-TkBytes -Bytes $size
            Detail   = $detail
        }
    }

    # --- Mapped drives ----------------------------------------------------
    foreach ($drive in (Get-TkCimInstanceSafe -ClassName 'Win32_NetworkConnection' -All)) {

        $results += [pscustomobject]@{
            Severity = $(if ($drive.ConnectionState -eq 'Connected') { 'Pass' } else { 'Warning' })
            Kind     = 'Mapped drive'
            Name     = $drive.LocalName
            Value    = $drive.RemoteName
            Detail   = 'State: {0}. Persistent: {1}.' -f $drive.ConnectionState, $drive.Persistent
        }
    }

    # --- Domain membership and secure channel ----------------------------
    $computer = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'

    if ($computer.PartOfDomain) {

        $channelHealthy = $null

        try {
            $channelHealthy = Test-ComputerSecureChannel -ErrorAction Stop
        }
        catch {
            $null = $_
        }

        $results += [pscustomobject]@{
            Severity = $(if ($channelHealthy -eq $false) { 'Fail' } elseif ($null -eq $channelHealthy) { 'Info' } else { 'Pass' })
            Kind     = 'Domain'
            Name     = $computer.Domain
            Value    = $(if ($null -eq $channelHealthy) { 'not tested' } elseif ($channelHealthy) { 'secure channel healthy' } else { 'SECURE CHANNEL BROKEN' })
            Detail   = $(if ($channelHealthy -eq $false) {
                             'The machine password no longer matches the directory. Domain logons will fail; reset it with Test-ComputerSecureChannel -Repair.'
                         }
                         else { 'Domain joined.' })
        }
    }
    else {
        $results += [pscustomobject]@{
            Severity = 'Info'; Kind = 'Domain'; Name = $computer.Workgroup
            Value = 'workgroup'; Detail = 'Not domain joined.'
        }
    }

    # --- Logon duration ---------------------------------------------------
    # Group policy processing time is the usual answer to "logon takes ages",
    # and it is recorded where nobody looks.
    $slowLogons = Get-TkWinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Id 8001 `
                                 -Since (Get-Date).AddDays(-14) -MaxEvents 20

    if ($slowLogons.Count -gt 0) {

        $durations = @($slowLogons | ForEach-Object {
            if ($_.Message -match '(\d+)\s*second') { [int] $Matches[1] } else { 0 }
        }) | Where-Object { $_ -gt 0 }

        if ($durations.Count -gt 0) {

            $average = [math]::Round(($durations | Measure-Object -Average).Average, 1)

            $results += [pscustomobject]@{
                Severity = $(if ($average -gt 60) { 'Warning' } else { 'Pass' })
                Kind     = 'Logon'
                Name     = 'Group policy processing'
                Value    = '{0} seconds average' -f $average
                Detail   = $(if ($average -gt 60) {
                                 'Slow. Look at drive mappings, printer deployment and logon scripts before blaming the network.'
                             }
                             else { 'Normal.' })
            }
        }
    }

    return $results
}
