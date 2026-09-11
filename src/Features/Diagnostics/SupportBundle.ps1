<#
    Toolkit - Features / Support bundle

    Packages everything a support ticket usually asks for into one timestamped
    ZIP: the machine identity, the network configuration, the diagnostic
    findings, the security posture, the recent error events and the toolkit's
    own log. It answers the request that ends every remote session, "can you
    send me the details", with one file instead of a dozen copy-and-pastes.

    Two rules hold it together.

    It changes nothing. Every part is a read, and the only thing written is the
    ZIP, under the log folder. A diagnostic that alters the machine while
    someone is still looking destroys the evidence it was meant to gather.

    It never fails as a whole. Each collector runs inside its own guard, and a
    collector that throws writes its error into the summary rather than sinking
    the bundle. A ticket is worth more with one section missing than not at all.

    What it contains is listed in the summary, in plain words, because the
    operator is about to send it to someone: the machine name, the signed in
    user, the network addresses and the recent error events are all in there,
    and nothing that is meant to stay secret, such as a stored API key or an
    autologon password, is.
#>

<#
.SYNOPSIS
    Formats a set of objects as a block of readable text for the bundle.

.DESCRIPTION
    A table when the objects are uniform, a list when they are not; either way
    a title and a blank line so the file reads as sections rather than a dump.
    Tolerates an empty set with a line saying so.

.OUTPUTS
    System.String
#>
function ConvertTo-TkBundleText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [ValidateSet('Table', 'List')]
        [string] $As = 'List'
    )

    $items = ConvertTo-TkArray $InputObject

    $builder = New-Object System.Text.StringBuilder

    [void] $builder.AppendLine($Title)
    [void] $builder.AppendLine(('-' * $Title.Length))

    if ($items.Count -eq 0) {
        [void] $builder.AppendLine('(nothing to report)')
        [void] $builder.AppendLine('')
        return $builder.ToString()
    }

    $rendered = if ($As -eq 'Table') {
        $items | Format-Table -AutoSize -Wrap | Out-String -Width 200
    }
    else {
        $items | Format-List | Out-String -Width 200
    }

    [void] $builder.AppendLine($rendered.TrimEnd())
    [void] $builder.AppendLine('')

    return $builder.ToString()
}

<#
.SYNOPSIS
    Runs a collector under a guard and returns its text, or an error note.

.DESCRIPTION
    The wrapper that keeps one broken collector from sinking the bundle. On a
    throw it returns a section that says which part failed and why, and adds a
    line to the shared error list the summary reports.

.OUTPUTS
    System.String
#>
function Get-TkBundleSection {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [scriptblock] $Collector,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $Errors
    )

    try {
        return (& $Collector)
    }
    catch {
        $message = '{0}: {1}' -f $Title, $_.Exception.Message

        $Errors.Add($message)

        return (ConvertTo-TkBundleText -Title $Title -InputObject (
            [pscustomobject] @{ Error = 'This section could not be collected.'; Reason = $_.Exception.Message }
        ))
    }
}

<#
.SYNOPSIS
    Builds the support bundle and returns the path to the ZIP.

.DESCRIPTION
    Collects into a temporary folder under the log folder, zips it, and removes
    the folder. Returns the ZIP path, or $null when even the container could
    not be created.

.PARAMETER IncludeEventLog
    Add the recent error and critical events. On by default; the one part that
    can be slow, so it can be turned off.

.OUTPUTS
    System.String, the path to the ZIP, or $null.
#>
function New-TkSupportBundle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [bool] $IncludeEventLog = $true
    )

    $ctx   = Get-TkContext
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $host_ = $env:COMPUTERNAME

    $bundleRoot = Join-Path -Path $ctx.LogRoot -ChildPath 'bundles'
    $workFolder = Join-Path -Path $bundleRoot -ChildPath ('work-{0}' -f $stamp)

    try {
        New-Item -Path $workFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-TkLog -Level Error -Category 'Bundle' -Message (
            'The support bundle folder could not be created: {0}' -f $_.Exception.Message
        )

        return $null
    }

    $errors    = New-Object 'System.Collections.Generic.List[string]'
    $elevated  = Test-TkIsElevated

    # --- The sections ----------------------------------------------------
    # Each block builds its parts into an array and joins them. The parts are
    # not added with "+" between command calls: in command mode a leading "+"
    # reads as another argument, not string concatenation.
    Get-TkBundleSection -Title 'System identity' -Errors $errors -Collector {
        @(
            (ConvertTo-TkBundleText -Title 'Machine identity'   -InputObject (Get-TkMachineIdentity))
            (ConvertTo-TkBundleText -Title 'Operating system'   -InputObject (Get-TkOperatingSystemInfo))
            (ConvertTo-TkBundleText -Title 'Platform security'  -InputObject (Get-TkPlatformSecurityInfo))
        ) -join ''
    } | Set-Content -LiteralPath (Join-Path $workFolder '10-system.txt') -Encoding UTF8

    Get-TkBundleSection -Title 'Hardware' -Errors $errors -Collector {
        $hardware = Get-TkHardwareInfo

        @(
            (ConvertTo-TkBundleText -Title 'Processor and memory' -InputObject ([pscustomobject] @{
                Processor   = $hardware.CpuName
                Cores       = $hardware.CpuCores
                Threads     = $hardware.CpuThreads
                MaxClockMHz = $hardware.CpuMaxClockMHz
                Memory      = $hardware.TotalMemory
                Graphics    = $hardware.Graphics
            }))
            (ConvertTo-TkBundleText -Title 'Memory modules' -As Table -InputObject $hardware.MemoryModules)
            (ConvertTo-TkBundleText -Title 'Volumes'        -As Table -InputObject $hardware.Volumes)
            (ConvertTo-TkBundleText -Title 'Physical disks' -As Table -InputObject $hardware.Disks)
        ) -join ''
    } | Set-Content -LiteralPath (Join-Path $workFolder '11-hardware.txt') -Encoding UTF8

    Get-TkBundleSection -Title 'Network' -Errors $errors -Collector {
        @(
            (ConvertTo-TkBundleText -Title 'Adapters' -As Table -InputObject (Get-TkNetworkAdapterInfo -IncludeDisconnected))
            (ConvertTo-TkBundleText -Title 'Routing table' -As Table -InputObject (Get-TkRouteTable))
            (ConvertTo-TkBundleText -Title 'Listening ports' -As Table -InputObject (Get-TkListeningPort))
        ) -join ''
    } | Set-Content -LiteralPath (Join-Path $workFolder '20-network.txt') -Encoding UTF8

    Get-TkBundleSection -Title 'Diagnostics' -Errors $errors -Collector {
        @(
            (ConvertTo-TkBundleText -Title 'Pending reboot'      -InputObject (Get-TkPendingRebootStatus))
            (ConvertTo-TkBundleText -Title 'Storage health'      -As Table -InputObject (Get-TkStorageHealth))
            (ConvertTo-TkBundleText -Title 'Stability'           -As Table -InputObject (Get-TkStabilityReport))
            (ConvertTo-TkBundleText -Title 'Update history'      -As Table -InputObject (Get-TkUpdateHistory))
            (ConvertTo-TkBundleText -Title 'Printing'            -As Table -InputObject (Get-TkPrintingReport))
            (ConvertTo-TkBundleText -Title 'Profiles and policy' -As Table -InputObject (Get-TkUserContextReport))
        ) -join ''
    } | Set-Content -LiteralPath (Join-Path $workFolder '30-diagnostics.txt') -Encoding UTF8

    # Hardening reads some values that need administrator rights; without them
    # it would report a misleading picture, so it is only included elevated.
    if ($elevated) {
        Get-TkBundleSection -Title 'Security posture' -Errors $errors -Collector {
            ConvertTo-TkBundleText -Title 'Hardening check' -As Table -InputObject (Invoke-TkHardeningCheck)
        } | Set-Content -LiteralPath (Join-Path $workFolder '40-security.txt') -Encoding UTF8
    }
    else {
        'The security posture check needs administrator rights and was skipped. Restart the toolkit elevated to include it.' |
            Set-Content -LiteralPath (Join-Path $workFolder '40-security-skipped.txt') -Encoding UTF8
    }

    if ($IncludeEventLog) {
        Get-TkBundleSection -Title 'Recent errors' -Errors $errors -Collector {
            ConvertTo-TkBundleText -Title 'System and Application errors, last 3 days' -As Table `
                -InputObject (Get-TkRecentErrorEvent -Days 3 -Maximum 200)
        } | Set-Content -LiteralPath (Join-Path $workFolder '50-event-errors.txt') -Encoding UTF8
    }

    # --- The toolkit log, copied in ---------------------------------------
    try {
        $todaysLog = Join-Path -Path $ctx.LogRoot -ChildPath ('toolkit-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))

        if (Test-Path -LiteralPath $todaysLog) {
            Copy-Item -LiteralPath $todaysLog -Destination (Join-Path $workFolder '60-toolkit-log.txt') -ErrorAction Stop
        }
    }
    catch {
        $errors.Add('Toolkit log: {0}' -f $_.Exception.Message)
    }

    # --- The summary, written last so it can report the errors ------------
    $summary = New-Object System.Text.StringBuilder

    [void] $summary.AppendLine('Toolkit support bundle')
    [void] $summary.AppendLine('======================')
    [void] $summary.AppendLine('')
    [void] $summary.AppendLine(('Machine    : {0}' -f $host_))
    [void] $summary.AppendLine(('User       : {0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
    [void] $summary.AppendLine(('Elevated   : {0}' -f $elevated))
    [void] $summary.AppendLine(('Created    : {0}' -f (Get-Date).ToString('u')))
    [void] $summary.AppendLine(('Toolkit    : {0} {1} ({2})' -f $ctx.AppName, $ctx.Version, $ctx.Commit))
    [void] $summary.AppendLine('')
    [void] $summary.AppendLine('Contents')
    [void] $summary.AppendLine('  10-system.txt        Machine identity, operating system, platform security')
    [void] $summary.AppendLine('  11-hardware.txt      Processor, memory, disks and volumes')
    [void] $summary.AppendLine('  20-network.txt       Adapters, routing table, listening ports')
    [void] $summary.AppendLine('  30-diagnostics.txt   Pending reboot, storage, stability, updates, printing, profiles')
    [void] $summary.AppendLine('  40-security.txt      Security posture (only when created elevated)')

    if ($IncludeEventLog) {
        [void] $summary.AppendLine('  50-event-errors.txt  System and Application errors of the last three days')
    }

    [void] $summary.AppendLine('  60-toolkit-log.txt   The toolkit log for today')
    [void] $summary.AppendLine('')
    [void] $summary.AppendLine('Before you send it')
    [void] $summary.AppendLine('  This bundle describes this machine: its name, the signed in user, the')
    [void] $summary.AppendLine('  network addresses and recent error events. That is what a support desk')
    [void] $summary.AppendLine('  needs, and it is normal to share. It contains no stored passwords or')
    [void] $summary.AppendLine('  API keys. Read it if you are unsure what you are sending.')
    [void] $summary.AppendLine('')

    if ($errors.Count -gt 0) {
        [void] $summary.AppendLine('Sections that could not be collected')

        foreach ($line in $errors) {
            [void] $summary.AppendLine('  - {0}' -f $line)
        }
    }
    else {
        [void] $summary.AppendLine('Every section was collected.')
    }

    $summary.ToString() | Set-Content -LiteralPath (Join-Path $workFolder '00-summary.txt') -Encoding UTF8

    # --- Zip it, and clear the work folder --------------------------------
    if (-not (Test-Path -LiteralPath $bundleRoot)) {
        New-Item -Path $bundleRoot -ItemType Directory -Force | Out-Null
    }

    $zipPath = Join-Path -Path $bundleRoot -ChildPath ('support-{0}-{1}.zip' -f $host_, $stamp)

    try {
        Compress-Archive -Path (Join-Path $workFolder '*') -DestinationPath $zipPath -Force -ErrorAction Stop
    }
    catch {
        Write-TkLog -Level Error -Category 'Bundle' -Message (
            'The support bundle could not be compressed: {0}' -f $_.Exception.Message
        )

        return $null
    }
    finally {
        Remove-Item -LiteralPath $workFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-TkLog -Level Information -Category 'Bundle' -Message (
        'Support bundle written to {0}{1}.' -f $zipPath,
        $(if ($errors.Count -gt 0) { ' with {0} section(s) missing' -f $errors.Count } else { '' })
    )

    return $zipPath
}

<#
.SYNOPSIS
    Returns the recent error and critical events, bounded.

.DESCRIPTION
    The System and Application logs, errors and worse, over a window and capped
    so a machine with a storm of them does not produce a gigabyte of text.
    Readable by a standard user for these two logs.

.PARAMETER Days
    How far back to look.

.PARAMETER Maximum
    The largest number of events to return.

.OUTPUTS
    An array of event objects.
#>
function Get-TkRecentErrorEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 30)]
        [int] $Days = 3,

        [Parameter()]
        [ValidateRange(10, 2000)]
        [int] $Maximum = 200
    )

    $events = @()
    $after  = (Get-Date).AddDays(-$Days)

    foreach ($logName in @('System', 'Application')) {

        try {
            # Level 1 is Critical, 2 is Error. Filtered at the source so the
            # log is not read into memory whole.
            $found = @(Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Level     = 1, 2
                StartTime = $after
            } -MaxEvents $Maximum -ErrorAction Stop)
        }
        catch {
            # No matching events raises a non terminating error on some builds;
            # treat it as an empty result rather than a failure.
            $found = @()
        }

        foreach ($entry in $found) {

            $events += [pscustomobject] @{
                Time     = $entry.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Log      = $logName
                Level    = if ($entry.Level -eq 1) { 'Critical' } else { 'Error' }
                Id       = $entry.Id
                Provider = $entry.ProviderName
                Message  = (Get-TkFirstLine -Text $entry.Message)
            }
        }
    }

    return , @($events | Sort-Object -Property Time -Descending | Select-Object -First $Maximum)
}
