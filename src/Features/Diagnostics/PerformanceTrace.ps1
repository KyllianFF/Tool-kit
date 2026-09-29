<#
    Toolkit - Features / Diagnostics: performance trace

    A report says what is slow; a trace shows why. Windows Performance
    Recorder, built into Windows 10 and 11, records what the processor, the
    disks, the files, the network or the power did into an ETL file, which
    Windows Performance Analyzer opens and a vendor's support asks for.

    Three rules shape this file. The profiles are a closed list: what reaches
    wpr.exe is a name from it, checked again in the elevated process. A trace
    is bounded: it starts and stops in one call that waits the time chosen,
    five minutes at most, and cancels the trace in its finally block whatever
    happened, so an error, or the window being closed while the elevated
    process waits, never leaves one recording. And it only reads: nothing
    changes on the machine but a file in the traces folder.
#>

<#
.SYNOPSIS
    The Windows Performance Recorder profiles a trace may use.

.OUTPUTS
    PSCustomObject[] with Name (as wpr.exe knows it), Label, Description and Default.
#>
function Get-TkTraceProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'GeneralProfile'; Label = 'General';   Default = $true;  Description = 'The first look: processor, disk, file, registry and memory activity together.' }
        [pscustomobject] @{ Name = 'CPU';            Label = 'Processor'; Default = $false; Description = 'Processor use with call stacks: which code keeps it busy, and what waits.' }
        [pscustomobject] @{ Name = 'DiskIO';         Label = 'Disk';      Default = $false; Description = 'Every disk read and write, with the process behind it and how long it took.' }
        [pscustomobject] @{ Name = 'FileIO';         Label = 'Files';     Default = $false; Description = 'File opens, reads and writes, and the processes behind them.' }
        [pscustomobject] @{ Name = 'Network';        Label = 'Network';   Default = $false; Description = 'Network input and output, by process.' }
        [pscustomobject] @{ Name = 'Power';          Label = 'Power';     Default = $false; Description = 'Processor power states, and what keeps the machine awake.' }
        [pscustomobject] @{ Name = 'GPU';            Label = 'Graphics';  Default = $false; Description = 'Graphics processor activity, for stutter and dropped frames.' }
    )
}

<#
.SYNOPSIS
    Checks what a trace is asked to record, and for how long.

.DESCRIPTION
    Pure. Each profile must be one of Get-TkTraceProfile, by name in any case,
    and the duration between 5 and 300 seconds. Profiles come back once each,
    as the list spells them.

.OUTPUTS
    PSCustomObject with Ok, Message and Profiles.
#>
function Test-TkTraceRequest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $TraceProfile = @(),
        [Parameter()] [int] $Seconds = 0
    )

    $known    = @(Get-TkTraceProfile)
    $selected = New-Object System.Collections.Generic.List[string]

    foreach ($name in @($TraceProfile | Where-Object { $_ })) {

        $match = $known | Where-Object { $_.Name -eq ([string] $name).Trim() } | Select-Object -First 1

        if (-not $match) {
            return [pscustomobject] @{ Ok = $false; Message = ('"{0}" is not a profile the toolkit records.' -f $name); Profiles = @() }
        }

        if (-not $selected.Contains($match.Name)) {
            $selected.Add($match.Name)
        }
    }

    if ($selected.Count -eq 0) {
        return [pscustomobject] @{ Ok = $false; Message = 'Choose at least one thing to record.'; Profiles = @() }
    }

    if ($Seconds -lt 5 -or $Seconds -gt 300) {
        return [pscustomobject] @{ Ok = $false; Message = 'A trace lasts between 5 seconds and 5 minutes.'; Profiles = @() }
    }

    return [pscustomobject] @{ Ok = $true; Message = ''; Profiles = @($selected.ToArray()) }
}

<#
.SYNOPSIS
    The path of wpr.exe, or empty where Windows does not ship it.

.OUTPUTS
    System.String
#>
function Get-TkWprPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $path = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'wpr.exe')

    if ([System.IO.File]::Exists($path)) {
        return $path
    }

    return ''
}

<#
.SYNOPSIS
    The folder the traces are written to, in the toolkit data folder.

.OUTPUTS
    System.String
#>
function Get-TkTraceFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return [System.IO.Path]::Combine((Get-TkContext).DataRoot, 'traces')
}

<#
.SYNOPSIS
    Asks Windows Performance Recorder whether a trace is recording.

.DESCRIPTION
    wpr -status needs no administrator rights. It answers in English on every
    build seen; any other answer is reported as unknown rather than guessed.

.OUTPUTS
    PSCustomObject with Available, Recording (true, false or null) and Text.
#>
function Get-TkTraceStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $wpr = Get-TkWprPath

    if (-not $wpr) {
        return [pscustomobject] @{ Available = $false; Recording = $null; Text = 'Windows Performance Recorder is not on this machine.' }
    }

    $run  = Invoke-TkProcess -FilePath $wpr -ArgumentList @('-status') -TimeoutSeconds 60
    $text = (([string] $run.StandardOutput) + [Environment]::NewLine + ([string] $run.StandardError)).Trim()

    $recording = if ($text -match 'WPR is not recording') { $false }
                 elseif ($text -match 'WPR is recording') { $true }
                 else { $null }

    return [pscustomobject] @{ Available = $true; Recording = $recording; Text = $text }
}

<#
.SYNOPSIS
    The traces already recorded, the newest first.

.OUTPUTS
    PSCustomObject[] with Name, Path, SizeBytes and Recorded.
#>
function Get-TkRecentTrace {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [string] $Folder = (Get-TkTraceFolder),
        [Parameter()] [int] $Maximum = 10
    )

    return @(Get-ChildItem -LiteralPath $Folder -Filter '*.etl' -File -ErrorAction SilentlyContinue |
             Sort-Object -Property LastWriteTime -Descending | Select-Object -First $Maximum | ForEach-Object {
                 [pscustomobject] @{ Name = $_.Name; Path = $_.FullName; SizeBytes = $_.Length; Recorded = $_.LastWriteTime }
             })
}

<#
.SYNOPSIS
    Records a bounded performance trace with Windows Performance Recorder.

.DESCRIPTION
    Needs administrator rights, as wpr.exe does: from the interface it runs
    in the per-action elevated process, which checks the request again. It
    refuses to start over a trace already recording, starts, waits the time
    asked, and stops into a file named for the moment. The finally block
    cancels the trace whenever it was started and not stopped.

.PARAMETER Folder
    Where the trace is written: a local folder named traces.

.OUTPUTS
    PSCustomObject with Ok, Message, Path, SizeBytes, Profiles and Seconds.
#>
function Invoke-TkPerformanceTrace {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $TraceProfile,
        [Parameter(Mandatory)] [int] $Seconds,
        [Parameter()] [string] $Folder = (Get-TkTraceFolder)
    )

    $fail = { param($message) [pscustomobject] @{ Ok = $false; Message = $message; Path = ''; SizeBytes = 0; Profiles = @($TraceProfile); Seconds = $Seconds } }

    $request = Test-TkTraceRequest -TraceProfile $TraceProfile -Seconds $Seconds

    if (-not $request.Ok) {
        return (& $fail $request.Message)
    }

    # Written only to a local traces folder: never a share, a device path or
    # a folder climbed out of.
    if ($Folder -notmatch '^[A-Za-z]:\\' -or $Folder -match '\.\.' -or [System.IO.Path]::GetFileName($Folder.TrimEnd('\')) -ne 'traces') {
        return (& $fail 'The traces folder must be a local folder named traces.')
    }

    if (-not (Assert-TkElevated -Operation 'Record a performance trace')) {
        return (& $fail 'Recording a trace needs administrator rights.')
    }

    $wpr = Get-TkWprPath

    if (-not $wpr) {
        return (& $fail 'Windows Performance Recorder is not on this machine.')
    }

    if ((Get-TkTraceStatus).Recording -eq $true) {
        return (& $fail 'A trace is already recording, started by another tool or left by an interruption. Cancel it first.')
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, ('Record {0} for {1} seconds' -f ($request.Profiles -join ', '), $Seconds))) {
        return (& $fail 'Cancelled.')
    }

    New-Item -ItemType Directory -Path $Folder -Force | Out-Null

    $path      = [System.IO.Path]::Combine($Folder, ('trace-{0}.etl' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
    $operation = 'Performance trace: {0}, {1} s' -f ($request.Profiles -join ', '), $Seconds
    $stopwatch = Start-TkOperation -Name $operation -Category 'Diagnostics'
    $started   = $false
    $stopped   = $false
    $message   = ''

    try {
        $arguments = @(foreach ($name in $request.Profiles) { '-start'; $name }) + @('-filemode')
        $start     = Invoke-TkProcess -FilePath $wpr -ArgumentList $arguments -TimeoutSeconds 120

        if ($start.ExitCode -ne 0) {
            $message = 'Windows Performance Recorder did not start the trace (exit code {0}): {1}' -f $start.ExitCode, ([string] $start.StandardOutput).Trim()
        }
        else {
            $started = $true

            Start-Sleep -Seconds $Seconds

            $stop = Invoke-TkProcess -FilePath $wpr -ArgumentList @('-stop', $path, 'Toolkit performance trace') -TimeoutSeconds 900

            if ($stop.ExitCode -eq 0 -and [System.IO.File]::Exists($path)) {
                $stopped = $true
            }
            else {
                $message = 'Windows Performance Recorder did not write the trace (exit code {0}): {1}' -f $stop.ExitCode, ([string] $stop.StandardOutput).Trim()
            }
        }
    }
    catch {
        $message = 'The trace failed: {0}' -f $_.Exception.Message
    }
    finally {
        # Whatever happened above, no trace is left recording.
        if ($started -and -not $stopped) {
            [void] (Invoke-TkProcess -FilePath $wpr -ArgumentList @('-cancel') -TimeoutSeconds 120)
        }

        Stop-TkOperation -Name $operation -Stopwatch $stopwatch -Category 'Diagnostics' -Success $stopped
    }

    if (-not $stopped) {
        return (& $fail $message)
    }

    return [pscustomobject] @{
        Ok        = $true
        Message   = ('Trace of {0} s written to {1}.' -f $Seconds, $path)
        Path      = $path
        SizeBytes = ([System.IO.FileInfo] $path).Length
        Profiles  = @($request.Profiles)
        Seconds   = $Seconds
    }
}

<#
.SYNOPSIS
    Cancels a trace left recording, without saving it.

.OUTPUTS
    PSCustomObject with Ok and Message.
#>
function Stop-TkPerformanceTrace {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param()

    if (-not (Assert-TkElevated -Operation 'Cancel a performance trace')) {
        return [pscustomobject] @{ Ok = $false; Message = 'Cancelling a trace needs administrator rights.' }
    }

    $wpr = Get-TkWprPath

    if (-not $wpr) {
        return [pscustomobject] @{ Ok = $false; Message = 'Windows Performance Recorder is not on this machine.' }
    }

    if ((Get-TkTraceStatus).Recording -eq $false) {
        return [pscustomobject] @{ Ok = $true; Message = 'No trace was recording.' }
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Cancel the trace recording')) {
        return [pscustomobject] @{ Ok = $false; Message = 'Cancelled.' }
    }

    $run = Invoke-TkProcess -FilePath $wpr -ArgumentList @('-cancel') -TimeoutSeconds 120

    if ($run.ExitCode -eq 0) {
        return [pscustomobject] @{ Ok = $true; Message = 'The trace that was recording is cancelled.' }
    }

    return [pscustomobject] @{ Ok = $false; Message = ('Windows Performance Recorder did not cancel the trace (exit code {0}).' -f $run.ExitCode) }
}
