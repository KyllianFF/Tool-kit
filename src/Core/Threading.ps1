<#
    Toolkit - Core / Threading

    Long operations (winget installs, port scans, VirusTotal lookups) must
    never run on the WPF dispatcher thread: a frozen window is the single
    most common defect in PowerShell GUI tools.

    The model used here is deliberately simple and safe:

      1. Work runs in a runspace from a shared pool.
      2. Work receives plain values only, never WPF objects or the context.
      3. Results come back to the UI thread through a DispatcherTimer, which
         is the only place UI controls are ever touched.

    That one way flow removes the need for locks in feature code.
#>

<#
.SYNOPSIS
    Creates the background runspace pool.

.DESCRIPTION
    The pool is seeded with every toolkit function currently defined, so a
    background job can call the same helpers as the UI thread. Size is capped
    to keep a technician laptop usable while a scan runs.

    Functions alone are not enough. A function carries its code but not the
    script scope it was defined in, so a helper that reads a module level
    variable finds $null in a child runspace. Write-TkLog indexes into
    $script:TkLogLevels, which meant every background task that logged
    anything died with "cannot index into a null array" and the page it was
    feeding stayed empty. The shared variables below are therefore declared
    in the session state as well.

.PARAMETER MaxRunspaces
    Upper bound on concurrent background jobs.
#>
function Initialize-TkRunspacePool {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $MaxRunspaces = 4
    )

    $ctx = Get-TkContext

    if ($null -ne $ctx.RunspacePool) {
        return
    }

    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

    # Re-declare the toolkit functions inside every child runspace. Passing
    # the definitions is what lets background code call Write-TkLog or
    # Invoke-TkProcess without importing a module from disk, which matters
    # because the toolkit often runs with no files on disk at all.
    #
    # Enumerated through Get-Command rather than the Function: drive: a drive
    # path that matches nothing is an error on PowerShell 7, and the pattern
    # for a prefix like Tk* legitimately matches nothing here.
    $functions = Get-Command -CommandType Function -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like '*-Tk*' -or $_.Name -eq 'Start-Toolkit' }

    foreach ($function in $functions) {

        $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry(
            $function.Name,
            $function.Definition
        )

        $sessionState.Commands.Add($entry)
    }

    # Shared state the functions above read. This is an explicit allow list,
    # not a sweep of every Tk variable: the application context holds WPF
    # objects that must not be touched off the dispatcher thread, and the
    # page level variables can hold a generated secret. Neither belongs in a
    # worker.
    $sharedVariables = @(
        'TkAppName', 'TkAppVersion', 'TkAppCommit', 'TkRepository',
        'TkLogLevels', 'TkMinimumLogLevel',
        'TkVirusTotalBaseUri',
        'TkEmbeddedCatalogs'
    )

    foreach ($name in $sharedVariables) {

        $variable = Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue

        if ($null -eq $variable) {
            continue
        }

        $entry = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry(
            $name,
            $variable.Value,
            ''
        )

        $sessionState.Variables.Add($entry)
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxRunspaces, $sessionState, $Host)
    $pool.ApartmentState = [System.Threading.ApartmentState]::MTA
    $pool.Open()

    $ctx.RunspacePool = $pool

    Write-TkLog -Level Debug -Category 'Threading' -Message (
        'Runspace pool opened with {0} slots.' -f $MaxRunspaces
    )
}

<#
.SYNOPSIS
    Queues a script block for background execution.

.DESCRIPTION
    Returns immediately. When the work finishes, OnComplete is invoked on the
    UI thread with the collected output, so the callback can update controls
    directly and safely.

.PARAMETER ScriptBlock
    Work to perform. Receives $ArgumentList through the params it declares.

.PARAMETER ArgumentList
    Positional values for the script block. Must be plain data: never pass
    WPF controls or the application context across the thread boundary.

    Only use it when every value is a scalar. A PowerShell array literal
    flattens nested arrays, so @($ids, $verb) becomes one argument per
    identifier followed by the verb, and the script block binds the wrong
    values. There is no way to fix that at the call site because the
    flattening happens before the call. Use ParameterList instead.

.PARAMETER ParameterList
    Named parameters for the script block, as a hashtable. Bound through
    AddParameters, which preserves an array value intact, so this is the
    correct way to pass a collection to background work.

.PARAMETER OnComplete
    Script block run on the UI thread once the work returns. Receives a
    result object with Output, HadErrors and Errors.

.PARAMETER Name
    Label used in the log entries.

.OUTPUTS
    System.Collections.Hashtable - the task handle.
#>
function Start-TkTask {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [Parameter()]
        [object[]] $ArgumentList = @(),

        [Parameter()]
        [hashtable] $ParameterList,

        [Parameter()]
        [scriptblock] $OnComplete,

        [Parameter()]
        [string] $Name = 'Background task'
    )

    $ctx = Get-TkContext

    if ($null -eq $ctx.RunspacePool) {
        Initialize-TkRunspacePool
    }

    $shell = [powershell]::Create()
    $shell.RunspacePool = $ctx.RunspacePool

    [void] $shell.AddScript($ScriptBlock)

    if ($ParameterList -and $ParameterList.Count -gt 0) {
        [void] $shell.AddParameters($ParameterList)
    }

    foreach ($argument in $ArgumentList) {
        [void] $shell.AddArgument($argument)
    }

    $task = @{
        Name       = $Name
        Shell      = $shell
        Handle     = $shell.BeginInvoke()
        OnComplete = $OnComplete
        Started    = Get-Date
    }

    [void] $ctx.Tasks.Add($task)

    Write-TkLog -Level Debug -Category 'Threading' -Message ('Queued: {0}' -f $Name)

    return $task
}

<#
.SYNOPSIS
    Starts the dispatcher timer that completes finished background tasks.

.DESCRIPTION
    Polling on the UI thread is intentional. Callbacks fired from a worker
    thread would have to marshal every control access themselves; here the
    callback already runs where WPF expects it.

.PARAMETER IntervalMilliseconds
    How often finished tasks are collected.
#>
function Start-TkTaskPump {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $IntervalMilliseconds = 200
    )

    $ctx = Get-TkContext

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds($IntervalMilliseconds)

    $timer.Add_Tick({

        $context = Get-TkContext
        $done    = @()

        foreach ($task in $context.Tasks) {

            if ($task.Handle.IsCompleted) {
                $done += $task
            }
        }

        foreach ($task in $done) {

            $context.Tasks.Remove($task)

            $output = $null
            $errors = @()
            $notes  = @()

            try {
                $output = $task.Shell.EndInvoke($task.Handle)
                $errors = @($task.Shell.Streams.Error)

                # Write-TkLog uses Write-Host, which lands in the information
                # stream. In a worker runspace it has no window to write to,
                # so those lines were written to the log file and never
                # appeared in the output panel. They are replayed here, on the
                # UI thread, where the panel exists.
                $notes += @($task.Shell.Streams.Information | ForEach-Object { [string] $_ })
                $notes += @($task.Shell.Streams.Warning     | ForEach-Object { [string] $_ })
            }
            catch {
                $errors = @($_)
            }
            finally {
                $task.Shell.Dispose()
            }

            foreach ($note in $notes) {

                if (-not [string]::IsNullOrWhiteSpace($note)) {
                    Write-TkUiConsole -Line $note
                }
            }

            foreach ($record in $errors) {
                Write-TkLog -Level Error -Category 'Threading' -Message (
                    '{0}: {1}' -f $task.Name, $record
                )
            }

            $result = [pscustomobject]@{
                Name      = $task.Name
                Output    = $output
                Errors    = $errors
                HadErrors = ($errors.Count -gt 0)
                Duration  = (Get-Date) - $task.Started
            }

            if ($task.OnComplete) {

                try {
                    & $task.OnComplete $result
                }
                catch {
                    Write-TkLog -Level Error -Category 'Threading' -Message (
                        'Completion handler for "{0}" failed: {1}' -f $task.Name, $_.Exception.Message
                    )
                }
            }
        }
    })

    $timer.Start()
    $ctx.Controls['TaskPump'] = $timer
}

<#
.SYNOPSIS
    Cancels outstanding work and closes the runspace pool.

.DESCRIPTION
    Called when the main window closes. Without this the host process stays
    alive holding open runspaces after the window is gone.
#>
function Stop-TkThreading {
    [CmdletBinding()]
    param()

    $ctx = Get-TkContext

    if ($ctx.Controls.ContainsKey('TaskPump') -and $ctx.Controls['TaskPump']) {
        $ctx.Controls['TaskPump'].Stop()
    }

    foreach ($task in @($ctx.Tasks)) {

        try {
            $task.Shell.Stop()
            $task.Shell.Dispose()
        }
        catch {
            # The task may already have completed between the two statements.
            $null = $_
        }
    }

    $ctx.Tasks.Clear()

    if ($ctx.RunspacePool) {

        try {
            $ctx.RunspacePool.Close()
            $ctx.RunspacePool.Dispose()
        }
        catch {
            # Nothing useful can be done while the process is shutting down.
            $null = $_
        }

        $ctx.RunspacePool = $null
    }

    Write-TkLog -Level Debug -Category 'Threading' -Message 'Runspace pool closed.'
}
