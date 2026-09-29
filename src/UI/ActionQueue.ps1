<#
    Toolkit - UI / Action queue

    Several actions run one after the other, each in a background task of its
    own, as Installed Apps first did for its updates and uninstalls: every
    step says whether it waits, runs, is done, failed or was not run; the run
    can be stopped between two steps; and a step marked critical that fails
    stops the rest, when the run asks for it.

    A queue is kept by name, and its completion handlers name it rather than
    close over it: a handler the task pump runs later cannot reach the scope
    of the function that started the work.
#>

$script:TkActionQueues = @{}

<#
.SYNOPSIS
    Creates a queue of steps, ready to start.

.PARAMETER Step
    Objects with Key, Label, Work (a script block run in the background),
    Parameters (a hashtable handed to it) and Critical.

.PARAMETER OnStep
    Runs on the UI thread when a step starts and when it ends, with the queue
    and the step.

.PARAMETER OnDone
    Runs on the UI thread once, when the queue has finished, with the queue.

.OUTPUTS
    PSCustomObject: the queue.
#>
function New-TkActionQueue {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9-]+$')] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Step,
        [Parameter()] [bool] $StopOnFailure = $true,
        [Parameter()] [AllowNull()] [scriptblock] $OnStep = $null,
        [Parameter()] [AllowNull()] [scriptblock] $OnDone = $null
    )

    $steps = foreach ($item in @($Step | Where-Object { $_ })) {
        [pscustomobject] @{
            Key        = [string] $item.Key
            Label      = [string] $item.Label
            Work       = $item.Work
            Parameters = $(if ($item.Parameters) { $item.Parameters } else { @{} })
            Critical   = [bool] $item.Critical
            State      = 'Waiting'
            Text       = ''
            Output     = $null
            Started    = $null
            Ended      = $null
        }
    }

    $queue = [pscustomobject] @{
        Name          = $Name
        Steps         = @($steps)
        Index         = 0
        Stop          = $false
        Finished      = $false
        StopOnFailure = $StopOnFailure
        OnStep        = $OnStep
        OnDone        = $OnDone
        Started       = Get-Date
    }

    if ($PSCmdlet.ShouldProcess($Name, 'Keep the queue')) {
        $script:TkActionQueues[$Name] = $queue
    }

    return $queue
}

<#
.SYNOPSIS
    Starts a queue created with New-TkActionQueue.
#>
function Start-TkActionQueue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    if ($PSCmdlet.ShouldProcess($Name, 'Start the queue')) {
        Step-TkActionQueue -Name $Name
    }
}

<#
.SYNOPSIS
    Runs the next step of a queue, or finishes it.
#>
function Step-TkActionQueue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    $queue = $script:TkActionQueues[$Name]

    if (-not $queue -or $queue.Finished) {
        return
    }

    if ($queue.Stop -or $queue.Index -ge $queue.Steps.Count) {
        Complete-TkActionQueue -Name $Name
        return
    }

    $step         = $queue.Steps[$queue.Index]
    $step.State   = 'Running'
    $step.Started = Get-Date

    if ($queue.OnStep) { & $queue.OnStep $queue $step }

    # The handler names the queue as a literal: it runs later, from the task pump.
    $complete = [scriptblock]::Create(('param($result) Complete-TkActionQueueStep -Name {0} -Result $result' -f (ConvertTo-TkPsLiteral -Value $Name)))

    Invoke-TkBackgroundAction -StatusText ('{0}...' -f $step.Label) -ScriptBlock $step.Work -ParameterList $step.Parameters -OnComplete $complete
}

<#
.SYNOPSIS
    Reads what a step's background task returned: done or failed, and why.

.DESCRIPTION
    Pure. The last object the work wrote decides: $true or $false, or an
    object with Ok (and Text). Anything else is done, unless the task
    recorded errors.

.OUTPUTS
    PSCustomObject with Ok, Text and Output.
#>
function Resolve-TkActionOutcome {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        $Result
    )

    $output = @(if ($Result) { @($Result.Output) | Where-Object { $null -ne $_ } })
    $last   = if ($output.Count -gt 0) { $output[-1] } else { $null }
    $errors = @(if ($Result -and $Result.PSObject.Properties['Errors']) { @($Result.Errors) | Where-Object { $_ } })

    if ($last -is [bool]) {
        return [pscustomobject] @{ Ok = $last; Text = $(if ($last) { '' } else { 'It did not complete; the log says why.' }); Output = $last }
    }

    if ($last -and $last.PSObject.Properties['Ok']) {
        return [pscustomobject] @{ Ok = [bool] $last.Ok; Text = $(if ($last.PSObject.Properties['Text']) { [string] $last.Text } else { '' }); Output = $last }
    }

    if ($errors.Count -gt 0) {
        return [pscustomobject] @{ Ok = $false; Text = [string] $errors[0]; Output = $last }
    }

    return [pscustomobject] @{ Ok = $true; Text = ''; Output = $last }
}

<#
.SYNOPSIS
    Records how a step ended, and moves the queue on.
#>
function Complete-TkActionQueueStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [AllowNull()] $Result
    )

    $queue = $script:TkActionQueues[$Name]

    if (-not $queue -or $queue.Finished -or $queue.Index -ge $queue.Steps.Count) {
        return
    }

    $step    = $queue.Steps[$queue.Index]
    $outcome = Resolve-TkActionOutcome -Result $Result

    $step.State  = if ($outcome.Ok) { 'Done' } else { 'Failed' }
    $step.Text   = $outcome.Text
    $step.Output = $outcome.Output
    $step.Ended  = Get-Date

    if ($queue.OnStep) { & $queue.OnStep $queue $step }

    $queue.Index++

    if (-not $outcome.Ok -and $step.Critical -and $queue.StopOnFailure) {
        $queue.Stop = $true
    }

    Step-TkActionQueue -Name $Name
}

<#
.SYNOPSIS
    Asks a queue to stop once the step running now has ended.
#>
function Stop-TkActionQueue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    $queue = $script:TkActionQueues[$Name]

    if ($queue -and -not $queue.Finished -and $PSCmdlet.ShouldProcess($Name, 'Stop after this step')) {
        $queue.Stop = $true
    }
}

<#
.SYNOPSIS
    Marks what was not run, and tells the caller the queue has finished.
#>
function Complete-TkActionQueue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    $queue = $script:TkActionQueues[$Name]

    if (-not $queue -or $queue.Finished) {
        return
    }

    $failed = @($queue.Steps | Where-Object { $_.State -eq 'Failed' -and $_.Critical }).Count -gt 0

    foreach ($step in @($queue.Steps | Where-Object { $_.State -eq 'Waiting' })) {
        $step.State = 'NotRun'
        $step.Text  = if ($failed -and $queue.StopOnFailure) { 'Not run: an earlier step failed.' } else { 'Not run: stopped.' }
    }

    $queue.Finished = $true

    if ($queue.OnDone) { & $queue.OnDone $queue }
}

<#
.SYNOPSIS
    Says where a queue stands, in one sentence.

.OUTPUTS
    System.String
#>
function Format-TkActionQueueProgress {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Queue
    )

    $count   = { param($state) @($Queue.Steps | Where-Object { $_.State -eq $state }).Count }
    $running = @($Queue.Steps | Where-Object { $_.State -eq 'Running' }) | Select-Object -First 1

    $text = if ($Queue.Finished) { 'Finished: {0} done, {1} failed, {2} not run.' -f (& $count 'Done'), (& $count 'Failed'), (& $count 'NotRun') }
            elseif ($running) { 'Step {0} of {1}: {2}. {3} done, {4} failed, {5} waiting.' -f ($Queue.Index + 1), $Queue.Steps.Count, $running.Label, (& $count 'Done'), (& $count 'Failed'), (& $count 'Waiting') }
            else { '{0} step(s) waiting.' -f (& $count 'Waiting') }

    if ($Queue.Stop -and -not $Queue.Finished) {
        $text += ' Stopping after this step.'
    }

    return $text
}
