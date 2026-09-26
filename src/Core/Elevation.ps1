<#
    Toolkit - Core / Elevation

    Privilege policy.

    The toolkit deliberately starts with the rights it was given instead of
    elevating on sight. Read only features (inventory, subnet maths, hashing,
    knowledge base) work as a standard user; anything that writes to HKLM,
    installs software or changes services is gated behind an explicit,
    operator driven elevation. This is least privilege applied to a tool that
    a technician runs on machines that are not their own.
#>

<#
.SYNOPSIS
    Tells whether the current process holds the local Administrators role.

.OUTPUTS
    System.Boolean
#>
function Test-TkIsElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)

        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Restarts the toolkit in an elevated process.

.DESCRIPTION
    Re-launches the current script through Start-Process -Verb RunAs, which
    raises the standard Windows consent prompt. The original, unelevated
    process is left to the caller to close.

    When the toolkit was started from a remote one liner there is no script
    file to re-run, so the source URL recorded at bootstrap time is replayed
    instead. That URL always comes from what the operator typed: it is never
    taken from downloaded content.

.PARAMETER SourceUri
    HTTPS location of the bootstrap script, used when no local file exists.

.OUTPUTS
    System.Boolean - $true when a new process was started.
#>
function Invoke-TkElevation {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string] $SourceUri
    )

    if (Test-TkIsElevated) {
        Write-TkLog -Level Information -Category 'Elevation' -Message 'Already elevated.'
        return $false
    }

    # Prefer the real binary of the running host so the elevated instance
    # behaves exactly like the current one.
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $shell = (Get-Process -Id $PID).Path
    }
    else {
        $shell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA')

    # The entry script, never $PSCommandPath. Inside this function the latter
    # points at src/Core/Elevation.ps1, which only declares functions, so the
    # elevated process would start, define them, and exit without a window.
    $entryScript = (Get-TkContext).EntryScript

    if ($entryScript -and (Test-Path -LiteralPath $entryScript)) {

        $arguments += @('-File', ('"{0}"' -f $entryScript))
    }
    elseif ($SourceUri) {

        # Only https is ever replayed. A plain http source would let an
        # on-path attacker choose the code that then runs as Administrator.
        if ($SourceUri -notmatch '^https://') {
            Write-TkLog -Level Error -Category 'Elevation' -Message 'Refusing to elevate a non-HTTPS source.'
            return $false
        }

        $command    = 'irm ''{0}'' | iex' -f $SourceUri
        $arguments += @('-Command', ('"{0}"' -f $command))
    }
    else {
        Write-TkLog -Level Error -Category 'Elevation' -Message (
            'No entry script and no source URI: cannot restart elevated. Start the toolkit again from an elevated console.'
        )

        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($shell, 'Restart elevated')) {
        return $false
    }

    try {
        Start-Process -FilePath $shell -ArgumentList $arguments -Verb RunAs -ErrorAction Stop
        Write-TkLog -Level Information -Category 'Elevation' -Message 'Elevated instance started.'

        return $true
    }
    catch {
        # A cancelled UAC prompt lands here. That is a normal outcome.
        Write-TkLog -Level Warning -Category 'Elevation' -Message (
            'Elevation was refused or failed: {0}' -f $_.Exception.Message
        )
        return $false
    }
}

<#
.SYNOPSIS
    Guards a privileged operation.

.DESCRIPTION
    Call at the top of any function that writes to HKLM, changes services,
    installs software or edits system policy. Emits a clear log entry and
    returns $false when the process lacks the rights, letting the caller fail
    gracefully instead of throwing an access denied deep inside the work.

.PARAMETER Operation
    Human readable name of the operation, used in the log entry.

.OUTPUTS
    System.Boolean
#>
function Assert-TkElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Operation
    )

    if (Test-TkIsElevated) {
        return $true
    }

    Write-TkLog -Level Warning -Category 'Elevation' -Message (
        'Blocked: "{0}" requires administrator rights. Restart the toolkit elevated.' -f $Operation
    )

    return $false
}

<#
.SYNOPSIS
    The privileged actions a standard user can run through a single UAC prompt.

.DESCRIPTION
    Rather than restart the whole toolkit elevated, a standard user can run one
    action elevated: clicking it raises the Windows consent prompt, the action
    runs in a short-lived elevated process, and the result comes back to the
    window. This is the fixed registry of what may be run that way.

    An entry is a name and a Worker script block. The worker receives one
    argument, the parameters (a hashtable in-process, the same shape decoded
    from JSON in the elevated child), and returns a result object with Ok and
    Message. Only a name from this list is ever run elevated; no code and no
    arbitrary command crosses the boundary, so a tampered parameter file can
    only feed data to a worker that validates it, never choose what runs.

.OUTPUTS
    PSCustomObject[] with Name and Worker.
#>
function Get-TkElevatedAction {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{
            Name   = 'RestorePoint'
            Worker = {
                param($Parameters)

                if (@(New-TkRestorePoint -Description 'Toolkit - manual checkpoint' -Confirm:$false) -contains $true) {
                    [pscustomobject] @{ Ok = $true;  Message = 'Restore point created.' }
                }
                else {
                    [pscustomobject] @{ Ok = $false; Message = 'No restore point was created. Windows allows one per 24 hours.' }
                }
            }
        }
        [pscustomobject] @{
            Name   = 'AddRoute'
            Worker = {
                param($Parameters)

                $ok = Add-TkPersistentRoute -DestinationPrefix ([string] $Parameters.DestinationPrefix) `
                                            -NextHop ([string] $Parameters.NextHop) `
                                            -InterfaceAlias ([string] $Parameters.InterfaceAlias) -Confirm:$false

                if ($ok) {
                    [pscustomobject] @{ Ok = $true;  Message = ('Route added: {0} via {1}' -f $Parameters.DestinationPrefix, $Parameters.NextHop) }
                }
                else {
                    [pscustomobject] @{ Ok = $false; Message = ('The route to {0} could not be added.' -f $Parameters.DestinationPrefix) }
                }
            }
        }
        [pscustomobject] @{
            Name   = 'RemoveRoute'
            Worker = {
                param($Parameters)

                if (Remove-TkRoute -DestinationPrefix ([string] $Parameters.DestinationPrefix) -Confirm:$false) {
                    [pscustomobject] @{ Ok = $true;  Message = ('Route removed: {0}' -f $Parameters.DestinationPrefix) }
                }
                else {
                    [pscustomobject] @{ Ok = $false; Message = ('The route to {0} could not be removed.' -f $Parameters.DestinationPrefix) }
                }
            }
        }
    )
}

<#
.SYNOPSIS
    Runs one registered action in the elevated child and writes its result.

.DESCRIPTION
    The entry point calls this when it was started with -RunAction: it decodes
    the parameters, looks the action up in Get-TkElevatedAction, runs its
    worker, and writes the result object as JSON to the result file the caller
    reads. It always writes a result, so the non-elevated parent never waits on
    a file that never appears.

.OUTPUTS
    PSCustomObject with Ok and Message.
#>
function Complete-TkElevatedAction {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [string] $ActionDataPath,

        [Parameter()]
        [string] $ResultFile
    )

    $result = [pscustomobject] @{ Ok = $false; Message = 'The elevated action did not run.' }

    try {
        $parameters = if ($ActionDataPath -and (Test-Path -LiteralPath $ActionDataPath)) {
            Get-Content -LiteralPath $ActionDataPath -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        else {
            [pscustomobject] @{}
        }

        $action = @(Get-TkElevatedAction) | Where-Object { $_.Name -eq $Name } | Select-Object -First 1

        if (-not $action) {
            $result = [pscustomobject] @{ Ok = $false; Message = ('Unknown elevated action: {0}' -f $Name) }
        }
        else {
            Write-TkLog -Level Information -Category 'Elevation' -Message ('Running elevated action: {0}' -f $Name)
            $result = & $action.Worker $parameters
        }
    }
    catch {
        $result = [pscustomobject] @{ Ok = $false; Message = ('The elevated action failed: {0}' -f $_.Exception.Message) }
    }
    finally {
        if ($ResultFile) {
            try {
                ($result | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $ResultFile -Encoding UTF8
            }
            catch {
                $null = $_
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Starts the elevated worker process and waits for it.

.DESCRIPTION
    Launches the host through Start-Process -Verb RunAs, which raises the UAC
    prompt, passing -RunAction so the child runs one action headless. It waits
    for the child to exit. The launch mirrors the elevation restart: the entry
    script when there is one, otherwise the HTTPS source replayed, and never a
    plain http source.

.OUTPUTS
    System.String: Ran, Cancelled, Refused, NoTarget or Failed.
#>
function Start-TkElevatedWorker {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $ActionDataPath,

        [Parameter(Mandatory)]
        [string] $ResultFile,

        [Parameter()]
        [string] $EntryScript,

        [Parameter()]
        [string] $SourceUri
    )

    if ($PSVersionTable.PSEdition -eq 'Core') {
        $shell = (Get-Process -Id $PID).Path
    }
    else {
        $shell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass')

    if ($EntryScript -and (Test-Path -LiteralPath $EntryScript)) {

        $arguments += @(
            '-File', ('"{0}"' -f $EntryScript),
            '-RunAction', $Name,
            '-ActionData', ('"{0}"' -f $ActionDataPath),
            '-ResultFile', ('"{0}"' -f $ResultFile)
        )
    }
    elseif ($SourceUri) {

        # Only https is ever replayed, exactly as the elevation restart does.
        if ($SourceUri -notmatch '^https://') {
            Write-TkLog -Level Error -Category 'Elevation' -Message 'Refusing to elevate a non-HTTPS source.'
            return 'Refused'
        }

        $command = "& ([scriptblock]::Create((irm '$SourceUri'))) -RunAction '$Name' -ActionData '$ActionDataPath' -ResultFile '$ResultFile'"
        $arguments += @('-Command', ('"{0}"' -f $command))
    }
    else {
        return 'NoTarget'
    }

    try {
        Start-Process -FilePath $shell -ArgumentList $arguments -Verb RunAs -Wait -ErrorAction Stop
        return 'Ran'
    }
    catch [System.ComponentModel.Win32Exception] {

        # 1223 is ERROR_CANCELLED: the operator dismissed the UAC prompt.
        if ($_.Exception.NativeErrorCode -eq 1223) {
            Write-TkLog -Level Information -Category 'Elevation' -Message ('Elevation cancelled for action: {0}' -f $Name)
            return 'Cancelled'
        }

        Write-TkLog -Level Warning -Category 'Elevation' -Message ('Elevated worker failed to start: {0}' -f $_.Exception.Message)
        return 'Failed'
    }
    catch {
        Write-TkLog -Level Warning -Category 'Elevation' -Message ('Elevated worker failed to start: {0}' -f $_.Exception.Message)
        return 'Failed'
    }
}

<#
.SYNOPSIS
    Runs a registered privileged action, elevating it alone when needed.

.DESCRIPTION
    When the process is already elevated the worker runs in place. Otherwise the
    parameters are written to a temporary file, the elevated worker is started
    (raising the UAC prompt) and waited for, and its result is read back. The
    temporary files are removed either way.

    Meant to run off the UI thread: Start-Process -Wait blocks until the child
    exits, and the UAC prompt is up for as long as the operator takes.

.OUTPUTS
    PSCustomObject with Ok and Message (and Cancelled when the prompt was
    dismissed).
#>
function Invoke-TkElevatedActionCore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [hashtable] $Parameters = @{},

        [Parameter()]
        [string] $EntryScript,

        [Parameter()]
        [string] $SourceUri
    )

    $action = @(Get-TkElevatedAction) | Where-Object { $_.Name -eq $Name } | Select-Object -First 1

    if (-not $action) {
        return [pscustomobject] @{ Ok = $false; Message = ('Unknown elevated action: {0}' -f $Name) }
    }

    if (Test-TkIsElevated) {

        try {
            return & $action.Worker $Parameters
        }
        catch {
            return [pscustomobject] @{ Ok = $false; Message = ('The action failed: {0}' -f $_.Exception.Message) }
        }
    }

    $dataFile   = Join-Path -Path $env:TEMP -ChildPath ('tk-action-{0}.json' -f [guid]::NewGuid())
    $resultFile = Join-Path -Path $env:TEMP -ChildPath ('tk-result-{0}.json' -f [guid]::NewGuid())

    try {
        ($Parameters | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $dataFile -Encoding UTF8

        $status = Start-TkElevatedWorker -Name $Name -ActionDataPath $dataFile -ResultFile $resultFile `
                                         -EntryScript $EntryScript -SourceUri $SourceUri

        switch ($status) {

            'Cancelled' { return [pscustomobject] @{ Ok = $false; Message = 'Elevation was cancelled. Nothing was changed.'; Cancelled = $true } }
            'Refused'   { return [pscustomobject] @{ Ok = $false; Message = 'Refusing to elevate a non-HTTPS source.' } }
            'NoTarget'  { return [pscustomobject] @{ Ok = $false; Message = 'Cannot elevate: no script file and no source to replay.' } }
            'Failed'    { return [pscustomobject] @{ Ok = $false; Message = 'The elevated process could not be started.' } }

            default {

                if (Test-Path -LiteralPath $resultFile) {
                    return (Get-Content -LiteralPath $resultFile -Raw -Encoding UTF8 | ConvertFrom-Json)
                }

                return [pscustomobject] @{ Ok = $false; Message = 'The elevated action did not report a result.' }
            }
        }
    }
    finally {
        foreach ($file in @($dataFile, $resultFile)) {
            if (Test-Path -LiteralPath $file) {
                Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
