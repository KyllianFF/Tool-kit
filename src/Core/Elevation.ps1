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
