<#
    Toolkit - Core / Logging

    Every privileged or state changing operation must leave a trace. Logs are
    written to the per-user data directory, never to the installation folder,
    and are also mirrored to the in-application console so the operator sees
    what the tool is doing while it does it.
#>

# Ordered severity levels. Used to filter what reaches the log file.
$script:TkLogLevels = @{
    Debug       = 0
    Information = 1
    Warning     = 2
    Error       = 3
}

# Anything below this level is discarded. Raised to Debug by -Verbose runs.
$script:TkMinimumLogLevel = 'Information'

<#
.SYNOPSIS
    Writes a structured entry to the toolkit log.

.DESCRIPTION
    Appends a timestamped line to the daily log file and forwards the message
    to the UI console when a window is open. File writes are best effort: a
    locked or unavailable log file must never break the calling operation.

.PARAMETER Message
    Text to record. Keep it factual and free of secrets.

.PARAMETER Level
    Severity of the entry. Defaults to Information.

.PARAMETER Category
    Optional subsystem name, for example 'Software' or 'Network'. Makes the
    log greppable once several modules write to it.

.EXAMPLE
    Write-TkLog -Level Warning -Category Software -Message 'winget not found'
#>
function Write-TkLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string] $Message,

        [Parameter()]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string] $Level = 'Information',

        [Parameter()]
        [string] $Category = 'General'
    )

    if ($script:TkLogLevels[$Level] -lt $script:TkLogLevels[$script:TkMinimumLogLevel]) {
        return
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line      = '{0} [{1,-11}] [{2}] {3}' -f $timestamp, $Level, $Category, $Message

    # --- File sink --------------------------------------------------------
    # Guarded: logging failures must stay silent rather than cascade.
    try {
        $ctx = Get-TkContext

        if ($ctx -and $ctx.LogFile) {
            Add-Content -LiteralPath $ctx.LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
    }
    catch {
        # Intentionally swallowed. See description above: a logging failure
        # must never break the operation that was being logged.
        $null = $_
    }

    # --- Console sink -----------------------------------------------------
    switch ($Level) {
        'Error'       { Write-Host $line -ForegroundColor Red    ; break }
        'Warning'     { Write-Host $line -ForegroundColor Yellow ; break }
        'Debug'       { Write-Verbose $line                      ; break }
        default       { Write-Host $line -ForegroundColor Gray   ; break }
    }

    # --- UI sink ----------------------------------------------------------
    Write-TkUiConsole -Line $line -Level $Level
}

<#
.SYNOPSIS
    Appends a line to the in-application output console.

.DESCRIPTION
    Marshals the write onto the WPF dispatcher thread so background tasks can
    log safely. Does nothing when the UI is not running, which keeps the same
    functions usable from a plain console session or from Pester.
#>
function Write-TkUiConsole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Line,

        [Parameter()]
        [string] $Level = 'Information'
    )

    # Debug entries stay in the file. Putting them in the window as well
    # would bury the two or three lines the operator actually needs to read.
    if ($Level -eq 'Debug') {
        return
    }

    $ctx = Get-TkContext

    if (-not $ctx.Controls -or -not $ctx.Controls.ContainsKey('OutputConsole')) {
        return
    }

    $console = $ctx.Controls['OutputConsole']

    if ($null -eq $console) {
        return
    }

    try {
        $console.Dispatcher.Invoke([action] {

            $console.AppendText($Line + [Environment]::NewLine)
            $console.ScrollToEnd()

            # Keep the buffer bounded: long install runs can emit thousands of
            # lines and an unbounded TextBox slowly starves the UI thread.
            if ($console.LineCount -gt 2000) {
                $console.Text = $console.Text.Substring($console.Text.Length - 60000)
            }
        })
    }
    catch {
        # The window may be closing while a background task still logs.
        $null = $_
    }
}

<#
.SYNOPSIS
    Records the start of an operation and returns a stopwatch for it.

.DESCRIPTION
    Pairs with Stop-TkOperation to produce consistent begin/end log entries
    including a duration, which is what makes slow operations findable later.

.OUTPUTS
    System.Diagnostics.Stopwatch
#>
function Start-TkOperation {
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Stopwatch])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [string] $Category = 'General'
    )

    Write-TkLog -Level Information -Category $Category -Message ('Start: {0}' -f $Name)
    return [System.Diagnostics.Stopwatch]::StartNew()
}

<#
.SYNOPSIS
    Closes an operation opened by Start-TkOperation.
#>
function Stop-TkOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [System.Diagnostics.Stopwatch] $Stopwatch,

        [Parameter()]
        [string] $Category = 'General',

        [Parameter()]
        [bool] $Success = $true
    )

    $Stopwatch.Stop()

    $level  = if ($Success) { 'Information' } else { 'Error' }
    $status = if ($Success) { 'Done' } else { 'Failed' }

    Write-TkLog -Level $level -Category $Category -Message (
        '{0}: {1} ({2} ms)' -f $status, $Name, $Stopwatch.ElapsedMilliseconds
    )
}
