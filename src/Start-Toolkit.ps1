<#
    Toolkit - Entry point

    Start-up sequence:

      1. Build the shared context and start logging.
      2. Validate the host.
      3. Check the thread apartment, because WPF needs STA.
      4. Load the data catalogs.
      5. Build the window, wire the pages and run the message loop.

    Nothing here touches the system. The toolkit is safe to start on any
    machine; only an explicit click changes anything.
#>

<#
.SYNOPSIS
    Starts the toolkit.

.DESCRIPTION
    The single public entry point. Called by the development launcher, by the
    compiled single file build, and by the tests.

.PARAMETER SourceUri
    HTTPS location this instance was launched from. Recorded so an elevation
    restart can replay the same source when there is no script file on disk.

.PARAMETER NoGui
    Loads everything and returns without showing a window. Used by the tests
    and by anyone wanting the functions in a plain console session.

.EXAMPLE
    Start-Toolkit

.EXAMPLE
    Start-Toolkit -NoGui
#>
function Start-Toolkit {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $SourceUri,

        [Parameter()]
        [switch] $NoGui
    )

    # --- 1. Context and logging ------------------------------------------
    $ctx = Initialize-TkContext
    Import-TkSettings | Out-Null

    # Recorded so the elevation restart can replay the same source when the
    # toolkit was piped in and there is no script file on disk to re-run.
    if ($SourceUri) {
        $ctx.SourceUri = $SourceUri
    }

    Write-TkLog -Level Information -Category 'Startup' -Message (
        '{0} {1} ({2}) starting.' -f $ctx.AppName, $ctx.Version, $ctx.Commit
    )

    # --- 2. Host validation ----------------------------------------------
    if (-not (Initialize-TkEnvironment)) {

        Write-TkLog -Level Error -Category 'Startup' -Message 'The host does not meet the requirements. Stopping.'
        return
    }

    # --- 3. Data ----------------------------------------------------------
    Import-TkAllCatalogs

    if ($NoGui) {

        Write-TkLog -Level Information -Category 'Startup' -Message (
            'Loaded without a window. Every Tk function is available in this session.'
        )

        return $ctx
    }

    # --- 4. Apartment state ----------------------------------------------
    # WPF requires STA. A console started with -MTA can load the assemblies
    # but faults when the window is shown, so this is caught here with an
    # actionable message rather than as a crash later.
    if (-not (Test-TkIsStaThread)) {

        Write-TkLog -Level Error -Category 'Startup' -Message (
            'This session is not single threaded (MTA). Restart with: powershell -STA -File <script>'
        )

        return
    }

    if (-not (Import-TkUiAssembly)) {
        return
    }

    # --- 5. Interface -----------------------------------------------------
    try {
        $window = New-TkMainWindow

        Initialize-TkShell
        Initialize-TkRunspacePool
        Start-TkTaskPump

        Initialize-TkSystemPage
        Initialize-TkSoftwarePage
        Initialize-TkTweaksPage
        Initialize-TkFixesPage
        Initialize-TkNetworkPage
        Initialize-TkNetworkAdminPage
        Initialize-TkSecurityPage
        Initialize-TkThreatHuntingPage
        Initialize-TkDiagnosticsPage
        Initialize-TkHardwarePage

        # After every page is wired, so each control exists to be disabled.
        Update-TkPrivilegedControls

        Show-TkPage -Name 'System'
        Update-TkSystemPage

        if (-not $ctx.IsElevated) {

            Write-TkLog -Level Warning -Category 'Startup' -Message (
                'Running as a standard user. Inventory, network and security tools work; anything that changes the system is disabled until you restart elevated.'
            )
        }

        Set-TkStatus -Text 'Ready.'

        Write-TkLog -Level Information -Category 'Startup' -Message 'Interface ready.'

        # Blocks until the window closes.
        $window.ShowDialog() | Out-Null
    }
    catch {
        Write-TkLog -Level Error -Category 'Startup' -Message (
            'The interface failed to start: {0}' -f $_.Exception.Message
        )

        Write-TkLog -Level Debug -Category 'Startup' -Message $_.ScriptStackTrace

        throw
    }
    finally {
        Stop-TkThreading
    }
}
