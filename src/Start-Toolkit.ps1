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

.PARAMETER ExpectedSha256
    The SHA-256 the verified launch command checked before running this
    instance. Kept with SourceUri, so an elevation restart downloads the same
    address again and runs it only if the hash still matches.

.PARAMETER NoGui
    Loads everything and returns without showing a window. Used by the tests
    and by anyone wanting the functions in a plain console session.

.PARAMETER Report
    Collects these reports without a window and returns them as JSON: report
    names, All, or List for the available ones.

.PARAMETER CompareWith
    Collects again the reports of this earlier document, without a window,
    and adds what changed since.

.PARAMETER OutFile
    With Report or CompareWith, writes the JSON to this file and returns its
    path.

.PARAMETER AuditLevel
    With Report, the depth of the Audit report: Essential or Full.

.PARAMETER Policy
    With Report, the organisation policy the Audit report is judged against:
    a .psd1 file, a share or an https:// address. Without it, the one set in
    Settings for this account.

.PARAMETER PolicyTrust
    With Policy, the certificate thumbprints or SHA-256 hashes that make it
    trusted. An untrusted policy is not applied: the audit stays generic.

.PARAMETER Redact
    With Report or CompareWith, pseudonymises the document: None, Personal
    (names, accounts, e-mails, serial numbers) or Strict (also addresses,
    Wi-Fi networks and domains). The table back to the real values stays on
    this PC, encrypted for this Windows account.

.PARAMETER Fix
    Fix ids to take without a window, or List. A plan unless Execute is given.

.PARAMETER Tweak
    Tweak ids to apply without a window (or revert, with Revert), or List.

.PARAMETER Remediate
    Audit correction ids to take without a window, or List.

.PARAMETER Revert
    With Tweak, reverts the tweaks instead of applying them.

.PARAMETER Execute
    With Fix, Tweak or Remediate, takes the actions. Without it nothing
    changes: the run says what would be taken and what would be refused.

.EXAMPLE
    Start-Toolkit

.EXAMPLE
    Start-Toolkit -NoGui

.EXAMPLE
    Start-Toolkit -Report Storage, Reboot -OutFile .\report.json

.EXAMPLE
    Start-Toolkit -CompareWith .\before.json -OutFile .\after.json

.EXAMPLE
    Start-Toolkit -Fix flush-dns, reset-print-spooler -Execute -OutFile .\fix.json
#>
function Start-Toolkit {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $SourceUri,

        [Parameter()]
        [string] $ExpectedSha256,

        [Parameter()]
        [switch] $NoGui,

        [Parameter()]
        [string[]] $Report,

        [Parameter()]
        [string] $CompareWith,

        [Parameter()]
        [string] $OutFile,

        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $AuditLevel = 'Essential',

        [Parameter()]
        [string] $Policy,

        [Parameter()]
        [string[]] $PolicyTrust,

        [Parameter()]
        [ValidateSet('None', 'Personal', 'Strict')]
        [string] $Redact = 'None',

        [Parameter()]
        [string[]] $Fix,

        [Parameter()]
        [string[]] $Tweak,

        [Parameter()]
        [string[]] $Remediate,

        [Parameter()]
        [switch] $Revert,

        [Parameter()]
        [switch] $Execute,

        [Parameter()]
        [string] $RunAction,

        [Parameter()]
        [string] $ActionData,

        [Parameter()]
        [string] $ResultFile
    )

    # Set on every start, so a headless run does not leave a later start
    # without its progress lines.
    $script:TkQuietConsole = [bool] ($Report -or $CompareWith -or $RunAction -or $Fix -or $Tweak -or $Remediate)

    # Said before anything is loaded: alone, these would open the window.
    if (($Execute -or $Revert) -and -not ($Fix -or $Tweak -or $Remediate)) {
        throw '-Execute and -Revert go with -Fix, -Tweak or -Remediate.'
    }

    if (($Fix -or $Tweak -or $Remediate) -and ($Report -or $CompareWith)) {
        throw 'Collect reports and take actions in two runs: -Report and -CompareWith do not mix with -Fix, -Tweak or -Remediate.'
    }

    # --- 1. Context and logging ------------------------------------------
    $ctx = Initialize-TkContext
    Import-TkSettings | Out-Null

    # Recorded so the elevation restart can replay the same source when the
    # toolkit was piped in and there is no script file on disk to re-run.
    #
    # irm | iex passes no argument at all, so a launch with neither a source
    # nor a script file falls back to the published build. Without it that
    # launch, the usual one, could never restart elevated.
    if ($SourceUri) {
        $ctx.SourceUri = $SourceUri
    }
    elseif (-not $ctx.EntryScript) {
        $ctx.SourceUri = $script:TkDefaultSourceUri
    }

    # Only with the address it belongs to, and only in its strict form: it is
    # written into the command an elevated process runs.
    if ($ExpectedSha256) {
        if ($SourceUri -and (Test-TkSha256Text -Value $ExpectedSha256)) {
            $ctx.SourceSha256 = $ExpectedSha256.ToUpperInvariant()
        }
        else {
            Write-TkLog -Level Warning -Category 'Startup' -Message 'The expected SHA-256 was ignored: it needs -SourceUri and 64 hexadecimal characters.'
        }
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

    # Fixes, tweaks and corrections without a window: a plan, unless -Execute.
    if ($Fix -or $Tweak -or $Remediate) {
        return Invoke-TkHeadlessAction -Fix @($Fix | Where-Object { $_ }) -Tweak @($Tweak | Where-Object { $_ }) -Remediate @($Remediate | Where-Object { $_ }) `
                                       -Revert:$Revert -Execute:$Execute -OutFile ([string] $OutFile) -Redact $Redact
    }

    # A headless run needs no window, no single threaded apartment and no WPF.
    if ($Report -or $CompareWith) {
        return Invoke-TkHeadlessReport -Report @($Report | Where-Object { $_ }) -CompareWith ([string] $CompareWith) `
                                       -OutFile ([string] $OutFile) -AuditLevel $AuditLevel -Redact $Redact `
                                       -Policy ([string] $Policy) -PolicyTrust @($PolicyTrust | Where-Object { $_ })
    }

    # The elevated worker: this process was started (as administrator) to run
    # one registered action and report its result. No window either.
    if ($RunAction) {
        return Complete-TkElevatedAction -Name $RunAction -ActionDataPath ([string] $ActionData) -ResultFile ([string] $ResultFile)
    }

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
            'This session is multi threaded (MTA) and WPF needs a single threaded one. Open a new PowerShell window, which is single threaded by default, and run the toolkit again; a console started with -MTA cannot show it.'
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

        Initialize-TkDashboardPage
        Initialize-TkSystemPage
        Initialize-TkSoftwarePage
        Initialize-TkTweaksPage
        Initialize-TkFixesPage
        Initialize-TkNetworkPage
        Initialize-TkNetworkAdminPage
        Initialize-TkMicrosoft365Page
        Initialize-TkMigrationPage
        Initialize-TkSecurityPage
        Initialize-TkThreatHuntingPage
        Initialize-TkDiagnosticsPage
        Initialize-TkHardwarePage
        Initialize-TkPlaybooksPage
        Initialize-TkInterventionPage
        Initialize-TkFleetPage

        # After every page is wired, so each control exists to be disabled.
        Update-TkPrivilegedControls

        # The Dashboard first: it answers the questions a support call starts
        # with. The System inventory loads when its own page is first opened.
        Show-TkPage -Name 'Dashboard'
        Update-TkDashboard

        # Only when the user turned it on in Settings: it is a network request.
        if ($ctx.Settings['CheckForUpdates'] -eq $true) {
            Invoke-TkUpdateCheckFromUi -Automatic
        }

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
