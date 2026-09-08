<#
    Toolkit - Core / Configuration

    Holds the single mutable context object shared by every module and every
    UI page. Nothing else in the code base is allowed to create global state:
    if a value must survive a function call, it belongs in $script:TkContext.

    Design note: a single context makes the compiled single-file build and the
    modular development build behave identically, and it keeps unit tests able
    to reset the whole application state in one assignment.
#>

# Application identity. The build script rewrites Version and Commit at
# compile time so a running instance can always report what it was built from.
$script:TkAppName    = 'Toolkit'
$script:TkAppVersion = '1.0.0'
$script:TkAppCommit  = 'dev'
$script:TkRepository = 'https://github.com/KyllianFF/Tool-kit'

<#
.SYNOPSIS
    Creates the shared application context.

.DESCRIPTION
    Initializes $script:TkContext with paths, runtime facts and empty data
    stores. Safe to call more than once: the context is rebuilt from scratch,
    which is what tests rely on.

.OUTPUTS
    System.Collections.Hashtable
#>
function Initialize-TkContext {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # Per-user data directory. Never write to the installation folder: the
    # toolkit is frequently executed from a read-only or temporary location.
    $dataRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Toolkit'
    $logRoot  = Join-Path -Path $dataRoot -ChildPath 'logs'

    foreach ($folder in @($dataRoot, $logRoot)) {

        if (-not (Test-Path -LiteralPath $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }
    }

    $script:TkContext = @{

        # --- Identity -----------------------------------------------------
        AppName    = $script:TkAppName
        Version    = $script:TkAppVersion
        Commit     = $script:TkAppCommit
        Repository = $script:TkRepository

        # --- Filesystem ---------------------------------------------------
        DataRoot   = $dataRoot
        LogRoot    = $logRoot
        LogFile    = Join-Path -Path $logRoot -ChildPath ('toolkit-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
        SettingsFile = Join-Path -Path $dataRoot -ChildPath 'settings.json'

        # Origin of this instance, when it was launched from a remote one
        # liner. Replayed verbatim by an elevation restart.
        SourceUri     = ''

        # --- Runtime facts (filled by Initialize-TkEnvironment) -----------
        IsElevated    = $false
        IsSupportedOS = $false
        PSEdition     = $PSVersionTable.PSEdition
        PSVersion     = $PSVersionTable.PSVersion.ToString()
        OSCaption     = ''
        OSBuild       = ''

        # --- Data catalogs (filled by Import-TkCatalog) -------------------
        Catalogs = @{}

        # --- User settings (filled by Import-TkSettings) ------------------
        Settings = @{}

        # --- UI handles ---------------------------------------------------
        Window   = $null
        Controls = @{}

        # --- Background work ----------------------------------------------
        RunspacePool = $null
        Tasks        = [System.Collections.ArrayList]::new()

        # Actions queued by background threads for the UI thread to run.
        UiQueue      = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    }

    return $script:TkContext
}

<#
.SYNOPSIS
    Returns the shared application context, creating it on first use.

.OUTPUTS
    System.Collections.Hashtable
#>
function Get-TkContext {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if ($null -eq $script:TkContext) {
        return (Initialize-TkContext)
    }

    return $script:TkContext
}

<#
.SYNOPSIS
    Loads persisted user settings from disk.

.DESCRIPTION
    Settings are stored as JSON in the per-user data directory. A missing or
    corrupted file is not an error: defaults are returned instead, so a bad
    file can never prevent the application from starting.
#>
function Import-TkSettings {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $ctx = Get-TkContext

    # Defaults are declared here so a new setting only needs to be added once.
    $settings = @{
        Theme                 = 'Dark'
        ConfirmPrivilegedOps  = $true
        LastPage              = 'System'
        VirusTotalKeyStored   = $false
    }

    if (Test-Path -LiteralPath $ctx.SettingsFile) {

        try {
            $raw = Get-Content -LiteralPath $ctx.SettingsFile -Raw -ErrorAction Stop

            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $parsed = $raw | ConvertFrom-Json -ErrorAction Stop

                foreach ($property in $parsed.PSObject.Properties) {
                    $settings[$property.Name] = $property.Value
                }
            }
        }
        catch {
            Write-TkLog -Level Warning -Message ('Unreadable settings file, falling back to defaults: {0}' -f $_.Exception.Message)
        }
    }

    $ctx.Settings = $settings
    return $settings
}

<#
.SYNOPSIS
    Persists the current user settings to disk.
#>
function Save-TkSettings {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $ctx = Get-TkContext

    if (-not $PSCmdlet.ShouldProcess($ctx.SettingsFile, 'Write settings')) {
        return
    }

    try {
        $ctx.Settings |
            ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $ctx.SettingsFile -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-TkLog -Level Warning -Message ('Could not save settings: {0}' -f $_.Exception.Message)
    }
}
