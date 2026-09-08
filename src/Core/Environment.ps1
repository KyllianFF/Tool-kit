<#
    Toolkit - Core / Environment

    Pre-flight checks. The toolkit refuses to start rather than half work on
    an unsupported host: a GUI that loads but cannot call CIM or winget is
    worse than a clear error message.
#>

<#
.SYNOPSIS
    Validates the host and records runtime facts in the context.

.DESCRIPTION
    Checks the operating system, the PowerShell version and the current
    privilege level. Returns $true when the toolkit can run, $false when a
    blocking condition was found.

.OUTPUTS
    System.Boolean
#>
function Initialize-TkEnvironment {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $ctx = Get-TkContext

    # --- Transport security ----------------------------------------------
    # Windows PowerShell 5.1 still negotiates TLS 1.0 by default on some
    # builds. Every download the toolkit performs must be TLS 1.2 or better.
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = (
            [System.Net.SecurityProtocolType]::Tls12 -bor
            [System.Net.SecurityProtocolType]::Tls13
        )
    }
    catch {
        # Tls13 is unknown on older frameworks. Fall back to 1.2 only.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }

    # --- Operating system -------------------------------------------------
    if (-not (Test-TkIsWindows)) {
        Write-TkLog -Level Error -Category 'Environment' -Message 'This toolkit targets Windows only.'
        return $false
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        $ctx.OSCaption = $os.Caption
        $ctx.OSBuild   = $os.BuildNumber

        # 10.0.x covers Windows 10, Windows 11 and Server 2016 and later.
        $ctx.IsSupportedOS = ([version] $os.Version).Major -ge 10
    }
    catch {
        Write-TkLog -Level Warning -Category 'Environment' -Message (
            'Could not query Win32_OperatingSystem: {0}' -f $_.Exception.Message
        )
    }

    if (-not $ctx.IsSupportedOS) {
        Write-TkLog -Level Warning -Category 'Environment' -Message (
            'Unsupported or unknown Windows build. Some features may be unavailable.'
        )
    }

    # --- PowerShell version ----------------------------------------------
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-TkLog -Level Error -Category 'Environment' -Message (
            'PowerShell 5.1 or later is required. Found {0}.' -f $PSVersionTable.PSVersion
        )
        return $false
    }

    # --- Privilege level --------------------------------------------------
    $ctx.IsElevated = Test-TkIsElevated

    Write-TkLog -Level Information -Category 'Environment' -Message (
        'Host: {0} (build {1}) - PowerShell {2} {3} - Elevated: {4}' -f
            $ctx.OSCaption, $ctx.OSBuild, $ctx.PSVersion, $ctx.PSEdition, $ctx.IsElevated
    )

    return $true
}

<#
.SYNOPSIS
    Tells whether the current host is Windows.

.DESCRIPTION
    $IsWindows only exists on PowerShell 6 and later; on 5.1 the absence of
    the variable is itself the answer, since 5.1 is Windows only.

.OUTPUTS
    System.Boolean
#>
function Test-TkIsWindows {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $variable = Get-Variable -Name 'IsWindows' -ErrorAction SilentlyContinue

    if ($null -eq $variable) {
        return $true
    }

    return [bool] $variable.Value
}

<#
.SYNOPSIS
    Tells whether WPF can be hosted by the current thread.

.DESCRIPTION
    Windows Presentation Foundation requires a single threaded apartment.
    A console started with -MTA can load the assemblies but faults as soon as
    a window is shown, so this is checked before any XAML is parsed.

.OUTPUTS
    System.Boolean
#>
function Test-TkIsStaThread {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $state = [System.Threading.Thread]::CurrentThread.GetApartmentState()

    return ($state -eq [System.Threading.ApartmentState]::STA)
}

<#
.SYNOPSIS
    Loads the assemblies required by the graphical interface.

.OUTPUTS
    System.Boolean
#>
function Import-TkUiAssembly {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore      -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase           -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms  -ErrorAction Stop

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Environment' -Message (
            'Failed to load the WPF assemblies: {0}' -f $_.Exception.Message
        )
        return $false
    }
}
