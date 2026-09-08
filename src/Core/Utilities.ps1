<#
    Toolkit - Core / Utilities

    Small, dependency free helpers shared by every feature module. Anything
    placed here must be pure enough to unit test without a GUI and without
    administrator rights.
#>

<#
.SYNOPSIS
    Tells whether a command is resolvable in the current session.

.PARAMETER Name
    Command, cmdlet, function or executable name.

.OUTPUTS
    System.Boolean
#>
function Test-TkCommand {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    return [bool] (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

<#
.SYNOPSIS
    Normalises a value into an array, treating null as empty.

.DESCRIPTION
    @($null) produces an array containing one null element, not an empty one.
    That single behaviour is behind most "cannot bind argument, it is null"
    failures when iterating over optional JSON fields, so every optional
    collection in the catalogs is read through this function.

.OUTPUTS
    System.Object[]
#>
function ConvertTo-TkArray {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return @()
    }

    return @($InputObject | Where-Object { $null -ne $_ })
}

<#
.SYNOPSIS
    Runs an external executable and captures its output and exit code.

.DESCRIPTION
    Wraps System.Diagnostics.Process so callers get structured results rather
    than parsing a console transcript. Arguments are passed as an array and
    never concatenated into a single string, which removes the whole class of
    quoting and argument injection problems that plague cmd based helpers.

.PARAMETER FilePath
    Executable to run. Resolved through the PATH when not fully qualified.

.PARAMETER ArgumentList
    Arguments, one array element per argument.

.PARAMETER TimeoutSeconds
    Maximum wait before the child process is killed. 0 disables the timeout.

.PARAMETER WorkingDirectory
    Optional working directory for the child process.

.OUTPUTS
    PSCustomObject with ExitCode, StandardOutput, StandardError, TimedOut.

.EXAMPLE
    Invoke-TkProcess -FilePath 'winget' -ArgumentList @('--version')
#>
function Invoke-TkProcess {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter()]
        [string[]] $ArgumentList = @(),

        [Parameter()]
        [int] $TimeoutSeconds = 600,

        [Parameter()]
        [string] $WorkingDirectory
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    # ArgumentList is the safe path: the runtime escapes each element itself.
    # It only exists on .NET Core, so Windows PowerShell falls back to a
    # command line built with the CommandLineToArgvW quoting rules.
    $supportsArgumentList = ($psi.PSObject.Properties.Name -contains 'ArgumentList')

    if ($supportsArgumentList) {

        foreach ($argument in $ArgumentList) {
            $psi.ArgumentList.Add($argument)
        }
    }
    elseif ($ArgumentList.Count -gt 0) {

        $psi.Arguments = ($ArgumentList |
            ForEach-Object { ConvertTo-TkProcessArgument -Value $_ }) -join ' '
    }

    if ($WorkingDirectory) {
        $psi.WorkingDirectory = $WorkingDirectory
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    $stdOut   = New-Object System.Text.StringBuilder
    $stdErr   = New-Object System.Text.StringBuilder
    $timedOut = $false

    try {
        [void] $process.Start()

        # Read both pipes asynchronously. Reading them one after the other
        # deadlocks as soon as a child fills the buffer it is not being read
        # from, which winget does regularly.
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()

        if ($TimeoutSeconds -gt 0) {
            $exited = $process.WaitForExit($TimeoutSeconds * 1000)
        }
        else {
            $process.WaitForExit()
            $exited = $true
        }

        if (-not $exited) {
            $timedOut = $true

            # The child may exit between the timeout and the kill, which
            # throws. That is the outcome we wanted anyway.
            try { $process.Kill() } catch { $null = $_ }

            Write-TkLog -Level Warning -Category 'Process' -Message (
                'Killed "{0}" after {1}s timeout.' -f $FilePath, $TimeoutSeconds
            )
        }

        [void] $stdOut.Append($outTask.GetAwaiter().GetResult())
        [void] $stdErr.Append($errTask.GetAwaiter().GetResult())

        $exitCode = if ($timedOut) { -1 } else { $process.ExitCode }
    }
    catch {
        Write-TkLog -Level Error -Category 'Process' -Message (
            'Failed to run "{0}": {1}' -f $FilePath, $_.Exception.Message
        )

        $exitCode = -1
        [void] $stdErr.Append($_.Exception.Message)
    }
    finally {
        if ($process) { $process.Dispose() }
    }

    return [pscustomobject]@{
        ExitCode       = $exitCode
        StandardOutput = $stdOut.ToString()
        StandardError  = $stdErr.ToString()
        TimedOut       = $timedOut
    }
}

<#
.SYNOPSIS
    Quotes a single argument for a Win32 command line.

.DESCRIPTION
    Implements the CommandLineToArgvW quoting rules: backslashes that precede
    a quote must be doubled, and the quote itself escaped. Used only on hosts
    where ProcessStartInfo.ArgumentList is unavailable.

.OUTPUTS
    System.String
#>
function ConvertTo-TkProcessArgument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value -eq '') {
        return '""'
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'

    return '"{0}"' -f $escaped
}

<#
.SYNOPSIS
    Reads a registry value without throwing when it does not exist.

.PARAMETER Path
    Full registry path, for example HKLM:\SOFTWARE\Example.

.PARAMETER Name
    Value name.

.OUTPUTS
    The value, or $null when the key or value is absent.
#>
function Get-TkRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Writes a registry value, creating the key when needed.

.DESCRIPTION
    Central choke point for every registry write in the toolkit. Keeping them
    all here means one place enforces the elevation check, the logging and
    the ShouldProcess support that make changes auditable and reversible.

.PARAMETER Path
    Full registry path.

.PARAMETER Name
    Value name.

.PARAMETER Value
    Data to write.

.PARAMETER Type
    Registry value type.

.OUTPUTS
    System.Boolean - $true on success.
#>
function Set-TkRegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        $Value,

        [Parameter()]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string] $Type = 'DWord'
    )

    # HKLM and HKCR writes always need elevation; HKCU does not.
    if ($Path -match '^HK(LM|CR|EY_LOCAL_MACHINE|EY_CLASSES_ROOT)' ) {

        if (-not (Assert-TkElevated -Operation ('Registry write to {0}' -f $Path))) {
            return $false
        }
    }

    if (-not $PSCmdlet.ShouldProcess(('{0}\{1}' -f $Path, $Name), 'Set registry value')) {
        return $false
    }

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value `
                         -PropertyType $Type -Force -ErrorAction Stop | Out-Null

        Write-TkLog -Level Information -Category 'Registry' -Message (
            'Set {0}\{1} = {2} ({3})' -f $Path, $Name, $Value, $Type
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Registry' -Message (
            'Failed to set {0}\{1}: {2}' -f $Path, $Name, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Removes a registry value, ignoring a missing one.

.OUTPUTS
    System.Boolean
#>
function Remove-TkRegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($Path -match '^HK(LM|CR|EY_LOCAL_MACHINE|EY_CLASSES_ROOT)') {

        if (-not (Assert-TkElevated -Operation ('Registry delete in {0}' -f $Path))) {
            return $false
        }
    }

    if (-not $PSCmdlet.ShouldProcess(('{0}\{1}' -f $Path, $Name), 'Remove registry value')) {
        return $false
    }

    try {
        if (Test-Path -LiteralPath $Path) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction SilentlyContinue
        }

        Write-TkLog -Level Information -Category 'Registry' -Message (
            'Removed {0}\{1}' -f $Path, $Name
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Registry' -Message (
            'Failed to remove {0}\{1}: {2}' -f $Path, $Name, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Opens a URL in the default browser.

.DESCRIPTION
    Validated before launch: only http and https are accepted, so a malformed
    or hostile catalog entry cannot turn a click into a local file execution.

.PARAMETER Uri
    Absolute URL to open.

.OUTPUTS
    System.Boolean
#>
function Open-TkUri {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Uri
    )

    $parsed = $null

    if (-not [System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref] $parsed)) {
        Write-TkLog -Level Warning -Category 'Shell' -Message ('Not a valid URL: {0}' -f $Uri)
        return $false
    }

    if ($parsed.Scheme -notin @('http', 'https')) {
        Write-TkLog -Level Warning -Category 'Shell' -Message (
            'Refusing to open a non-web URL: {0}' -f $Uri
        )
        return $false
    }

    try {
        Start-Process -FilePath $parsed.AbsoluteUri -ErrorAction Stop
        Write-TkLog -Level Information -Category 'Shell' -Message ('Opened {0}' -f $parsed.AbsoluteUri)

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Shell' -Message (
            'Could not open {0}: {1}' -f $Uri, $_.Exception.Message
        )
        return $false
    }
}

<#
.SYNOPSIS
    Creates a system restore point before a batch of system changes.

.DESCRIPTION
    Best effort safety net for tweak and fix operations. Windows silently
    throttles restore point creation to one per 24 hours, so a failure here
    is logged and never blocks the caller.

.PARAMETER Description
    Label shown in the System Restore user interface.

.OUTPUTS
    System.Boolean
#>
function New-TkRestorePoint {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string] $Description = 'Toolkit - before changes'
    )

    if (-not (Assert-TkElevated -Operation 'Create a system restore point')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Create restore point')) {
        return $false
    }

    try {
        # System protection must be on for the system drive, otherwise the
        # call fails with a non obvious COM error.
        Enable-ComputerRestore -Drive ($env:SystemDrive + '\') -ErrorAction SilentlyContinue

        Checkpoint-Computer -Description $Description `
                            -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop

        Write-TkLog -Level Information -Category 'System' -Message (
            'Restore point created: {0}' -f $Description
        )

        return $true
    }
    catch {
        Write-TkLog -Level Warning -Category 'System' -Message (
            'Restore point not created ({0}). Windows limits these to one per 24 hours.' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Formats a byte count as a human readable size.

.OUTPUTS
    System.String
#>
function Format-TkBytes {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Nullable[double]] $Bytes
    )

    if ($null -eq $Bytes -or $Bytes -le 0) {
        return 'n/a'
    }

    $units = @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $index = 0
    $value = [double] $Bytes

    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value = $value / 1024
        $index++
    }

    # Formatted with the invariant culture on purpose. These strings end up in
    # exported reports and in tickets, where "1.50 GB" must not become
    # "1,50 GB" depending on the regional settings of the machine it was
    # collected from.
    return [string]::Format(
        [System.Globalization.CultureInfo]::InvariantCulture,
        '{0:N2} {1}', $value, $units[$index]
    )
}

<#
.SYNOPSIS
    Returns a value or a placeholder when it is empty.

.DESCRIPTION
    Hardware inventory fields are frequently blank, whitespace or filled with
    vendor placeholders. Normalising them in one place keeps the UI honest.

.OUTPUTS
    System.String
#>
function Format-TkValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value,

        [Parameter()]
        [string] $Placeholder = 'Not available'
    )

    if ($null -eq $Value) {
        return $Placeholder
    }

    $text = ([string] $Value).Trim()

    # Values OEMs ship when a field was never programmed at the factory.
    $junk = @(
        '', 'To be filled by O.E.M.', 'To Be Filled By O.E.M.', 'Default string',
        'System Serial Number', 'None', 'Not Specified', 'Not Applicable',
        'Chassis Serial Number', 'Filled by OEM', 'O.E.M.', 'Unknown'
    )

    if ($junk -contains $text) {
        return $Placeholder
    }

    return $text
}
