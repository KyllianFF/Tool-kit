<#
    Toolkit - Features / System fixes

    Repair actions a technician runs several times a week. Each one is a real
    function, and the catalog only references it by name through the allow
    list below.

    Security note on the dispatch: the fixes catalog is data, and data can be
    modified by whoever controls the file. Resolving a catalog string
    straight to a command would turn an edited JSON file into arbitrary code
    execution. The allow list is what prevents that, so any new fix must be
    registered in it explicitly.
#>

<#
.SYNOPSIS
    Maps catalog action names to the functions allowed to run.

.DESCRIPTION
    The single source of truth for what a fix is permitted to invoke.

.OUTPUTS
    System.Collections.Hashtable
#>
function Get-TkFixDispatchTable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'ResetNetworkStack'      = 'Reset-TkNetworkStack'
        'RepairWindowsUpdate'    = 'Repair-TkWindowsUpdate'
        'RunSystemFileCheck'     = 'Invoke-TkSystemFileCheck'
        'RepairComponentStore'   = 'Repair-TkComponentStore'
        'ClearTemporaryFiles'    = 'Clear-TkTemporaryFile'
        'RebuildIconCache'       = 'Reset-TkIconCache'
        'ResetPrintSpooler'      = 'Reset-TkPrintSpooler'
        'ResetWindowsStore'      = 'Reset-TkWindowsStore'
        'RebuildSearchIndex'     = 'Reset-TkSearchIndex'
        'RestartExplorer'        = 'Restart-TkExplorer'
        'FlushDnsCache'          = 'Clear-TkDnsCache'
        'ResetWindowsFirewall'   = 'Reset-TkWindowsFirewall'
    }
}

<#
.SYNOPSIS
    Runs a fix declared in the catalog.

.PARAMETER Fix
    Fix object from the catalog.

.OUTPUTS
    System.Boolean
#>
function Invoke-TkFix {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Fix
    )

    $dispatch = Get-TkFixDispatchTable

    if (-not $dispatch.ContainsKey($Fix.action)) {

        Write-TkLog -Level Error -Category 'Fixes' -Message (
            'Refused: "{0}" is not a registered fix action.' -f $Fix.action
        )

        return $false
    }

    if ($Fix.requiresElevation -and -not (Assert-TkElevated -Operation ('Fix: {0}' -f $Fix.name))) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($Fix.name, 'Run fix')) {
        return $false
    }

    $functionName = $dispatch[$Fix.action]
    $stopwatch    = Start-TkOperation -Name $Fix.name -Category 'Fixes'

    try {
        $result = & $functionName -Confirm:$false
        $success = ($result -ne $false)
    }
    catch {
        Write-TkLog -Level Error -Category 'Fixes' -Message (
            '{0} failed: {1}' -f $Fix.name, $_.Exception.Message
        )

        $success = $false
    }

    Stop-TkOperation -Name $Fix.name -Stopwatch $stopwatch -Category 'Fixes' -Success $success

    return $success
}

<#
.SYNOPSIS
    Returns the fixes catalog.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkFix {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $catalog = Import-TkCatalog -Name 'fixes'

    if (-not $catalog) {
        return @()
    }

    return @($catalog.fixes)
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Resets the TCP/IP stack, Winsock catalog and DNS cache.

.DESCRIPTION
    The standard sequence for a workstation that has network connectivity at
    the link layer but not above it. A restart is required afterwards.

.OUTPUTS
    System.Boolean
#>
function Reset-TkNetworkStack {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Reset the network stack')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset TCP/IP and Winsock')) {
        return $false
    }

    $steps = @(
        @{ File = 'netsh'; Args = @('winsock', 'reset') },
        @{ File = 'netsh'; Args = @('int', 'ip', 'reset') },
        @{ File = 'netsh'; Args = @('int', 'ipv6', 'reset') },
        @{ File = 'ipconfig'; Args = @('/flushdns') },
        @{ File = 'ipconfig'; Args = @('/registerdns') }
    )

    $failures = 0

    foreach ($step in $steps) {

        $result = Invoke-TkProcess -FilePath $step.File -ArgumentList $step.Args -TimeoutSeconds 120

        if ($result.ExitCode -ne 0) {
            $failures++

            Write-TkLog -Level Warning -Category 'Fixes' -Message (
                '{0} {1} returned {2}.' -f $step.File, ($step.Args -join ' '), $result.ExitCode
            )
        }
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'Network stack reset finished. A restart is required to complete it.'
    )

    return ($failures -eq 0)
}

<#
.SYNOPSIS
    Flushes the DNS resolver cache.

.OUTPUTS
    System.Boolean
#>
function Clear-TkDnsCache {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Flush DNS cache')) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'ipconfig' -ArgumentList @('/flushdns') -TimeoutSeconds 60

    Write-TkLog -Level Information -Category 'Fixes' -Message 'DNS resolver cache flushed.'

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Restores the Windows Firewall to its default policy.

.DESCRIPTION
    Destructive by nature: every custom rule is removed. Used when a machine
    has accumulated conflicting rules from uninstalled software.

.OUTPUTS
    System.Boolean
#>
function Reset-TkWindowsFirewall {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Reset the Windows Firewall')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset firewall policy to defaults')) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'netsh' -ArgumentList @('advfirewall', 'reset') -TimeoutSeconds 120

    Write-TkLog -Level Warning -Category 'Fixes' -Message (
        'Firewall policy reset to defaults. Custom rules were removed.'
    )

    return ($result.ExitCode -eq 0)
}

# ---------------------------------------------------------------------------
# Servicing
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Rebuilds the Windows Update client state.

.DESCRIPTION
    Stops the servicing stack, renames the download and catalog folders so
    Windows recreates them, then restarts the services. This clears the large
    majority of 0x8007000x update failures.

.OUTPUTS
    System.Boolean
#>
function Repair-TkWindowsUpdate {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Repair Windows Update')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset Windows Update components')) {
        return $false
    }

    $services = @('wuauserv', 'cryptSvc', 'bits', 'msiserver')

    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }

    # Renaming rather than deleting keeps a rollback available if the reset
    # turns out not to be the cause of the failure.
    $stamp   = Get-Date -Format 'yyyyMMddHHmmss'
    $folders = @(
        @{ Path = (Join-Path $env:SystemRoot 'SoftwareDistribution'); Suffix = ('.bak-{0}' -f $stamp) },
        @{ Path = (Join-Path $env:SystemRoot 'System32\catroot2');    Suffix = ('.bak-{0}' -f $stamp) }
    )

    foreach ($folder in $folders) {

        if (-not (Test-Path -LiteralPath $folder.Path)) {
            continue
        }

        try {
            Rename-Item -LiteralPath $folder.Path -NewName ((Split-Path $folder.Path -Leaf) + $folder.Suffix) -ErrorAction Stop

            Write-TkLog -Level Information -Category 'Fixes' -Message (
                'Renamed {0}' -f $folder.Path
            )
        }
        catch {
            Write-TkLog -Level Warning -Category 'Fixes' -Message (
                'Could not rename {0}: {1}' -f $folder.Path, $_.Exception.Message
            )
        }
    }

    foreach ($service in $services) {
        Start-Service -Name $service -ErrorAction SilentlyContinue
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'Windows Update components reset. Run a new update scan to verify.'
    )

    return $true
}

<#
.SYNOPSIS
    Runs the System File Checker.

.OUTPUTS
    System.Boolean
#>
function Invoke-TkSystemFileCheck {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Run sfc /scannow')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run sfc /scannow')) {
        return $false
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message 'sfc /scannow started. This takes several minutes.'

    $result = Invoke-TkProcess -FilePath 'sfc' -ArgumentList @('/scannow') -TimeoutSeconds 3600

    # sfc writes UTF-16 to the console, which surfaces as text with embedded
    # null characters when captured. Strip them before matching.
    $output = $result.StandardOutput -replace "`0", ''

    if ($output -match 'did not find any integrity violations') {
        Write-TkLog -Level Information -Category 'Fixes' -Message 'sfc: no integrity violations found.'
    }
    elseif ($output -match 'successfully repaired') {
        Write-TkLog -Level Information -Category 'Fixes' -Message 'sfc: corrupt files were found and repaired.'
    }
    elseif ($output -match 'unable to fix') {
        Write-TkLog -Level Warning -Category 'Fixes' -Message 'sfc: corrupt files remain. Run the component store repair next.'
    }

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Repairs the component store with DISM.

.DESCRIPTION
    The companion to sfc: when sfc cannot repair a file it is because its
    source, the component store, is itself damaged.

.OUTPUTS
    System.Boolean
#>
function Repair-TkComponentStore {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Run DISM /RestoreHealth')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run DISM /Online /Cleanup-Image /RestoreHealth')) {
        return $false
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'DISM /RestoreHealth started. This can take 15 minutes or more.'
    )

    $result = Invoke-TkProcess -FilePath 'DISM.exe' `
                               -ArgumentList @('/Online', '/Cleanup-Image', '/RestoreHealth') `
                               -TimeoutSeconds 5400

    return ($result.ExitCode -eq 0)
}

# ---------------------------------------------------------------------------
# Shell and caches
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Deletes temporary files for the current user and the system.

.DESCRIPTION
    Files locked by a running process are skipped silently, which is normal
    and not worth reporting per file.

.OUTPUTS
    System.Boolean
#>
function Clear-TkTemporaryFile {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Delete temporary files')) {
        return $false
    }

    $targets = @(
        $env:TEMP,
        (Join-Path $env:SystemRoot 'Temp'),
        (Join-Path $env:SystemRoot 'Prefetch')
    )

    $freedBytes = 0

    foreach ($target in $targets) {

        if (-not $target -or -not (Test-Path -LiteralPath $target)) {
            continue
        }

        $items = Get-ChildItem -LiteralPath $target -Force -Recurse -ErrorAction SilentlyContinue

        foreach ($item in $items) {

            if ($item.PSIsContainer) {
                continue
            }

            try {
                $size = $item.Length
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                $freedBytes += $size
            }
            catch {
                # Locked by a running process: expected, skip it.
                $null = $_
            }
        }
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'Temporary files cleaned, {0} reclaimed.' -f (Format-TkBytes -Bytes $freedBytes)
    )

    return $true
}

<#
.SYNOPSIS
    Rebuilds the Explorer icon and thumbnail caches.

.OUTPUTS
    System.Boolean
#>
function Reset-TkIconCache {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Rebuild the icon cache')) {
        return $false
    }

    $cachePath = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'

    Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue

    Get-ChildItem -LiteralPath $cachePath -Filter 'iconcache*' -Force -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    Get-ChildItem -LiteralPath $cachePath -Filter 'thumbcache*' -Force -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    Start-Process -FilePath 'explorer.exe'

    Write-TkLog -Level Information -Category 'Fixes' -Message 'Icon and thumbnail caches rebuilt.'

    return $true
}

<#
.SYNOPSIS
    Restarts the Explorer shell.

.OUTPUTS
    System.Boolean
#>
function Restart-TkExplorer {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart Explorer')) {
        return $false
    }

    Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue

    # Explorer normally restarts itself; start it manually when the shell was
    # configured not to.
    Start-Sleep -Seconds 2

    if (-not (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath 'explorer.exe'
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message 'Explorer restarted.'

    return $true
}

<#
.SYNOPSIS
    Restarts the print spooler and clears the pending print queue.

.OUTPUTS
    System.Boolean
#>
function Reset-TkPrintSpooler {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Reset the print spooler')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset print spooler')) {
        return $false
    }

    Stop-Service -Name 'Spooler' -Force -ErrorAction SilentlyContinue

    $spoolPath = Join-Path $env:SystemRoot 'System32\spool\PRINTERS'

    if (Test-Path -LiteralPath $spoolPath) {
        Get-ChildItem -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    Start-Service -Name 'Spooler' -ErrorAction SilentlyContinue

    Write-TkLog -Level Information -Category 'Fixes' -Message 'Print spooler reset and queue cleared.'

    return $true
}

<#
.SYNOPSIS
    Clears the Microsoft Store cache.

.OUTPUTS
    System.Boolean
#>
function Reset-TkWindowsStore {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset the Microsoft Store cache')) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'wsreset.exe' -ArgumentList @('-i') -TimeoutSeconds 120

    Write-TkLog -Level Information -Category 'Fixes' -Message 'Microsoft Store cache reset requested.'

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Forces a rebuild of the Windows Search index.

.OUTPUTS
    System.Boolean
#>
function Reset-TkSearchIndex {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Rebuild the search index')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Rebuild the Windows Search index')) {
        return $false
    }

    Stop-Service -Name 'WSearch' -Force -ErrorAction SilentlyContinue

    # SetupCompletedSuccessfully = 0 makes the indexer rebuild from scratch
    # the next time it starts.
    Set-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' `
                        -Name 'SetupCompletedSuccessfully' -Value 0 -Type DWord -Confirm:$false | Out-Null

    Start-Service -Name 'WSearch' -ErrorAction SilentlyContinue

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'Search index rebuild started. Full indexing runs in the background.'
    )

    return $true
}
