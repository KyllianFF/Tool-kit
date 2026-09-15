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
        'ResetProxySettings'     = 'Reset-TkProxySetting'
        'PurgeKerberosTickets'   = 'Clear-TkKerberosTicket'
        'ResyncTime'             = 'Sync-TkTime'
        'ResetSecureChannel'     = 'Reset-TkSecureChannel'
        'RepairWmiRepository'    = 'Repair-TkWmiRepository'
        'ResetOneDrive'          = 'Reset-TkOneDrive'
        'ClearTeamsCache'        = 'Clear-TkTeamsCache'
        'RestartAudioServices'   = 'Restart-TkAudioService'
        'RestartBluetoothService' = 'Restart-TkBluetoothService'
        'RestartStartMenu'       = 'Restart-TkStartMenu'
        'ResetDefenderSignatures' = 'Reset-TkDefenderSignature'
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

# ---------------------------------------------------------------------------
# Network and domain
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Puts the proxy settings back to their defaults.

.DESCRIPTION
    Resets both proxies Windows keeps: the one Windows Update, BITS and the
    agents read (WinHTTP), and the one applications read, for the account the
    toolkit runs as, or for the whole machine when ProxySettingsPerUser says
    so. The binary values the Settings page keeps the real state in are
    removed too, or the old proxy would come back from them.

    The settings in force are written to the log first, so they can be put
    back by hand. Environment variables are left alone: a command line tool
    may rely on them on purpose.

.OUTPUTS
    System.Boolean
#>
function Reset-TkProxySetting {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Reset the proxy settings')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset the WinHTTP and application proxy settings')) {
        return $false
    }

    try {
        Write-TkLog -Level Information -Category 'Fixes' -Message (
            'Proxy settings before the reset: {0}' -f (Get-TkProxySetting | ConvertTo-Json -Depth 4 -Compress)
        )
    }
    catch {
        Write-TkLog -Level Warning -Category 'Fixes' -Message (
            'The proxy settings could not be recorded before the reset: {0}' -f $_.Exception.Message
        )
    }

    $failures = 0
    $result   = Invoke-TkProcess -FilePath 'netsh' -ArgumentList @('winhttp', 'reset', 'proxy') -TimeoutSeconds 60

    if ($result.ExitCode -ne 0) {
        $failures++
        Write-TkLog -Level Warning -Category 'Fixes' -Message ('netsh winhttp reset proxy returned {0}.' -f $result.ExitCode)
    }

    $settingsPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $perUser      = Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxySettingsPerUser'
    $root         = if ($null -ne $perUser -and [int] $perUser -eq 0) { 'HKLM:' } else { 'HKCU:' }

    if (-not (Set-TkRegistryValue -Path "$root\$settingsPath" -Name 'ProxyEnable' -Value 0 -Type DWord -Confirm:$false)) {
        $failures++
    }

    foreach ($name in @('ProxyServer', 'ProxyOverride', 'AutoConfigURL')) {
        Remove-TkRegistryValue -Path "$root\$settingsPath" -Name $name -Confirm:$false | Out-Null
    }

    # Without these two, Windows starts again from automatic detection.
    foreach ($name in @('DefaultConnectionSettings', 'SavedLegacySettings')) {
        Remove-TkRegistryValue -Path "$root\$settingsPath\Connections" -Name $name -Confirm:$false | Out-Null
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'Proxy settings reset under {0}. A proxy set by group policy or Intune comes back at the next refresh.' -f $root
    )

    return ($failures -eq 0)
}

<#
.SYNOPSIS
    Purges cached Kerberos tickets and applies Group Policy again.

.DESCRIPTION
    Tickets carry the group memberships of the moment they were issued, so a
    new membership only counts once they are requested again. The computer
    tickets (logon session 0x3e7) and those of the session the toolkit runs in
    are purged. An elevated toolkit runs in a session of its own: a user's
    desktop session keeps its tickets until the user signs out.

.OUTPUTS
    System.Boolean
#>
function Clear-TkKerberosTicket {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Purge the Kerberos tickets')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Purge Kerberos tickets and refresh Group Policy')) {
        return $false
    }

    $steps = @(
        @{ File = 'klist.exe';    Args = @('-li', '0x3e7', 'purge'); Timeout = 60 },
        @{ File = 'klist.exe';    Args = @('purge');                 Timeout = 60 },
        @{ File = 'gpupdate.exe'; Args = @('/force');                Timeout = 300 }
    )

    $failures = 0

    foreach ($step in $steps) {

        $result = Invoke-TkProcess -FilePath $step.File -ArgumentList $step.Args -TimeoutSeconds $step.Timeout

        if ($result.ExitCode -ne 0) {
            $failures++

            Write-TkLog -Level Warning -Category 'Fixes' -Message (
                '{0} {1} returned {2}.' -f $step.File, ($step.Args -join ' '), $result.ExitCode
            )
        }
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message 'Kerberos tickets purged and Group Policy applied again.'

    return ($failures -eq 0)
}

<#
.SYNOPSIS
    Resynchronises the clock with its time source.

.DESCRIPTION
    Starts the Windows Time service when it is stopped but allowed to run. A
    disabled service is left disabled and reported: someone chose that, or a
    policy did.

.OUTPUTS
    System.Boolean
#>
function Sync-TkTime {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Resynchronise the clock')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Resynchronise the clock')) {
        return $false
    }

    $service = Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-TkLog -Level Error -Category 'Fixes' -Message 'The Windows Time service is not installed.'
        return $false
    }

    if ($service.Status -ne 'Running') {

        if ([string] $service.StartType -eq 'Disabled') {
            Write-TkLog -Level Warning -Category 'Fixes' -Message 'The Windows Time service is disabled, and was left so.'
            return $false
        }

        Start-Service -Name 'W32Time' -ErrorAction SilentlyContinue
    }

    $result = Invoke-TkProcess -FilePath 'w32tm.exe' -ArgumentList @('/resync') -TimeoutSeconds 60

    if ($result.ExitCode -ne 0) {

        # Usually a source not reached yet: have the service find its sources
        # again, then synchronise.
        $result = Invoke-TkProcess -FilePath 'w32tm.exe' -ArgumentList @('/resync', '/rediscover') -TimeoutSeconds 90
    }

    if ($result.ExitCode -eq 0) {
        Write-TkLog -Level Information -Category 'Fixes' -Message 'Clock resynchronised.'
    }
    else {
        Write-TkLog -Level Warning -Category 'Fixes' -Message (
            'The clock could not be resynchronised (exit code {0}). Check the source with w32tm /query /status.' -f $result.ExitCode
        )
    }

    return ($result.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Resets the secure channel between this computer and its domain.

.DESCRIPTION
    nltest /sc_reset rebuilds the channel with the machine account password
    the computer already holds. It cannot help when that password no longer
    matches Active Directory, typically after a restored snapshot: the repair
    then needs a domain credential, which a background fix must not ask for,
    so the log says how to do it.

.OUTPUTS
    System.Boolean
#>
function Reset-TkSecureChannel {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Reset the domain secure channel')) {
        return $false
    }

    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    if (-not $system -or -not $system.PartOfDomain) {
        Write-TkLog -Level Warning -Category 'Fixes' -Message 'This computer is not joined to an Active Directory domain.'
        return $false
    }

    $domain = [string] $system.Domain

    if ($domain -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$') {
        Write-TkLog -Level Error -Category 'Fixes' -Message ('Refused: "{0}" is not a domain name.' -f $domain)
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($domain, 'Reset the secure channel')) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'nltest.exe' -ArgumentList @(('/sc_reset:{0}' -f $domain)) -TimeoutSeconds 120

    if ($result.ExitCode -eq 0) {
        Write-TkLog -Level Information -Category 'Fixes' -Message ('Secure channel with {0} reset.' -f $domain)
        return $true
    }

    Write-TkLog -Level Warning -Category 'Fixes' -Message (
        ('The secure channel with {0} could not be reset (exit code {1}). If the machine account password no longer matches, ' +
         'run Test-ComputerSecureChannel -Repair -Credential (Get-Credential) in an elevated Windows PowerShell 5.1 with a domain account, then restart.') -f $domain, $result.ExitCode
    )

    return $false
}

# ---------------------------------------------------------------------------
# Servicing: WMI and Defender
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Verifies the WMI repository and salvages it only when it is damaged.

.DESCRIPTION
    Never /resetrepository: Microsoft warns against throwing the repository
    away as a first step, because the classes applications registered in it
    are not all rebuilt.

.OUTPUTS
    System.Boolean
#>
function Repair-TkWmiRepository {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Repair the WMI repository')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Verify and, if needed, salvage the WMI repository')) {
        return $false
    }

    $verify = Invoke-TkProcess -FilePath 'winmgmt.exe' -ArgumentList @('/verifyrepository') -TimeoutSeconds 300

    if ($verify.ExitCode -eq 0) {
        Write-TkLog -Level Information -Category 'Fixes' -Message 'The WMI repository is consistent: nothing to salvage.'
        return $true
    }

    Write-TkLog -Level Warning -Category 'Fixes' -Message (
        'The WMI repository is not consistent (exit code {0}); salvaging it.' -f $verify.ExitCode
    )

    $salvage = Invoke-TkProcess -FilePath 'winmgmt.exe' -ArgumentList @('/salvagerepository') -TimeoutSeconds 900

    if ($salvage.ExitCode -ne 0) {
        Write-TkLog -Level Error -Category 'Fixes' -Message (
            'The WMI repository could not be salvaged (exit code {0}).' -f $salvage.ExitCode
        )
    }

    return ($salvage.ExitCode -eq 0)
}

<#
.SYNOPSIS
    Finds the newest copy of the Defender command line tool.

.DESCRIPTION
    Platform updates install into a versioned folder under ProgramData, and
    the copy in Program Files is the one Windows shipped with. Folders are
    compared as versions, where 4.18.9999 would otherwise sort after
    4.18.25080.

.PARAMETER PlatformRoot
    The Windows Defender Platform folder under ProgramData.

.PARAMETER ProgramFiles
    The Program Files folder.

.OUTPUTS
    System.String, or null when neither holds the tool.
#>
function Get-TkMpCmdRunPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $PlatformRoot,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ProgramFiles
    )

    if ($PlatformRoot -and (Test-Path -LiteralPath $PlatformRoot)) {

        $newest = Get-ChildItem -LiteralPath $PlatformRoot -Directory -ErrorAction SilentlyContinue |
                  Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'MpCmdRun.exe') } |
                  Sort-Object -Descending -Property {
                      $version = $null
                      if ([version]::TryParse(($_.Name -replace '-.*$', ''), [ref] $version)) { $version } else { [version] '0.0' }
                  } |
                  Select-Object -First 1

        if ($newest) {
            return (Join-Path $newest.FullName 'MpCmdRun.exe')
        }
    }

    if ($ProgramFiles) {

        $shipped = Join-Path $ProgramFiles 'Windows Defender\MpCmdRun.exe'

        if (Test-Path -LiteralPath $shipped) {
            return $shipped
        }
    }

    return $null
}

<#
.SYNOPSIS
    Removes the dynamically downloaded Defender signatures and updates again.

.OUTPUTS
    System.Boolean
#>
function Reset-TkDefenderSignature {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Reload the Defender signatures')) {
        return $false
    }

    $tool = Get-TkMpCmdRunPath -PlatformRoot ([string] (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform')) `
                               -ProgramFiles ([string] $env:ProgramFiles)

    if (-not $tool) {
        Write-TkLog -Level Warning -Category 'Fixes' -Message 'The Microsoft Defender command line tool was not found on this machine.'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Remove dynamic Defender signatures and update them')) {
        return $false
    }

    $remove = Invoke-TkProcess -FilePath $tool -ArgumentList @('-RemoveDefinitions', '-DynamicSignatures') -TimeoutSeconds 300

    if ($remove.ExitCode -ne 0) {
        Write-TkLog -Level Warning -Category 'Fixes' -Message (
            'Removing the dynamic signatures returned {0}; updating anyway.' -f $remove.ExitCode
        )
    }

    $update = Invoke-TkProcess -FilePath $tool -ArgumentList @('-SignatureUpdate') -TimeoutSeconds 900

    if ($update.ExitCode -eq 0) {
        Write-TkLog -Level Information -Category 'Fixes' -Message 'Defender security intelligence updated.'
    }
    else {
        Write-TkLog -Level Warning -Category 'Fixes' -Message (
            'The signature update returned {0}. Check the connection to Windows Update or the configured update source.' -f $update.ExitCode
        )
    }

    return ($update.ExitCode -eq 0)
}

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the first OneDrive executable that exists.

.PARAMETER Candidate
    Paths in order of preference: per user first, then per machine.

.OUTPUTS
    System.String, or null.
#>
function Get-TkOneDriveExecutable {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Candidate
    )

    foreach ($path in $Candidate) {

        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $path
        }
    }

    return $null
}

<#
.SYNOPSIS
    Resets the OneDrive sync app for the account the toolkit runs as.

.DESCRIPTION
    OneDrive refuses to run with administrator rights, so an elevated toolkit
    resets it and leaves the start to the user; otherwise OneDrive is started
    again when the reset has not done it already.

.OUTPUTS
    System.Boolean
#>
function Reset-TkOneDrive {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    $executable = Get-TkOneDriveExecutable -Candidate @(
        ('{0}\Microsoft\OneDrive\OneDrive.exe' -f $env:LOCALAPPDATA)
        ('{0}\Microsoft OneDrive\OneDrive.exe' -f $env:ProgramFiles)
        ('{0}\Microsoft OneDrive\OneDrive.exe' -f ${env:ProgramFiles(x86)})
    )

    if (-not $executable) {
        Write-TkLog -Level Warning -Category 'Fixes' -Message 'OneDrive is not installed for this account.'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($executable, 'Reset OneDrive')) {
        return $false
    }

    Start-Process -FilePath $executable -ArgumentList '/reset'

    if (Test-TkIsElevated) {
        Write-TkLog -Level Information -Category 'Fixes' -Message (
            'OneDrive reset. Start it again from the Start menu: it does not run with administrator rights.'
        )

        return $true
    }

    # The reset closes OneDrive and normally starts it again by itself.
    Start-Sleep -Seconds 15

    if (-not (Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath $executable
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message 'OneDrive reset; it syncs every file again.'

    return $true
}

<#
.SYNOPSIS
    Returns where new and classic Teams keep their cache.

.PARAMETER LocalAppData
    The local application data folder of the account.

.PARAMETER AppData
    The roaming application data folder of the account.

.OUTPUTS
    PSCustomObject[] with Name, Path and Process.
#>
function Get-TkTeamsCacheFolder {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $LocalAppData,

        [Parameter(Mandatory)]
        [string] $AppData
    )

    return @(
        [pscustomobject] @{ Name = 'New Teams';     Path = (Join-Path $LocalAppData 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'); Process = 'ms-teams' }
        [pscustomobject] @{ Name = 'Classic Teams'; Path = (Join-Path $AppData 'Microsoft\Teams');                                              Process = 'Teams' }
    )
}

<#
.SYNOPSIS
    Closes Teams and empties its cache for the account the toolkit runs as.

.OUTPUTS
    System.Boolean
#>
function Clear-TkTeamsCache {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    $folders = @(Get-TkTeamsCacheFolder -LocalAppData $env:LOCALAPPDATA -AppData $env:APPDATA |
                 Where-Object { Test-Path -LiteralPath $_.Path })

    if ($folders.Count -eq 0) {
        Write-TkLog -Level Information -Category 'Fixes' -Message 'No Teams cache was found for this account.'
        return $true
    }

    if (-not $PSCmdlet.ShouldProcess(($folders.Name -join ', '), 'Close Teams and clear its cache')) {
        return $false
    }

    foreach ($folder in $folders) {
        Get-Process -Name $folder.Process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # Let the processes release their files.
    Start-Sleep -Seconds 3

    $freedBytes = 0

    foreach ($folder in $folders) {

        foreach ($item in @(Get-ChildItem -LiteralPath $folder.Path -Force -ErrorAction SilentlyContinue)) {

            $size = (Get-ChildItem -LiteralPath $item.FullName -Force -Recurse -File -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum

            if (-not $item.PSIsContainer) {
                $size = $item.Length
            }

            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue

            if (-not (Test-Path -LiteralPath $item.FullName)) {
                $freedBytes += [double] $size
            }
        }
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message (
        'Teams cache cleared ({0}), {1} reclaimed. Teams rebuilds it at its next start.' -f ($folders.Name -join ', '), (Format-TkBytes -Bytes $freedBytes)
    )

    return $true
}

# ---------------------------------------------------------------------------
# Devices and shell
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Restarts the Windows audio services.

.DESCRIPTION
    Restarting the endpoint builder stops Windows Audio, which depends on it,
    without starting it again, hence the second step.

.OUTPUTS
    System.Boolean
#>
function Restart-TkAudioService {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Restart the audio services')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart AudioEndpointBuilder and Audiosrv')) {
        return $false
    }

    try {
        Restart-Service -Name 'AudioEndpointBuilder' -Force -ErrorAction Stop
        Start-Service -Name 'Audiosrv' -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Fixes' -Message 'Audio services restarted.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Fixes' -Message ('The audio services could not be restarted: {0}' -f $_.Exception.Message)
        return $false
    }
}

<#
.SYNOPSIS
    Restarts the Bluetooth Support Service.

.OUTPUTS
    System.Boolean
#>
function Restart-TkBluetoothService {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Restart the Bluetooth support service')) {
        return $false
    }

    if (-not (Get-Service -Name 'bthserv' -ErrorAction SilentlyContinue)) {
        Write-TkLog -Level Warning -Category 'Fixes' -Message 'This machine has no Bluetooth Support Service.'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart bthserv')) {
        return $false
    }

    try {
        Restart-Service -Name 'bthserv' -Force -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Fixes' -Message 'Bluetooth Support Service restarted.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Fixes' -Message ('The Bluetooth service could not be restarted: {0}' -f $_.Exception.Message)
        return $false
    }
}

<#
.SYNOPSIS
    Ends the processes behind Start, search and the notification area.

.DESCRIPTION
    Windows starts each of them again the next time it is opened, so nothing
    has to be started here.

.OUTPUTS
    System.Boolean
#>
function Restart-TkStartMenu {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart the Start menu, search and shell experience hosts')) {
        return $false
    }

    foreach ($name in @('StartMenuExperienceHost', 'SearchHost', 'ShellExperienceHost')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    Write-TkLog -Level Information -Category 'Fixes' -Message 'Start menu and search restarted; they come back when opened.'

    return $true
}
