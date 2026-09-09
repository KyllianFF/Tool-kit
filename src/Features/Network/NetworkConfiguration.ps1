<#
    Toolkit - Features / Network configuration

    The changes a network administrator makes on the machine in front of
    them: swapping an adapter between a site profile and DHCP, reading and
    editing the routing table, and publishing a port through the built in
    proxy.

    Everything here writes to the system, so everything here is guarded by
    Assert-TkElevated, supports ShouldProcess, and logs what it did.

    IP profiles exist because the alternative is what technicians actually do:
    retype an address, a mask, a gateway and two DNS servers from a note,
    on a bench, several times a day. A saved profile removes the typo that
    then costs an hour.
#>

<#
.SYNOPSIS
    Returns the file holding the saved adapter profiles.

.OUTPUTS
    System.String
#>
function Get-TkAdapterProfilePath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Join-Path -Path (Get-TkContext).DataRoot -ChildPath 'adapter-profiles.json')
}

<#
.SYNOPSIS
    Returns every saved adapter profile.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkAdapterProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $path = Get-TkAdapterProfilePath

    if (-not (Test-Path -LiteralPath $path)) {
        return , @()
    }

    try {
        $content = Get-Content -LiteralPath $path -Raw -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($content)) {
            return , @()
        }

        return , @($content | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The saved adapter profiles could not be read: {0}' -f $_.Exception.Message
        )

        return , @()
    }
}

<#
.SYNOPSIS
    Saves an IP configuration under a name.

.DESCRIPTION
    Stores a static configuration, or a DHCP profile when -UseDhcp is given.
    A profile with the same name is replaced, so re-saving is how you edit
    one.

    Nothing is applied here. Saving a profile is deliberately separate from
    applying it, because the two are done at different times: you write the
    profile once in the office, and apply it on site.

.PARAMETER Name
    Profile name, for example 'Site Lyon - VLAN 30'.

.PARAMETER IPAddress
    Static address. Required unless -UseDhcp.

.PARAMETER PrefixLength
    Prefix length of the static address.

.PARAMETER Gateway
    Default gateway. Optional: a management VLAN often has none.

.PARAMETER DnsServer
    DNS servers, in order.

.PARAMETER UseDhcp
    Saves a profile that returns the adapter to DHCP.

.OUTPUTS
    System.Boolean

.EXAMPLE
    Save-TkAdapterProfile -Name 'Bench static' -IPAddress 192.168.50.10 -PrefixLength 24 -Gateway 192.168.50.1 -DnsServer 192.168.50.1

.EXAMPLE
    Save-TkAdapterProfile -Name 'Back to DHCP' -UseDhcp
#>
function Save-TkAdapterProfile {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter()]
        [string] $IPAddress,

        [Parameter()]
        [ValidateRange(1, 32)]
        [int] $PrefixLength = 24,

        [Parameter()]
        [string] $Gateway,

        [Parameter()]
        [string[]] $DnsServer = @(),

        [Parameter()]
        [switch] $UseDhcp
    )

    if (-not $UseDhcp) {

        if ([string]::IsNullOrWhiteSpace($IPAddress)) {
            Write-TkLog -Level Error -Category 'Network' -Message 'A static profile needs an address.'
            return $false
        }

        # Validated now rather than at apply time, when the operator is on
        # site and the machine may be their only way onto the network.
        try {
            ConvertTo-TkIPv4Integer -Address $IPAddress | Out-Null

            if ($Gateway) {
                ConvertTo-TkIPv4Integer -Address $Gateway | Out-Null
            }

            foreach ($server in $DnsServer) {
                ConvertTo-TkIPv4Integer -Address $server | Out-Null
            }
        }
        catch {
            Write-TkLog -Level Error -Category 'Network' -Message (
                'The profile was not saved: {0}' -f $_.Exception.Message
            )

            return $false
        }

        # A gateway outside the address prefix is unreachable, and it is the
        # mistake that produces a machine that pings its own subnet and
        # nothing else.
        if ($Gateway) {

            $network = '{0}/{1}' -f $IPAddress, $PrefixLength

            if (-not (Test-TkAddressInSubnet -Address $Gateway -Network $network)) {

                Write-TkLog -Level Warning -Category 'Network' -Message (
                    'The gateway {0} is outside {1}. It will not be reachable unless a route already exists.' -f $Gateway, $network
                )
            }
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Save an adapter profile')) {
        return $false
    }

    $profiles = @(Get-TkAdapterProfile | Where-Object { $_.Name -ne $Name })

    $profiles += [pscustomobject]@{
        Name         = $Name
        UseDhcp      = [bool] $UseDhcp
        IPAddress    = $IPAddress
        PrefixLength = $PrefixLength
        Gateway      = $Gateway
        DnsServer    = @($DnsServer)
        SavedAt      = (Get-Date).ToString('s')
    }

    try {
        $profiles | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Get-TkAdapterProfilePath) -Encoding UTF8 -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Network' -Message ('Profile saved: {0}' -f $Name)

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The profile could not be written: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Deletes a saved adapter profile.

.OUTPUTS
    System.Boolean
#>
function Remove-TkAdapterProfile {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    if (-not $PSCmdlet.ShouldProcess($Name, 'Delete an adapter profile')) {
        return $false
    }

    $profiles = @(Get-TkAdapterProfile | Where-Object { $_.Name -ne $Name })

    try {
        $profiles | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Get-TkAdapterProfilePath) -Encoding UTF8 -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Network' -Message ('Profile deleted: {0}' -f $Name)

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The profile could not be deleted: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Applies a saved profile to an adapter.

.DESCRIPTION
    Removes the current IPv4 addresses, gateways and DNS servers, then writes
    the profile. Applying a DHCP profile hands the interface back to the DHCP
    client and clears any static resolver.

    Be aware of what this is: if you run it over a remote session on the
    adapter you are connected through, you will disconnect yourself. The
    interface warns before it runs.

.PARAMETER InterfaceAlias
    Adapter to configure, by its friendly name.

.PARAMETER Name
    Profile to apply.

.OUTPUTS
    System.Boolean
#>
function Set-TkAdapterProfile {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $InterfaceAlias,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if (-not (Assert-TkElevated -Operation ('Apply the profile {0}' -f $Name))) {
        return $false
    }

    $adapterProfile = Get-TkAdapterProfile | Where-Object { $_.Name -eq $Name } | Select-Object -First 1

    if (-not $adapterProfile) {
        Write-TkLog -Level Error -Category 'Network' -Message ('No profile named "{0}".' -f $Name)
        return $false
    }

    $adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue

    if (-not $adapter) {
        Write-TkLog -Level Error -Category 'Network' -Message ('No adapter named "{0}".' -f $InterfaceAlias)
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($InterfaceAlias, ('Apply the profile {0}' -f $Name))) {
        return $false
    }

    $stopwatch = Start-TkOperation -Name ('Apply {0} to {1}' -f $Name, $InterfaceAlias) -Category 'Network'

    try {
        # --- Clear the current configuration ------------------------------
        Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 `
                            -Confirm:$false -ErrorAction SilentlyContinue

        Remove-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' `
                        -Confirm:$false -ErrorAction SilentlyContinue

        if ($adapterProfile.UseDhcp) {

            Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp Enabled -ErrorAction Stop
            Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ResetServerAddresses -ErrorAction Stop

            Write-TkLog -Level Information -Category 'Network' -Message (
                '{0} returned to DHCP.' -f $InterfaceAlias
            )
        }
        else {
            Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp Disabled -ErrorAction SilentlyContinue

            $parameters = @{
                InterfaceAlias = $InterfaceAlias
                IPAddress      = $adapterProfile.IPAddress
                PrefixLength   = $adapterProfile.PrefixLength
                AddressFamily  = 'IPv4'
                ErrorAction    = 'Stop'
            }

            if ($adapterProfile.Gateway) {
                $parameters['DefaultGateway'] = $adapterProfile.Gateway
            }

            New-NetIPAddress @parameters | Out-Null

            $servers = @($adapterProfile.DnsServer | Where-Object { $_ })

            if ($servers.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
                                           -ServerAddresses $servers -ErrorAction Stop
            }

            Write-TkLog -Level Information -Category 'Network' -Message (
                '{0} set to {1}/{2}.' -f $InterfaceAlias, $adapterProfile.IPAddress, $adapterProfile.PrefixLength
            )
        }

        Stop-TkOperation -Name ('Apply {0} to {1}' -f $Name, $InterfaceAlias) `
                         -Stopwatch $stopwatch -Category 'Network' -Success $true

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The profile could not be applied: {0}' -f $_.Exception.Message
        )

        Stop-TkOperation -Name ('Apply {0} to {1}' -f $Name, $InterfaceAlias) `
                         -Stopwatch $stopwatch -Category 'Network' -Success $false

        return $false
    }
}

<#
.SYNOPSIS
    Captures the live configuration of an adapter as a profile.

.DESCRIPTION
    Reads what an adapter is set to right now and saves it under a name. The
    fastest way to build a profile is to configure the machine once by hand,
    confirm it works, and then capture it.

.OUTPUTS
    System.Boolean
#>
function Save-TkCurrentAdapterProfile {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $InterfaceAlias,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $adapter = Get-TkNetworkAdapterInfo -IncludeDisconnected |
               Where-Object { $_.Name -eq $InterfaceAlias } |
               Select-Object -First 1

    if (-not $adapter) {
        Write-TkLog -Level Error -Category 'Network' -Message ('No adapter named "{0}".' -f $InterfaceAlias)
        return $false
    }

    if ($adapter.Dhcp -eq 'Enabled') {
        return (Save-TkAdapterProfile -Name $Name -UseDhcp -Confirm:$false)
    }

    if ($adapter.IPv4Address -eq 'None') {
        Write-TkLog -Level Error -Category 'Network' -Message (
            '{0} has no IPv4 address to capture.' -f $InterfaceAlias
        )

        return $false
    }

    $servers = @()

    if ($adapter.DnsServers) {
        $servers = @($adapter.DnsServers -split ',\s*' | Where-Object { $_ })
    }

    $parameters = @{
        Name         = $Name
        IPAddress    = $adapter.IPv4Address
        PrefixLength = $adapter.PrefixLength
        DnsServer    = $servers
        Confirm      = $false
    }

    if ($adapter.Gateway -ne 'None') {
        $parameters['Gateway'] = $adapter.Gateway
    }

    return (Save-TkAdapterProfile @parameters)
}

# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the IPv4 routing table.

.DESCRIPTION
    Sorted the way a router evaluates it: longest prefix first, then metric.
    Reading it in that order is what makes an unexpected route obvious.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkRouteTable {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $results = @()

    try {
        foreach ($route in (Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop)) {

            $prefixLength = 0

            if ($route.DestinationPrefix -match '/(?<prefix>\d{1,2})$') {
                $prefixLength = [int] $Matches['prefix']
            }

            $results += [pscustomobject]@{
                Destination  = $route.DestinationPrefix
                PrefixLength = $prefixLength
                NextHop      = $route.NextHop
                Interface    = $route.InterfaceAlias
                Metric       = $route.RouteMetric
                Persistent   = ($route.Store -eq 'PersistentStore')
                Origin       = [string] $route.Protocol
            }
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not read the routing table: {0}' -f $_.Exception.Message
        )
    }

    return , @($results | Sort-Object -Property @{ Expression = 'PrefixLength'; Descending = $true },
                                                 @{ Expression = 'Metric'; Descending = $false })
}

<#
.SYNOPSIS
    Adds a persistent IPv4 route.

.DESCRIPTION
    Persistent means it survives a reboot, which is what a route to a
    management network needs to be. A non persistent route is a diagnostic
    tool, not a configuration.

.PARAMETER DestinationPrefix
    Destination in CIDR notation, for example 10.50.0.0/16.

.PARAMETER NextHop
    Gateway address.

.PARAMETER InterfaceAlias
    Adapter the route leaves through.

.PARAMETER Metric
    Route metric. Lower wins between routes of the same prefix length.

.OUTPUTS
    System.Boolean
#>
function Add-TkPersistentRoute {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $DestinationPrefix,

        [Parameter(Mandatory)]
        [string] $NextHop,

        [Parameter(Mandatory)]
        [string] $InterfaceAlias,

        [Parameter()]
        [ValidateRange(1, 9999)]
        [int] $Metric = 256
    )

    if (-not (Assert-TkElevated -Operation ('Add a route to {0}' -f $DestinationPrefix))) {
        return $false
    }

    # Validated before the write: a malformed prefix produces a confusing
    # error from the cmdlet itself.
    try {
        Get-TkSubnetInfo -Address $DestinationPrefix | Out-Null
        ConvertTo-TkIPv4Integer -Address $NextHop | Out-Null
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The route was not added: {0}' -f $_.Exception.Message
        )

        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($DestinationPrefix, ('Add a persistent route via {0}' -f $NextHop))) {
        return $false
    }

    try {
        New-NetRoute -DestinationPrefix $DestinationPrefix -NextHop $NextHop `
                     -InterfaceAlias $InterfaceAlias -RouteMetric $Metric `
                     -PolicyStore PersistentStore -ErrorAction Stop | Out-Null

        # Written to the active store as well, so it applies now rather than
        # at the next reboot.
        New-NetRoute -DestinationPrefix $DestinationPrefix -NextHop $NextHop `
                     -InterfaceAlias $InterfaceAlias -RouteMetric $Metric `
                     -ErrorAction SilentlyContinue | Out-Null

        Write-TkLog -Level Information -Category 'Network' -Message (
            'Persistent route added: {0} via {1} on {2}.' -f $DestinationPrefix, $NextHop, $InterfaceAlias
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The route could not be added: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Removes a route from both the active and the persistent store.

.OUTPUTS
    System.Boolean
#>
function Remove-TkRoute {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $DestinationPrefix,

        [Parameter()]
        [string] $NextHop
    )

    if (-not (Assert-TkElevated -Operation ('Remove the route to {0}' -f $DestinationPrefix))) {
        return $false
    }

    # Refusing the default route by accident is worth one explicit check: a
    # technician removing 0.0.0.0/0 on a remote machine loses it.
    if ($DestinationPrefix -eq '0.0.0.0/0') {

        Write-TkLog -Level Warning -Category 'Network' -Message (
            'Removing the default route will cut this machine off from everything outside its own subnets.'
        )
    }

    if (-not $PSCmdlet.ShouldProcess($DestinationPrefix, 'Remove the route')) {
        return $false
    }

    try {
        $parameters = @{
            DestinationPrefix = $DestinationPrefix
            Confirm           = $false
            ErrorAction       = 'Stop'
        }

        if ($NextHop) {
            $parameters['NextHop'] = $NextHop
        }

        Remove-NetRoute @parameters

        # And from the persistent store, or it comes back after a reboot.
        Remove-NetRoute @parameters -PolicyStore PersistentStore -ErrorAction SilentlyContinue

        Write-TkLog -Level Information -Category 'Network' -Message (
            'Route removed: {0}' -f $DestinationPrefix
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The route could not be removed: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

# ---------------------------------------------------------------------------
# Port forwarding
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the configured IPv4 port proxy rules.

.DESCRIPTION
    netsh interface portproxy is the port forwarder built into Windows. It is
    how you reach a service bound to a WSL instance, a Hyper-V guest on an
    internal switch, or a loopback-only listener, without installing
    anything.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkPortProxy {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $result = Invoke-TkProcess -FilePath 'netsh' `
                               -ArgumentList @('interface', 'portproxy', 'show', 'v4tov4') `
                               -TimeoutSeconds 30

    $rules = @()

    foreach ($line in ($result.StandardOutput -split "`r?`n")) {

        # Four whitespace separated columns of address, port, address, port.
        # Matched by shape rather than by the column headings, which are
        # localised.
        if ($line -match '^\s*(?<la>\S+)\s+(?<lp>\d{1,5})\s+(?<ca>\S+)\s+(?<cp>\d{1,5})\s*$') {

            $rules += [pscustomobject]@{
                ListenAddress  = $Matches['la']
                ListenPort     = [int] $Matches['lp']
                ConnectAddress = $Matches['ca']
                ConnectPort    = [int] $Matches['cp']
            }
        }
    }

    return , $rules
}

<#
.SYNOPSIS
    Publishes a local port to another address and port.

.DESCRIPTION
    Adds a v4tov4 portproxy rule. Note that the rule alone is not enough:
    Windows Firewall must also allow the listening port inbound, which this
    reports but deliberately does not change on its own.

.PARAMETER ListenPort
    Port to listen on.

.PARAMETER ConnectAddress
    Where to forward to.

.PARAMETER ConnectPort
    Port to forward to.

.PARAMETER ListenAddress
    Address to listen on. 0.0.0.0 means every interface, which is what makes
    the port reachable from the network rather than only from this machine.

.OUTPUTS
    System.Boolean

.EXAMPLE
    Add-TkPortProxy -ListenPort 8080 -ConnectAddress 172.28.5.2 -ConnectPort 80
#>
function Add-TkPortProxy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $ListenPort,

        [Parameter(Mandatory)]
        [string] $ConnectAddress,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $ConnectPort,

        [Parameter()]
        [string] $ListenAddress = '0.0.0.0'
    )

    if (-not (Assert-TkElevated -Operation 'Add a port proxy rule')) {
        return $false
    }

    try {
        ConvertTo-TkIPv4Integer -Address $ConnectAddress | Out-Null
        ConvertTo-TkIPv4Integer -Address $ListenAddress  | Out-Null
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'The rule was not added: {0}' -f $_.Exception.Message
        )

        return $false
    }

    $description = '{0}:{1} -> {2}:{3}' -f $ListenAddress, $ListenPort, $ConnectAddress, $ConnectPort

    if (-not $PSCmdlet.ShouldProcess($description, 'Add a port proxy rule')) {
        return $false
    }

    $arguments = @(
        'interface', 'portproxy', 'add', 'v4tov4',
        ('listenport={0}' -f $ListenPort),
        ('listenaddress={0}' -f $ListenAddress),
        ('connectport={0}' -f $ConnectPort),
        ('connectaddress={0}' -f $ConnectAddress)
    )

    $result  = Invoke-TkProcess -FilePath 'netsh' -ArgumentList $arguments -TimeoutSeconds 30
    $success = ($result.ExitCode -eq 0)

    if ($success) {

        Write-TkLog -Level Information -Category 'Network' -Message (
            'Port proxy added: {0}. Remember that Windows Firewall must also allow {1} inbound.' -f $description, $ListenPort
        )
    }
    else {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'netsh refused the rule: {0}' -f (Get-TkFirstLine -Text ($result.StandardOutput + $result.StandardError))
        )
    }

    return $success
}

<#
.SYNOPSIS
    Removes a port proxy rule.

.OUTPUTS
    System.Boolean
#>
function Remove-TkPortProxy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $ListenPort,

        [Parameter()]
        [string] $ListenAddress = '0.0.0.0'
    )

    if (-not (Assert-TkElevated -Operation 'Remove a port proxy rule')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess(('{0}:{1}' -f $ListenAddress, $ListenPort), 'Remove a port proxy rule')) {
        return $false
    }

    $arguments = @(
        'interface', 'portproxy', 'delete', 'v4tov4',
        ('listenport={0}' -f $ListenPort),
        ('listenaddress={0}' -f $ListenAddress)
    )

    $result  = Invoke-TkProcess -FilePath 'netsh' -ArgumentList $arguments -TimeoutSeconds 30
    $success = ($result.ExitCode -eq 0)

    if ($success) {
        Write-TkLog -Level Information -Category 'Network' -Message (
            'Port proxy removed: {0}:{1}' -f $ListenAddress, $ListenPort
        )
    }

    return $success
}
