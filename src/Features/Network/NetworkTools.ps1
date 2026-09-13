<#
    Toolkit - Features / Network diagnostics

    Day to day troubleshooting: what am I connected to, can I reach it, and
    what is listening on this machine.

    Scope note on the port checks: they are administration tools for networks
    you are responsible for. They are rate limited and capped, they log every
    target, and the sweep refuses ranges larger than a /22. That keeps the
    feature useful for a technician and unattractive as a scanner.
#>

<#
.SYNOPSIS
    Returns the configuration of every connected network adapter.

.DESCRIPTION
    Addresses, default routes, interfaces and DNS servers are each read once
    for the whole machine and matched to adapters by interface index, rather
    than asked for adapter by adapter.

    That is faster, and it is sturdier. The earlier version called
    Get-NetIPConfiguration for each adapter inside a single try block, so one
    adapter that failed to answer, typically a VPN tunnel or a virtual switch
    changing state, abandoned every adapter after it. The Dashboard then showed
    no address at all on a machine with a working Ethernet link. Each adapter
    is now built on its own, and one that fails is logged and skipped.

.PARAMETER IncludeDisconnected
    Also returns adapters that are not up.

.OUTPUTS
    PSCustomObject[], as built by ConvertTo-TkAdapterRecord.
#>
function Get-TkNetworkAdapterInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [switch] $IncludeDisconnected
    )

    $results = @()

    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not enumerate adapters: {0}' -f $_.Exception.Message
        )

        return $results
    }

    if (-not $IncludeDisconnected) {
        $adapters = @($adapters | Where-Object { [string] $_.Status -eq 'Up' })
    }

    # Loaded explicitly rather than on first use. Inside a background runspace
    # the modules load when a cmdlet is first called, several workers start at
    # once when the toolkit opens, and the reads below ignore their errors. A
    # module that fails to load would then look exactly like a machine with no
    # address. Loading here puts that failure in the log instead.
    try {
        Import-Module -Name 'NetTCPIP', 'DnsClient' -ErrorAction Stop
    }
    catch {
        Write-TkLog -Level Warning -Category 'Network' -Message (
            'The network modules could not be loaded: {0}' -f $_.Exception.Message
        )
    }

    # Ignore rather than SilentlyContinue: SilentlyContinue still sends each
    # record to the runspace error stream, where the task pump reports it as a
    # failure of a call that succeeded. Each read is also caught on its own, so
    # a missing DNS client module costs the DNS column, not the adapters.
    $addresses  = @(try { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore } catch { $null })
    $routes     = @(try { Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Ignore } catch { $null })
    $interfaces = @(try { Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Ignore } catch { $null })
    $dnsServers = @(try { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Ignore } catch { $null })

    # Adapters up and not a single address read is not a real machine: it is a
    # read that failed without saying so. Said here, so the next time the
    # Dashboard shows no address the log explains it.
    if ($adapters.Count -gt 0 -and @($addresses | Where-Object { $null -ne $_ }).Count -eq 0) {

        Write-TkLog -Level Warning -Category 'Network' -Message (
            '{0} adapter(s) are up but no IPv4 address could be read for any of them.' -f $adapters.Count
        )
    }

    foreach ($adapter in $adapters) {

        try {
            $results += ConvertTo-TkAdapterRecord -Adapter $adapter `
                                                  -Address @($addresses | Where-Object { $null -ne $_ }) `
                                                  -Route @($routes | Where-Object { $null -ne $_ }) `
                                                  -Interface @($interfaces | Where-Object { $null -ne $_ }) `
                                                  -DnsServer @($dnsServers | Where-Object { $null -ne $_ })
        }
        catch {
            Write-TkLog -Level Warning -Category 'Network' -Message (
                'Adapter "{0}" could not be read and was skipped: {1}' -f $adapter.Name, $_.Exception.Message
            )
        }
    }

    return $results
}

<#
.SYNOPSIS
    Builds the record for one adapter from the machine wide readings.

.DESCRIPTION
    Kept apart from the reading, so the matching, and the choices it makes, can
    be tested with made up adapters.

    The gateway comes from this interface's IPv4 default route. Its effective
    metric, route metric plus interface metric, is the number Windows itself
    compares to decide which link carries traffic, so it is what
    Select-TkPrimaryAdapter sorts on. An adapter with no default route has no
    metric at all.

.PARAMETER Adapter
    One adapter from Get-NetAdapter.

.PARAMETER Address
    Output of Get-NetIPAddress for the whole machine.

.PARAMETER Route
    Output of Get-NetRoute for 0.0.0.0/0.

.PARAMETER Interface
    Output of Get-NetIPInterface for IPv4.

.PARAMETER DnsServer
    Output of Get-DnsClientServerAddress for IPv4.

.OUTPUTS
    PSCustomObject
#>
function ConvertTo-TkAdapterRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Adapter,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Address = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Route = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Interface = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $DnsServer = @()
    )

    # InterfaceIndex is the real CIM property; ifIndex is an alias added by the
    # module's type data, which is not loaded in every host.
    $index = $Adapter.InterfaceIndex

    if ($null -eq $index) {
        $index = $Adapter.ifIndex
    }

    $ipv4 = Select-TkUsableIPv4 -Address @($Address | Where-Object { $_.InterfaceIndex -eq $index })

    $binding = $Interface | Where-Object { $_.InterfaceIndex -eq $index } | Select-Object -First 1

    $defaultRoute = $Route |
                    Where-Object { $_.InterfaceIndex -eq $index } |
                    Sort-Object -Property @{ Expression = { [int] $_.RouteMetric } } |
                    Select-Object -First 1

    $metric = $null

    if ($defaultRoute) {

        $metric = [int] $defaultRoute.RouteMetric

        if ($binding -and $null -ne $binding.InterfaceMetric) {
            $metric += [int] $binding.InterfaceMetric
        }
    }

    $servers = @($DnsServer |
                 Where-Object { $_.InterfaceIndex -eq $index } |
                 ForEach-Object { $_.ServerAddresses } |
                 Where-Object { $_ })

    return [pscustomobject]@{
        Name           = [string] $Adapter.Name
        Description    = [string] $Adapter.InterfaceDescription
        Status         = [string] $Adapter.Status
        MacAddress     = $Adapter.MacAddress
        LinkSpeed      = $Adapter.LinkSpeed
        IPv4Address    = if ($ipv4) { [string] $ipv4.IPAddress } else { 'None' }
        PrefixLength   = if ($ipv4) { [int] $ipv4.PrefixLength } else { $null }
        SubnetMask     = if ($ipv4) { ConvertTo-TkSubnetMask -PrefixLength $ipv4.PrefixLength } else { 'None' }
        Gateway        = if ($defaultRoute) { [string] $defaultRoute.NextHop } else { 'None' }
        RouteMetric    = $metric
        DnsServers     = ($servers -join ', ')
        Dhcp           = if ($binding) { [string] $binding.Dhcp } else { 'No IPv4 binding' }
        Physical       = [bool] $Adapter.HardwareInterface
        InterfaceIndex = $index
    }
}

<#
.SYNOPSIS
    Picks the address an adapter is actually using.

.DESCRIPTION
    An interface can carry several IPv4 addresses, and on a machine with VPN
    clients and virtual switches most of them are not in use: link local
    169.254 addresses handed out when DHCP never answered, and addresses still
    Tentative because the tunnel is down. Only a Preferred, routable address
    counts. Among those, one from DHCP or set by hand comes before one Windows
    made up itself.

.PARAMETER Address
    Output of Get-NetIPAddress for one interface.

.OUTPUTS
    One address record, or nothing.
#>
function Select-TkUsableIPv4 {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Address
    )

    return ($Address |
            Where-Object {
                $null -ne $_ -and
                [string] $_.AddressState -eq 'Preferred' -and
                [string] $_.IPAddress -notlike '169.254.*' -and
                [string] $_.IPAddress -notlike '127.*'
            } |
            Sort-Object -Property @{ Expression = { if ([string] $_.PrefixOrigin -in @('Dhcp', 'Manual')) { 0 } else { 1 } } } |
            Select-Object -First 1)
}

<#
.SYNOPSIS
    Tests whether a TCP port accepts a connection.

.DESCRIPTION
    Uses an asynchronous connect with an explicit timeout. Test-NetConnection
    is convenient but takes seconds per closed port, which makes checking a
    list of ports unusably slow.

.PARAMETER ComputerName
    Host name or IP address.

.PARAMETER Port
    TCP port.

.PARAMETER TimeoutMilliseconds
    How long to wait for the handshake.

.OUTPUTS
    PSCustomObject with Open and ResponseTime.
#>
function Test-TkTcpPort {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $Port,

        [Parameter()]
        [ValidateRange(50, 30000)]
        [int] $TimeoutMilliseconds = 1000
    )

    $client    = New-Object System.Net.Sockets.TcpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $open      = $false

    try {
        $connect = $client.BeginConnect($ComputerName, $Port, $null, $null)

        if ($connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {

            # WaitOne returning true only means the attempt finished; the
            # connection may still have been refused.
            try {
                $client.EndConnect($connect)
                $open = $client.Connected
            }
            catch {
                $open = $false
            }
        }
    }
    catch {
        $open = $false
    }
    finally {
        $stopwatch.Stop()
        $client.Close()
    }

    return [pscustomobject]@{
        ComputerName = $ComputerName
        Port         = $Port
        Open         = $open
        Service      = Get-TkWellKnownService -Port $Port
        ResponseMs   = $stopwatch.ElapsedMilliseconds
    }
}

<#
.SYNOPSIS
    Checks a list of TCP ports on one host.

.DESCRIPTION
    Defaults to the ports a technician actually cares about on a corporate
    endpoint or server rather than a full 65535 sweep.

.PARAMETER ComputerName
    Target host.

.PARAMETER Port
    Ports to test. Defaults to a common service list.

.PARAMETER OpenOnly
    Returns only the ports that answered.

.OUTPUTS
    PSCustomObject[]
#>
function Test-TkPortList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter()]
        [int[]] $Port = @(21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443,
                          445, 636, 993, 995, 1433, 3268, 3306, 3389, 5432, 5985,
                          5986, 8080, 8443),

        [Parameter()]
        [int] $TimeoutMilliseconds = 800,

        [Parameter()]
        [switch] $OpenOnly
    )

    Write-TkLog -Level Information -Category 'Network' -Message (
        'Port check against {0} on {1} ports.' -f $ComputerName, $Port.Count
    )

    $results = @()

    foreach ($single in $Port) {

        $result = Test-TkTcpPort -ComputerName $ComputerName -Port $single `
                                 -TimeoutMilliseconds $TimeoutMilliseconds

        if (-not $OpenOnly -or $result.Open) {
            $results += $result
        }
    }

    $openCount = @($results | Where-Object { $_.Open }).Count

    Write-TkLog -Level Information -Category 'Network' -Message (
        '{0}: {1} open port(s) found.' -f $ComputerName, $openCount
    )

    return $results
}

<#
.SYNOPSIS
    Discovers responding hosts on a local subnet.

.DESCRIPTION
    Sends one ICMP echo per address and resolves the names that answer. The
    prefix is refused below /22 so this stays a tool for a single VLAN.

.PARAMETER Network
    Network in CIDR notation, for example 192.168.1.0/24.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkSubnetHost {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Network,

        [Parameter()]
        [ValidateRange(100, 5000)]
        [int] $TimeoutMilliseconds = 500
    )

    $subnet = Get-TkSubnetInfo -Address $Network

    if ($subnet.PrefixLength -lt 22) {

        Write-TkLog -Level Error -Category 'Network' -Message (
            'Refused: /{0} is too large to sweep. Use /22 or smaller.' -f $subnet.PrefixLength
        )

        return @()
    }

    Write-TkLog -Level Information -Category 'Network' -Message (
        'Sweeping {0} ({1} addresses).' -f $subnet.Cidr, $subnet.UsableHosts
    )

    $first   = ConvertTo-TkIPv4Integer -Address $subnet.FirstHost
    $last    = ConvertTo-TkIPv4Integer -Address $subnet.LastHost
    $results = @()

    # A shared ping object per address keeps the sweep sequential and gentle
    # on the network, which is the intent.
    for ($value = $first; $value -le $last; $value++) {

        $address = ConvertFrom-TkIPv4Integer -Value $value
        $ping    = New-Object System.Net.NetworkInformation.Ping

        try {
            $reply = $ping.Send($address, $TimeoutMilliseconds)

            if ($reply.Status -eq 'Success') {

                $hostName = ''

                try {
                    $hostName = [System.Net.Dns]::GetHostEntry($address).HostName
                }
                catch {
                    # No reverse record: normal on most client networks.
                    $null = $_
                }

                $results += [pscustomobject]@{
                    Address   = $address
                    HostName  = $hostName
                    RoundTrip = $reply.RoundtripTime
                    Ttl       = $reply.Options.Ttl
                }
            }
        }
        catch {
            # Unreachable address; nothing to record.
            $null = $_
        }
        finally {
            $ping.Dispose()
        }
    }

    Write-TkLog -Level Information -Category 'Network' -Message (
        'Sweep finished: {0} host(s) responded.' -f $results.Count
    )

    return $results
}

<#
.SYNOPSIS
    Resolves DNS records for a name.

.PARAMETER Name
    Name to resolve.

.PARAMETER Type
    Record type.

.PARAMETER Server
    Optional DNS server to query instead of the configured resolvers.

.OUTPUTS
    PSCustomObject[]
#>
function Resolve-TkDnsRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [ValidateSet('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR', 'ANY')]
        [string] $Type = 'A',

        [Parameter()]
        [string] $Server
    )

    try {
        $parameters = @{
            Name        = $Name
            Type        = $Type
            ErrorAction = 'Stop'
        }

        if ($Server) {
            $parameters['Server'] = $Server
        }

        # DnsOnly avoids answers coming from the hosts file or NetBIOS, which
        # is usually the point of running the query manually.
        $parameters['DnsOnly'] = $true

        $records = Resolve-DnsName @parameters

        return @($records | ForEach-Object {

            [pscustomobject]@{
                Name    = $_.Name
                Type    = $_.Type
                Ttl     = $_.TTL
                Data    = if ($_.IPAddress)      { $_.IPAddress }
                          elseif ($_.NameHost)   { $_.NameHost }
                          elseif ($_.NameExchange) { '{0} (priority {1})' -f $_.NameExchange, $_.Preference }
                          elseif ($_.Strings)    { $_.Strings -join ' ' }
                          elseif ($_.PrimaryServer) { $_.PrimaryServer }
                          else { $_.ToString() }
            }
        })
    }
    catch {
        Write-TkLog -Level Warning -Category 'Network' -Message (
            'DNS lookup for {0} ({1}) failed: {2}' -f $Name, $Type, $_.Exception.Message
        )

        return @()
    }
}

<#
.SYNOPSIS
    Lists the TCP ports this machine is listening on, with the owning process.

.DESCRIPTION
    The local counterpart of a port scan and the one that answers "what is
    holding port 8080". Process names require elevation for services owned by
    other accounts.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkListeningPort {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $results = @()

    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction Stop

        foreach ($connection in $connections) {

            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue

            $results += [pscustomobject]@{
                LocalAddress = $connection.LocalAddress
                Port         = $connection.LocalPort
                Service      = Get-TkWellKnownService -Port $connection.LocalPort
                ProcessId    = $connection.OwningProcess
                ProcessName  = if ($process) { $process.ProcessName } else { 'Access denied' }
                Path         = if ($process) { $process.Path } else { '' }
            }
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not read TCP connections: {0}' -f $_.Exception.Message
        )
    }

    return @($results | Sort-Object -Property Port)
}

<#
.SYNOPSIS
    Names the service conventionally assigned to a TCP port.

.OUTPUTS
    System.String
#>
function Get-TkWellKnownService {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int] $Port
    )

    $map = @{
        20   = 'FTP data'        ; 21   = 'FTP'              ; 22   = 'SSH / SFTP'
        23   = 'Telnet'          ; 25   = 'SMTP'             ; 53   = 'DNS'
        67   = 'DHCP server'     ; 68   = 'DHCP client'      ; 69   = 'TFTP'
        80   = 'HTTP'            ; 88   = 'Kerberos'         ; 110  = 'POP3'
        123  = 'NTP'             ; 135  = 'RPC endpoint'     ; 137  = 'NetBIOS name'
        139  = 'NetBIOS session' ; 143  = 'IMAP'             ; 161  = 'SNMP'
        162  = 'SNMP trap'       ; 389  = 'LDAP'             ; 443  = 'HTTPS'
        445  = 'SMB'             ; 465  = 'SMTPS'            ; 514  = 'Syslog'
        587  = 'SMTP submission' ; 636  = 'LDAPS'            ; 993  = 'IMAPS'
        995  = 'POP3S'           ; 1433 = 'MSSQL'            ; 1521 = 'Oracle'
        1723 = 'PPTP'            ; 3268 = 'Global catalog'   ; 3269 = 'Global catalog TLS'
        3306 = 'MySQL'           ; 3389 = 'RDP'              ; 5060 = 'SIP'
        5432 = 'PostgreSQL'      ; 5900 = 'VNC'              ; 5985 = 'WinRM HTTP'
        5986 = 'WinRM HTTPS'     ; 6379 = 'Redis'            ; 8006 = 'Proxmox'
        8080 = 'HTTP alternate'  ; 8443 = 'HTTPS alternate'  ; 9100 = 'Printer raw'
        27017 = 'MongoDB'
    }

    if ($map.ContainsKey($Port)) {
        return $map[$Port]
    }

    return ''
}

<#
.SYNOPSIS
    Runs the standard connectivity checks from gateway to internet.

.DESCRIPTION
    Walks the path a technician checks by hand: default gateway, DNS
    resolution, then an outbound HTTPS request. Reporting which step failed
    is the whole value: a failure at step one is a very different problem
    from a failure at step three.

.OUTPUTS
    PSCustomObject[]
#>
function Test-TkConnectivity {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [string] $TestHost = 'www.microsoft.com'
    )

    $results = @()

    # --- Step 1: default gateway -----------------------------------------
    $gateway = (Get-TkNetworkAdapterInfo | Where-Object { $_.Gateway -ne 'None' } |
                Select-Object -First 1).Gateway

    if ($gateway) {
        $reply = Test-Connection -TargetName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue

        $results += [pscustomobject]@{
            Step    = '1. Default gateway'
            Target  = $gateway
            Success = [bool] $reply
            Detail  = if ($reply) { 'Gateway reachable' } else { 'No answer from the gateway: check the link and the VLAN' }
        }
    }
    else {
        $results += [pscustomobject]@{
            Step    = '1. Default gateway'
            Target  = 'None'
            Success = $false
            Detail  = 'No default gateway configured on any active adapter'
        }
    }

    # --- Step 2: DNS resolution ------------------------------------------
    $records = Resolve-TkDnsRecord -Name $TestHost -Type A

    $results += [pscustomobject]@{
        Step    = '2. DNS resolution'
        Target  = $TestHost
        Success = ($records.Count -gt 0)
        Detail  = if ($records.Count -gt 0) { 'Resolved to ' + ($records[0].Data) }
                  else { 'Name not resolved: check the DNS servers on the adapter' }
    }

    # --- Step 3: outbound HTTPS ------------------------------------------
    $httpsOk     = $false
    $httpsDetail = ''

    try {
        $response = Invoke-WebRequest -Uri ('https://{0}' -f $TestHost) -UseBasicParsing `
                                      -TimeoutSec 10 -ErrorAction Stop

        $httpsOk     = ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400)
        $httpsDetail = 'HTTP {0}' -f $response.StatusCode
    }
    catch {
        $httpsDetail = 'Blocked or failed: {0}' -f (Get-TkFirstLine -Text $_.Exception.Message)
    }

    $results += [pscustomobject]@{
        Step    = '3. Outbound HTTPS'
        Target  = ('https://{0}' -f $TestHost)
        Success = $httpsOk
        Detail  = $httpsDetail
    }

    return $results
}

<#
.SYNOPSIS
    Returns the public IP address seen by an external service.

.DESCRIPTION
    Sends a request to a third party. That is an outbound disclosure of this
    machine's presence, so it only ever runs when the operator asks for it.

.OUTPUTS
    System.String
#>
function Get-TkPublicIpAddress {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $response = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' `
                                      -TimeoutSec 10 -ErrorAction Stop

        Write-TkLog -Level Information -Category 'Network' -Message (
            'Public address reported as {0}.' -f $response.ip
        )

        return $response.ip
    }
    catch {
        Write-TkLog -Level Warning -Category 'Network' -Message (
            'Could not determine the public address: {0}' -f $_.Exception.Message
        )

        return 'Not available'
    }
}

<#
.SYNOPSIS
    Picks the adapter that carries this machine's traffic.

.DESCRIPTION
    The one Windows itself would choose: among adapters with a usable address
    and a default route, the lowest effective metric. When Ethernet and Wi-Fi
    are both connected that is the wired link, and when a VPN is up it is the
    tunnel, which really is where traffic goes.

    Virtual switches for VMware, Hyper-V and WSL carry addresses but no
    default route, so they never win that way. Without any default route the
    machine is offline or on an isolated network; then a physical adapter with
    an address comes before a virtual one, and only then anything at all.

.PARAMETER Adapter
    Output of Get-TkNetworkAdapterInfo.

.OUTPUTS
    PSCustomObject, or null when there is no adapter.
#>
function Select-TkPrimaryAdapter {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Adapter
    )

    $present     = @($Adapter | Where-Object { $null -ne $_ })
    $withAddress = @($present | Where-Object { $_.IPv4Address -and $_.IPv4Address -ne 'None' })

    $routed = @($withAddress |
                Where-Object { $null -ne $_.RouteMetric } |
                Sort-Object -Property @{ Expression = { [int] $_.RouteMetric } })

    if ($routed.Count -gt 0) {
        return $routed[0]
    }

    # A record built without a metric, by a caller or an older reader, still
    # answers to its gateway.
    $withGateway = @($withAddress | Where-Object { $_.Gateway -and $_.Gateway -ne 'None' })

    if ($withGateway.Count -gt 0) {
        return $withGateway[0]
    }

    $physical = @($withAddress | Where-Object { $_.Physical -eq $true })

    if ($physical.Count -gt 0) {
        return $physical[0]
    }

    if ($withAddress.Count -gt 0) {
        return $withAddress[0]
    }

    return ($present | Select-Object -First 1)
}

<#
.SYNOPSIS
    Describes, in one line, the adapters that are up besides the primary one.

.DESCRIPTION
    Ethernet and Wi-Fi connected together, or a VPN beside the physical link,
    change what a user sees, so the other connected links are named with their
    address. Virtual switches for virtual machines and WSL are only counted:
    naming four of them would bury the one line that matters.

    A virtual adapter with a default route is a VPN tunnel carrying traffic,
    and is named like a physical link.

.PARAMETER Adapter
    Output of Get-TkNetworkAdapterInfo.

.PARAMETER Primary
    The adapter already shown, left out of the line.

.OUTPUTS
    System.String, empty when there is nothing else to say.
#>
function Get-TkSecondaryAdapterSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Adapter,

        [Parameter()]
        $Primary
    )

    $others = @($Adapter | Where-Object {
        $null -ne $_ -and
        $_.IPv4Address -and $_.IPv4Address -ne 'None' -and
        ($null -eq $Primary -or $_.InterfaceIndex -ne $Primary.InterfaceIndex)
    })

    $connected = @($others | Where-Object { $_.Physical -eq $true -or $null -ne $_.RouteMetric })
    $virtual   = @($others | Where-Object { -not ($_.Physical -eq $true -or $null -ne $_.RouteMetric) })

    $parts = @()

    if ($connected.Count -gt 0) {
        $parts += 'Also connected: {0}.' -f ((@($connected | ForEach-Object { '{0} {1}' -f $_.Name, $_.IPv4Address })) -join ', ')
    }

    if ($virtual.Count -gt 0) {
        $parts += '{0} virtual adapter(s) up: {1}.' -f $virtual.Count, ((@($virtual | ForEach-Object { $_.Name })) -join ', ')
    }

    return ($parts -join ' ')
}
