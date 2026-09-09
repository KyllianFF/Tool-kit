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

.OUTPUTS
    PSCustomObject[]
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
        $adapters = Get-NetAdapter -ErrorAction Stop

        if (-not $IncludeDisconnected) {
            $adapters = $adapters | Where-Object { $_.Status -eq 'Up' }
        }

        foreach ($adapter in $adapters) {

            # InterfaceIndex is the real CIM property; ifIndex is an alias
            # added by the module's type data, which is not always loaded in
            # every host and comes back null when it is not. Reading the real
            # property first, and skipping an adapter with no index at all,
            # removes a whole class of "argument is null" failures.
            $index = $adapter.InterfaceIndex

            if ($null -eq $index) {
                $index = $adapter.ifIndex
            }

            if ($null -eq $index) {
                continue
            }

            # Ignore, not SilentlyContinue. Get-NetIPConfiguration writes a
            # record for every adapter with no connection profile or no IPv4
            # address, and SilentlyContinue only hides the display: the record
            # still reaches $Error and, in a worker, the runspace error stream,
            # where the task pump reports it. On a machine with VPN, VMware and
            # Bluetooth adapters that was dozens of alarming lines in the
            # output panel for a call that had actually succeeded. Ignore is
            # the only preference that records nothing at all.
            $configuration = Get-NetIPConfiguration -InterfaceIndex $index -ErrorAction Ignore

            $ipv4 = $configuration.IPv4Address | Select-Object -First 1
            $dns  = @()

            if ($configuration.DNSServer) {
                $dns = @($configuration.DNSServer |
                    Where-Object { $_.AddressFamily -eq 2 } |
                    ForEach-Object { $_.ServerAddresses }) | Where-Object { $_ }
            }

            # DHCP state lives on the interface binding, not on the adapter.
            # Wrapped in try/catch because this CDXML cmdlet raises a
            # terminating error, not a suppressible one, for an adapter with
            # no IPv4 binding. Bluetooth and disconnected virtual adapters hit
            # that every time, and the error surfaced in the task log as if
            # the whole enumeration had failed.
            $dhcp = 'Unknown'

            $binding = Get-NetIPInterface -InterfaceIndex $index `
                                          -AddressFamily IPv4 -ErrorAction Ignore |
                       Select-Object -First 1

            if ($binding) {
                $dhcp = $binding.Dhcp
            }
            else {
                $dhcp = 'No IPv4 binding'
            }

            $results += [pscustomobject]@{
                Name           = $adapter.Name
                Description    = $adapter.InterfaceDescription
                Status         = $adapter.Status
                MacAddress     = $adapter.MacAddress
                LinkSpeed      = $adapter.LinkSpeed
                IPv4Address    = if ($ipv4) { $ipv4.IPAddress } else { 'None' }
                PrefixLength   = if ($ipv4) { $ipv4.PrefixLength } else { $null }
                SubnetMask     = if ($ipv4) { ConvertTo-TkSubnetMask -PrefixLength $ipv4.PrefixLength } else { 'None' }
                Gateway        = if ($configuration.IPv4DefaultGateway) { $configuration.IPv4DefaultGateway.NextHop } else { 'None' }
                DnsServers     = ($dns -join ', ')
                Dhcp           = $dhcp
                InterfaceIndex = $index
            }
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not enumerate adapters: {0}' -f $_.Exception.Message
        )
    }

    return $results
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
