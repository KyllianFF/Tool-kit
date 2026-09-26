<#
    Toolkit - Features / LAN throughput test

    A file copy that crawls between two machines can be the network, the disk
    at either end or the protocol on top. This measures the network alone, the
    way iperf does: one machine listens, the other sends to it for a few
    seconds and then receives from it, memory to memory, and both directions
    are reported in Mbps next to the link speed the adapter announces.

    Both machines run the toolkit, so nothing has to be installed. The protocol
    is deliberately small: a one line request, "TKTHRU1 UP 5" or
    "TKTHRU1 DOWN 5", answered by "OK", then raw bytes for the given number of
    seconds. The listener is bounded in every way it can be: it waits two
    minutes at most, serves one test (both directions) and stops, answers only
    addresses of the local network, and caps a direction at thirty seconds.
    It never runs anything it is sent; the bytes are counted and dropped.

    Windows Firewall blocks the incoming connection unless a rule allows it.
    The page offers a temporary rule, scoped to the local subnet and to the
    private and domain profiles, added and removed around the test.
#>

<#
.SYNOPSIS
    The name of the temporary firewall rule, so it is added and removed by the same name.

.OUTPUTS
    System.String
#>
function Get-TkThroughputRuleName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return 'Toolkit LAN throughput test (temporary)'
}

<#
.SYNOPSIS
    Reads a throughput request line.

.DESCRIPTION
    Pure. Anything but the exact form is refused, so a stray connection (a
    port scanner, a browser) is closed without a byte of test traffic.

.PARAMETER Line
    The first line the peer sent, without its line break.

.OUTPUTS
    PSCustomObject with Direction (UP or DOWN) and Seconds, or $null.
#>
function ConvertFrom-TkThroughputRequest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Line
    )

    if ($Line -cnotmatch '^TKTHRU1 (UP|DOWN) (\d{1,2})$') {
        return $null
    }

    $seconds = [int] $Matches[2]

    if ($seconds -lt 1 -or $seconds -gt 30) {
        return $null
    }

    return [pscustomobject] @{ Direction = $Matches[1]; Seconds = $seconds }
}

<#
.SYNOPSIS
    Says whether an address belongs to a local network.

.DESCRIPTION
    Pure. Loopback, the private IPv4 ranges, IPv4 link local, and the IPv6
    unique local and link local ranges. An IPv4 address seen through a dual
    mode socket is unwrapped first.

.PARAMETER Address
    The peer address.

.OUTPUTS
    System.Boolean
#>
function Test-TkLocalNetworkAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Address
    )

    $ip = $null

    if ($Address -is [System.Net.IPAddress]) {
        $ip = $Address
    }
    elseif (-not [System.Net.IPAddress]::TryParse([string] $Address, [ref] $ip)) {
        return $false
    }

    if ($ip.IsIPv4MappedToIPv6) {
        $ip = $ip.MapToIPv4()
    }

    if ([System.Net.IPAddress]::IsLoopback($ip)) {
        return $true
    }

    $bytes = $ip.GetAddressBytes()

    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return (
            $bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254)
        )
    }

    # fc00::/7 unique local, fe80::/10 link local.
    return (($bytes[0] -band 0xFE) -eq 0xFC -or ($bytes[0] -eq 0xFE -and ($bytes[1] -band 0xC0) -eq 0x80))
}

<#
.SYNOPSIS
    Turns a byte count over a duration into megabits per second.

.OUTPUTS
    System.Double, rounded to one decimal; 0 when nothing was timed.
#>
function Get-TkThroughputRate {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)] [long] $Bytes,
        [Parameter(Mandatory)] [long] $Milliseconds
    )

    if ($Milliseconds -le 0) {
        return 0.0
    }

    return [math]::Round(($Bytes * 8.0) / ($Milliseconds * 1000.0), 1)
}

<#
.SYNOPSIS
    Puts a measured rate next to the link speed and says what it means.

.DESCRIPTION
    Pure. A test that reaches most of the link speed says the network is not
    the bottleneck. Wi-Fi rarely carries more than half of its announced rate,
    so a low ratio there is expected rather than a fault.

.PARAMETER Mbps
    The measured rate.

.PARAMETER LinkMbps
    The link speed this machine's adapter announces, 0 when unknown.

.PARAMETER Wireless
    Whether that adapter is Wi-Fi.

.OUTPUTS
    PSCustomObject with Severity (Pass, Info, Warning) and Text.
#>
function Get-TkThroughputVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [double] $Mbps,
        [Parameter()] [double] $LinkMbps = 0,
        [Parameter()] [switch] $Wireless
    )

    if ($Mbps -le 0) {
        return [pscustomobject] @{ Severity = 'Warning'; Text = 'Nothing was measured.' }
    }

    if ($LinkMbps -le 0) {
        return [pscustomobject] @{ Severity = 'Info'; Text = 'The link speed of this adapter is unknown, so the rate cannot be put against it.' }
    }

    $ratio   = $Mbps / $LinkMbps
    $percent = [math]::Round($ratio * 100)

    if ($ratio -gt 1.1) {
        return [pscustomobject] @{ Severity = 'Info'; Text = 'Faster than the link of this adapter: the traffic did not cross it, so the test measured another route, not this link.' }
    }

    if ($Wireless) {
        if ($ratio -ge 0.35) {
            return [pscustomobject] @{ Severity = 'Pass'; Text = ('{0}% of the Wi-Fi link rate, which is normal: Wi-Fi rarely carries more than half of it.' -f $percent) }
        }

        return [pscustomobject] @{ Severity = 'Warning'; Text = ('Only {0}% of the Wi-Fi link rate: interference, a crowded channel, distance, or other traffic on the same access point.' -f $percent) }
    }

    if ($ratio -ge 0.7) {
        return [pscustomobject] @{ Severity = 'Pass'; Text = ('{0}% of the link speed: the network is not what slows a transfer down.' -f $percent) }
    }

    if ($ratio -ge 0.3) {
        return [pscustomobject] @{ Severity = 'Info'; Text = ('{0}% of the link speed: a busy link, a slower hop between the two machines (a 100 Mbps switch or cable), or a slow machine at the other end.' -f $percent) }
    }

    return [pscustomobject] @{ Severity = 'Warning'; Text = ('Only {0}% of the link speed: look for a damaged cable, a duplex mismatch, a port negotiated down, or a slow hop between the two machines.' -f $percent) }
}

<#
.SYNOPSIS
    Reads one line from a stream, byte by byte, up to a bound.

.OUTPUTS
    System.String without the line break, or $null when the peer closed first
    or sent too much without one.
#>
function Read-TkThroughputLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.IO.Stream] $Stream,
        [Parameter()] [int] $MaxLength = 64
    )

    $builder = New-Object System.Text.StringBuilder

    while ($builder.Length -le $MaxLength) {

        $value = $Stream.ReadByte()

        if ($value -lt 0) { return $null }
        if ($value -eq 10) { return $builder.ToString().TrimEnd("`r") }

        [void] $builder.Append([char] $value)
    }

    return $null
}

<#
.SYNOPSIS
    Writes one ASCII line to a stream.
#>
function Write-TkThroughputLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.IO.Stream] $Stream,
        [Parameter(Mandatory)] [string] $Text
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Text + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

<#
.SYNOPSIS
    Sends bytes for a number of seconds, then says it has finished.

.OUTPUTS
    PSCustomObject with Bytes and Milliseconds.
#>
function Send-TkThroughputData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.Sockets.TcpClient] $Client,
        [Parameter(Mandatory)] [int] $Seconds
    )

    # Random rather than zeros, so a link that compresses cannot flatter the result.
    $buffer = New-Object byte[] (256KB)
    (New-Object System.Random).NextBytes($buffer)

    $stream = $Client.GetStream()
    $clock  = [System.Diagnostics.Stopwatch]::StartNew()
    $limit  = $Seconds * 1000
    [long] $sent = 0

    while ($clock.ElapsedMilliseconds -lt $limit) {
        $stream.Write($buffer, 0, $buffer.Length)
        $sent += $buffer.Length
    }

    $stream.Flush()
    $Client.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)

    return [pscustomobject] @{ Bytes = $sent; Milliseconds = $clock.ElapsedMilliseconds }
}

<#
.SYNOPSIS
    Receives and drops bytes until the peer says it has finished.

.OUTPUTS
    PSCustomObject with Bytes and Milliseconds, timed from the first byte.
#>
function Receive-TkThroughputData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.Sockets.TcpClient] $Client
    )

    $buffer = New-Object byte[] (256KB)
    $stream = $Client.GetStream()
    $clock  = New-Object System.Diagnostics.Stopwatch
    [long] $received = 0

    while ($true) {

        $read = $stream.Read($buffer, 0, $buffer.Length)

        if ($read -le 0) { break }

        if (-not $clock.IsRunning) { $clock.Start() }
        $received += $read
    }

    $clock.Stop()

    return [pscustomobject] @{ Bytes = $received; Milliseconds = $clock.ElapsedMilliseconds }
}

<#
.SYNOPSIS
    Waits for one throughput test and serves it.

.DESCRIPTION
    Listens on every address of the machine, IPv4 and IPv6, and serves at most
    MaxSessions connections (a test is two: up, then down) within
    TimeoutSeconds, then stops. A connection from outside the local network,
    or one that does not open with a valid request, is closed at once and
    counted.

.PARAMETER Port
    The TCP port.

.PARAMETER TimeoutSeconds
    How long to wait for the other machine.

.PARAMETER MaxSessions
    How many connections to serve before stopping.

.OUTPUTS
    PSCustomObject with Port, Sessions (Remote, Direction, Bytes,
    Milliseconds, Mbps), Refused (addresses), TimedOut and Error.
#>
function Start-TkThroughputListener {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [ValidateRange(1, 65535)] [int] $Port = 5201,
        [Parameter()] [ValidateRange(1, 600)] [int] $TimeoutSeconds = 120,
        [Parameter()] [ValidateRange(1, 10)] [int] $MaxSessions = 2
    )

    $sessions = New-Object System.Collections.Generic.List[object]
    $refused  = New-Object System.Collections.Generic.List[string]
    $timedOut = $false
    $failure  = ''
    $listener = $null

    try {
        $listener = [System.Net.Sockets.TcpListener]::Create($Port)
        $listener.Start()
    }
    catch {
        return [pscustomobject] @{
            Port = $Port; Sessions = @(); Refused = @(); TimedOut = $false
            Error = ('Port {0} could not be opened: {1}' -f $Port, $_.Exception.Message)
        }
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

    try {
        while ($sessions.Count -lt $MaxSessions) {

            if (-not $listener.Pending()) {
                if ([DateTime]::UtcNow -ge $deadline) { $timedOut = $true; break }
                Start-Sleep -Milliseconds 100
                continue
            }

            $client = $listener.AcceptTcpClient()

            try {
                $remote = $client.Client.RemoteEndPoint.Address
                if ($remote.IsIPv4MappedToIPv6) { $remote = $remote.MapToIPv4() }

                if (-not (Test-TkLocalNetworkAddress -Address $remote)) {
                    $refused.Add([string] $remote)
                    continue
                }

                $client.ReceiveTimeout = 5000
                $client.SendTimeout    = 5000
                $stream  = $client.GetStream()
                $request = ConvertFrom-TkThroughputRequest -Line (Read-TkThroughputLine -Stream $stream)

                if (-not $request) {
                    $refused.Add([string] $remote)
                    continue
                }

                Write-TkThroughputLine -Stream $stream -Text 'OK'
                $client.ReceiveTimeout = ($request.Seconds + 15) * 1000

                if ($request.Direction -eq 'UP') {
                    $measure = Receive-TkThroughputData -Client $client
                    Write-TkThroughputLine -Stream $stream -Text ('RESULT {0} {1}' -f $measure.Bytes, $measure.Milliseconds)
                }
                else {
                    $measure = Send-TkThroughputData -Client $client -Seconds $request.Seconds
                }

                $sessions.Add([pscustomobject] @{
                    Remote       = [string] $remote
                    Direction    = $request.Direction
                    Bytes        = $measure.Bytes
                    Milliseconds = $measure.Milliseconds
                    Mbps         = Get-TkThroughputRate -Bytes $measure.Bytes -Milliseconds $measure.Milliseconds
                })
            }
            catch {
                $failure = ('A test was cut short: {0}' -f $_.Exception.Message)
            }
            finally {
                $client.Close()
            }
        }
    }
    finally {
        $listener.Stop()
    }

    return [pscustomobject] @{
        Port     = $Port
        Sessions = @($sessions.ToArray())
        Refused  = @($refused.ToArray() | Select-Object -Unique)
        TimedOut = $timedOut
        Error    = $failure
    }
}

<#
.SYNOPSIS
    Finds the adapter behind a local address and its link speed.

.OUTPUTS
    PSCustomObject with Name, LinkMbps and Wireless, or $null.
#>
function Get-TkInterfaceLinkSpeed {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress] $LocalAddress
    )

    if ([System.Net.IPAddress]::IsLoopback($LocalAddress)) {
        return $null
    }

    [void] (Import-TkCommandModule -Command @('Get-NetAdapter', 'Get-NetIPAddress'))

    try {
        $address = @(Get-NetIPAddress -IPAddress ([string] $LocalAddress) -ErrorAction Stop) | Select-Object -First 1
        $adapter = Get-NetAdapter -InterfaceIndex $address.InterfaceIndex -ErrorAction Stop
    }
    catch {
        return $null
    }

    return [pscustomobject] @{
        Name     = [string] $adapter.Name
        LinkMbps = [math]::Round([double] $adapter.TransmitLinkSpeed / 1e6)
        Wireless = ([string] $adapter.PhysicalMediaType -match '802\.11|Wireless' -or [string] $adapter.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11')
    }
}

<#
.SYNOPSIS
    Opens one test connection and asks for a direction.

.OUTPUTS
    System.Net.Sockets.TcpClient, connected and accepted. Throws otherwise.
#>
function Open-TkThroughputSession {
    [CmdletBinding()]
    [OutputType([System.Net.Sockets.TcpClient])]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Direction,
        [Parameter(Mandatory)] [int] $Seconds
    )

    $client = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    $client.Client.DualMode = $true

    try {
        $connect = $client.ConnectAsync($ComputerName, $Port)

        if (-not $connect.Wait(5000)) {
            throw ('{0} did not answer on port {1} within five seconds.' -f $ComputerName, $Port)
        }

        $client.ReceiveTimeout = 5000
        $client.SendTimeout    = 5000
        $stream = $client.GetStream()

        Write-TkThroughputLine -Stream $stream -Text ('TKTHRU1 {0} {1}' -f $Direction, $Seconds)

        if ((Read-TkThroughputLine -Stream $stream) -ne 'OK') {
            throw ('{0} answered on port {1}, but it is not a toolkit waiting for a test.' -f $ComputerName, $Port)
        }

        $client.ReceiveTimeout = ($Seconds + 15) * 1000
        return $client
    }
    catch {
        $client.Close()
        throw
    }
}

<#
.SYNOPSIS
    Measures the throughput to a machine where the toolkit is listening.

.DESCRIPTION
    Sends for Seconds, then receives for Seconds, over two connections. The
    upload is timed by the listener, which sees when the bytes actually
    arrive; the download is timed here, for the same reason.

.PARAMETER ComputerName
    The other machine: a name or an address.

.PARAMETER Port
    The port it listens on.

.PARAMETER Seconds
    The length of each direction.

.OUTPUTS
    PSCustomObject with ComputerName, Remote, Upload and Download (Bytes,
    Milliseconds, Mbps), Adapter (Name, LinkMbps, Wireless) and Error.
#>
function Test-TkLanThroughput {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter()] [ValidateRange(1, 65535)] [int] $Port = 5201,
        [Parameter()] [ValidateRange(1, 30)] [int] $Seconds = 5
    )

    $result = [pscustomobject] @{
        ComputerName = $ComputerName
        Remote       = ''
        SameMachine  = $false
        Upload       = $null
        Download     = $null
        Adapter      = $null
        Error        = ''
    }

    $client = $null

    try {
        # --- Up: this machine sends, the listener times what arrives ------
        $client = Open-TkThroughputSession -ComputerName $ComputerName -Port $Port -Direction 'UP' -Seconds $Seconds

        $unwrap = { param($ip) if ($ip.IsIPv4MappedToIPv6) { $ip.MapToIPv4() } else { $ip } }

        $remote = & $unwrap $client.Client.RemoteEndPoint.Address
        $local  = & $unwrap $client.Client.LocalEndPoint.Address

        $result.Remote      = [string] $remote
        $result.SameMachine = ($remote.Equals($local) -or [System.Net.IPAddress]::IsLoopback($remote))
        $result.Adapter     = Get-TkInterfaceLinkSpeed -LocalAddress $local

        # Taken before the send: once this side has said it is finished,
        # the client refuses to hand out its stream again.
        $stream = $client.GetStream()
        $null   = Send-TkThroughputData -Client $client -Seconds $Seconds
        $reply  = Read-TkThroughputLine -Stream $stream

        if ($reply -notmatch '^RESULT (\d+) (\d+)$') {
            throw 'The other machine did not report what it received.'
        }

        $result.Upload = [pscustomobject] @{
            Bytes        = [long] $Matches[1]
            Milliseconds = [long] $Matches[2]
            Mbps         = Get-TkThroughputRate -Bytes ([long] $Matches[1]) -Milliseconds ([long] $Matches[2])
        }

        $client.Close()

        # --- Down: the listener sends, this machine times what arrives ----
        $client  = Open-TkThroughputSession -ComputerName $ComputerName -Port $Port -Direction 'DOWN' -Seconds $Seconds
        $measure = Receive-TkThroughputData -Client $client

        $result.Download = [pscustomobject] @{
            Bytes        = $measure.Bytes
            Milliseconds = $measure.Milliseconds
            Mbps         = Get-TkThroughputRate -Bytes $measure.Bytes -Milliseconds $measure.Milliseconds
        }
    }
    catch {
        # A task wraps the socket error; the innermost one says what happened.
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }

        $result.Error = $exception.Message
    }
    finally {
        if ($client) { $client.Close() }
    }

    return $result
}

<#
.SYNOPSIS
    What the listener needs to know before it starts: its addresses, the network profile, the firewall.

.OUTPUTS
    PSCustomObject with Addresses, PublicNetworks (aliases of the networks
    marked Public), FirewallOn (for an active profile) and RuleExists.
#>
function Get-TkThroughputListenContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    [void] (Import-TkCommandModule -Command @('Get-NetIPAddress', 'Get-NetConnectionProfile', 'Get-NetFirewallProfile', 'Get-NetFirewallRule'))

    $addresses = @(try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore |
            Where-Object { $_.IPAddress -ne '127.0.0.1' -and (Test-TkLocalNetworkAddress -Address $_.IPAddress) -and $_.AddressState -eq 'Preferred' } |
            Sort-Object @{ Expression = { [string] $_.InterfaceAlias -match 'vEthernet|VMware|VirtualBox|Hyper-V|Loopback' } }, InterfaceAlias |
            ForEach-Object { '{0} ({1})' -f $_.IPAddress, $_.InterfaceAlias }
    } catch { $null })

    $connections = @(try { Get-NetConnectionProfile -ErrorAction Ignore } catch { $null })
    $categories  = @($connections | ForEach-Object { [string] $_.NetworkCategory } | Select-Object -Unique)
    $public      = @($connections | Where-Object { [string] $_.NetworkCategory -eq 'Public' } | ForEach-Object { [string] $_.InterfaceAlias })

    $firewallOn = $true
    try {
        $active     = @($categories | ForEach-Object { if ($_ -eq 'DomainAuthenticated') { 'Domain' } else { $_ } })
        $firewallOn = [bool] (@(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $active -contains [string] $_.Name -and [string] $_.Enabled -eq 'True' }).Count -gt 0)
    }
    catch {
        $firewallOn = $true
    }

    $ruleExists = [bool] (@(try { Get-NetFirewallRule -DisplayName (Get-TkThroughputRuleName) -ErrorAction Ignore } catch { $null }) | Where-Object { $_ }).Count

    return [pscustomobject] @{
        Addresses      = @($addresses | Where-Object { $_ })
        PublicNetworks = @($public | Where-Object { $_ })
        FirewallOn     = $firewallOn
        RuleExists     = $ruleExists
    }
}

<#
.SYNOPSIS
    Adds the temporary inbound rule for the test port.

.DESCRIPTION
    Needs administrator rights: it runs in the elevated worker. The rule is
    scoped as narrowly as the test allows: one TCP port, from the local subnet
    only, on the private and domain profiles only.

.OUTPUTS
    System.Boolean
#>
function Add-TkThroughputFirewallRule {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter()] [ValidateRange(1, 65535)] [int] $Port = 5201
    )

    if (-not $PSCmdlet.ShouldProcess(('TCP {0}' -f $Port), 'Allow inbound from the local subnet')) {
        return $false
    }

    [void] (Import-TkCommandModule -Command @('New-NetFirewallRule'))
    $name = Get-TkThroughputRuleName

    try {
        Get-NetFirewallRule -DisplayName $name -ErrorAction Ignore | Remove-NetFirewallRule -ErrorAction Stop

        New-NetFirewallRule -DisplayName $name -Group 'Toolkit' -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $Port -RemoteAddress LocalSubnet -Profile Private, Domain `
            -Description 'Added by the toolkit for a LAN throughput test and removed when the test ends.' `
            -ErrorAction Stop | Out-Null

        Write-TkLog -Level Information -Category 'Network' -Message ('Temporary firewall rule added for TCP {0}.' -f $Port)
        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message ('The firewall rule could not be added: {0}' -f $_.Exception.Message)
        return $false
    }
}

<#
.SYNOPSIS
    Removes the temporary inbound rule.

.OUTPUTS
    System.Boolean
#>
function Remove-TkThroughputFirewallRule {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    $name = Get-TkThroughputRuleName

    if (-not $PSCmdlet.ShouldProcess($name, 'Remove the firewall rule')) {
        return $false
    }

    [void] (Import-TkCommandModule -Command @('Remove-NetFirewallRule'))

    try {
        Get-NetFirewallRule -DisplayName $name -ErrorAction Ignore | Remove-NetFirewallRule -ErrorAction Stop
        Write-TkLog -Level Information -Category 'Network' -Message 'Temporary firewall rule removed.'
        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message ('The firewall rule could not be removed: {0}' -f $_.Exception.Message)
        return $false
    }
}

<#
.SYNOPSIS
    Formats a throughput test for the output box.

.OUTPUTS
    System.String
#>
function Format-TkThroughputText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Result
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('LAN throughput test')
    $lines.Add('-' * 60)
    $lines.Add('')
    $lines.Add(('Other machine   {0}{1}' -f $Result.ComputerName, $(if ($Result.Remote -and $Result.Remote -ne $Result.ComputerName) { ' ({0})' -f $Result.Remote } else { '' })))

    if ($Result.Adapter) {
        $lines.Add(('This adapter    {0}, link at {1} Mbps' -f $Result.Adapter.Name, $Result.Adapter.LinkMbps))
    }

    foreach ($pair in @(@('Upload', 'Sent to it'), @('Download', 'Received'))) {
        $measure = $Result.($pair[0])
        if ($measure) {
            $lines.Add(('{0,-15} {1} Mbps  ({2} in {3:N1} s)' -f $pair[1], $measure.Mbps, (Format-TkBytes -Bytes $measure.Bytes), ($measure.Milliseconds / 1000.0)))
        }
    }

    $lines.Add('')

    if ($Result.Error) {
        $lines.Add(('The test did not complete: {0}' -f $Result.Error))
        $lines.Add('')
        $lines.Add('On the other machine, open the toolkit, Network > Admin tools, and click "Listen for a test" first.')
        $lines.Add('It waits two minutes. If it is listening and nothing arrives, its firewall is blocking the port:')
        $lines.Add('accept the temporary rule it offers, and check that its network is marked Private rather than Public.')
    }

    $rates = @(@($Result.Upload, $Result.Download) | Where-Object { $_ } | ForEach-Object { $_.Mbps })

    if ($rates.Count -gt 0 -and $Result.SameMachine) {
        $lines.Add('This is the same machine: the traffic never left it, so the rate is that of its memory, not of the network.')
        $lines.Add('Run Listen for a test on another machine and enter its address here.')
    }
    elseif ($rates.Count -gt 0) {
        $linkMbps = if ($Result.Adapter) { [double] $Result.Adapter.LinkMbps } else { 0 }
        $wireless = [bool] ($Result.Adapter -and $Result.Adapter.Wireless)
        $verdict  = Get-TkThroughputVerdict -Mbps ([double] ($rates | Measure-Object -Maximum).Maximum) -LinkMbps $linkMbps -Wireless:$wireless

        $lines.Add($verdict.Text)
        $lines.Add('')
        $lines.Add('Measured memory to memory: a file copy slower than this is held back by a disk or the sharing protocol, not by the network.')
        $lines.Add('The slower of the two machines, or of the links between them, sets the rate.')
    }

    return ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Formats what the listener served.

.OUTPUTS
    System.String
#>
function Format-TkThroughputListenerText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Result
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('LAN throughput test, listening side')
    $lines.Add('-' * 60)
    $lines.Add('')

    if ($Result.Error -and @($Result.Sessions).Count -eq 0) {
        $lines.Add($Result.Error)
    }

    foreach ($session in @($Result.Sessions)) {
        $what = if ($session.Direction -eq 'UP') { 'Received from' } else { 'Sent to' }
        $lines.Add(('{0,-14} {1,-16} {2} Mbps  ({3} in {4:N1} s)' -f $what, $session.Remote, $session.Mbps, (Format-TkBytes -Bytes $session.Bytes), ($session.Milliseconds / 1000.0)))
    }

    if (@($Result.Sessions).Count -gt 0 -and $Result.Error) {
        $lines.Add($Result.Error)
    }

    if (@($Result.Refused).Count -gt 0) {
        $lines.Add('')
        $lines.Add(('Refused: {0}. Only a toolkit test from the local network is answered.' -f (@($Result.Refused) -join ', ')))
    }

    if ($Result.TimedOut -and @($Result.Sessions).Count -eq 0) {
        $lines.Add('No test arrived in time, and the port is closed again.')
        $lines.Add('If the other machine tried, the firewall here probably blocked it: accept the temporary rule next time,')
        $lines.Add('and check that this network is marked Private rather than Public.')
    }
    else {
        $lines.Add('')
        $lines.Add('The port is closed again. The other machine shows the full result.')
    }

    return ($lines -join [Environment]::NewLine)
}
