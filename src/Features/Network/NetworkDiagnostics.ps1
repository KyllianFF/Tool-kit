<#
    Toolkit - Features / Network diagnostics for administrators

    The measurements a network administrator takes when a link is up but
    something above it is wrong: what fits through the path, how bad the loss
    is, where the packets stop, and what certificate the other end presents.

    Everything here uses System.Net directly rather than shelling out to
    ping.exe or tracert.exe. Parsing localised console output is how these
    tools break on a French or German Windows, and the managed API gives the
    round trip time and the reply status as data instead of as text.
#>

<#
.SYNOPSIS
    Finds the largest packet that crosses a path without fragmentation.

.DESCRIPTION
    Binary searches the ICMP payload size with the do-not-fragment bit set.
    The MTU is the payload that still gets through plus 28 bytes of IPv4 and
    ICMP headers.

    This is the measurement that explains the classic complaint "the VPN
    connects, small things work, file copies and web pages hang". A tunnel
    adds overhead; when the resulting packet exceeds the path MTU and the
    ICMP "fragmentation needed" message is filtered somewhere, TCP never
    learns to send less and the transfer stalls forever.

    A path that drops ICMP entirely cannot be measured. That is reported as
    such rather than as an MTU of zero.

.PARAMETER ComputerName
    Destination to measure towards.

.PARAMETER Minimum
    Smallest MTU to consider. 576 is the IPv4 minimum every host must accept.

.PARAMETER Maximum
    Largest MTU to consider. 1500 is standard Ethernet; raise it to 9000 to
    verify a jumbo frame path.

.PARAMETER TimeoutMilliseconds
    Per probe timeout.

.OUTPUTS
    PSCustomObject with PathMtu, Reachable, ProbeCount and an interpretation.

.EXAMPLE
    Test-TkPathMtu -ComputerName 'fileserver01'

.EXAMPLE
    Test-TkPathMtu -ComputerName '10.0.0.1' -Maximum 9000
#>
function Test-TkPathMtu {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter()]
        [ValidateRange(68, 9000)]
        [int] $Minimum = 576,

        [Parameter()]
        [ValidateRange(68, 9216)]
        [int] $Maximum = 1500,

        [Parameter()]
        [ValidateRange(200, 10000)]
        [int] $TimeoutMilliseconds = 1500
    )

    if ($Minimum -ge $Maximum) {
        throw 'The minimum MTU must be smaller than the maximum.'
    }

    $probes = 0

    try {
        # A reachability check first. Without it, a firewall that drops all
        # ICMP would be reported as an MTU below the IPv4 minimum rather than
        # as an unmeasurable path.
        $probes++

        if (-not (Test-TkMtuProbe -ComputerName $ComputerName -Mtu $Minimum -TimeoutMilliseconds $TimeoutMilliseconds)) {

            Write-TkLog -Level Warning -Category 'Network' -Message (
                'No ICMP answer from {0} even at the minimum size. The path MTU cannot be measured.' -f $ComputerName
            )

            return [pscustomobject]@{
                ComputerName   = $ComputerName
                Reachable      = $false
                PathMtu        = $null
                ProbeCount     = $probes
                Interpretation = 'No ICMP reply at any size. Either the host is down, or ICMP echo is filtered along the path, which also means real Path MTU Discovery cannot work here.'
            }
        }

        $probes++

        if (Test-TkMtuProbe -ComputerName $ComputerName -Mtu $Maximum -TimeoutMilliseconds $TimeoutMilliseconds) {

            Write-TkLog -Level Information -Category 'Network' -Message (
                'Path MTU to {0} is at least {1}.' -f $ComputerName, $Maximum
            )

            return [pscustomobject]@{
                ComputerName   = $ComputerName
                Reachable      = $true
                PathMtu        = $Maximum
                ProbeCount     = $probes
                Interpretation = 'The whole search range passes. Raise -Maximum to look for a larger MTU.'
            }
        }

        # Binary search on the invariant that low always passes and high
        # always fails, so the answer is low when they become adjacent.
        $low  = $Minimum
        $high = $Maximum

        while (($high - $low) -gt 1) {

            $middle  = [int](($low + $high) / 2)
            $probes++

            if (Test-TkMtuProbe -ComputerName $ComputerName -Mtu $middle -TimeoutMilliseconds $TimeoutMilliseconds) {
                $low = $middle
            }
            else {
                $high = $middle
            }
        }

        $interpretation = 'Standard Ethernet path.'

        if ($low -lt 1500) {
            # 40 bytes of IPv4 and TCP header come off the MTU to give the MSS.
            $interpretation = 'Below 1500. Something on the path encapsulates: a VPN, PPPoE, or a tunnel. Clamp the TCP MSS to {0} on that interface to stop large transfers stalling.' -f ($low - 40)
        }
        elseif ($low -gt 1500) {
            $interpretation = 'Jumbo frames are carried end to end on this path.'
        }

        Write-TkLog -Level Information -Category 'Network' -Message (
            'Path MTU to {0}: {1} bytes, found in {2} probes.' -f $ComputerName, $low, $probes
        )

        return [pscustomobject]@{
            ComputerName   = $ComputerName
            Reachable      = $true
            PathMtu        = $low
            ProbeCount     = $probes
            Interpretation = $interpretation
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Path MTU discovery failed: {0}' -f $_.Exception.Message
        )

        return [pscustomobject]@{
            ComputerName   = $ComputerName
            Reachable      = $false
            PathMtu        = $null
            ProbeCount     = $probes
            Interpretation = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Sends one do-not-fragment echo of a given MTU.

.DESCRIPTION
    The single probe behind Test-TkPathMtu, kept separate so the search reads
    as a search and the byte arithmetic lives in one place: an MTU carries
    28 fewer bytes of payload, being 20 of IPv4 header and 8 of ICMP.

.OUTPUTS
    System.Boolean - $true when a packet of that size crossed the path whole.
#>
function Test-TkMtuProbe {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter(Mandatory)]
        [int] $Mtu,

        [Parameter()]
        [int] $TimeoutMilliseconds = 1500
    )

    $ping    = New-Object System.Net.NetworkInformation.Ping
    $options = New-Object System.Net.NetworkInformation.PingOptions
    $options.DontFragment = $true

    try {
        $buffer = [byte[]]::new($Mtu - 28)
        $reply  = $ping.Send($ComputerName, $TimeoutMilliseconds, $buffer, $options)

        return ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    }
    catch {
        # A name that will not resolve throws; anything else is a failed probe.
        if ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) {
            throw
        }

        return $false
    }
    finally {
        $ping.Dispose()
    }
}

<#
.SYNOPSIS
    Sends a Wake-on-LAN magic packet.

.DESCRIPTION
    The packet is six 0xFF bytes followed by the target MAC repeated sixteen
    times, sent as a UDP broadcast. It is sent to the broadcast address
    because a sleeping machine has no ARP entry and cannot be addressed
    directly.

    Two things this cannot do, and they are the usual reasons it "does not
    work": a broadcast does not cross a router unless the router is
    configured to forward directed broadcasts, and the target must have Wake
    on LAN enabled in both its firmware and its adapter power settings.

.PARAMETER MacAddress
    Target MAC, in any common separator style.

.PARAMETER BroadcastAddress
    Where to send it. Defaults to the all-subnets broadcast; set it to the
    directed broadcast of the target subnet, for example 192.168.10.255, when
    waking a machine on another VLAN through a router that relays it.

.PARAMETER Port
    UDP port. 9 by convention, 7 on some hardware.

.OUTPUTS
    System.Boolean

.EXAMPLE
    Send-TkWakeOnLan -MacAddress '00-1A-2B-3C-4D-5E'

.EXAMPLE
    Send-TkWakeOnLan -MacAddress '001A2B3C4D5E' -BroadcastAddress '10.20.30.255'
#>
function Send-TkWakeOnLan {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $MacAddress,

        [Parameter()]
        [string] $BroadcastAddress = '255.255.255.255',

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $Port = 9
    )

    $clean = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()

    if ($clean.Length -ne 12) {

        Write-TkLog -Level Error -Category 'Network' -Message (
            '"{0}" is not a 48 bit MAC address.' -f $MacAddress
        )

        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($clean, 'Send a Wake-on-LAN packet')) {
        return $false
    }

    $mac = for ($i = 0; $i -lt 12; $i += 2) {
        [Convert]::ToByte($clean.Substring($i, 2), 16)
    }

    $mac = @($mac)

    # Six 0xFF bytes, then the MAC sixteen times: 102 bytes in total.
    $packet = [byte[]]::new(102)

    for ($i = 0; $i -lt 6; $i++) {
        $packet[$i] = 0xFF
    }

    for ($repeat = 0; $repeat -lt 16; $repeat++) {
        for ($i = 0; $i -lt 6; $i++) {
            $packet[6 + ($repeat * 6) + $i] = $mac[$i]
        }
    }

    $client = New-Object System.Net.Sockets.UdpClient

    try {
        $client.EnableBroadcast = $true
        $client.Connect($BroadcastAddress, $Port)

        [void] $client.Send($packet, $packet.Length)

        Write-TkLog -Level Information -Category 'Network' -Message (
            'Magic packet sent to {0} via {1}:{2}.' -f $clean, $BroadcastAddress, $Port
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not send the magic packet: {0}' -f $_.Exception.Message
        )

        return $false
    }
    finally {
        $client.Close()
    }
}

<#
.SYNOPSIS
    Measures loss, latency and jitter towards a host.

.DESCRIPTION
    What a single ping cannot tell you. Averages hide the problem: a link
    that answers in 8 ms on average but swings between 2 and 400 ms is
    unusable for voice, and one that loses 2 percent of packets will ruin a
    file transfer while looking healthy in a ping test.

    Jitter is reported as the mean absolute difference between consecutive
    round trips, which is the figure voice and video quality actually depend
    on.

.PARAMETER ComputerName
    Target host.

.PARAMETER Count
    Number of echoes to send.

.PARAMETER IntervalMilliseconds
    Delay between echoes. Keep it at 200 or more on a production link.

.OUTPUTS
    PSCustomObject

.EXAMPLE
    Test-TkLinkQuality -ComputerName '8.8.8.8' -Count 50
#>
function Test-TkLinkQuality {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter()]
        [ValidateRange(4, 500)]
        [int] $Count = 20,

        [Parameter()]
        [ValidateRange(0, 5000)]
        [int] $IntervalMilliseconds = 200,

        [Parameter()]
        [ValidateRange(200, 10000)]
        [int] $TimeoutMilliseconds = 2000
    )

    Write-TkLog -Level Information -Category 'Network' -Message (
        'Measuring link quality to {0} over {1} echoes.' -f $ComputerName, $Count
    )

    $ping     = New-Object System.Net.NetworkInformation.Ping
    $times    = @()
    $received = 0

    try {
        for ($i = 0; $i -lt $Count; $i++) {

            try {
                $reply = $ping.Send($ComputerName, $TimeoutMilliseconds)

                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $received++
                    $times += [double] $reply.RoundtripTime
                }
            }
            catch {
                # A resolution failure on the first echo is fatal; a single
                # lost packet is data, not an error.
                if ($i -eq 0) {
                    throw
                }
            }

            if ($IntervalMilliseconds -gt 0 -and $i -lt ($Count - 1)) {
                Start-Sleep -Milliseconds $IntervalMilliseconds
            }
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Link quality test failed: {0}' -f $_.Exception.Message
        )

        return [pscustomobject]@{
            ComputerName = $ComputerName
            Sent         = $Count
            Received     = 0
            LossPercent  = 100
            Assessment   = $_.Exception.Message
        }
    }
    finally {
        $ping.Dispose()
    }

    $lost        = $Count - $received
    $lossPercent = [math]::Round(($lost / $Count) * 100, 1)

    # Jitter as the mean absolute deviation between consecutive samples,
    # which is what RFC 3550 calls interarrival jitter in spirit.
    $jitter = 0

    if ($times.Count -gt 1) {

        $differences = @()

        for ($i = 1; $i -lt $times.Count; $i++) {
            $differences += [math]::Abs($times[$i] - $times[$i - 1])
        }

        $jitter = [math]::Round(($differences | Measure-Object -Average).Average, 1)
    }

    $statistics = $times | Measure-Object -Minimum -Maximum -Average

    $assessment = 'Healthy.'

    if ($received -eq 0) {
        $assessment = 'No reply at all. The host is down, or ICMP is filtered.'
    }
    elseif ($lossPercent -ge 5) {
        $assessment = 'Loss above 5 percent. Expect stalled transfers and dropped calls. Check the physical layer and the interface error counters first.'
    }
    elseif ($lossPercent -gt 0) {
        $assessment = 'Occasional loss. Tolerable for browsing, not for voice.'
    }
    elseif ($jitter -gt 30) {
        $assessment = 'No loss but high jitter. Voice and video will suffer; look for congestion or a saturated uplink.'
    }
    elseif ($statistics.Average -gt 150) {
        $assessment = 'Stable but high latency. Expected on a satellite or long haul path, a problem on a local one.'
    }

    return [pscustomobject]@{
        ComputerName = $ComputerName
        Sent         = $Count
        Received     = $received
        Lost         = $lost
        LossPercent  = $lossPercent
        MinimumMs    = if ($times.Count) { [int] $statistics.Minimum } else { $null }
        AverageMs    = if ($times.Count) { [math]::Round($statistics.Average, 1) } else { $null }
        MaximumMs    = if ($times.Count) { [int] $statistics.Maximum } else { $null }
        JitterMs     = $jitter
        Assessment   = $assessment
    }
}

<#
.SYNOPSIS
    Traces the path to a host, with per hop timing.

.DESCRIPTION
    Sends echoes with an increasing TTL and records which router reports the
    expiry. Each hop is probed several times, because a single sample says
    nothing about whether a slow hop is really slow or just deprioritising
    the ICMP it has to generate itself.

    A hop that shows no reply is usually a router configured not to answer,
    not a break in the path. What matters is whether the hops after it
    answer.

.PARAMETER ComputerName
    Destination.

.PARAMETER MaxHops
    Give up after this many hops.

.PARAMETER Queries
    Probes per hop.

.PARAMETER ResolveNames
    Reverse resolve each hop. Adds a DNS round trip per hop.

.OUTPUTS
    PSCustomObject[]

.EXAMPLE
    Get-TkTraceRoute -ComputerName 'www.example.com' -ResolveNames
#>
function Get-TkTraceRoute {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int] $MaxHops = 30,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int] $Queries = 3,

        [Parameter()]
        [ValidateRange(200, 10000)]
        [int] $TimeoutMilliseconds = 2000,

        [Parameter()]
        [switch] $ResolveNames
    )

    Write-TkLog -Level Information -Category 'Network' -Message (
        'Tracing the path to {0}.' -f $ComputerName
    )

    $ping    = New-Object System.Net.NetworkInformation.Ping
    $buffer  = [byte[]]::new(32)
    $results = @()

    try {
        for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {

            $options = New-Object System.Net.NetworkInformation.PingOptions($ttl, $false)

            $address = ''
            $times   = @()
            $status  = 'No reply'

            for ($query = 0; $query -lt $Queries; $query++) {

                try {
                    $reply = $ping.Send($ComputerName, $TimeoutMilliseconds, $buffer, $options)

                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::TtlExpired -or
                        $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {

                        $address = $reply.Address.ToString()
                        $times  += [double] $reply.RoundtripTime
                        $status  = [string] $reply.Status
                    }
                    elseif ($reply.Address -and $reply.Address.ToString() -ne '0.0.0.0') {

                        $address = $reply.Address.ToString()
                        $status  = [string] $reply.Status
                    }
                }
                catch {
                    # A hop that refuses to answer is normal. Keep tracing.
                    $null = $_
                }
            }

            $hostName = ''

            if ($ResolveNames -and $address) {

                try {
                    $hostName = [System.Net.Dns]::GetHostEntry($address).HostName
                }
                catch {
                    $null = $_
                }
            }

            $results += [pscustomobject]@{
                Hop       = $ttl
                Address   = if ($address) { $address } else { '*' }
                HostName  = $hostName
                AverageMs = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
                BestMs    = if ($times.Count) { [int] ($times | Measure-Object -Minimum).Minimum } else { $null }
                Replies   = '{0}/{1}' -f $times.Count, $Queries
                Status    = $status
            }

            if ($status -eq 'Success') {

                Write-TkLog -Level Information -Category 'Network' -Message (
                    'Destination reached in {0} hops.' -f $ttl
                )

                break
            }
        }
    }
    finally {
        $ping.Dispose()
    }

    return , $results
}

<#
.SYNOPSIS
    Inspects the TLS certificate a remote endpoint presents.

.DESCRIPTION
    Connects, completes the handshake, and reports the certificate, the
    negotiated protocol and the chain status. The expiry date is the number
    everyone actually wants: an expired certificate on an internal service is
    the single most common self inflicted outage.

    Certificate validation is deliberately bypassed during the handshake.
    That is not a weakness here: the point is to inspect what is presented,
    including a chain that does not validate, and no data is ever sent over
    the connection. The chain is then evaluated separately and reported
    honestly.

.PARAMETER ComputerName
    Host to connect to.

.PARAMETER Port
    TLS port. 443 for HTTPS, 636 for LDAPS, 993 for IMAPS, 8443 and 5986 for
    management interfaces.

.OUTPUTS
    PSCustomObject

.EXAMPLE
    Get-TkTlsCertificate -ComputerName 'intranet.example.com'

.EXAMPLE
    Get-TkTlsCertificate -ComputerName 'dc01' -Port 636
#>
function Get-TkTlsCertificate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $Port = 443,

        [Parameter()]
        [ValidateRange(1000, 30000)]
        [int] $TimeoutMilliseconds = 8000
    )

    $client     = New-Object System.Net.Sockets.TcpClient
    $sslStream  = $null
    $certificate = $null

    try {
        $connect = $client.BeginConnect($ComputerName, $Port, $null, $null)

        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            throw ('No answer from {0}:{1} within {2} ms.' -f $ComputerName, $Port, $TimeoutMilliseconds)
        }

        $client.EndConnect($connect)

        # Accept whatever is presented so a broken chain can be reported
        # rather than hidden behind a handshake failure. Nothing is sent.
        # Parameters deliberately not named $sender or $errors: both are
        # automatic variables in PowerShell.
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($callbackSource, $remoteCertificate, $remoteChain, $policyErrors)
            return $true
        }

        $sslStream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $callback)
        $sslStream.AuthenticateAsClient($ComputerName)

        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $sslStream.RemoteCertificate
        )

        # --- Subject alternative names ------------------------------------
        # X509Extension.Format localises its labels: the same extension reads
        # "DNS Name=" on an English system and "Nom DNS=" on a French one.
        # Only the value after the equals sign is kept, so the result is the
        # same whatever the machine language.
        $subjectAltNames = ''

        foreach ($extension in $certificate.Extensions) {

            if ($extension.Oid.Value -ne '2.5.29.17') {
                continue
            }

            $names = foreach ($entry in ($extension.Format($false) -split ',\s*')) {

                $separator = $entry.IndexOf('=')

                if ($separator -ge 0) {
                    $entry.Substring($separator + 1).Trim()
                }
                else {
                    $entry.Trim()
                }
            }

            $subjectAltNames = (@($names | Where-Object { $_ }) -join ', ')
        }

        # --- Chain evaluation ---------------------------------------------
        $chainStatus = 'Not evaluated'

        try {
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

            if ($chain.Build($certificate)) {
                $chainStatus = 'Valid and trusted by this machine'
            }
            else {
                $reasons = @($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() })
                $chainStatus = 'Not trusted: ' + (($reasons | Where-Object { $_ }) -join '; ')
            }
        }
        catch {
            $chainStatus = 'Chain could not be built: {0}' -f $_.Exception.Message
        }

        $daysRemaining = [int] ($certificate.NotAfter - (Get-Date)).TotalDays

        $verdict = 'Valid for {0} more days.' -f $daysRemaining

        if ($daysRemaining -lt 0) {
            $verdict = 'EXPIRED {0} days ago.' -f [math]::Abs($daysRemaining)
        }
        elseif ($daysRemaining -le 14) {
            $verdict = 'Expires in {0} days. Renew it now.' -f $daysRemaining
        }
        elseif ($daysRemaining -le 30) {
            $verdict = 'Expires in {0} days. Schedule the renewal.' -f $daysRemaining
        }

        $level = if ($daysRemaining -le 14) { 'Warning' } else { 'Information' }

        Write-TkLog -Level $level -Category 'Network' -Message (
            'Certificate for {0}:{1} - {2}' -f $ComputerName, $Port, $verdict
        )

        return [pscustomobject]@{
            ComputerName    = $ComputerName
            Port            = $Port
            Subject         = $certificate.Subject
            Issuer          = $certificate.Issuer
            SubjectAltNames = $subjectAltNames
            NotBefore       = $certificate.NotBefore
            NotAfter        = $certificate.NotAfter
            DaysRemaining   = $daysRemaining
            Thumbprint      = $certificate.Thumbprint
            SerialNumber    = $certificate.SerialNumber
            SignatureAlgorithm = $certificate.SignatureAlgorithm.FriendlyName
            KeySize         = $certificate.PublicKey.Key.KeySize
            Protocol        = [string] $sslStream.SslProtocol
            CipherAlgorithm = [string] $sslStream.CipherAlgorithm
            ChainStatus     = $chainStatus
            Verdict         = $verdict
            SelfSigned      = ($certificate.Subject -eq $certificate.Issuer)
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not read the certificate from {0}:{1}: {2}' -f $ComputerName, $Port, $_.Exception.Message
        )

        return [pscustomobject]@{
            ComputerName = $ComputerName
            Port         = $Port
            Verdict      = 'Failed: {0}' -f $_.Exception.Message
        }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        $client.Close()
    }
}

<#
.SYNOPSIS
    Names the manufacturer that owns a MAC address prefix.

.DESCRIPTION
    Resolves the first three octets, the organisationally unique identifier,
    against a table of the vendors met on a corporate network. It is a
    deliberately small table, not the full IEEE registry: it answers "is that
    unknown device a printer, an access point or a virtual machine" without
    shipping a megabyte of data or calling out to a web service.

.PARAMETER MacAddress
    MAC address in any common separator style.

.OUTPUTS
    System.String
#>
function Get-TkMacVendor {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $MacAddress
    )

    if ([string]::IsNullOrWhiteSpace($MacAddress)) {
        return ''
    }

    $clean = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()

    if ($clean.Length -lt 6) {
        return ''
    }

    $oui = $clean.Substring(0, 6)

    # A locally administered address has the second least significant bit of
    # the first octet set. It belongs to no vendor, and saying so is more
    # useful than reporting nothing.
    $firstOctet = [Convert]::ToByte($clean.Substring(0, 2), 16)

    $table = Get-TkOuiTable

    if ($table.ContainsKey($oui)) {
        return $table[$oui]
    }

    if (($firstOctet -band 0x02) -eq 0x02) {
        return 'Locally administered (randomised or assigned by software)'
    }

    return 'Unknown vendor'
}

<#
.SYNOPSIS
    Returns the OUI lookup table.

.DESCRIPTION
    Kept in code rather than in a catalog so neighbour lookups keep working
    in a build with no data files reachable. Covers the hardware that turns
    up on a corporate LAN: hypervisors, network vendors, printers, phones,
    cameras and the common laptop manufacturers.

.OUTPUTS
    System.Collections.Hashtable
#>
function Get-TkOuiTable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        # --- Virtualisation, the entries most worth recognising on a LAN ----
        '000C29' = 'VMware'
        '005056' = 'VMware'
        '000569' = 'VMware'
        '001C14' = 'VMware'
        '00155D' = 'Microsoft Hyper-V'
        '080027' = 'Oracle VirtualBox'
        '0A0027' = 'Oracle VirtualBox'
        '525400' = 'QEMU or KVM'
        '001C42' = 'Parallels'
        '00163E' = 'Xen'
        '0242AC' = 'Docker container'

        # --- Network equipment ---------------------------------------------
        '00000C' = 'Cisco'
        '000142' = 'Cisco'
        '0001C9' = 'Cisco'
        '001B0C' = 'Cisco'
        '001A1E' = 'Aruba Networks'
        '6CF37F' = 'Aruba Networks'
        '000B86' = 'Aruba Networks'
        '18649C' = 'HPE Aruba'
        '9C8CD8' = 'HPE'
        '0017A4' = 'HPE'
        '00090F' = 'Fortinet'
        '085B0E' = 'Fortinet'
        '906CAC' = 'Fortinet'
        '0418D6' = 'Ubiquiti'
        '24A43C' = 'Ubiquiti'
        '788A20' = 'Ubiquiti'
        'FCECDA' = 'Ubiquiti'
        '687251' = 'Ubiquiti'
        '74ACB9' = 'Ubiquiti'
        '4C5E0C' = 'MikroTik'
        '6C3B6B' = 'MikroTik'
        '48A98A' = 'MikroTik'
        'DC2C6E' = 'MikroTik'
        '000E83' = 'Juniper'
        '2C6BF5' = 'Juniper'
        '84B59C' = 'Juniper'
        '001F12' = 'Juniper'
        '00E0FC' = 'Huawei'
        '000FE2' = 'H3C'
        '744401' = 'Netgear'
        '00907F' = 'WatchGuard'

        # --- Adapters and single board computers ---------------------------
        '00E04C' = 'Realtek'
        '001B21' = 'Intel'
        '00A0C9' = 'Intel'
        '8C1645' = 'Intel'
        '3C58C2' = 'Intel'
        'A0369F' = 'Intel'
        '00D0B7' = 'Intel'
        '000AF7' = 'Broadcom'
        '001018' = 'Broadcom'
        '005043' = 'Marvell'
        'B827EB' = 'Raspberry Pi'
        'DCA632' = 'Raspberry Pi'
        'E45F01' = 'Raspberry Pi'
        '2CCF67' = 'Raspberry Pi'

        # --- Endpoints -----------------------------------------------------
        '18C04D' = 'Hewlett Packard'
        '3CD92B' = 'Hewlett Packard'
        '9457A5' = 'Hewlett Packard'
        'B499BA' = 'Hewlett Packard'
        'E4E749' = 'Hewlett Packard'
        '2C4138' = 'Hewlett Packard'
        '005C86' = 'Dell'
        '00188B' = 'Dell'
        '14FEB5' = 'Dell'
        'B8CA3A' = 'Dell'
        'F8BC12' = 'Dell'
        '00219B' = 'Dell'
        '18DBF2' = 'Dell'
        '002268' = 'Lenovo'
        '3897D6' = 'Lenovo'
        '54EE75' = 'Lenovo'
        '8CDCD4' = 'Lenovo'
        '00D861' = 'Micro-Star MSI'
        '3C0754' = 'Apple'
        'F01898' = 'Apple'
        'A45E60' = 'Apple'
        '7CD1C3' = 'Apple'
        '040CCE' = 'Apple'
        '001451' = 'Apple'
        'D0E140' = 'Apple'
        '1C1AC0' = 'Apple'
        '8C8590' = 'Apple'
        '001632' = 'Samsung'
        '5CF6DC' = 'Samsung'
        '8C7712' = 'Samsung'
        '0017C9' = 'Samsung'
        '00E091' = 'LG Electronics'

        # --- Printers, telephony, cameras ----------------------------------
        '0000AA' = 'Xerox'
        '9C934E' = 'Xerox'
        '002673' = 'Canon'
        '001E8F' = 'Canon'
        '008077' = 'Brother'
        '3C2AF4' = 'Brother'
        '000048' = 'Epson'
        '9C441C' = 'Konica Minolta'
        '00206B' = 'Konica Minolta'
        '002481' = 'Ricoh'
        '583879' = 'Ricoh'
        '0004F2' = 'Polycom'
        '64167F' = 'Polycom'
        '0060B9' = 'NEC'
        '001344' = 'Hikvision'
        '4CBD8F' = 'Hikvision'
        'BCAD28' = 'Hikvision'
        '000F7C' = 'Axis Communications'
        'ACCC8E' = 'Axis Communications'
        'B8A44F' = 'Axis Communications'
        '000BF4' = 'Dahua'
        '9C1463' = 'Dahua'
    }
}

<#
.SYNOPSIS
    Returns the neighbour cache with vendor names resolved.

.DESCRIPTION
    The ARP table, made readable. A row whose vendor says VMware on a
    physical network segment, or Raspberry Pi on a corporate VLAN, is the
    kind of thing worth knowing about.

.PARAMETER ReachableOnly
    Only rows whose state is Reachable or Stale, which are the ones that
    correspond to a device that recently spoke.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkNeighborTable {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [switch] $ReachableOnly
    )

    $results = @()

    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
                     Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' }

        if ($ReachableOnly) {
            $neighbors = $neighbors | Where-Object { $_.State -in @('Reachable', 'Stale', 'Permanent') }
        }

        foreach ($neighbor in $neighbors) {

            $results += [pscustomobject]@{
                Address    = $neighbor.IPAddress
                MacAddress = $neighbor.LinkLayerAddress
                Vendor     = Get-TkMacVendor -MacAddress $neighbor.LinkLayerAddress
                State      = [string] $neighbor.State
                Interface  = $neighbor.InterfaceAlias
            }
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Network' -Message (
            'Could not read the neighbour cache: {0}' -f $_.Exception.Message
        )
    }

    return , @($results | Sort-Object -Property { [version] ($_.Address -replace '[^0-9.]', '') } -ErrorAction SilentlyContinue)
}
