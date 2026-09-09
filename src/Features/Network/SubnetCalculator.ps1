<#
    Toolkit - Features / IPv4 subnet calculator

    Pure arithmetic: no CIM, no network access, no elevation. That is what
    makes this file the one with real unit test coverage, and it is also why
    the maths lives here rather than inside a UI event handler.

    All internal work is done on unsigned 32 bit integers.

    Deliberately no bit shifting. In PowerShell the literal 0xFFFFFFFF is an
    Int32 holding -1, and the shift operators promote to Int64, so the usual
    "shift then mask" idiom silently produces values outside the 32 bit range.
    Masks are therefore derived arithmetically and conversions go through
    BitConverter, which has no sign surprises.
#>

<#
.SYNOPSIS
    Returns the 32 bit value of a subnet mask for a prefix length.

.DESCRIPTION
    A /24 mask is every address minus the host range: 4294967295 - (2^8 - 1).
    Expressed this way the arithmetic never leaves the unsigned range.

.OUTPUTS
    System.UInt32
#>
function Get-TkMaskValue {
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 32)]
        [int] $PrefixLength
    )

    $hostBits  = 32 - $PrefixLength
    $hostRange = [uint64] ([math]::Pow(2, $hostBits)) - 1

    return [uint32] ([uint64] 4294967295 - $hostRange)
}

<#
.SYNOPSIS
    Returns the 32 bit value of the wildcard mask for a prefix length.

.OUTPUTS
    System.UInt32
#>
function Get-TkWildcardValue {
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 32)]
        [int] $PrefixLength
    )

    return [uint32] ([uint64] ([math]::Pow(2, 32 - $PrefixLength)) - 1)
}

<#
.SYNOPSIS
    Converts a dotted quad IPv4 address into a 32 bit integer.

.OUTPUTS
    System.UInt32
#>
function ConvertTo-TkIPv4Integer {
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory)]
        [string] $Address
    )

    $parsed = $null

    if (-not [System.Net.IPAddress]::TryParse($Address, [ref] $parsed)) {
        throw ('"{0}" is not a valid IP address.' -f $Address)
    }

    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw ('"{0}" is not an IPv4 address.' -f $Address)
    }

    # GetAddressBytes returns network order; BitConverter reads host order,
    # which on x86 and ARM is little endian, hence the reverse.
    $bytes = $parsed.GetAddressBytes()
    [array]::Reverse($bytes)

    return [BitConverter]::ToUInt32($bytes, 0)
}

<#
.SYNOPSIS
    Converts a 32 bit integer into a dotted quad IPv4 address.

.OUTPUTS
    System.String
#>
function ConvertFrom-TkIPv4Integer {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [uint32] $Value
    )

    $bytes = [BitConverter]::GetBytes([uint32] $Value)
    [array]::Reverse($bytes)

    return ($bytes -join '.')
}

<#
.SYNOPSIS
    Converts a prefix length into a subnet mask.

.PARAMETER PrefixLength
    CIDR prefix, 0 to 32.

.OUTPUTS
    System.String
#>
function ConvertTo-TkSubnetMask {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 32)]
        [int] $PrefixLength
    )

    return (ConvertFrom-TkIPv4Integer -Value (Get-TkMaskValue -PrefixLength $PrefixLength))
}

<#
.SYNOPSIS
    Converts a subnet mask into a prefix length.

.DESCRIPTION
    Rejects non contiguous masks such as 255.0.255.0: they are invalid in
    CIDR and accepting them silently would produce nonsense ranges.

.OUTPUTS
    System.Int32
#>
function ConvertFrom-TkSubnetMask {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string] $SubnetMask
    )

    $value = ConvertTo-TkIPv4Integer -Address $SubnetMask

    # Converted through Int64: a mask such as 255.0.0.0 does not fit in an
    # Int32 and casting to one throws instead of returning a negative value.
    $binary = [Convert]::ToString([int64] $value, 2).PadLeft(32, '0')

    if ($binary -notmatch '^1*0*$') {
        throw ('"{0}" is not a contiguous subnet mask.' -f $SubnetMask)
    }

    return ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

<#
.SYNOPSIS
    Computes every property of an IPv4 subnet.

.DESCRIPTION
    Accepts CIDR notation (192.168.1.10/24), an address with a mask, or an
    address and a prefix length. Returns network address, broadcast, usable
    range, host count, wildcard mask, class and scope.

    Point to point (/31) and host (/32) prefixes are handled as the RFC
    intends rather than reported as having negative host counts, which is the
    classic bug in home grown calculators.

.PARAMETER Address
    IPv4 address, optionally in CIDR form.

.PARAMETER PrefixLength
    Prefix length when not given in the address.

.PARAMETER SubnetMask
    Subnet mask when a prefix length is not used.

.OUTPUTS
    PSCustomObject

.EXAMPLE
    Get-TkSubnetInfo -Address '10.20.30.40/22'
#>
function Get-TkSubnetInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Address,

        [Parameter()]
        [ValidateRange(0, 32)]
        [int] $PrefixLength = -1,

        [Parameter()]
        [string] $SubnetMask
    )

    # --- Normalise the input ---------------------------------------------
    if ($Address -match '^(?<ip>[^/]+)/(?<prefix>\d{1,2})$') {

        $Address      = $Matches['ip']
        $PrefixLength = [int] $Matches['prefix']

        if ($PrefixLength -gt 32) {
            throw ('Prefix length {0} is out of range.' -f $PrefixLength)
        }
    }

    if ($PrefixLength -lt 0 -and $SubnetMask) {
        $PrefixLength = ConvertFrom-TkSubnetMask -SubnetMask $SubnetMask
    }

    if ($PrefixLength -lt 0) {
        throw 'Provide a prefix length, either in CIDR notation or with -PrefixLength or -SubnetMask.'
    }

    # --- Core arithmetic --------------------------------------------------
    $addressValue = ConvertTo-TkIPv4Integer -Address $Address
    $maskValue    = Get-TkMaskValue     -PrefixLength $PrefixLength
    $wildcard     = Get-TkWildcardValue -PrefixLength $PrefixLength

    # -band on two UInt32 values stays inside the range, so no re-masking is
    # needed here. The broadcast is the network plus the whole host range.
    $networkValue   = [uint32] ($addressValue -band $maskValue)
    $broadcastValue = [uint32] ([uint64] $networkValue + [uint64] $wildcard)

    $totalAddresses = [math]::Pow(2, 32 - $PrefixLength)

    # --- Usable range -----------------------------------------------------
    # /32 is a single host route; /31 is a point to point link where both
    # addresses are usable (RFC 3021).
    if ($PrefixLength -eq 32) {
        $firstHost  = $networkValue
        $lastHost   = $networkValue
        $usableHosts = 1
    }
    elseif ($PrefixLength -eq 31) {
        $firstHost  = $networkValue
        $lastHost   = $broadcastValue
        $usableHosts = 2
    }
    else {
        $firstHost  = $networkValue + 1
        $lastHost   = $broadcastValue - 1
        $usableHosts = $totalAddresses - 2
    }

    return [pscustomobject]@{
        Address         = ConvertFrom-TkIPv4Integer -Value $addressValue
        PrefixLength    = $PrefixLength
        SubnetMask      = ConvertFrom-TkIPv4Integer -Value $maskValue
        WildcardMask    = ConvertFrom-TkIPv4Integer -Value $wildcard
        NetworkAddress  = ConvertFrom-TkIPv4Integer -Value $networkValue
        BroadcastAddress = ConvertFrom-TkIPv4Integer -Value $broadcastValue
        FirstHost       = ConvertFrom-TkIPv4Integer -Value ([uint32] $firstHost)
        LastHost        = ConvertFrom-TkIPv4Integer -Value ([uint32] $lastHost)
        TotalAddresses  = [int64] $totalAddresses
        UsableHosts     = [int64] $usableHosts
        Cidr            = '{0}/{1}' -f (ConvertFrom-TkIPv4Integer -Value $networkValue), $PrefixLength
        AddressClass    = Get-TkAddressClass -Value $addressValue
        Scope           = Get-TkAddressScope -Value $addressValue
        BinaryMask      = ConvertTo-TkBinaryOctets -Value $maskValue
        BinaryAddress   = ConvertTo-TkBinaryOctets -Value $addressValue
    }
}

<#
.SYNOPSIS
    Returns the classful address class of an IPv4 address.

.DESCRIPTION
    Classful addressing has not been used for routing since CIDR arrived in
    1993, but the letters are still spoken daily and asked for in exams, so
    the calculator reports them.

.OUTPUTS
    System.String
#>
function Get-TkAddressClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [uint32] $Value
    )

    $firstOctet = [int] ((ConvertFrom-TkIPv4Integer -Value $Value) -split '\.')[0]

    if ($firstOctet -lt 128) { return 'A (1-126)' }
    if ($firstOctet -lt 192) { return 'B (128-191)' }
    if ($firstOctet -lt 224) { return 'C (192-223)' }
    if ($firstOctet -lt 240) { return 'D (multicast)' }

    return 'E (reserved)'
}

<#
.SYNOPSIS
    Classifies an address as private, loopback, link local, CGNAT or public.

.OUTPUTS
    System.String
#>
function Get-TkAddressScope {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [uint32] $Value
    )

    # Ranges expressed as network and prefix, evaluated most specific first.
    $ranges = @(
        @{ Network = '127.0.0.0';    Prefix = 8;  Label = 'Loopback (RFC 1122)' },
        @{ Network = '10.0.0.0';     Prefix = 8;  Label = 'Private (RFC 1918)' },
        @{ Network = '172.16.0.0';   Prefix = 12; Label = 'Private (RFC 1918)' },
        @{ Network = '192.168.0.0';  Prefix = 16; Label = 'Private (RFC 1918)' },
        @{ Network = '169.254.0.0';  Prefix = 16; Label = 'Link local / APIPA (RFC 3927)' },
        @{ Network = '100.64.0.0';   Prefix = 10; Label = 'Carrier grade NAT (RFC 6598)' },
        @{ Network = '192.0.2.0';    Prefix = 24; Label = 'Documentation (RFC 5737)' },
        @{ Network = '198.51.100.0'; Prefix = 24; Label = 'Documentation (RFC 5737)' },
        @{ Network = '203.0.113.0';  Prefix = 24; Label = 'Documentation (RFC 5737)' },
        @{ Network = '224.0.0.0';    Prefix = 4;  Label = 'Multicast (RFC 5771)' },
        @{ Network = '0.0.0.0';      Prefix = 8;  Label = 'This network (RFC 1122)' }
    )

    foreach ($range in $ranges) {

        $mask    = Get-TkMaskValue -PrefixLength $range.Prefix
        $network = ConvertTo-TkIPv4Integer -Address $range.Network

        if (($Value -band $mask) -eq $network) {
            return $range.Label
        }
    }

    return 'Public'
}

<#
.SYNOPSIS
    Renders a 32 bit value as four binary octets.

.OUTPUTS
    System.String
#>
function ConvertTo-TkBinaryOctets {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [uint32] $Value
    )

    $bytes = [BitConverter]::GetBytes([uint32] $Value)
    [array]::Reverse($bytes)

    $octets = @()

    foreach ($byte in $bytes) {
        $octets += [Convert]::ToString([int] $byte, 2).PadLeft(8, '0')
    }

    return ($octets -join '.')
}

<#
.SYNOPSIS
    Splits a network into equally sized subnets.

.DESCRIPTION
    The everyday VLAN planning task: take 10.0.0.0/16 and cut it into /24s.
    The count is capped so a careless /8 into /30 request cannot allocate
    four million objects and hang the interface.

.PARAMETER Network
    Parent network in CIDR notation.

.PARAMETER NewPrefixLength
    Prefix length of the resulting subnets.

.PARAMETER MaxResults
    Safety cap on how many subnets are returned.

.OUTPUTS
    PSCustomObject[]

.EXAMPLE
    Split-TkSubnet -Network '10.0.0.0/16' -NewPrefixLength 24
#>
function Split-TkSubnet {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Network,

        [Parameter(Mandatory)]
        [ValidateRange(1, 32)]
        [int] $NewPrefixLength,

        [Parameter()]
        [int] $MaxResults = 1024
    )

    $parent = Get-TkSubnetInfo -Address $Network

    if ($NewPrefixLength -lt $parent.PrefixLength) {
        throw ('The new prefix /{0} must be longer than the parent prefix /{1}.' -f $NewPrefixLength, $parent.PrefixLength)
    }

    $subnetCount = [math]::Pow(2, $NewPrefixLength - $parent.PrefixLength)
    $step        = [uint64] ([math]::Pow(2, 32 - $NewPrefixLength))
    $start       = [uint64] (ConvertTo-TkIPv4Integer -Address $parent.NetworkAddress)

    $truncated = $false

    if ($subnetCount -gt $MaxResults) {
        $subnetCount = $MaxResults
        $truncated   = $true

        Write-TkLog -Level Warning -Category 'Network' -Message (
            'Subnet list truncated to the first {0} entries.' -f $MaxResults
        )
    }

    $results = @()

    for ($i = 0; $i -lt $subnetCount; $i++) {

        # Accumulated in 64 bits: the last subnet of a /1 split would overflow
        # a UInt32 during the multiplication otherwise.
        $networkValue = [uint32] ($start + ([uint64] $i * $step))
        $address      = ConvertFrom-TkIPv4Integer -Value $networkValue

        $info = Get-TkSubnetInfo -Address $address -PrefixLength $NewPrefixLength

        $results += [pscustomobject]@{
            Index          = $i + 1
            Cidr           = $info.Cidr
            NetworkAddress = $info.NetworkAddress
            FirstHost      = $info.FirstHost
            LastHost       = $info.LastHost
            Broadcast      = $info.BroadcastAddress
            UsableHosts    = $info.UsableHosts
        }
    }

    if ($truncated) {
        Write-TkLog -Level Information -Category 'Network' -Message (
            'The parent network holds {0} subnets of /{1}.' -f
                [math]::Pow(2, $NewPrefixLength - $parent.PrefixLength), $NewPrefixLength
        )
    }

    return $results
}

<#
.SYNOPSIS
    Finds the smallest prefix that fits a given number of hosts.

.DESCRIPTION
    The inverse of the usual question: "I need 300 devices on this VLAN,
    what do I ask for?" Answers /23, not /24.

.PARAMETER HostCount
    Number of usable host addresses required.

.OUTPUTS
    PSCustomObject
#>
function Get-TkPrefixForHostCount {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 2147483647)]
        [int] $HostCount
    )

    for ($prefix = 32; $prefix -ge 0; $prefix--) {

        $total = [math]::Pow(2, 32 - $prefix)

        $usable = switch ($prefix) {
            32 { 1 ; break }
            31 { 2 ; break }
            default { $total - 2 }
        }

        if ($usable -ge $HostCount) {

            return [pscustomobject]@{
                RequestedHosts = $HostCount
                PrefixLength   = $prefix
                SubnetMask     = ConvertTo-TkSubnetMask -PrefixLength $prefix
                UsableHosts    = [int64] $usable
                WastedAddresses = [int64] ($usable - $HostCount)
            }
        }
    }

    throw ('No IPv4 prefix can hold {0} hosts.' -f $HostCount)
}

<#
.SYNOPSIS
    Tells whether an address belongs to a network.

.OUTPUTS
    System.Boolean

.EXAMPLE
    Test-TkAddressInSubnet -Address '10.1.2.3' -Network '10.0.0.0/8'
#>
function Test-TkAddressInSubnet {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Address,

        [Parameter(Mandatory)]
        [string] $Network
    )

    $subnet       = Get-TkSubnetInfo -Address $Network
    $addressValue = ConvertTo-TkIPv4Integer -Address $Address
    $maskValue    = ConvertTo-TkIPv4Integer -Address $subnet.SubnetMask
    $networkValue = ConvertTo-TkIPv4Integer -Address $subnet.NetworkAddress

    return (($addressValue -band $maskValue) -eq $networkValue)
}
