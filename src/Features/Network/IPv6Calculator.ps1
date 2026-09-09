<#
    Toolkit - Features / IPv6 subnet calculator

    The IPv6 counterpart of SubnetCalculator.ps1, and pure arithmetic for the
    same reason: it is the part that can be tested exhaustively.

    IPv6 needs different machinery from IPv4. A prefix can hold more
    addresses than a UInt64 can count, so sizes are carried in a BigInteger,
    and the 128 bit masking is done on the 16 byte array rather than on an
    integer. There is no broadcast address and no "minus two": every address
    in a prefix is usable, and the subnet-router anycast address is a
    convention rather than a reservation.
#>

<#
.SYNOPSIS
    Parses an IPv6 address into its 16 bytes.

.DESCRIPTION
    Rejects an IPv4 address explicitly rather than letting it through as a
    mapped address, because silently answering an IPv6 question about
    192.168.1.1 is worse than refusing.

.OUTPUTS
    System.Byte[]
#>
function ConvertTo-TkIPv6Bytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Address
    )

    $parsed = $null

    if (-not [System.Net.IPAddress]::TryParse($Address, [ref] $parsed)) {
        throw ('"{0}" is not a valid IP address.' -f $Address)
    }

    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw ('"{0}" is an IPv4 address. Use the IPv4 calculator for it.' -f $Address)
    }

    return $parsed.GetAddressBytes()
}

<#
.SYNOPSIS
    Formats 16 bytes as a compressed IPv6 address.

.OUTPUTS
    System.String
#>
function ConvertFrom-TkIPv6Bytes {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    # .NET applies the RFC 5952 rules, including the longest run of zero
    # groups, so there is no reason to reimplement the compression here.
    return (New-Object System.Net.IPAddress(, $Bytes)).ToString()
}

<#
.SYNOPSIS
    Writes an IPv6 address in its full, uncompressed form.

.DESCRIPTION
    The form to paste into an access list or a firewall that refuses the
    compressed notation, and the one to compare two addresses by eye.

.OUTPUTS
    System.String

.EXAMPLE
    Expand-TkIPv6Address -Address '2001:db8::1'
    2001:0db8:0000:0000:0000:0000:0000:0001
#>
function Expand-TkIPv6Address {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Address
    )

    $bytes  = ConvertTo-TkIPv6Bytes -Address $Address
    $groups = @()

    for ($i = 0; $i -lt 16; $i += 2) {
        $groups += '{0:x2}{1:x2}' -f $bytes[$i], $bytes[$i + 1]
    }

    return ($groups -join ':')
}

<#
.SYNOPSIS
    Applies a prefix length to a 16 byte address.

.PARAMETER FillHostBits
    Sets the host bits to one instead of zero, which yields the last address
    of the prefix.

.OUTPUTS
    System.Byte[]
#>
function Set-TkIPv6PrefixBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [ValidateRange(0, 128)]
        [int] $PrefixLength,

        [Parameter()]
        [switch] $FillHostBits
    )

    $result = [byte[]]::new(16)
    $Bytes.CopyTo($result, 0)

    for ($bit = $PrefixLength; $bit -lt 128; $bit++) {

        $byteIndex = [math]::Floor($bit / 8)
        $mask      = [byte] (1 -shl (7 - ($bit % 8)))

        if ($FillHostBits) {
            $result[$byteIndex] = $result[$byteIndex] -bor $mask
        }
        else {
            $result[$byteIndex] = $result[$byteIndex] -band (-bnot $mask)
        }
    }

    return $result
}

<#
.SYNOPSIS
    Computes every property of an IPv6 prefix.

.DESCRIPTION
    Accepts CIDR notation, or an address with -PrefixLength. Returns the
    prefix, the first and last address, the address count as a BigInteger,
    the scope and, for a /64, the interface identifier.

.PARAMETER Address
    IPv6 address, optionally in CIDR form.

.PARAMETER PrefixLength
    Prefix length when it is not part of the address.

.OUTPUTS
    PSCustomObject

.EXAMPLE
    Get-TkIPv6SubnetInfo -Address '2001:db8:abcd:1234::5/64'
#>
function Get-TkIPv6SubnetInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Address,

        [Parameter()]
        [ValidateRange(0, 128)]
        [int] $PrefixLength = -1
    )

    if ($Address -match '^(?<ip>.+)/(?<prefix>\d{1,3})$') {

        $Address      = $Matches['ip']
        $PrefixLength = [int] $Matches['prefix']

        if ($PrefixLength -gt 128) {
            throw ('Prefix length {0} is out of range for IPv6.' -f $PrefixLength)
        }
    }

    if ($PrefixLength -lt 0) {
        # /64 is the size of a normal link, and assuming it is far more
        # helpful than refusing an address that has no prefix on it.
        $PrefixLength = 64
    }

    $bytes   = ConvertTo-TkIPv6Bytes -Address $Address
    $network = Set-TkIPv6PrefixBytes -Bytes $bytes -PrefixLength $PrefixLength
    $last    = Set-TkIPv6PrefixBytes -Bytes $bytes -PrefixLength $PrefixLength -FillHostBits

    # 2^(128 - prefix) overflows every fixed width integer, so the count is a
    # BigInteger and is reported as text.
    $count = [System.Numerics.BigInteger]::Pow(2, 128 - $PrefixLength)

    $networkText = ConvertFrom-TkIPv6Bytes -Bytes $network

    # The interface identifier is the low 64 bits, which is what a SLAAC or
    # EUI-64 address is built from and what you compare when tracking a host.
    $interfaceId = ''

    if ($PrefixLength -le 64) {

        $groups = @()

        for ($i = 8; $i -lt 16; $i += 2) {
            $groups += '{0:x2}{1:x2}' -f $bytes[$i], $bytes[$i + 1]
        }

        $interfaceId = ($groups -join ':')
    }

    return [pscustomobject]@{
        Address        = ConvertFrom-TkIPv6Bytes -Bytes $bytes
        AddressFull    = Expand-TkIPv6Address -Address (ConvertFrom-TkIPv6Bytes -Bytes $bytes)
        PrefixLength   = $PrefixLength
        Network        = $networkText
        NetworkFull    = Expand-TkIPv6Address -Address $networkText
        Cidr           = '{0}/{1}' -f $networkText, $PrefixLength
        FirstAddress   = $networkText
        LastAddress    = ConvertFrom-TkIPv6Bytes -Bytes $last
        AddressCount   = $count.ToString()
        SubnetCount64  = if ($PrefixLength -le 64) {
                             ([System.Numerics.BigInteger]::Pow(2, 64 - $PrefixLength)).ToString()
                         }
                         else { '0' }
        InterfaceId    = $interfaceId
        Scope          = Get-TkIPv6Scope -Bytes $bytes
        IsUniqueLocal  = (($bytes[0] -band 0xFE) -eq 0xFC)
        IsLinkLocal    = (($bytes[0] -eq 0xFE) -and (($bytes[1] -band 0xC0) -eq 0x80))
    }
}

<#
.SYNOPSIS
    Classifies an IPv6 address by its reserved range.

.OUTPUTS
    System.String
#>
function Get-TkIPv6Scope {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    # Evaluated most specific first, the same way a routing table would.
    $text = (ConvertFrom-TkIPv6Bytes -Bytes $Bytes)

    if ($text -eq '::1')  { return 'Loopback (RFC 4291)' }
    if ($text -eq '::')   { return 'Unspecified (RFC 4291)' }

    if ($Bytes[0] -eq 0xFF) { return 'Multicast (RFC 4291)' }

    if (($Bytes[0] -eq 0xFE) -and (($Bytes[1] -band 0xC0) -eq 0x80)) {
        return 'Link local (RFC 4291)'
    }

    if (($Bytes[0] -band 0xFE) -eq 0xFC) {
        return 'Unique local, the IPv6 equivalent of RFC 1918 (RFC 4193)'
    }

    # 2001:db8::/32 is the documentation range; it must never be routed.
    if ($Bytes[0] -eq 0x20 -and $Bytes[1] -eq 0x01 -and $Bytes[2] -eq 0x0D -and $Bytes[3] -eq 0xB8) {
        return 'Documentation (RFC 3849)'
    }

    if ($Bytes[0] -eq 0x20 -and $Bytes[1] -eq 0x02) {
        return '6to4 (RFC 3056)'
    }

    if ($Bytes[0] -eq 0x00 -and $Bytes[1] -eq 0x64 -and $Bytes[2] -eq 0xFF -and $Bytes[3] -eq 0x9B) {
        return 'NAT64 well known prefix (RFC 6052)'
    }

    if (($Bytes[0] -band 0xE0) -eq 0x20) {
        return 'Global unicast (RFC 4291)'
    }

    return 'Reserved or unassigned'
}

<#
.SYNOPSIS
    Builds the EUI-64 interface identifier for a MAC address.

.DESCRIPTION
    The transform behind a SLAAC address without privacy extensions: split
    the MAC, insert fffe in the middle, and flip the universal/local bit.
    Useful in reverse, to recognise which machine an address belongs to.

.PARAMETER MacAddress
    MAC address in any common separator style.

.OUTPUTS
    System.String

.EXAMPLE
    ConvertTo-TkEui64 -MacAddress '00:1A:2B:3C:4D:5E'
    021a:2bff:fe3c:4d5e
#>
function ConvertTo-TkEui64 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $MacAddress
    )

    $clean = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()

    if ($clean.Length -ne 12) {
        throw ('"{0}" is not a 48 bit MAC address.' -f $MacAddress)
    }

    $bytes = for ($i = 0; $i -lt 12; $i += 2) {
        [Convert]::ToByte($clean.Substring($i, 2), 16)
    }

    $bytes = @($bytes)

    # Flip the universal/local bit of the first octet.
    $bytes[0] = $bytes[0] -bxor 0x02

    return '{0:x2}{1:x2}:{2:x2}ff:fe{3:x2}:{4:x2}{5:x2}' -f
        $bytes[0], $bytes[1], $bytes[2], $bytes[3], $bytes[4], $bytes[5]
}
