<#
    Toolkit - Features / Switch port discovery

    "Which switch, which port, which VLAN is this machine on?" answered from the
    switch itself. Managed switches announce themselves on every port: LLDP,
    the IEEE standard, every 30 seconds by default, and CDP, the Cisco protocol,
    every 60. Reading one announcement gives the switch name, the port, the
    VLAN and often the management address, without walking to the cabinet or
    logging on to the switch.

    Windows has no LLDP client on a workstation, so the announcements are
    captured with Packet Monitor (pktmon.exe), which ships with Windows 10 1809
    and later. pktmon needs administrator rights. The capture is filtered on the
    two multicast addresses those protocols are sent to, so nothing else is
    recorded, and the capture file is deleted once read.

    Decoding is plain PowerShell over the pcapng file pktmon writes, kept in
    functions that take bytes and return objects, so every field is tested
    without a network.
#>

# The destination addresses LLDP and CDP are sent to. A switch never forwards
# them, so a frame seen here came from the port this machine is plugged into.
$script:TkLldpMultiCast = '01-80-C2-00-00-0E'
$script:TkCdpMultiCast  = '01-00-0C-CC-CC-CC'

<#
.SYNOPSIS
    Reads a big-endian 16-bit number from a byte array.
#>
function Get-TkUInt16BigEndian {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter(Mandatory)] [int] $Offset
    )

    return (([int] $Bytes[$Offset]) -shl 8) -bor [int] $Bytes[$Offset + 1]
}

<#
.SYNOPSIS
    Formats bytes as a MAC address, 00-11-22-33-44-55.
#>
function Format-TkMacBytes {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter(Mandatory)] [int] $Offset,
        [Parameter()] [int] $Count = 6
    )

    return ((0..($Count - 1) | ForEach-Object { '{0:X2}' -f $Bytes[$Offset + $_] }) -join '-')
}

<#
.SYNOPSIS
    Decodes bytes as text, without the trailing zeros some switches add.
#>
function Get-TkFrameText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter(Mandatory)] [int] $Offset,
        [Parameter(Mandatory)] [int] $Count
    )

    if ($Count -le 0) {
        return ''
    }

    return [System.Text.Encoding]::UTF8.GetString($Bytes, $Offset, $Count).Trim([char] 0).Trim()
}

<#
.SYNOPSIS
    Extracts the frames from a pcapng capture.

.DESCRIPTION
    Walks the blocks: enhanced packet blocks (type 6) and simple packet blocks
    (type 3) carry a frame. A section written big-endian, or a block that runs
    past the end of the file, stops the walk rather than producing garbage.

    Frames are returned wrapped in objects: an array of byte arrays is
    flattened by the PowerShell pipeline into one long array of bytes.

.PARAMETER Bytes
    The content of the pcapng file.

.OUTPUTS
    PSCustomObject[] with Data, the bytes of one frame.
#>
function ConvertFrom-TkPcapNg {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    $frames = New-Object System.Collections.Generic.List[object]
    $offset = 0

    while ($offset + 12 -le $Bytes.Length) {

        $type   = [BitConverter]::ToUInt32($Bytes, $offset)
        $length = [BitConverter]::ToUInt32($Bytes, $offset + 4)

        if ($length -lt 12 -or $offset + $length -gt $Bytes.Length) {
            break
        }

        if ($type -eq 0x0A0D0D0A -and [BitConverter]::ToUInt32($Bytes, $offset + 8) -ne 0x1A2B3C4D) {
            break
        }

        $start    = -1
        $captured = 0

        if ($type -eq 6 -and $length -ge 32) {
            $captured = [int] [BitConverter]::ToUInt32($Bytes, $offset + 20)
            $start    = $offset + 28
        }
        elseif ($type -eq 3 -and $length -ge 16) {
            $captured = [int] [math]::Min([BitConverter]::ToUInt32($Bytes, $offset + 8), $length - 16)
            $start    = $offset + 12
        }

        if ($start -ge 0 -and $captured -gt 0 -and $start + $captured -le $offset + $length) {

            $data = New-Object byte[] $captured
            [Array]::Copy($Bytes, $start, $data, 0, $captured)

            $frames.Add([pscustomobject] @{ Data = $data })
        }

        $offset += [int] $length
    }

    return $frames.ToArray()
}

<#
.SYNOPSIS
    Reads the Ethernet header of a frame, past an 802.1Q tag when there is one.

.OUTPUTS
    PSCustomObject with Destination, Source, TypeOrLength and Offset, or $null.
#>
function Get-TkEthernetHeader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Frame
    )

    if ($Frame.Length -lt 14) {
        return $null
    }

    $typeOrLength = Get-TkUInt16BigEndian -Bytes $Frame -Offset 12
    $offset       = 14

    if ($typeOrLength -eq 0x8100 -and $Frame.Length -ge 18) {
        $typeOrLength = Get-TkUInt16BigEndian -Bytes $Frame -Offset 16
        $offset       = 18
    }

    return [pscustomobject] @{
        Destination  = Format-TkMacBytes -Bytes $Frame -Offset 0
        Source       = Format-TkMacBytes -Bytes $Frame -Offset 6
        TypeOrLength = $typeOrLength
        Offset       = $offset
    }
}

<#
.SYNOPSIS
    Builds the neighbour record both protocols fill.
#>
function New-TkSwitchNeighbour {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Protocol
    )

    return [pscustomobject] @{
        Protocol          = $Protocol
        SwitchName        = ''
        Port              = ''
        PortDescription   = ''
        Vlan              = $null
        VoiceVlan         = $null
        Platform          = ''
        ManagementAddress = ''
        ChassisId         = ''
        Capabilities      = ''
        Source            = ''
    }
}

<#
.SYNOPSIS
    Decodes an LLDP announcement.

.DESCRIPTION
    LLDP is a list of TLVs after EtherType 0x88CC: a 7-bit type and a 9-bit
    length, then the value. Read here: chassis ID, port ID, port description,
    system name and description, capabilities, the first management address,
    the port VLAN ID from the IEEE 802.1 organisation TLV, and the voice VLAN
    from the LLDP-MED network policy.

.PARAMETER Frame
    The bytes of one Ethernet frame.

.OUTPUTS
    PSCustomObject from New-TkSwitchNeighbour, or $null for any other frame.
#>
function ConvertFrom-TkLldpFrame {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Frame
    )

    $header = Get-TkEthernetHeader -Frame $Frame

    if ($null -eq $header -or $header.TypeOrLength -ne 0x88CC) {
        return $null
    }

    $neighbour = New-TkSwitchNeighbour -Protocol 'LLDP'
    $neighbour.Source = $header.Source

    $capabilityNames = @{ 1 = 'Other'; 2 = 'Repeater'; 4 = 'Bridge'; 8 = 'Access point'; 16 = 'Router'; 32 = 'Telephone'; 64 = 'DOCSIS'; 128 = 'Station' }

    $offset = $header.Offset

    while ($offset + 2 -le $Frame.Length) {

        $word   = Get-TkUInt16BigEndian -Bytes $Frame -Offset $offset
        $type   = $word -shr 9
        $length = $word -band 0x1FF
        $value  = $offset + 2

        if ($type -eq 0 -or $value + $length -gt $Frame.Length) {
            break
        }

        switch ($type) {

            1 {
                $neighbour.ChassisId = if ($Frame[$value] -eq 4 -and $length -eq 7) { Format-TkMacBytes -Bytes $Frame -Offset ($value + 1) }
                                       else { Get-TkFrameText -Bytes $Frame -Offset ($value + 1) -Count ($length - 1) }
            }

            2 {
                $neighbour.Port = if ($Frame[$value] -eq 3 -and $length -eq 7) { Format-TkMacBytes -Bytes $Frame -Offset ($value + 1) }
                                  else { Get-TkFrameText -Bytes $Frame -Offset ($value + 1) -Count ($length - 1) }
            }

            4 { $neighbour.PortDescription = Get-TkFrameText -Bytes $Frame -Offset $value -Count $length }
            5 { $neighbour.SwitchName      = Get-TkFrameText -Bytes $Frame -Offset $value -Count $length }
            6 { $neighbour.Platform        = Get-TkFrameText -Bytes $Frame -Offset $value -Count $length }

            7 {
                if ($length -ge 4) {
                    $enabled = Get-TkUInt16BigEndian -Bytes $Frame -Offset ($value + 2)
                    $neighbour.Capabilities = (@($capabilityNames.Keys | Sort-Object | Where-Object { $enabled -band $_ } |
                                                 ForEach-Object { $capabilityNames[$_] }) -join ', ')
                }
            }

            8 {
                # Address string length (subtype included), subtype, address.
                $addressLength = [int] $Frame[$value] - 1
                $subtype       = $Frame[$value + 1]

                if (-not $neighbour.ManagementAddress) {
                    if ($subtype -eq 1 -and $addressLength -eq 4) {
                        $neighbour.ManagementAddress = (($value + 2)..($value + 5) | ForEach-Object { $Frame[$_] }) -join '.'
                    }
                    elseif ($subtype -eq 2 -and $addressLength -eq 16) {
                        $bytes = New-Object byte[] 16
                        [Array]::Copy($Frame, $value + 2, $bytes, 0, 16)
                        $neighbour.ManagementAddress = ([System.Net.IPAddress]::new($bytes)).ToString()
                    }
                }
            }

            127 {
                if ($length -ge 6) {

                    $oui     = Format-TkMacBytes -Bytes $Frame -Offset $value -Count 3
                    $subtype = $Frame[$value + 3]

                    if ($oui -eq '00-80-C2' -and $subtype -eq 1) {
                        $neighbour.Vlan = Get-TkUInt16BigEndian -Bytes $Frame -Offset ($value + 4)
                    }
                    elseif ($oui -eq '00-12-BB' -and $subtype -eq 2 -and $length -ge 8 -and $Frame[$value + 4] -eq 1) {
                        # Network policy for voice: U, T, X bits, then the 12-bit VLAN.
                        $policy = (([int] $Frame[$value + 5]) -shl 16) -bor (([int] $Frame[$value + 6]) -shl 8) -bor [int] $Frame[$value + 7]
                        $neighbour.VoiceVlan = ($policy -shr 9) -band 0xFFF
                    }
                }
            }
        }

        $offset = $value + $length
    }

    return $neighbour
}

<#
.SYNOPSIS
    Decodes a CDP announcement.

.DESCRIPTION
    CDP rides in an 802.3 frame with an LLC/SNAP header (AA AA 03, Cisco OUI
    00 00 0C, protocol 0x2000) to 01-00-0C-CC-CC-CC. After a 4-byte header come
    TLVs of a 16-bit type and a 16-bit length that counts the TLV header.
    Read here: device ID, addresses, port ID, capabilities, software version,
    platform, VTP domain, native VLAN, voice VLAN and management address.

.PARAMETER Frame
    The bytes of one Ethernet frame.

.OUTPUTS
    PSCustomObject from New-TkSwitchNeighbour, or $null for any other frame.
#>
function ConvertFrom-TkCdpFrame {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Frame
    )

    $header = Get-TkEthernetHeader -Frame $Frame

    if ($null -eq $header -or $header.TypeOrLength -gt 1500 -or $header.Destination -ne $script:TkCdpMultiCast) {
        return $null
    }

    $snap = $header.Offset

    if ($Frame.Length -lt $snap + 12 -or $Frame[$snap] -ne 0xAA -or $Frame[$snap + 1] -ne 0xAA -or $Frame[$snap + 2] -ne 0x03 -or
        (Format-TkMacBytes -Bytes $Frame -Offset ($snap + 3) -Count 3) -ne '00-00-0C' -or
        (Get-TkUInt16BigEndian -Bytes $Frame -Offset ($snap + 6)) -ne 0x2000) {
        return $null
    }

    $neighbour = New-TkSwitchNeighbour -Protocol 'CDP'
    $neighbour.Source = $header.Source

    $firstAddress = {
        param($start, $end)

        $count = (([int] $Frame[$start]) -shl 24) -bor (([int] $Frame[$start + 1]) -shl 16) -bor (([int] $Frame[$start + 2]) -shl 8) -bor [int] $Frame[$start + 3]
        $p     = $start + 4

        for ($i = 0; $i -lt $count -and $p + 2 -le $end; $i++) {

            $protocolLength = [int] $Frame[$p + 1]
            $addressAt      = $p + 2 + $protocolLength

            if ($addressAt + 2 -gt $end) { break }

            $addressLength = Get-TkUInt16BigEndian -Bytes $Frame -Offset $addressAt

            if ($Frame[$p] -eq 1 -and $protocolLength -eq 1 -and $Frame[$p + 2] -eq 0xCC -and $addressLength -eq 4 -and $addressAt + 6 -le $end) {
                return (($addressAt + 2)..($addressAt + 5) | ForEach-Object { $Frame[$_] }) -join '.'
            }

            $p = $addressAt + 2 + $addressLength
        }

        return ''
    }

    $offset = $snap + 8 + 4

    while ($offset + 4 -le $Frame.Length) {

        $type   = Get-TkUInt16BigEndian -Bytes $Frame -Offset $offset
        $length = Get-TkUInt16BigEndian -Bytes $Frame -Offset ($offset + 2)
        $value  = $offset + 4
        $size   = $length - 4

        if ($length -lt 4 -or $offset + $length -gt $Frame.Length) {
            break
        }

        switch ($type) {
            0x0001 { $neighbour.SwitchName = Get-TkFrameText -Bytes $Frame -Offset $value -Count $size }
            0x0002 { if (-not $neighbour.ManagementAddress) { $neighbour.ManagementAddress = & $firstAddress $value ($offset + $length) } }
            0x0003 { $neighbour.Port = Get-TkFrameText -Bytes $Frame -Offset $value -Count $size }
            0x0005 { $neighbour.Platform = (Get-TkFrameText -Bytes $Frame -Offset $value -Count $size) + $(if ($neighbour.Platform) { ' ' + $neighbour.Platform } else { '' }) }
            0x0006 { $neighbour.Platform = (Get-TkFrameText -Bytes $Frame -Offset $value -Count $size) + $(if ($neighbour.Platform) { ', ' + $neighbour.Platform } else { '' }) }
            0x0009 { $neighbour.PortDescription = 'VTP domain {0}' -f (Get-TkFrameText -Bytes $Frame -Offset $value -Count $size) }
            0x000A { if ($size -ge 2) { $neighbour.Vlan = Get-TkUInt16BigEndian -Bytes $Frame -Offset $value } }
            0x000E { if ($size -ge 3) { $neighbour.VoiceVlan = Get-TkUInt16BigEndian -Bytes $Frame -Offset ($value + 1) } }
            0x0016 { $address = & $firstAddress $value ($offset + $length); if ($address) { $neighbour.ManagementAddress = $address } }
        }

        $offset += $length
    }

    return $neighbour
}

<#
.SYNOPSIS
    Decodes every LLDP and CDP announcement among captured frames.

.DESCRIPTION
    A switch announces the same thing again and again during a capture; one
    record is kept per protocol, switch and port.

.PARAMETER Frame
    Output of ConvertFrom-TkPcapNg.

.OUTPUTS
    PSCustomObject[] from New-TkSwitchNeighbour.
#>
function Get-TkSwitchNeighbour {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Frame
    )

    $seen = [ordered] @{}

    foreach ($item in @($Frame | Where-Object { $_ -and $_.Data })) {

        $neighbour = ConvertFrom-TkLldpFrame -Frame $item.Data

        if ($null -eq $neighbour) {
            $neighbour = ConvertFrom-TkCdpFrame -Frame $item.Data
        }

        if ($neighbour) {
            $seen[('{0}|{1}|{2}' -f $neighbour.Protocol, $neighbour.SwitchName, $neighbour.Port)] = $neighbour
        }
    }

    return @($seen.Values)
}

<#
.SYNOPSIS
    Reads a pcapng capture file and decodes the announcements in it.

.DESCRIPTION
    A missing file and a file with no packet in it both give no frame and no
    neighbour, never a null: the first version assigned the result of an if
    statement, which yields nothing at all when its branch is an empty array,
    and the null that followed failed the whole discovery after a capture that
    had simply heard nothing.

.PARAMETER Path
    The pcapng file pktmon wrote.

.OUTPUTS
    PSCustomObject with Frames, a count, and Neighbours, an array.
#>
function Read-TkSwitchCapture {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $frames = @(
        if (Test-Path -LiteralPath $Path) {
            ConvertFrom-TkPcapNg -Bytes ([System.IO.File]::ReadAllBytes($Path))
        }
    )

    return [pscustomobject] @{
        Frames     = $frames.Count
        Neighbours = @(Get-TkSwitchNeighbour -Frame $frames)
    }
}

<#
.SYNOPSIS
    Writes the result of a discovery as text for the output box.

.PARAMETER Discovery
    Output of Invoke-TkSwitchPortDiscovery.

.OUTPUTS
    System.String
#>
function Format-TkSwitchDiscoveryText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        $Discovery
    )

    if ($null -eq $Discovery) {
        return 'The discovery returned nothing. The log has the reason.'
    }

    switch ([string] $Discovery.Status) {

        'Found' {
            $blocks = foreach ($neighbour in @($Discovery.Neighbours)) {

                $lines = @(
                    'Switch         : {0}' -f $(if ($neighbour.SwitchName) { $neighbour.SwitchName } else { $neighbour.ChassisId })
                    'Port           : {0}{1}' -f $neighbour.Port, $(if ($neighbour.PortDescription) { ' ({0})' -f $neighbour.PortDescription } else { '' })
                )

                if ($null -ne $neighbour.Vlan)       { $lines += 'VLAN           : {0}' -f $neighbour.Vlan }
                if ($null -ne $neighbour.VoiceVlan)  { $lines += 'Voice VLAN     : {0}' -f $neighbour.VoiceVlan }
                if ($neighbour.ManagementAddress)    { $lines += 'Management IP  : {0}' -f $neighbour.ManagementAddress }
                if ($neighbour.Platform)             { $lines += 'Platform       : {0}' -f (($neighbour.Platform -split "`r?`n")[0]) }
                if ($neighbour.Capabilities)         { $lines += 'Capabilities   : {0}' -f $neighbour.Capabilities }

                $lines += 'Heard over     : {0}, from {1}' -f $neighbour.Protocol, $neighbour.Source

                $lines -join [Environment]::NewLine
            }

            return ('Announcement heard in {0} seconds.{1}{1}{2}' -f $Discovery.Seconds, [Environment]::NewLine,
                    ($blocks -join ([Environment]::NewLine + [Environment]::NewLine)))
        }

        'Silent' {
            return ('No LLDP or CDP announcement was heard in {0} seconds ({1} frame(s) captured).{2}{2}' -f $Discovery.Seconds, $Discovery.Frames, [Environment]::NewLine) +
                   'The usual reasons: the port is on an unmanaged switch, LLDP and CDP are turned off on it, an IP phone in between answers for the machine, or this machine is on Wi-Fi, which never carries them.'
        }

        default {
            return 'Switch port discovery did not run: {0}' -f $Discovery.Error
        }
    }
}

<#
.SYNOPSIS
    Listens for LLDP and CDP announcements with Packet Monitor.

.DESCRIPTION
    Needs administrator rights. Packet Monitor keeps one set of filters for the
    whole machine, so any capture or filter already configured in pktmon is
    stopped and cleared first, and the filters are cleared again afterwards,
    whatever happens.

    The MAC format pktmon expects is tried with hyphens, then with colons.

.PARAMETER Seconds
    How long to listen. CDP is sent every 60 seconds by default, LLDP every 30.

.OUTPUTS
    PSCustomObject with Status (Found, Silent, NotElevated, Unavailable or
    Failed), Neighbours, Frames, Seconds and Error.
#>
function Invoke-TkSwitchPortDiscovery {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(5, 180)]
        [int] $Seconds = 65
    )

    $result = { param($status, $neighbours, $frames, $message)
        [pscustomobject] @{ Status = $status; Neighbours = @($neighbours); Frames = $frames; Seconds = $Seconds; Error = $message }
    }

    if (-not (Assert-TkElevated -Operation 'Switch port discovery')) {
        return (& $result 'NotElevated' @() 0 'Packet Monitor needs administrator rights.')
    }

    $tool = Join-Path -Path $env:SystemRoot -ChildPath 'System32\PktMon.exe'

    if (-not (Test-Path -LiteralPath $tool)) {
        return (& $result 'Unavailable' @() 0 'Packet Monitor (pktmon.exe) is not on this version of Windows. It ships with Windows 10 1809 and later.')
    }

    $work = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('toolkit-neighbours-{0}' -f [guid]::NewGuid())
    $etl  = Join-Path -Path $work -ChildPath 'capture.etl'
    $pcap = Join-Path -Path $work -ChildPath 'capture.pcapng'

    $stopwatch = Start-TkOperation -Name 'Switch port discovery' -Category 'Capture'

    try {
        New-Item -Path $work -ItemType Directory -Force | Out-Null

        & $tool stop 2>&1 | Out-Null
        & $tool filter remove 2>&1 | Out-Null

        try {
            foreach ($filter in @(
                [pscustomobject] @{ Name = 'Toolkit LLDP'; Mac = $script:TkLldpMultiCast }
                [pscustomobject] @{ Name = 'Toolkit CDP';  Mac = $script:TkCdpMultiCast }
            )) {
                $added = $false

                foreach ($spelling in @($filter.Mac, ($filter.Mac -replace '-', ':'))) {

                    & $tool filter add $filter.Name -m $spelling 2>&1 | Out-Null

                    if ($LASTEXITCODE -eq 0) {

                        # Recorded, so a silent capture can be told from a
                        # filter that matched nothing because of its spelling.
                        Write-TkLog -Level Information -Category 'Capture' -Message (
                            'Packet Monitor filter "{0}" set on {1}.' -f $filter.Name, $spelling
                        )

                        $added = $true
                        break
                    }
                }

                if (-not $added) {
                    throw ('Packet Monitor refused the {0} filter.' -f $filter.Name)
                }
            }

            & $tool start --capture --comp nics --pkt-size 0 --file-name $etl 2>&1 | Out-Null

            if ($LASTEXITCODE -ne 0) {
                throw ('Packet Monitor could not start the capture (exit code {0}).' -f $LASTEXITCODE)
            }

            Start-Sleep -Seconds $Seconds
        }
        finally {
            & $tool stop 2>&1 | Out-Null
            & $tool filter remove 2>&1 | Out-Null
        }

        & $tool etl2pcap $etl --out $pcap 2>&1 | Out-Null

        $capture = Read-TkSwitchCapture -Path $pcap

        Stop-TkOperation -Name 'Switch port discovery' -Stopwatch $stopwatch -Category 'Capture'

        return (& $result $(if ($capture.Neighbours.Count -gt 0) { 'Found' } else { 'Silent' }) $capture.Neighbours $capture.Frames '')
    }
    catch {
        Stop-TkOperation -Name 'Switch port discovery' -Stopwatch $stopwatch -Category 'Capture' -Success $false
        return (& $result 'Failed' @() 0 $_.Exception.Message)
    }
    finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
