<#
    Toolkit - Features / Wireless

    "The Wi-Fi is bad" split into what can be measured: whether the radio is on
    and connected, how strong the signal is, the band and channel, the rate
    the link agreed on, how the network is protected, how crowded the channel
    is, and how often the connection dropped.

    Everything comes from the Native Wi-Fi API rather than from netsh, whose
    output is translated into the display language. The API hands back raw
    structures; they are copied into byte arrays and decoded here, so each
    decoder is tested without a wireless card.

    Since Windows 11 24H2 the current connection and the list of access points
    are only given to a desktop application allowed to use location. Without
    that consent the report says so and opens the setting, rather than
    reporting an empty connection.
#>

<#
.SYNOPSIS
    Loads the read only calls to the Native Wi-Fi API.

.DESCRIPTION
    Each call opens its own session, copies the answer into a managed array
    and frees the unmanaged memory before returning, so no handle or pointer
    ever reaches PowerShell. Nothing here connects, scans or changes a setting.

.OUTPUTS
    System.Boolean, $false when the type cannot be compiled.
#>
function Initialize-TkWlanApi {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ('TkWlanApi' -as [type]) {
        return $true
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

public static class TkWlanApi
{
    [DllImport("wlanapi.dll")]
    private static extern int WlanOpenHandle(int clientVersion, IntPtr reserved, out int negotiatedVersion, out IntPtr clientHandle);

    [DllImport("wlanapi.dll")]
    private static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern int WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern int WlanQueryInterface(IntPtr clientHandle, ref Guid interfaceGuid, int opCode, IntPtr reserved, out int dataSize, out IntPtr data, IntPtr valueType);

    [DllImport("wlanapi.dll")]
    private static extern int WlanGetNetworkBssList(IntPtr clientHandle, ref Guid interfaceGuid, IntPtr ssid, int bssType, bool securityEnabled, IntPtr reserved, out IntPtr bssList);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);

    // Version 2 is the API of Windows Vista and later.
    private const int ClientVersion = 2;

    // dot11_BSS_type_any: infrastructure and ad hoc networks alike.
    private const int AnyBssType = 3;

    private static IntPtr Open(out int error)
    {
        int version;
        IntPtr handle;

        error = WlanOpenHandle(ClientVersion, IntPtr.Zero, out version, out handle);

        return error == 0 ? handle : IntPtr.Zero;
    }

    private static byte[] Copy(IntPtr memory, int size)
    {
        byte[] bytes = new byte[size];
        Marshal.Copy(memory, bytes, 0, size);
        return bytes;
    }

    /// <summary>The WLAN_INTERFACE_INFO_LIST, or null with the error code.</summary>
    public static byte[] EnumInterfaces(out int error)
    {
        IntPtr handle = Open(out error);
        if (error != 0) return null;

        IntPtr list = IntPtr.Zero;

        try
        {
            error = WlanEnumInterfaces(handle, IntPtr.Zero, out list);
            if (error != 0) return null;

            // WLAN_INTERFACE_INFO is 532 bytes: a GUID, 256 wide characters and a state.
            return Copy(list, 8 + 532 * Marshal.ReadInt32(list, 0));
        }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    /// <summary>One interface parameter, or null with the error code.</summary>
    public static byte[] QueryInterface(Guid interfaceGuid, int opCode, out int error)
    {
        IntPtr handle = Open(out error);
        if (error != 0) return null;

        IntPtr data = IntPtr.Zero;

        try
        {
            int size;
            error = WlanQueryInterface(handle, ref interfaceGuid, opCode, IntPtr.Zero, out size, out data, IntPtr.Zero);
            if (error != 0) return null;

            return Copy(data, size);
        }
        finally
        {
            if (data != IntPtr.Zero) WlanFreeMemory(data);
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    /// <summary>The access points last seen by the adapter, or null with the error code.</summary>
    public static byte[] GetBssList(Guid interfaceGuid, out int error)
    {
        IntPtr handle = Open(out error);
        if (error != 0) return null;

        IntPtr list = IntPtr.Zero;

        try
        {
            error = WlanGetNetworkBssList(handle, ref interfaceGuid, IntPtr.Zero, AnyBssType, false, IntPtr.Zero, out list);
            if (error != 0) return null;

            // The first field is the total size, information elements included.
            return Copy(list, Marshal.ReadInt32(list, 0));
        }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }
}
'@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
        return $true
    }
    catch {
        Write-TkLog -Level Warning -Category 'Wireless' -Message ('The Wi-Fi API could not be loaded: {0}' -f $_.Exception.Message)
        return $false
    }
}

<#
.SYNOPSIS
    Names a value of the Wi-Fi API.

.PARAMETER Kind
    State (WLAN_INTERFACE_STATE), Phy (DOT11_PHY_TYPE), Authentication
    (DOT11_AUTH_ALGORITHM) or Cipher (DOT11_CIPHER_ALGORITHM).

.PARAMETER Value
    The number the API returned.

.OUTPUTS
    System.String
#>
function Get-TkWlanName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('State', 'Phy', 'Authentication', 'Cipher')]
        [string] $Kind,

        [Parameter(Mandatory)]
        [int] $Value
    )

    $names = switch ($Kind) {

        'State' {
            @{
                0 = 'Not ready';    1 = 'Connected';   2 = 'Ad hoc network formed'; 3 = 'Disconnecting'
                4 = 'Disconnected'; 5 = 'Associating'; 6 = 'Discovering';           7 = 'Authenticating'
            }
        }

        'Phy' {
            @{
                1 = 'FHSS';               2 = 'DSSS';               3  = 'Infrared';           4  = '802.11a'
                5 = '802.11b';            6 = '802.11g';            7  = '802.11n (Wi-Fi 4)';  8  = '802.11ac (Wi-Fi 5)'
                9 = '802.11ad';           10 = '802.11ax (Wi-Fi 6)'; 11 = '802.11be (Wi-Fi 7)'
            }
        }

        'Authentication' {
            @{
                1 = 'Open';                    2 = 'Shared key (WEP)';     3  = 'WPA-Enterprise'
                4 = 'WPA-Personal';            5 = 'WPA-None';             6  = 'WPA2-Enterprise'
                7 = 'WPA2-Personal';           8 = 'WPA3-Enterprise 192-bit'; 9 = 'WPA3-Personal'
                10 = 'Enhanced Open (OWE)';    11 = 'WPA3-Enterprise'
            }
        }

        'Cipher' {
            @{
                0 = 'None';     1 = 'WEP-40';   2 = 'TKIP';     4 = 'AES-CCMP'; 5 = 'WEP-104'
                6 = 'BIP';      8 = 'GCMP';     9 = 'GCMP-256'; 10 = 'CCMP-256'
                0x100 = 'Group cipher'; 0x101 = 'WEP'
            }
        }
    }

    if ($names.ContainsKey($Value)) {
        return $names[$Value]
    }

    return ('Unknown ({0})' -f $Value)
}

<#
.SYNOPSIS
    Returns the band and channel number of a Wi-Fi frequency.

.DESCRIPTION
    Channel numbers repeat across bands: channel 1 exists at 2.4 GHz and at
    6 GHz. The frequency is the only unambiguous value, and the API gives it
    for every access point.

.PARAMETER FrequencyMHz
    The channel centre frequency.

.OUTPUTS
    PSCustomObject with Band ('2.4 GHz', '5 GHz', '6 GHz' or '') and Channel.
#>
function Get-TkWifiChannel {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $FrequencyMHz
    )

    $band    = ''
    $channel = 0

    if ($FrequencyMHz -eq 2484) {
        $band    = '2.4 GHz'
        $channel = 14
    }
    elseif ($FrequencyMHz -ge 2412 -and $FrequencyMHz -le 2472) {
        $band    = '2.4 GHz'
        $channel = ($FrequencyMHz - 2407) / 5
    }
    elseif ($FrequencyMHz -ge 5150 -and $FrequencyMHz -le 5895) {
        $band    = '5 GHz'
        $channel = ($FrequencyMHz - 5000) / 5
    }
    elseif ($FrequencyMHz -eq 5935) {
        $band    = '6 GHz'
        $channel = 2
    }
    elseif ($FrequencyMHz -ge 5955 -and $FrequencyMHz -le 7115) {
        $band    = '6 GHz'
        $channel = ($FrequencyMHz - 5950) / 5
    }

    return [pscustomobject] @{
        Band    = $band
        Channel = [int] $channel
    }
}

<#
.SYNOPSIS
    Reads a DOT11_SSID: a length, then up to 32 bytes of network name.

.PARAMETER Bytes
    The structure bytes.

.PARAMETER Offset
    Where the DOT11_SSID starts.

.OUTPUTS
    System.String
#>
function Get-TkSsidText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter(Mandatory)] [int] $Offset
    )

    $length = [int] [BitConverter]::ToUInt32($Bytes, $Offset)

    if ($length -gt 32) {
        $length = 32
    }

    if ($length -le 0) {
        return ''
    }

    return [Text.Encoding]::UTF8.GetString($Bytes, $Offset + 4, $length)
}

<#
.SYNOPSIS
    Decodes a WLAN_INTERFACE_INFO_LIST.

.PARAMETER Bytes
    The list as returned by WlanEnumInterfaces.

.OUTPUTS
    PSCustomObject[] with Guid, Description, State and StateName.
#>
function ConvertFrom-TkWlanInterfaceList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -lt 8) {
        return @()
    }

    $count = [BitConverter]::ToInt32($Bytes, 0)

    $rows = for ($index = 0; $index -lt $count; $index++) {

        $offset = 8 + 532 * $index

        if ($offset + 532 -gt $Bytes.Length) {
            break
        }

        $state = [BitConverter]::ToInt32($Bytes, $offset + 528)

        [pscustomobject] @{
            Guid        = [guid]::new([byte[]] $Bytes[$offset..($offset + 15)])
            Description = ([Text.Encoding]::Unicode.GetString($Bytes, $offset + 16, 512) -split "`0")[0]
            State       = $state
            StateName   = Get-TkWlanName -Kind State -Value $state
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Decodes a WLAN_CONNECTION_ATTRIBUTES: the network the adapter is on.

.DESCRIPTION
    604 bytes: the state and mode, the profile name in 256 wide characters,
    the association (network name, access point, standard, signal quality,
    receive and transmit rates in kilobits per second) and the security.

.PARAMETER Bytes
    The structure as returned for wlan_intf_opcode_current_connection.

.OUTPUTS
    PSCustomObject, or $null when the bytes are too short.
#>
function ConvertFrom-TkWlanConnection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -lt 604) {
        return $null
    }

    $state  = [BitConverter]::ToInt32($Bytes, 0)
    $phy    = [BitConverter]::ToInt32($Bytes, 568)
    $auth   = [BitConverter]::ToInt32($Bytes, 596)
    $cipher = [BitConverter]::ToInt32($Bytes, 600)

    return [pscustomobject] @{
        State           = $state
        StateName       = Get-TkWlanName -Kind State -Value $state
        ProfileName     = ([Text.Encoding]::Unicode.GetString($Bytes, 8, 512) -split "`0")[0]
        Ssid            = Get-TkSsidText -Bytes $Bytes -Offset 520
        Bssid           = Format-TkMacBytes -Bytes $Bytes -Offset 560
        PhyType         = $phy
        Standard        = Get-TkWlanName -Kind Phy -Value $phy
        SignalQuality   = [int] [BitConverter]::ToUInt32($Bytes, 576)
        RxMbps          = [math]::Round([BitConverter]::ToUInt32($Bytes, 580) / 1000, 1)
        TxMbps          = [math]::Round([BitConverter]::ToUInt32($Bytes, 584) / 1000, 1)
        SecurityEnabled = ([BitConverter]::ToInt32($Bytes, 588) -ne 0)
        OneXEnabled     = ([BitConverter]::ToInt32($Bytes, 592) -ne 0)
        AuthAlgorithm   = $auth
        Authentication  = Get-TkWlanName -Kind Authentication -Value $auth
        CipherAlgorithm = $cipher
        Cipher          = Get-TkWlanName -Kind Cipher -Value $cipher
    }
}

<#
.SYNOPSIS
    Decodes a WLAN_RADIO_STATE: whether the radio is on, per PHY.

.DESCRIPTION
    A count, then 12 bytes per PHY: its index, the software state and the
    hardware state, where 1 is on and 2 is off. The radio is off when every
    PHY says so.

.PARAMETER Bytes
    The structure as returned for wlan_intf_opcode_radio_state.

.OUTPUTS
    PSCustomObject with Phys, SoftwareOff and HardwareOff, or $null.
#>
function ConvertFrom-TkWlanRadioState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -lt 4) {
        return $null
    }

    $count    = [BitConverter]::ToInt32($Bytes, 0)
    $software = @()
    $hardware = @()

    for ($index = 0; $index -lt $count -and (4 + 12 * ($index + 1)) -le $Bytes.Length; $index++) {

        $offset = 4 + 12 * $index

        $software += [BitConverter]::ToInt32($Bytes, $offset + 4)
        $hardware += [BitConverter]::ToInt32($Bytes, $offset + 8)
    }

    return [pscustomobject] @{
        Phys        = $software.Count
        SoftwareOff = ($software.Count -gt 0 -and @($software | Where-Object { $_ -ne 2 }).Count -eq 0)
        HardwareOff = ($hardware.Count -gt 0 -and @($hardware | Where-Object { $_ -ne 2 }).Count -eq 0)
    }
}

<#
.SYNOPSIS
    Decodes a WLAN_BSS_LIST: the access points the adapter last saw.

.DESCRIPTION
    A total size and a count, then one 360 byte WLAN_BSS_ENTRY per access
    point. The information elements of each beacon follow the entries and
    are not read.

.PARAMETER Bytes
    The list as returned by WlanGetNetworkBssList.

.OUTPUTS
    PSCustomObject[] with Ssid, Bssid, PhyType, Standard, Rssi, LinkQuality,
    FrequencyMHz, Band, Channel and Protected.
#>
function ConvertFrom-TkWlanBssList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -lt 8) {
        return @()
    }

    $count = [BitConverter]::ToInt32($Bytes, 4)

    $rows = for ($index = 0; $index -lt $count; $index++) {

        $offset = 8 + 360 * $index

        if ($offset + 360 -gt $Bytes.Length) {
            break
        }

        $phy       = [BitConverter]::ToInt32($Bytes, $offset + 52)
        $frequency = [int] ([BitConverter]::ToUInt32($Bytes, $offset + 92) / 1000)
        $channel   = Get-TkWifiChannel -FrequencyMHz $frequency

        [pscustomobject] @{
            Ssid         = Get-TkSsidText -Bytes $Bytes -Offset $offset
            Bssid        = Format-TkMacBytes -Bytes $Bytes -Offset ($offset + 40)
            PhyType      = $phy
            Standard     = Get-TkWlanName -Kind Phy -Value $phy
            Rssi         = [BitConverter]::ToInt32($Bytes, $offset + 56)
            LinkQuality  = [int] [BitConverter]::ToUInt32($Bytes, $offset + 60)
            FrequencyMHz = $frequency
            Band         = $channel.Band
            Channel      = $channel.Channel

            # Bit 4 of the capability field: the network requires encryption.
            Protected    = (([BitConverter]::ToUInt16($Bytes, $offset + 88) -band 0x10) -ne 0)
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Turns one WLAN-AutoConfig event into a record.

.DESCRIPTION
    Event 8001 is a connection, 8002 a failed attempt and 8003 a
    disconnection. The reason text is written in the display language; the
    reason code is not.

.PARAMETER Id
    The event identifier.

.PARAMETER Data
    The event data as a hashtable of name to text.

.PARAMETER When
    When the event was written.

.OUTPUTS
    PSCustomObject, or $null for an identifier this does not read.
#>
function ConvertFrom-TkWlanEvent {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [int] $Id,
        [Parameter(Mandatory)] [hashtable] $Data,
        [Parameter()] [datetime] $When = (Get-Date)
    )

    $kind = switch ($Id) { 8001 { 'Connected' } 8002 { 'Failed' } 8003 { 'Disconnected' } default { '' } }

    if (-not $kind) {
        return $null
    }

    $code = 0L
    [void] [long]::TryParse([string] $Data['ReasonCode'], [ref] $code)

    $reason = @([string] $Data['Reason'], [string] $Data['FailureReason']) | Where-Object { $_ } | Select-Object -First 1

    return [pscustomobject] @{
        When          = $When
        Kind          = $kind
        Ssid          = [string] $Data['SSID']
        InterfaceGuid = [string] $Data['InterfaceGuid']
        ReasonCode    = $code
        Reason        = [string] $reason

        # Code 2 is a disconnection the user asked for, and code 5 a policy
        # turning automatic connection off on the interface, which is what
        # Windows does to Wi-Fi once a cable is plugged in. Neither is a fault.
        Expected      = ($kind -eq 'Connected') -or ($kind -eq 'Disconnected' -and $code -in @(2, 5))
    }
}

<#
.SYNOPSIS
    Reads the Wi-Fi connections, failures and disconnections of the last days.

.PARAMETER Days
    How far back to look.

.OUTPUTS
    PSCustomObject[] from ConvertFrom-TkWlanEvent.
#>
function Get-TkWlanConnectionEvent {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 90)]
        [int] $Days = 7
    )

    $records = @()

    try {
        $records = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
            Id        = 8001, 8002, 8003
            StartTime = (Get-Date).AddDays(-$Days)
        } -MaxEvents 2000 -ErrorAction Stop)
    }
    catch {
        # No event in the period is reported as an error too.
        $records = @()
    }

    $rows = foreach ($record in $records) {

        $data = @{}

        try {
            foreach ($item in ([xml] $record.ToXml()).Event.EventData.Data) {
                $data[[string] $item.Name] = [string] $item.'#text'
            }
        }
        catch {
            continue
        }

        ConvertFrom-TkWlanEvent -Id $record.Id -Data $data -When $record.TimeCreated
    }

    return @($rows | Where-Object { $_ })
}

<#
.SYNOPSIS
    Reads the state of every Wi-Fi adapter.

.PARAMETER Days
    How far back to read the connection events.

.OUTPUTS
    PSCustomObject with Available, ServiceRunning, Error, Days and Interfaces.
    Each interface carries Radio, LocationDenied, Connection, AccessPoint,
    Rssi, Networks and Events.
#>
function Get-TkWifiStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 90)]
        [int] $Days = 7
    )

    $service = Get-Service -Name 'WlanSvc' -ErrorAction SilentlyContinue

    $status = [pscustomobject] @{
        Available      = [bool] $service
        ServiceRunning = [bool] ($service -and $service.Status -eq 'Running')
        Error          = ''
        Days           = $Days
        Interfaces     = @()
    }

    if (-not $status.ServiceRunning) {
        return $status
    }

    if (-not (Initialize-TkWlanApi)) {
        $status.Error = 'The Wi-Fi API could not be loaded.'
        return $status
    }

    $code  = 0
    $bytes = [TkWlanApi]::EnumInterfaces([ref] $code)

    if ($code -ne 0) {
        $status.Error = ('The Wi-Fi API answered error {0}.' -f $code)
        return $status
    }

    $events = @(Get-TkWlanConnectionEvent -Days $Days)

    $status.Interfaces = @(foreach ($adapter in @(ConvertFrom-TkWlanInterfaceList -Bytes $bytes)) {

        # wlan_intf_opcode_radio_state
        $radio = $null
        $raw   = [TkWlanApi]::QueryInterface($adapter.Guid, 4, [ref] $code)

        if ($code -eq 0) {
            $radio = ConvertFrom-TkWlanRadioState -Bytes $raw
        }

        # Error 5, access denied, is location turned off for desktop apps.
        $locationDenied = $false
        $networks       = @()
        $raw            = [TkWlanApi]::GetBssList($adapter.Guid, [ref] $code)

        if ($code -eq 0) {
            $networks = @(ConvertFrom-TkWlanBssList -Bytes $raw)
        }
        elseif ($code -eq 5) {
            $locationDenied = $true
        }

        $connection = $null
        $rssi       = $null

        if ($adapter.State -eq 1) {

            # wlan_intf_opcode_current_connection
            $raw = [TkWlanApi]::QueryInterface($adapter.Guid, 7, [ref] $code)

            if ($code -eq 0) {
                $connection = ConvertFrom-TkWlanConnection -Bytes $raw
            }
            elseif ($code -eq 5) {
                $locationDenied = $true
            }

            # wlan_intf_opcode_rssi, in dBm
            $raw = [TkWlanApi]::QueryInterface($adapter.Guid, 0x10000102, [ref] $code)

            if ($code -eq 0 -and $raw.Length -ge 4) {
                $rssi = [BitConverter]::ToInt32($raw, 0)
            }
        }

        $guidText = $adapter.Guid.ToString('B')

        [pscustomobject] @{
            Guid           = $adapter.Guid
            Description    = $adapter.Description
            State          = $adapter.State
            StateName      = $adapter.StateName
            Radio          = $radio
            LocationDenied = $locationDenied
            Connection     = $connection
            AccessPoint    = $(if ($connection) { @($networks | Where-Object { $_.Bssid -eq $connection.Bssid }) | Select-Object -First 1 } else { $null })
            Rssi           = $rssi
            Networks       = $networks
            Events         = @($events | Where-Object { $_.InterfaceGuid -eq $guidText })
        }
    })

    return $status
}

<#
.SYNOPSIS
    Judges the Wi-Fi readings.

.PARAMETER Status
    Output of Get-TkWifiStatus.

.OUTPUTS
    PSCustomObject[] with Severity, Heading, Detail, Note and RemediationId.
#>
function Get-TkWifiFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        $Status
    )

    # Numbers go through [string] before -f, so a rate reads 6.5 Mbps on a
    # French Windows too.
    $findings = @()
    $finding  = {
        param($severity, $heading, $detail, $note, $remediation)
        [pscustomobject] @{ Severity = $severity; Heading = $heading; Detail = $detail; Note = $note; RemediationId = [string] $remediation }
    }

    if (-not $Status.Available) {
        return @(& $finding 'Info' 'No Wi-Fi on this machine' 'The WLAN AutoConfig service is not installed' 'Windows Server and some reduced images leave it out.' '')
    }

    if (-not $Status.ServiceRunning) {
        return @(& $finding 'Warning' 'The WLAN AutoConfig service is stopped' 'WlanSvc' 'Windows cannot see or join a Wi-Fi network while it is stopped. Start it in Services and set it back to Automatic.' '')
    }

    if ($Status.Error) {
        return @(& $finding 'Info' 'Wi-Fi not read' $Status.Error '' '')
    }

    $adapters = @($Status.Interfaces | Where-Object { $_ })

    if ($adapters.Count -eq 0) {
        return @(& $finding 'Info' 'No Wi-Fi adapter' 'The service runs but no wireless adapter is enabled' 'An adapter disabled in Network Connections or Device Manager, or turned off in the firmware, does not appear.' '')
    }

    foreach ($adapter in $adapters) {

        $prefix = if ($adapters.Count -gt 1) { '{0}: ' -f $adapter.Description } else { '' }

        # --- Radio --------------------------------------------------------
        if ($adapter.Radio -and $adapter.Radio.HardwareOff) {
            $findings += & $finding 'Warning' ($prefix + 'Wi-Fi is switched off by the hardware') $adapter.Description `
                'A physical switch, a function key or the firmware turned the radio off, and Windows cannot turn it back on.' ''
            continue
        }

        if ($adapter.Radio -and $adapter.Radio.SoftwareOff) {
            $findings += & $finding 'Warning' ($prefix + 'Wi-Fi is turned off') $adapter.Description `
                'Turned off in Windows, from quick settings or by airplane mode.' 'open-wifi-settings'
            continue
        }

        if ($adapter.LocationDenied) {
            $findings += & $finding 'Warning' ($prefix + 'Windows hides the Wi-Fi details from this toolkit') 'Location is off for desktop apps' `
                'Since Windows 11 24H2 the network, the access point and the signal are only given to desktop apps allowed to use location. Allow "Let desktop apps access your location", run this report again, and turn it back off afterwards if you prefer.' 'open-location-privacy'
        }

        $connection = $adapter.Connection

        if ($adapter.State -ne 1) {
            $findings += & $finding 'Info' ($prefix + 'Not connected to a Wi-Fi network') ('{0}, {1}' -f $adapter.Description, $adapter.StateName.ToLowerInvariant()) `
                $(if (@($adapter.Networks).Count -gt 0) { '{0} network(s) in range.' -f @($adapter.Networks).Count } else { '' }) ''
        }
        elseif (-not $connection) {
            if (-not $adapter.LocationDenied) {
                $findings += & $finding 'Info' ($prefix + 'Connected, details not read') $adapter.Description '' ''
            }
        }
        else {

            $point = $adapter.AccessPoint

            # --- Signal ---------------------------------------------------
            # The strength of the access point is the measured value; the
            # quality percentage maps linearly from -100 dBm to -50 dBm.
            $rssi = if ($point) { $point.Rssi }
                    elseif ($null -ne $adapter.Rssi -and $adapter.Rssi -lt 0) { $adapter.Rssi }
                    else { -100 + [int] ($connection.SignalQuality / 2) }

            $severity = if ($rssi -lt -80) { 'Fail' } elseif ($rssi -lt -67) { 'Warning' } else { 'Pass' }

            $note = switch ($severity) {
                'Pass'    { 'Strong enough for calls and video.' }
                'Warning' { 'Fine for browsing, not for calls or large transfers: expect a lower rate and short drops. Move closer to the access point, or add one.' }
                'Fail'    { 'Too weak for a stable connection: the machine is at the edge of the coverage. Move closer, away from walls and metal, or add an access point.' }
            }

            $findings += & $finding $severity ('{0}Signal {1} dBm on "{2}"' -f $prefix, [string] $rssi, $connection.Ssid) `
                ('Quality {0}%, access point {1}' -f [string] $connection.SignalQuality, $connection.Bssid) $note ''

            # --- Band, channel and crowding ------------------------------
            if ($point -and $point.Band) {

                $otherBands = @($adapter.Networks |
                                Where-Object { $_.Ssid -eq $connection.Ssid -and $_.Band -and $_.Band -ne $point.Band } |
                                ForEach-Object { $_.Band } | Sort-Object -Unique)

                if ($point.Band -eq '2.4 GHz' -and $otherBands.Count -gt 0) {
                    $findings += & $finding 'Warning' ('{0}On 2.4 GHz while "{1}" is also offered on {2}' -f $prefix, $connection.Ssid, ($otherBands -join ' and ')) `
                        ('Channel {0}, {1}' -f [string] $point.Channel, $connection.Standard) `
                        'The 2.4 GHz band is slower and shared with neighbours, Bluetooth and microwave ovens. Windows moves to the faster band when its signal is good enough; if it stays here, set the preferred band to 5 GHz in the adapter advanced properties, or give each band its own name on the access point.' ''
                }
                else {
                    $findings += & $finding 'Info' ('{0}Band {1}, channel {2}' -f $prefix, $point.Band, [string] $point.Channel) `
                        ('{0}, {1} MHz' -f $connection.Standard, [string] $point.FrequencyMHz) `
                        $(if ($point.Band -eq '2.4 GHz') { 'Reaches further than 5 and 6 GHz, but is slower and more crowded.' } else { 'Faster than 2.4 GHz, over a shorter range and through fewer walls.' }) ''
                }

                # Channels 5 MHz apart overlap on 2.4 GHz unless four or more
                # apart; on 5 and 6 GHz only the same channel is counted.
                $reach   = if ($point.Band -eq '2.4 GHz') { 4 } else { 0 }
                $limit   = if ($point.Band -eq '2.4 GHz') { 8 } else { 5 }
                $sharing = @($adapter.Networks | Where-Object {
                               $_.Bssid -ne $point.Bssid -and $_.Band -eq $point.Band -and [math]::Abs($_.Channel - $point.Channel) -le $reach
                           })

                if ($sharing.Count -ge $limit) {
                    $findings += & $finding 'Warning' ('{0}Channel {1} is crowded' -f $prefix, [string] $point.Channel) `
                        ('{0} other access point(s) on it or overlapping it' -f $sharing.Count) `
                        'Access points that share a channel take turns to talk. On 2.4 GHz only channels 1, 6 and 11 do not overlap: move the access point to the least used of them, or use 5 GHz.' ''
                }
            }

            # --- Link rate ------------------------------------------------
            $slowest = [math]::Min([double] $connection.RxMbps, [double] $connection.TxMbps)

            if ($slowest -gt 0) {
                $findings += & $finding $(if ($slowest -lt 20) { 'Warning' } else { 'Pass' }) `
                    ('{0}Link rate {1} Mbps received, {2} Mbps sent' -f $prefix, [string] $connection.RxMbps, [string] $connection.TxMbps) `
                    $connection.Standard `
                    $(if ($slowest -lt 20) { 'The rate the adapter and the access point agreed on caps the speed, whatever the internet connection. A low rate follows a weak signal, interference or an old standard.' } else { 'What the adapter and the access point agreed on. The internet connection can still be slower.' }) ''
            }

            # --- Standard -------------------------------------------------
            if ($connection.PhyType -in @(2, 4, 5, 6)) {
                $findings += & $finding 'Warning' ('{0}Connected with {1}' -f $prefix, $connection.Standard) 'A standard limited to 54 Mbps' `
                    'Either the access point, the adapter or its driver is very old, or the adapter is set to a legacy mode in its advanced properties.' ''
            }

            # --- Security -------------------------------------------------
            $auth   = [int] $connection.AuthAlgorithm
            $cipher = [int] $connection.CipherAlgorithm
            $label  = '{0}, {1}' -f $connection.Authentication, $connection.Cipher

            if ($auth -eq 1 -and $cipher -eq 0) {
                $findings += & $finding 'Fail' ($prefix + 'Open network: nothing is encrypted') $label `
                    'Anyone nearby can read what is not protected by HTTPS or a VPN. Use a VPN on this network, or a protected one.' ''
            }
            elseif ($auth -eq 2 -or $cipher -in @(1, 5, 0x101)) {
                $findings += & $finding 'Fail' ($prefix + 'Protected with WEP') $label `
                    'WEP is broken in minutes. Set the access point to WPA2 or WPA3.' ''
            }
            elseif ($auth -in @(3, 4) -or $cipher -eq 2) {
                $findings += & $finding 'Warning' ($prefix + 'Protected with WPA or TKIP') $label `
                    'Deprecated, and TKIP limits the rate to 54 Mbps. Set the access point to WPA2 with AES, or WPA3.' ''
            }
            elseif ($auth -eq 10) {
                $findings += & $finding 'Info' ($prefix + 'Enhanced Open') $label `
                    'Encrypted without a password: it stops eavesdropping but does not prove the access point is the real one.' ''
            }
            else {
                $findings += & $finding 'Pass' ('{0}Protected with {1}' -f $prefix, $label) `
                    $(if ($connection.OneXEnabled) { '802.1X enterprise sign-in' } else { 'Shared password' }) '' ''
            }
        }

        # --- Drops and failures -----------------------------------------------
        $drops    = @($adapter.Events | Where-Object { $_ -and $_.Kind -eq 'Disconnected' -and -not $_.Expected })
        $failures = @($adapter.Events | Where-Object { $_ -and $_.Kind -eq 'Failed' })

        # The reason is a sentence Windows wrote in the display language, so it
        # goes in the note; the networks involved are short enough for the detail.
        $networksOf = {
            param($rows)

            $names = @($rows | ForEach-Object { $_.Ssid } | Where-Object { $_ } | Sort-Object -Unique)
            $shown = (@($names | Select-Object -First 3 | ForEach-Object { '"{0}"' -f $_ })) -join ', '

            $shown + $(if ($names.Count -gt 3) { ' and {0} more' -f ($names.Count - 3) } else { '' })
        }

        $mostOften = {
            param($rows)

            $top    = @($rows | Group-Object -Property Reason | Sort-Object -Property Count -Descending)[0]
            $reason = if ($top.Name) { ([string] $top.Name).TrimEnd('.', ' ') } else { 'no reason recorded' }

            'Most often: {0} ({1}).' -f $reason, $top.Count
        }

        if ($drops.Count -gt 0) {

            $findings += & $finding $(if ($drops.Count -ge 5) { 'Warning' } else { 'Info' }) `
                ('{0}The connection dropped {1} time(s) in {2} days' -f $prefix, $drops.Count, $Status.Days) `
                (& $networksOf $drops) `
                ('{0} Drops nobody asked for come from the signal, the access point or the driver. Check the signal, update the Wi-Fi driver from the manufacturer, and turn off power saving for the adapter in Device Manager.' -f (& $mostOften $drops)) ''
        }

        if ($failures.Count -gt 0) {

            $findings += & $finding $(if ($failures.Count -ge 3) { 'Warning' } else { 'Info' }) `
                ('{0}{1} failed connection attempt(s) in {2} days' -f $prefix, $failures.Count, $Status.Days) `
                (& $networksOf $failures) `
                ('{0} Usually a changed password, a certificate the machine does not trust on an enterprise network, or an access point refusing new clients.' -f (& $mostOften $failures)) ''
        }
    }

    return $findings
}
