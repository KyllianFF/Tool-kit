<#
    Toolkit - Features / Windows Firewall rule builder

    A firewall rule is quick to write and easy to get too wide: an inbound
    allow with no remote address on the Public profile opens the port to every
    network the laptop ever joins, and a remote desktop or SMB port opened that
    way is what a worm looks for first. This builds the rule from its parts,
    writes it both as New-NetFirewallRule and as netsh advfirewall, with the
    commands that check and remove it, and says what is too wide before the
    rule exists.

    Nothing is applied here: it writes the commands, which are run elevated.
#>

<#
.SYNOPSIS
    Ports that should never be reachable from any network.

.DESCRIPTION
    Remote administration and file sharing: opened inbound to any address,
    each one is an entry point attackers scan for.

.OUTPUTS
    Hashtable of port number to service name.
#>
function Get-TkSensitiveFirewallPort {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        22 = 'SSH'; 23 = 'Telnet'; 135 = 'RPC endpoint mapper'; 139 = 'NetBIOS session'; 445 = 'SMB'
        1433 = 'SQL Server'; 3306 = 'MySQL'; 3389 = 'Remote Desktop'; 5432 = 'PostgreSQL'
        5900 = 'VNC'; 5985 = 'WinRM (HTTP)'; 5986 = 'WinRM (HTTPS)'
    }
}

<#
.SYNOPSIS
    Reads a list of ports: single ports and ranges, separated by commas.

.DESCRIPTION
    Pure. An empty list means any port.

.PARAMETER Value
    For example "80, 443, 8000-8080".

.OUTPUTS
    PSCustomObject with Items (normalised, for example "8000-8080"), Ranges
    (each item as a low and high port, for the warnings) and Error.
#>
function ConvertFrom-TkFirewallPortList {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Value
    )

    $items   = New-Object System.Collections.Generic.List[string]
    $ranges  = New-Object System.Collections.Generic.List[object]

    foreach ($part in @(([string] $Value) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {

        if ($part -match '^(\d{1,5})$') {
            $port = [int] $Matches[1]
            if ($port -lt 1 -or $port -gt 65535) {
                return [pscustomobject] @{ Items = @(); Ranges = @(); Error = ('Port {0} is out of range: ports go from 1 to 65535.' -f $part) }
            }
            $items.Add([string] $port)
            $ranges.Add(@($port, $port))
            continue
        }

        if ($part -match '^(\d{1,5})\s*-\s*(\d{1,5})$') {
            $low  = [int] $Matches[1]
            $high = [int] $Matches[2]
            if ($low -lt 1 -or $high -gt 65535 -or $low -ge $high) {
                return [pscustomobject] @{ Items = @(); Ranges = @(); Error = ('The range {0} is not valid: the first port must be lower than the second, both from 1 to 65535.' -f $part) }
            }
            $items.Add(('{0}-{1}' -f $low, $high))
            $ranges.Add(@($low, $high))
            continue
        }

        return [pscustomobject] @{ Items = @(); Ranges = @(); Error = ('"{0}" is not a port or a range (for example 443 or 8000-8080).' -f $part) }
    }

    return [pscustomobject] @{ Items = @($items.ToArray()); Ranges = @($ranges.ToArray()); Error = '' }
}

<#
.SYNOPSIS
    Reads a list of remote addresses.

.DESCRIPTION
    Pure. Accepts the keywords both New-NetFirewallRule and netsh know (Any,
    LocalSubnet, DNS, DHCP, WINS, DefaultGateway), single IPv4 or IPv6
    addresses, subnets in CIDR form and ranges written a-b. An empty list
    means any address.

.PARAMETER Value
    For example "LocalSubnet" or "192.168.1.0/24, 10.0.0.5".

.OUTPUTS
    PSCustomObject with Items (for New-NetFirewallRule), NetshItems, IsAny
    and Error.
#>
function ConvertFrom-TkFirewallAddressList {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Value
    )

    $keywords = [ordered] @{ 'any' = 'Any'; 'localsubnet' = 'LocalSubnet'; 'dns' = 'DNS'; 'dhcp' = 'DHCP'; 'wins' = 'WINS'; 'defaultgateway' = 'DefaultGateway' }
    $items    = New-Object System.Collections.Generic.List[string]
    $parsed   = $null

    # Dotted IPv4 or IPv6 only: TryParse alone takes "10" for 0.0.0.10.
    $readAddress = {
        param($text)
        $ip = $null
        if (($text -match '^\d{1,3}(\.\d{1,3}){3}$' -or ($text -match '^[0-9A-Fa-f:.]+$' -and $text.Contains(':'))) -and
            [System.Net.IPAddress]::TryParse($text, [ref] $ip)) {
            return $ip
        }
        return $null
    }

    foreach ($part in @(([string] $Value) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {

        if ($keywords.Contains($part.ToLowerInvariant())) {
            $items.Add($keywords[$part.ToLowerInvariant()])
            continue
        }

        if ($part -match '^([^/]+)/(\d{1,3})$') {
            $prefix = [int] $Matches[2]
            $parsed = & $readAddress $Matches[1].Trim()
            if ($parsed) {
                $max = if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
                if ($prefix -le $max) {
                    $items.Add(('{0}/{1}' -f $parsed, $prefix))
                    continue
                }
            }
            return [pscustomobject] @{ Items = @(); NetshItems = @(); IsAny = $false; Error = ('"{0}" is not a valid subnet (for example 192.168.1.0/24).' -f $part) }
        }

        if ($part -match '^([^-]+)-([^-]+)$') {
            $first = & $readAddress $Matches[1].Trim()
            $last  = & $readAddress $Matches[2].Trim()
            if ($first -and $last -and $first.AddressFamily -eq $last.AddressFamily) {
                $items.Add(('{0}-{1}' -f $first, $last))
                continue
            }
            return [pscustomobject] @{ Items = @(); NetshItems = @(); IsAny = $false; Error = ('"{0}" is not a valid address range (for example 10.0.0.10-10.0.0.20).' -f $part) }
        }

        $parsed = & $readAddress $part

        if (-not $parsed) {
            return [pscustomobject] @{ Items = @(); NetshItems = @(); IsAny = $false; Error = ('"{0}" is not an address, a subnet, a range or a keyword (Any, LocalSubnet, DNS, DHCP, WINS, DefaultGateway).' -f $part) }
        }

        $items.Add([string] $parsed)
    }

    $isAny = ($items.Count -eq 0 -or $items.Contains('Any'))

    if ($isAny) {
        $items.Clear()
    }

    return [pscustomobject] @{
        Items      = @($items.ToArray())
        NetshItems = @($items.ToArray() | ForEach-Object { if ($keywords.Values -contains $_) { $_.ToLowerInvariant() } else { $_ } })
        IsAny      = $isAny
        Error      = ''
    }
}

<#
.SYNOPSIS
    Ready-made rules, to fill the builder from a list.

.OUTPUTS
    PSCustomObject[] with Name and the rule fields.
#>
function Get-TkFirewallRulePreset {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $preset = {
        param($name, $ruleName, $direction, $action, $protocol, $localPort, $remotePort, $remoteAddress, $program, $profiles)
        [pscustomobject] @{
            Name = $name; RuleName = $ruleName; Direction = $direction; Action = $action; Protocol = $protocol
            LocalPort = $localPort; RemotePort = $remotePort; RemoteAddress = $remoteAddress; Program = $program; Profile = $profiles
        }
    }

    return @(
        (& $preset 'Ping from the local subnet'     'Allow ping (ICMPv4) from the local subnet' 'Inbound'  'Allow' 'ICMPv4 (ping)' '' '' 'LocalSubnet' '' @('Domain', 'Private'))
        (& $preset 'Remote Desktop from a subnet'   'Allow Remote Desktop from the admin subnet' 'Inbound' 'Allow' 'TCP' '3389' '' '192.168.1.0/24' '' @('Domain', 'Private'))
        (& $preset 'File sharing (SMB) from a subnet' 'Allow SMB from the local subnet'         'Inbound'  'Allow' 'TCP' '445'  '' 'LocalSubnet' '' @('Domain', 'Private'))
        (& $preset 'WinRM from a management host'   'Allow WinRM from the management host'      'Inbound'  'Allow' 'TCP' '5985' '' '192.168.1.10' '' @('Domain', 'Private'))
        (& $preset 'Web server (80 and 443)'        'Allow web server'                          'Inbound'  'Allow' 'TCP' '80, 443' '' '' '' @('Domain', 'Private', 'Public'))
        (& $preset 'Block an application outbound'  'Block app outbound'                        'Outbound' 'Block' 'Any' '' '' '' 'C:\Program Files\App\app.exe' @('Domain', 'Private', 'Public'))
        (& $preset 'Block outbound SMB'             'Block outbound SMB to the internet'        'Outbound' 'Block' 'TCP' '' '445' '' '' @('Public'))
    )
}

<#
.SYNOPSIS
    Builds a firewall rule as New-NetFirewallRule and netsh commands, and says what is too wide.

.DESCRIPTION
    Pure. Errors stop the commands from being written; warnings and notes go
    with them.

.PARAMETER Name
    The display name of the rule.

.PARAMETER Direction
    Inbound or Outbound.

.PARAMETER Action
    Allow or Block.

.PARAMETER Protocol
    TCP, UDP, ICMPv4 (ping), ICMPv6 (ping) or Any.

.PARAMETER LocalPort
    Ports on this machine; empty for any.

.PARAMETER RemotePort
    Ports on the other end; empty for any.

.PARAMETER RemoteAddress
    Who the rule applies to; empty for any.

.PARAMETER Program
    A full path to limit the rule to one program; empty for every program.

.PARAMETER NetworkProfile
    Domain, Private and/or Public.

.OUTPUTS
    PSCustomObject with Errors, Warnings, Notes, PowerShell, Netsh,
    PowerShellRemove, NetshRemove and Check.
#>
function New-TkFirewallRuleCommand {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Name = '',
        [Parameter()] [ValidateSet('Inbound', 'Outbound')] [string] $Direction = 'Inbound',
        [Parameter()] [ValidateSet('Allow', 'Block')] [string] $Action = 'Allow',
        [Parameter()] [ValidateSet('TCP', 'UDP', 'ICMPv4 (ping)', 'ICMPv6 (ping)', 'Any')] [string] $Protocol = 'TCP',
        [Parameter()] [AllowEmptyString()] [string] $LocalPort = '',
        [Parameter()] [AllowEmptyString()] [string] $RemotePort = '',
        [Parameter()] [AllowEmptyString()] [string] $RemoteAddress = '',
        [Parameter()] [AllowEmptyString()] [string] $Program = '',
        [Parameter()] [AllowEmptyCollection()] [string[]] $NetworkProfile = @('Domain', 'Private')
    )

    $errors   = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $notes    = New-Object System.Collections.Generic.List[string]

    $ruleName = $Name.Trim()
    $program  = $Program.Trim().Trim('"')
    $profiles = @('Domain', 'Private', 'Public' | Where-Object { $NetworkProfile -contains $_ })

    if ($ruleName.Length -eq 0) {
        $errors.Add('Give the rule a name: it is how it is found, checked and removed later.')
    }
    elseif ($ruleName.Contains('"')) {
        $errors.Add('The name cannot contain a double quote: netsh could not take it.')
    }

    if ($profiles.Count -eq 0) {
        $errors.Add('Tick at least one network profile: a rule on no profile never applies.')
    }

    $local  = ConvertFrom-TkFirewallPortList -Value $LocalPort
    $remote = ConvertFrom-TkFirewallPortList -Value $RemotePort
    $peers  = ConvertFrom-TkFirewallAddressList -Value $RemoteAddress

    foreach ($problem in @($local.Error, $remote.Error, $peers.Error)) {
        if ($problem) { $errors.Add($problem) }
    }

    $portable = $Protocol -in @('TCP', 'UDP')

    if (-not $portable -and ($local.Items.Count -gt 0 -or $remote.Items.Count -gt 0)) {
        $errors.Add('Ports only exist for TCP and UDP: choose one of them, or clear the ports.')
    }

    if ($program) {
        if ($program -notmatch '^([A-Za-z]:\\|\\\\|%[A-Za-z_]+%\\)') {
            $errors.Add('The program needs a full path, such as C:\Program Files\App\app.exe or %ProgramFiles%\App\app.exe.')
        }
        elseif ($program.Contains('"')) {
            $errors.Add('The program path cannot contain a double quote.')
        }
    }

    # --- What is too wide -------------------------------------------------
    if ($Direction -eq 'Inbound' -and $Action -eq 'Allow') {

        $sensitive = Get-TkSensitiveFirewallPort
        $exposed   = @($sensitive.Keys | Sort-Object | Where-Object {
                           $port = $_
                           @($local.Ranges | Where-Object { $port -ge $_[0] -and $port -le $_[1] }).Count -gt 0
                       } | ForEach-Object { '{0} ({1})' -f $_, $sensitive[$_] })

        if ($peers.IsAny -and $profiles -contains 'Public') {
            $warnings.Add('Open to any address on the Public profile: on a hotel or cafe network, everyone connected can reach it. Limit the remote address, or leave Public unticked.')
        }
        elseif ($peers.IsAny) {
            $notes.Add('Open to any address that can reach this machine. A remote address (LocalSubnet or a subnet) keeps it narrower.')
        }

        if ($exposed.Count -gt 0 -and $peers.IsAny) {
            $warnings.Add(('{0} opened to any address: remote administration and file sharing ports are the first ones scanned for. Allow only the admin subnet or host.' -f ($exposed -join ', ')))
        }

        if ($portable -and $local.Items.Count -eq 0 -and -not $program) {
            $warnings.Add('Every port and every program: this allows the whole protocol in. Name the port, or limit the rule to a program.')
        }
        elseif ($Protocol -eq 'Any' -and -not $program) {
            $warnings.Add('Every protocol and every program: this allows everything in from those addresses. Name a protocol and port, or a program.')
        }
    }

    if ($Action -eq 'Block') {
        $notes.Add('A block rule wins over every allow rule, the ones Windows and applications add included.')
    }

    if ($Direction -eq 'Outbound' -and $Action -eq 'Allow') {
        $notes.Add('Outbound traffic is allowed by default: an outbound allow rule only matters where the profile blocks outbound by default.')
    }

    if ($errors.Count -gt 0) {
        return [pscustomobject] @{
            Errors = @($errors.ToArray()); Warnings = @($warnings.ToArray()); Notes = @($notes.ToArray())
            PowerShell = ''; Netsh = ''; PowerShellRemove = ''; NetshRemove = ''; Check = ''
        }
    }

    # --- The commands -------------------------------------------------------
    $quoted = "'{0}'" -f ($ruleName -replace "'", "''")

    $ps = New-Object System.Collections.Generic.List[string]
    $ps.Add(('New-NetFirewallRule -DisplayName {0} -Direction {1} -Action {2}' -f $quoted, $Direction, $Action))

    $netsh = New-Object System.Collections.Generic.List[string]
    $netsh.Add(('netsh advfirewall firewall add rule name="{0}" dir={1} action={2}' -f $ruleName, $(if ($Direction -eq 'Inbound') { 'in' } else { 'out' }), $Action.ToLowerInvariant()))

    switch ($Protocol) {
        'TCP'           { $ps.Add('-Protocol TCP');                  $netsh.Add('protocol=tcp') }
        'UDP'           { $ps.Add('-Protocol UDP');                  $netsh.Add('protocol=udp') }
        'ICMPv4 (ping)' { $ps.Add('-Protocol ICMPv4 -IcmpType 8');   $netsh.Add('protocol=icmpv4:8,any') }
        'ICMPv6 (ping)' { $ps.Add('-Protocol ICMPv6 -IcmpType 128'); $netsh.Add('protocol=icmpv6:128,any') }
        default         { $netsh.Add('protocol=any') }
    }

    if ($local.Items.Count -gt 0) {
        $ps.Add(('-LocalPort {0}' -f ((@($local.Items | ForEach-Object { if ($_ -match '-') { "'$_'" } else { $_ } })) -join ',')))
        $netsh.Add(('localport={0}' -f ($local.Items -join ',')))
    }

    if ($remote.Items.Count -gt 0) {
        $ps.Add(('-RemotePort {0}' -f ((@($remote.Items | ForEach-Object { if ($_ -match '-') { "'$_'" } else { $_ } })) -join ',')))
        $netsh.Add(('remoteport={0}' -f ($remote.Items -join ',')))
    }

    if (-not $peers.IsAny) {
        $ps.Add(('-RemoteAddress {0}' -f ((@($peers.Items | ForEach-Object { if ($_ -match '[-/:]') { "'$_'" } else { $_ } })) -join ',')))
        $netsh.Add(('remoteip={0}' -f ($peers.NetshItems -join ',')))
    }

    if ($program) {
        $ps.Add(("-Program '{0}'" -f ($program -replace "'", "''")))
        $netsh.Add(('program="{0}"' -f $program))
    }

    $ps.Add(('-Profile {0}' -f ($profiles -join ',')))
    $netsh.Add(('profile={0}' -f (($profiles | ForEach-Object { $_.ToLowerInvariant() }) -join ',')))
    $netsh.Add('enable=yes')

    return [pscustomobject] @{
        Errors           = @()
        Warnings         = @($warnings.ToArray())
        Notes            = @($notes.ToArray())
        PowerShell       = ($ps -join ' ')
        Netsh            = ($netsh -join ' ')
        PowerShellRemove = ('Remove-NetFirewallRule -DisplayName {0}' -f $quoted)
        NetshRemove      = ('netsh advfirewall firewall delete rule name="{0}"' -f $ruleName)
        Check            = ('Get-NetFirewallRule -DisplayName {0} | Format-List DisplayName, Enabled, Direction, Action, Profile; Get-NetFirewallRule -DisplayName {0} | Get-NetFirewallPortFilter; Get-NetFirewallRule -DisplayName {0} | Get-NetFirewallAddressFilter' -f $quoted)
    }
}

<#
.SYNOPSIS
    Formats the rule for the output box.

.OUTPUTS
    System.String[]
#>
function Format-TkFirewallRuleReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Rule
    )

    $lines = New-Object System.Collections.Generic.List[string]

    if (@($Rule.Errors).Count -gt 0) {
        foreach ($problem in $Rule.Errors) { $lines.Add(('Fix first: {0}' -f $problem)) }
        return @($lines.ToArray())
    }

    foreach ($warning in @($Rule.Warnings)) { $lines.Add(('Warning: {0}' -f $warning)) }
    foreach ($note in @($Rule.Notes))       { $lines.Add(('Note: {0}' -f $note)) }
    if ($lines.Count -gt 0) { $lines.Add('') }

    $lines.Add('PowerShell (elevated):')
    $lines.Add(('  {0}' -f $Rule.PowerShell))
    $lines.Add('')
    $lines.Add('netsh (elevated command prompt):')
    $lines.Add(('  {0}' -f $Rule.Netsh))
    $lines.Add('')
    $lines.Add('Check it:')
    $lines.Add(('  {0}' -f $Rule.Check))
    $lines.Add('')
    $lines.Add('Remove it:')
    $lines.Add(('  {0}' -f $Rule.PowerShellRemove))
    $lines.Add(('  {0}' -f $Rule.NetshRemove))

    return @($lines.ToArray())
}
