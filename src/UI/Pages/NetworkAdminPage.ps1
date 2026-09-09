<#
    Toolkit - UI / Network administration tabs

    Wires the two tabs added to the Network page: the measurement tools and
    the configuration editor. Kept in its own file rather than growing
    NetworkPage.ps1, so the original five tabs stay readable.

    Everything that touches the network runs in the background. Path MTU
    discovery sends up to a dozen probes and a link quality run sends fifty,
    which would freeze the window if either ran on the dispatcher thread.
#>

<#
.SYNOPSIS
    Wires the Admin tools and Configuration tabs.
#>
function Initialize-TkNetworkAdminPage {
    [CmdletBinding()]
    param()

    # --- Measurement tools ------------------------------------------------
    Register-TkClick -Name 'BtnPathMtu'        -Action { Invoke-TkPathMtuFromUi }
    Register-TkClick -Name 'BtnLinkQuality'    -Action { Invoke-TkLinkQualityFromUi }
    Register-TkClick -Name 'BtnTraceRoute'     -Action { Invoke-TkTraceRouteFromUi }
    Register-TkClick -Name 'BtnTlsCertificate' -Action { Invoke-TkTlsInspectionFromUi }
    Register-TkClick -Name 'BtnWakeOnLan'      -Action { Invoke-TkWakeOnLanFromUi }
    Register-TkClick -Name 'BtnNeighbours'     -Action { Invoke-TkNeighbourTableFromUi }

    # --- Configuration ----------------------------------------------------
    Register-TkClick -Name 'BtnApplyProfile'     -Action { Invoke-TkApplyProfileFromUi }
    Register-TkClick -Name 'BtnSaveProfile'      -Action { Invoke-TkSaveProfileFromUi }
    Register-TkClick -Name 'BtnSaveDhcpProfile'  -Action { Invoke-TkSaveProfileFromUi -UseDhcp }
    Register-TkClick -Name 'BtnCaptureProfile'   -Action { Invoke-TkCaptureProfileFromUi }
    Register-TkClick -Name 'BtnDeleteProfile'    -Action { Invoke-TkDeleteProfileFromUi }

    Register-TkClick -Name 'BtnShowRoutes'  -Action {

        Invoke-TkBackgroundAction -StatusText 'Reading the routing table...' `
            -ScriptBlock { Get-TkRouteTable } `
            -OnComplete {
                param($result)

                Set-TkOutput -ControlName 'ConfigOutput' -Text (
                    'Routing table, longest prefix first, which is the order a router evaluates it in.' +
                    [Environment]::NewLine + [Environment]::NewLine +
                    (Format-TkTableText -InputObject (@($result.Output) |
                        Select-Object Destination, NextHop, Interface, Metric, Persistent, Origin))
                )
            }
    }

    Register-TkClick -Name 'BtnAddRoute'    -Action { Invoke-TkAddRouteFromUi }
    Register-TkClick -Name 'BtnRemoveRoute' -Action { Invoke-TkRemoveRouteFromUi }

    Register-TkClick -Name 'BtnShowProxies' -Action {

        Invoke-TkBackgroundAction -StatusText 'Reading the port proxy rules...' `
            -ScriptBlock { Get-TkPortProxy } `
            -OnComplete {
                param($result)

                $rules = @($result.Output)

                $text = if ($rules.Count -eq 0) { 'No port proxy rule is configured.' }
                        else { Format-TkTableText -InputObject $rules }

                Set-TkOutput -ControlName 'ConfigOutput' -Text (
                    $text + [Environment]::NewLine + [Environment]::NewLine +
                    'A rule only forwards. Windows Firewall must also allow the listening port inbound.'
                )
            }
    }

    Register-TkClick -Name 'BtnAddProxy'    -Action { Invoke-TkAddPortProxyFromUi }
    Register-TkClick -Name 'BtnRemoveProxy' -Action { Invoke-TkRemovePortProxyFromUi }

    Update-TkAdapterSelectors
    Update-TkProfileSelector
}

# ---------------------------------------------------------------------------
# Measurement tools
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads the target host from the Admin tools tab.

.OUTPUTS
    System.String
#>
function Get-TkAdminTarget {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $control = Get-TkControl -Name 'AdminTarget'

    if (-not $control) {
        return ''
    }

    return $control.Text.Trim()
}

<#
.SYNOPSIS
    Runs path MTU discovery against the target.
#>
function Invoke-TkPathMtuFromUi {
    [CmdletBinding()]
    param()

    $target = Get-TkAdminTarget

    if ([string]::IsNullOrWhiteSpace($target)) {
        Set-TkStatus -Text 'Enter a host first.'
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Measuring the path MTU to {0}...' -f $target) `
        -ParameterList @{ target = $target } `
        -ScriptBlock {
            param($target)
            Test-TkPathMtu -ComputerName $target
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                Set-TkOutput -ControlName 'AdminOutput' -Text 'No result.'
                return
            }

            $lines = @(
                'Path MTU discovery'
                ('-' * 60)
                ''
                'Destination     {0}' -f $report.ComputerName
                'Reachable       {0}' -f $report.Reachable
                'Path MTU        {0}' -f $(if ($report.PathMtu) { '{0} bytes' -f $report.PathMtu } else { 'not measurable' })
                'Probes sent     {0}' -f $report.ProbeCount
                ''
                $report.Interpretation
            )

            Set-TkOutput -ControlName 'AdminOutput' -Text ($lines -join [Environment]::NewLine)
        }
}

<#
.SYNOPSIS
    Measures loss, latency and jitter towards the target.
#>
function Invoke-TkLinkQualityFromUi {
    [CmdletBinding()]
    param()

    $target = Get-TkAdminTarget

    if ([string]::IsNullOrWhiteSpace($target)) {
        Set-TkStatus -Text 'Enter a host first.'
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Measuring the link to {0}, this takes a few seconds...' -f $target) `
        -ParameterList @{ target = $target } `
        -ScriptBlock {
            param($target)
            Test-TkLinkQuality -ComputerName $target -Count 25 -IntervalMilliseconds 150
        } `
        -OnComplete {
            param($result)

            $report = @($result.Output) | Select-Object -First 1

            if (-not $report) {
                return
            }

            $lines = @(
                'Link quality'
                ('-' * 60)
                ''
                'Destination     {0}' -f $report.ComputerName
                'Sent            {0}' -f $report.Sent
                'Received        {0}' -f $report.Received
                'Loss            {0} percent' -f $report.LossPercent
                ''
                'Latency min     {0} ms' -f $report.MinimumMs
                'Latency average {0} ms' -f $report.AverageMs
                'Latency max     {0} ms' -f $report.MaximumMs
                'Jitter          {0} ms' -f $report.JitterMs
                ''
                $report.Assessment
            )

            Set-TkOutput -ControlName 'AdminOutput' -Text ($lines -join [Environment]::NewLine)
        }
}

<#
.SYNOPSIS
    Traces the path to the target.
#>
function Invoke-TkTraceRouteFromUi {
    [CmdletBinding()]
    param()

    $target = Get-TkAdminTarget

    if ([string]::IsNullOrWhiteSpace($target)) {
        Set-TkStatus -Text 'Enter a host first.'
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Tracing the path to {0}...' -f $target) `
        -ParameterList @{ target = $target } `
        -ScriptBlock {
            param($target)
            Get-TkTraceRoute -ComputerName $target -ResolveNames
        } `
        -OnComplete {
            param($result)

            $hops = @($result.Output)

            Set-TkOutput -ControlName 'AdminOutput' -Text (
                ('Path to the destination, {0} hops.' -f $hops.Count) + [Environment]::NewLine +
                'A hop showing * is usually a router configured not to answer, not a break in the path.' +
                [Environment]::NewLine + [Environment]::NewLine +
                (Format-TkTableText -InputObject ($hops |
                    Select-Object Hop, Address, HostName, BestMs, AverageMs, Replies))
            )
        }
}

<#
.SYNOPSIS
    Inspects the certificate presented by a TLS endpoint.
#>
function Invoke-TkTlsInspectionFromUi {
    [CmdletBinding()]
    param()

    $hostName = (Get-TkControl -Name 'TlsHost').Text.Trim()
    $portText = (Get-TkControl -Name 'TlsPort').Text.Trim()

    $port = 443

    if (-not [int]::TryParse($portText, [ref] $port)) {
        $port = 443
    }

    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Set-TkStatus -Text 'Enter a host first.'
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Reading the certificate from {0}:{1}...' -f $hostName, $port) `
        -ParameterList @{ target = $hostName; port = $port } `
        -ScriptBlock {
            param($target, $port)
            Get-TkTlsCertificate -ComputerName $target -Port $port
        } `
        -OnComplete {
            param($result)

            $certificate = @($result.Output) | Select-Object -First 1

            if (-not $certificate) {
                return
            }

            if (-not $certificate.Subject) {
                Set-TkOutput -ControlName 'AdminOutput' -Text $certificate.Verdict
                return
            }

            $lines = @(
                'TLS certificate'
                ('-' * 60)
                ''
                'Endpoint        {0}:{1}' -f $certificate.ComputerName, $certificate.Port
                'Subject         {0}' -f $certificate.Subject
                'Issuer          {0}' -f $certificate.Issuer
                'Alt names       {0}' -f $certificate.SubjectAltNames
                ''
                'Valid from      {0}' -f $certificate.NotBefore
                'Valid until     {0}' -f $certificate.NotAfter
                'Days remaining  {0}' -f $certificate.DaysRemaining
                ''
                'Protocol        {0}' -f $certificate.Protocol
                'Signature       {0}' -f $certificate.SignatureAlgorithm
                'Key size        {0} bits' -f $certificate.KeySize
                'Self signed     {0}' -f $certificate.SelfSigned
                'Thumbprint      {0}' -f $certificate.Thumbprint
                ''
                'Chain           {0}' -f $certificate.ChainStatus
                ''
                $certificate.Verdict
            )

            Set-TkOutput -ControlName 'AdminOutput' -Text ($lines -join [Environment]::NewLine)
        }
}

<#
.SYNOPSIS
    Sends a Wake-on-LAN packet from the values on the tab.
#>
function Invoke-TkWakeOnLanFromUi {
    [CmdletBinding()]
    param()

    $mac       = (Get-TkControl -Name 'WolMac').Text.Trim()
    $broadcast = (Get-TkControl -Name 'WolBroadcast').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($mac)) {
        Set-TkStatus -Text 'Enter the MAC address of the machine to wake.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($broadcast)) {
        $broadcast = '255.255.255.255'
    }

    $sent = Send-TkWakeOnLan -MacAddress $mac -BroadcastAddress $broadcast -Confirm:$false

    $lines = @(
        'Wake-on-LAN'
        ('-' * 60)
        ''
        'Target MAC      {0}' -f $mac
        'Sent to         {0}:9' -f $broadcast
        'Result          {0}' -f $(if ($sent) { 'Packet sent' } else { 'Not sent, see the output panel' })
        ''
        'A magic packet is fire and forget: there is no acknowledgement, so a'
        'successful send does not mean the machine woke up.'
        ''
        'If it does not wake, check in this order:'
        '  1. Wake on LAN enabled in the firmware.'
        '  2. The adapter power settings allow it to wake the machine.'
        '  3. Fast start-up disabled, because it puts the machine in a state'
        '     many adapters will not wake from.'
        '  4. The broadcast reaches the target VLAN. From another subnet you'
        '     need the directed broadcast and a router that relays it.'
    )

    Set-TkOutput -ControlName 'AdminOutput' -Text ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Shows the neighbour cache with vendor names.
#>
function Invoke-TkNeighbourTableFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the neighbour cache...' `
        -ScriptBlock { Get-TkNeighborTable -ReachableOnly } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)

            Set-TkOutput -ControlName 'AdminOutput' -Text (
                ('Neighbour cache, {0} entries. The vendor comes from a built in table of the' -f $rows.Count) +
                [Environment]::NewLine +
                'hardware usually met on a corporate LAN, so an unknown prefix is not unusual.' +
                [Environment]::NewLine + [Environment]::NewLine +
                (Format-TkTableText -InputObject $rows)
            )
        }
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Fills the adapter combo boxes.
#>
function Update-TkAdapterSelectors {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Listing adapters...' `
        -ScriptBlock { Get-TkNetworkAdapterInfo -IncludeDisconnected } `
        -OnComplete {
            param($result)

            $names = @($result.Output | ForEach-Object { $_.Name })

            foreach ($controlName in @('ProfileAdapter', 'RouteAdapter')) {

                $combo = Get-TkControl -Name $controlName

                if (-not $combo) {
                    continue
                }

                $previous = [string] $combo.SelectedItem
                $combo.Items.Clear()

                foreach ($name in $names) {
                    [void] $combo.Items.Add($name)
                }

                if ($previous -and $combo.Items.Contains($previous)) {
                    $combo.SelectedItem = $previous
                }
                elseif ($combo.Items.Count -gt 0) {
                    $combo.SelectedIndex = 0
                }
            }
        }
}

<#
.SYNOPSIS
    Refreshes the saved profile list.
#>
function Update-TkProfileSelector {
    [CmdletBinding()]
    param()

    $combo = Get-TkControl -Name 'ProfileSelect'

    if (-not $combo) {
        return
    }

    $previous = [string] $combo.SelectedItem
    $combo.Items.Clear()

    foreach ($item in (Get-TkAdapterProfile)) {
        [void] $combo.Items.Add($item.Name)
    }

    if ($previous -and $combo.Items.Contains($previous)) {
        $combo.SelectedItem = $previous
    }
    elseif ($combo.Items.Count -gt 0) {
        $combo.SelectedIndex = 0
    }
}

<#
.SYNOPSIS
    Saves a profile from the fields on the tab.

.PARAMETER UseDhcp
    Saves a profile that returns the adapter to DHCP, ignoring the address
    fields.
#>
function Invoke-TkSaveProfileFromUi {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch] $UseDhcp
    )

    $name = (Get-TkControl -Name 'ProfileName').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($name)) {
        Set-TkStatus -Text 'Give the profile a name.'
        return
    }

    if ($UseDhcp) {

        if (Save-TkAdapterProfile -Name $name -UseDhcp -Confirm:$false) {
            Update-TkProfileSelector
            Set-TkStatus -Text ('DHCP profile saved: {0}' -f $name)
        }

        return
    }

    $prefix = 24

    if (-not [int]::TryParse((Get-TkControl -Name 'ProfilePrefix').Text.Trim(), [ref] $prefix)) {
        $prefix = 24
    }

    $parameters = @{
        Name         = $name
        IPAddress    = (Get-TkControl -Name 'ProfileAddress').Text.Trim()
        PrefixLength = $prefix
        Confirm      = $false
    }

    $gateway = (Get-TkControl -Name 'ProfileGateway').Text.Trim()

    if ($gateway) {
        $parameters['Gateway'] = $gateway
    }

    $dns = (Get-TkControl -Name 'ProfileDns').Text.Trim()

    if ($dns) {
        $parameters['DnsServer'] = @($dns -split '[,;]\s*' | Where-Object { $_ })
    }

    if (Save-TkAdapterProfile @parameters) {
        Update-TkProfileSelector
        Set-TkStatus -Text ('Profile saved: {0}' -f $name)
    }
}

<#
.SYNOPSIS
    Captures the live configuration of the selected adapter as a profile.
#>
function Invoke-TkCaptureProfileFromUi {
    [CmdletBinding()]
    param()

    $adapter = [string] (Get-TkControl -Name 'ProfileAdapter').SelectedItem
    $name    = (Get-TkControl -Name 'ProfileName').Text.Trim()

    if (-not $adapter) {
        Set-TkStatus -Text 'Select an adapter first.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($name)) {
        Set-TkStatus -Text 'Give the captured profile a name.'
        return
    }

    if (Save-TkCurrentAdapterProfile -InterfaceAlias $adapter -Name $name -Confirm:$false) {
        Update-TkProfileSelector
        Set-TkStatus -Text ('Captured the configuration of {0} as "{1}".' -f $adapter, $name)
    }
}

<#
.SYNOPSIS
    Deletes the selected profile.
#>
function Invoke-TkDeleteProfileFromUi {
    [CmdletBinding()]
    param()

    $name = [string] (Get-TkControl -Name 'ProfileSelect').SelectedItem

    if (-not $name) {
        Set-TkStatus -Text 'Select a profile first.'
        return
    }

    if (Remove-TkAdapterProfile -Name $name -Confirm:$false) {
        Update-TkProfileSelector
        Set-TkStatus -Text ('Profile deleted: {0}' -f $name)
    }
}

<#
.SYNOPSIS
    Applies the selected profile to the selected adapter.

.DESCRIPTION
    Confirmed explicitly, because reconfiguring the adapter carrying a remote
    session ends that session, and doing it to the wrong adapter on a bench
    machine costs a trip back to it.
#>
function Invoke-TkApplyProfileFromUi {
    [CmdletBinding()]
    param()

    $adapter = [string] (Get-TkControl -Name 'ProfileAdapter').SelectedItem
    $name    = [string] (Get-TkControl -Name 'ProfileSelect').SelectedItem

    if (-not $adapter -or -not $name) {
        Set-TkStatus -Text 'Select both an adapter and a profile.'
        return
    }

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Changing an adapter configuration requires an elevated instance.'
        return
    }

    $confirmed = Confirm-TkAction -Title 'Apply an IP profile' -Message (
        "Apply `"{0}`" to {1}?`n`nThe current addresses, gateway and DNS servers on that adapter are replaced. If your remote session runs over it, you will be disconnected." -f $name, $adapter
    )

    if (-not $confirmed) {
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Applying {0} to {1}...' -f $name, $adapter) `
        -ParameterList @{ alias = $adapter; profileName = $name } `
        -ScriptBlock {
            param($alias, $profileName)
            Set-TkAdapterProfile -InterfaceAlias $alias -Name $profileName -Confirm:$false
        } `
        -OnComplete {
            param($result)

            if (@($result.Output) -contains $true) {
                Set-TkStatus -Text 'Profile applied.'
            }
            else {
                Set-TkStatus -Text 'The profile could not be applied. See the output panel.'
            }

            Update-TkAdapterList
        }
}

<#
.SYNOPSIS
    Adds a persistent route from the fields on the tab.
#>
function Invoke-TkAddRouteFromUi {
    [CmdletBinding()]
    param()

    $prefix  = (Get-TkControl -Name 'RoutePrefix').Text.Trim()
    $nextHop = (Get-TkControl -Name 'RouteNextHop').Text.Trim()
    $adapter = [string] (Get-TkControl -Name 'RouteAdapter').SelectedItem

    if (-not $prefix -or -not $nextHop -or -not $adapter) {
        Set-TkStatus -Text 'A destination prefix, a next hop and an adapter are all required.'
        return
    }

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Adding a route requires an elevated instance.'
        return
    }

    if (Add-TkPersistentRoute -DestinationPrefix $prefix -NextHop $nextHop -InterfaceAlias $adapter -Confirm:$false) {
        Set-TkStatus -Text ('Route added: {0} via {1}' -f $prefix, $nextHop)
    }
}

<#
.SYNOPSIS
    Removes the route named in the fields on the tab.
#>
function Invoke-TkRemoveRouteFromUi {
    [CmdletBinding()]
    param()

    $prefix = (Get-TkControl -Name 'RoutePrefix').Text.Trim()

    if (-not $prefix) {
        Set-TkStatus -Text 'Enter the destination prefix to remove.'
        return
    }

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Removing a route requires an elevated instance.'
        return
    }

    $confirmed = Confirm-TkAction -Title 'Remove a route' -Message (
        "Remove the route to {0}?" -f $prefix
    )

    if (-not $confirmed) {
        return
    }

    if (Remove-TkRoute -DestinationPrefix $prefix -Confirm:$false) {
        Set-TkStatus -Text ('Route removed: {0}' -f $prefix)
    }
}

<#
.SYNOPSIS
    Publishes a port through the built in proxy.
#>
function Invoke-TkAddPortProxyFromUi {
    [CmdletBinding()]
    param()

    $listenPort  = 0
    $connectPort = 0

    if (-not [int]::TryParse((Get-TkControl -Name 'ProxyListenPort').Text.Trim(), [ref] $listenPort) -or
        -not [int]::TryParse((Get-TkControl -Name 'ProxyConnectPort').Text.Trim(), [ref] $connectPort)) {

        Set-TkStatus -Text 'Both ports must be numbers.'
        return
    }

    $address = (Get-TkControl -Name 'ProxyConnectAddress').Text.Trim()

    if (-not $address) {
        Set-TkStatus -Text 'Enter the address to forward to.'
        return
    }

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Adding a port proxy rule requires an elevated instance.'
        return
    }

    if (Add-TkPortProxy -ListenPort $listenPort -ConnectAddress $address -ConnectPort $connectPort -Confirm:$false) {
        Set-TkStatus -Text ('Publishing {0} to {1}:{2}' -f $listenPort, $address, $connectPort)
    }
}

<#
.SYNOPSIS
    Removes a port proxy rule.
#>
function Invoke-TkRemovePortProxyFromUi {
    [CmdletBinding()]
    param()

    $listenPort = 0

    if (-not [int]::TryParse((Get-TkControl -Name 'ProxyListenPort').Text.Trim(), [ref] $listenPort)) {
        Set-TkStatus -Text 'Enter the listening port to remove.'
        return
    }

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Removing a port proxy rule requires an elevated instance.'
        return
    }

    if (Remove-TkPortProxy -ListenPort $listenPort -Confirm:$false) {
        Set-TkStatus -Text ('Port proxy removed on {0}.' -f $listenPort)
    }
}
