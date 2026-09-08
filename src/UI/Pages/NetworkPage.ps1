<#
    Toolkit - UI / Network page

    Five tabs: subnet calculator, adapter inventory, live diagnostics, the
    knowledge base and the vendor command reference.

    The calculator runs on the UI thread because it is pure arithmetic and
    instant. Everything that touches the network runs in the background.
#>

<#
.SYNOPSIS
    Wires the Network page.
#>
function Initialize-TkNetworkPage {
    [CmdletBinding()]
    param()

    # --- Subnet calculator ------------------------------------------------
    Register-TkClick -Name 'BtnCalculateSubnet' -Action { Invoke-TkSubnetCalculation }
    Register-TkClick -Name 'BtnSplitSubnet'     -Action { Invoke-TkSubnetSplit }
    Register-TkClick -Name 'BtnPrefixForHosts'  -Action { Invoke-TkPrefixForHosts }

    $subnetInput = Get-TkControl -Name 'SubnetInput'

    if ($subnetInput) {

        # Enter is the natural way to run a calculator.
        $subnetInput.Add_KeyDown({
            param($eventSource, $routedArgs)

            if ($routedArgs.Key -eq [System.Windows.Input.Key]::Return) {
                Invoke-TkSubnetCalculation
            }
        })
    }

    # --- Adapters ---------------------------------------------------------
    Register-TkClick -Name 'BtnRefreshAdapters' -Action { Update-TkAdapterList }

    Register-TkClick -Name 'BtnPublicIp' -Action {

        Invoke-TkBackgroundAction -StatusText 'Querying the public address...' `
            -ScriptBlock { Get-TkPublicIpAddress } `
            -OnComplete {
                param($result)
                Set-TkStatus -Text ('Public address: {0}' -f (@($result.Output) | Select-Object -Last 1))
            }
    }

    Register-TkClick -Name 'BtnListeningPorts' -Action {

        Invoke-TkBackgroundAction -StatusText 'Reading listening sockets...' `
            -ScriptBlock { Get-TkListeningPort } `
            -OnComplete {
                param($result)

                $tabs = Get-TkControl -Name 'NetworkTabs'

                if ($tabs) {
                    $tabs.SelectedIndex = 2
                }

                Set-TkOutput -ControlName 'NetworkOutput' -Text (Format-TkTableText -InputObject $result.Output)
            }
    }

    # --- Diagnostics ------------------------------------------------------
    Register-TkClick -Name 'BtnTestConnectivity' -Action { Invoke-TkConnectivityCheck }
    Register-TkClick -Name 'BtnPortScan'         -Action { Invoke-TkPortCheck }
    Register-TkClick -Name 'BtnSweep'            -Action { Invoke-TkSubnetSweep }
    Register-TkClick -Name 'BtnResolveDns'       -Action { Invoke-TkDnsLookup }

    $dnsType = Get-TkControl -Name 'DnsType'

    if ($dnsType) {

        foreach ($type in @('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR')) {
            [void] $dnsType.Items.Add($type)
        }

        $dnsType.SelectedIndex = 0
    }

    Initialize-TkKnowledgeBase
    Initialize-TkVendorCommands

    Update-TkAdapterList
}

# ---------------------------------------------------------------------------
# Subnet calculator
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Computes and displays the properties of a subnet.
#>
function Invoke-TkSubnetCalculation {
    [CmdletBinding()]
    param()

    # Not named $input: that is an automatic variable in PowerShell.
    $expression = (Get-TkControl -Name 'SubnetInput').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($expression)) {
        return
    }

    try {
        $info = Get-TkSubnetInfo -Address $expression
    }
    catch {
        Set-TkOutput -ControlName 'SubnetOutput' -Text ('Error: {0}' -f $_.Exception.Message)
        return
    }

    $lines = @(
        'Input                 {0}' -f $info.Address
        ''
        'Network               {0}' -f $info.NetworkAddress
        'CIDR                  {0}' -f $info.Cidr
        'Subnet mask           {0}' -f $info.SubnetMask
        'Wildcard mask         {0}' -f $info.WildcardMask
        'Broadcast             {0}' -f $info.BroadcastAddress
        ''
        'First usable host     {0}' -f $info.FirstHost
        'Last usable host      {0}' -f $info.LastHost
        'Usable hosts          {0:N0}' -f $info.UsableHosts
        'Total addresses       {0:N0}' -f $info.TotalAddresses
        ''
        'Address class         {0}' -f $info.AddressClass
        'Scope                 {0}' -f $info.Scope
        ''
        'Address in binary     {0}' -f $info.BinaryAddress
        'Mask in binary        {0}' -f $info.BinaryMask
    )

    if ($info.PrefixLength -eq 31) {
        $lines += ''
        $lines += 'Note: a /31 is a point to point link. RFC 3021 makes both addresses usable,'
        $lines += 'which is why there is no broadcast address to reserve here.'
    }

    if ($info.PrefixLength -eq 32) {
        $lines += ''
        $lines += 'Note: a /32 is a single host route, used for loopbacks and host specific routes.'
    }

    Set-TkOutput -ControlName 'SubnetOutput' -Text ($lines -join [Environment]::NewLine)
    Set-TkStatus -Text ('{0}: {1:N0} usable host(s).' -f $info.Cidr, $info.UsableHosts)
}

<#
.SYNOPSIS
    Splits the network in the input box into smaller subnets.
#>
function Invoke-TkSubnetSplit {
    [CmdletBinding()]
    param()

    $network = (Get-TkControl -Name 'SubnetInput').Text.Trim()
    $prefix  = (Get-TkControl -Name 'SplitPrefixInput').Text.Trim()

    $parsedPrefix = 0

    if (-not [int]::TryParse($prefix, [ref] $parsedPrefix)) {
        Set-TkOutput -ControlName 'SubnetOutput' -Text 'The new prefix must be a number between 1 and 32.'
        return
    }

    try {
        $subnets = Split-TkSubnet -Network $network -NewPrefixLength $parsedPrefix
    }
    catch {
        Set-TkOutput -ControlName 'SubnetOutput' -Text ('Error: {0}' -f $_.Exception.Message)
        return
    }

    $header = 'Splitting {0} into /{1} subnets: {2} result(s).' -f $network, $parsedPrefix, $subnets.Count

    Set-TkOutput -ControlName 'SubnetOutput' -Text (
        $header + [Environment]::NewLine + [Environment]::NewLine + (Format-TkTableText -InputObject $subnets)
    )

    Set-TkStatus -Text $header
}

<#
.SYNOPSIS
    Finds the smallest prefix able to hold a number of hosts.
#>
function Invoke-TkPrefixForHosts {
    [CmdletBinding()]
    param()

    $value = (Get-TkControl -Name 'HostCountInput').Text.Trim()
    $count = 0

    if (-not [int]::TryParse($value, [ref] $count) -or $count -lt 1) {
        Set-TkOutput -ControlName 'SubnetOutput' -Text 'Enter a host count of 1 or more.'
        return
    }

    try {
        $result = Get-TkPrefixForHostCount -HostCount $count
    }
    catch {
        Set-TkOutput -ControlName 'SubnetOutput' -Text ('Error: {0}' -f $_.Exception.Message)
        return
    }

    $lines = @(
        'Hosts required        {0:N0}' -f $result.RequestedHosts
        ''
        'Smallest prefix       /{0}' -f $result.PrefixLength
        'Subnet mask           {0}'  -f $result.SubnetMask
        'Usable hosts          {0:N0}' -f $result.UsableHosts
        'Spare addresses       {0:N0}' -f $result.WastedAddresses
        ''
        'Size on a power of two boundary so the prefix can be summarised later.'
    )

    Set-TkOutput -ControlName 'SubnetOutput' -Text ($lines -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# Adapters and diagnostics
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Refreshes the adapter list.
#>
function Update-TkAdapterList {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading network adapters...' `
        -ScriptBlock { Get-TkNetworkAdapterInfo -IncludeDisconnected } `
        -OnComplete {
            param($result)

            $list = Get-TkControl -Name 'ListAdapters'

            if ($list) {
                $list.ItemsSource = @($result.Output)
            }

            Set-TkStatus -Text ('{0} adapter(s).' -f @($result.Output).Count)
        }
}

<#
.SYNOPSIS
    Runs the gateway, DNS and outbound HTTPS checks.
#>
function Invoke-TkConnectivityCheck {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Testing connectivity...' `
        -ScriptBlock { Test-TkConnectivity } `
        -OnComplete {
            param($result)

            $rows    = @($result.Output)
            $failed  = @($rows | Where-Object { -not $_.Success })

            $text = Format-TkTableText -InputObject ($rows | Select-Object Step, Target, Success, Detail)

            if ($failed.Count -gt 0) {
                $text += [Environment]::NewLine + [Environment]::NewLine +
                         ('First failing step: {0}. Fix that before looking further up the stack.' -f $failed[0].Step)
            }

            Set-TkOutput -ControlName 'NetworkOutput' -Text $text
        }
}

<#
.SYNOPSIS
    Checks the common service ports on the target host.
#>
function Invoke-TkPortCheck {
    [CmdletBinding()]
    param()

    $target = (Get-TkControl -Name 'DiagTarget').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($target)) {
        Set-TkStatus -Text 'Enter a target host first.'
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Checking common ports on {0}...' -f $target) `
        -ArgumentList @($target) `
        -ScriptBlock {
            # Not named $host: that is an automatic variable in PowerShell.
            param($targetHost)
            Test-TkPortList -ComputerName $targetHost
        } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)
            $open = @($rows | Where-Object { $_.Open })

            $text = 'Open ports:' + [Environment]::NewLine +
                    (Format-TkTableText -InputObject ($open | Select-Object Port, Service, ResponseMs))

            $text += [Environment]::NewLine + [Environment]::NewLine +
                     ('{0} of {1} checked ports answered.' -f $open.Count, $rows.Count)

            Set-TkOutput -ControlName 'NetworkOutput' -Text $text
        }
}

<#
.SYNOPSIS
    Sweeps a subnet for responding hosts.
#>
function Invoke-TkSubnetSweep {
    [CmdletBinding()]
    param()

    $target = (Get-TkControl -Name 'DiagTarget').Text.Trim()

    if ($target -notmatch '/\d{1,2}$') {
        Set-TkStatus -Text 'Enter the network in CIDR notation, for example 192.168.1.0/24.'
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Sweeping {0}...' -f $target) `
        -ArgumentList @($target) `
        -ScriptBlock {
            param($network)
            Get-TkSubnetHost -Network $network
        } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)

            Set-TkOutput -ControlName 'NetworkOutput' -Text (
                ('{0} host(s) responded.' -f $rows.Count) + [Environment]::NewLine + [Environment]::NewLine +
                (Format-TkTableText -InputObject $rows)
            )
        }
}

<#
.SYNOPSIS
    Resolves a DNS record.
#>
function Invoke-TkDnsLookup {
    [CmdletBinding()]
    param()

    $name   = (Get-TkControl -Name 'DnsName').Text.Trim()
    $type   = [string] (Get-TkControl -Name 'DnsType').SelectedItem
    $server = (Get-TkControl -Name 'DnsServer').Text.Trim()

    if ([string]::IsNullOrWhiteSpace($name)) {
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Resolving {0} ({1})...' -f $name, $type) `
        -ArgumentList @($name, $type, $server) `
        -ScriptBlock {
            param($queryName, $queryType, $queryServer)

            if ([string]::IsNullOrWhiteSpace($queryServer)) {
                return Resolve-TkDnsRecord -Name $queryName -Type $queryType
            }

            return Resolve-TkDnsRecord -Name $queryName -Type $queryType -Server $queryServer
        } `
        -OnComplete {
            param($result)

            $rows = @($result.Output)

            if ($rows.Count -eq 0) {
                Set-TkOutput -ControlName 'NetworkOutput' -Text 'No record was returned. A negative answer is cached too, so retry after the negative TTL if the record was just created.'
                return
            }

            Set-TkOutput -ControlName 'NetworkOutput' -Text (Format-TkTableText -InputObject $rows)
        }
}

# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Fills the knowledge base list and wires its selection.
#>
function Initialize-TkKnowledgeBase {
    [CmdletBinding()]
    param()

    $catalog = Import-TkCatalog -Name 'network-knowledge'

    if (-not $catalog) {
        return
    }

    $list = Get-TkControl -Name 'KnowledgeList'

    if (-not $list) {
        return
    }

    Update-TkKnowledgeList -Filter ''

    $list.Add_SelectionChanged({

        $selected = (Get-TkControl -Name 'KnowledgeList').SelectedItem

        if ($null -eq $selected) {
            return
        }

        Show-TkKnowledgeTopic -Title ([string] $selected)
    })

    $search = Get-TkControl -Name 'KnowledgeSearch'

    if ($search) {

        $search.Add_TextChanged({
            Update-TkKnowledgeList -Filter (Get-TkControl -Name 'KnowledgeSearch').Text
        })
    }
}

<#
.SYNOPSIS
    Rebuilds the topic list, optionally filtered.

.DESCRIPTION
    The search looks at the whole topic body, not only the title, so a term
    such as "Responder" finds the LLMNR note even though the word is not in
    any heading.
#>
function Update-TkKnowledgeList {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Filter
    )

    $catalog = Import-TkCatalog -Name 'network-knowledge'
    $list    = Get-TkControl -Name 'KnowledgeList'

    if (-not $catalog -or -not $list) {
        return
    }

    $list.Items.Clear()

    foreach ($topic in $catalog.topics) {

        if (-not [string]::IsNullOrWhiteSpace($Filter)) {

            $haystack = '{0} {1} {2} {3}' -f
                $topic.title, $topic.summary, ($topic.content -join ' '), ($topic.keyPoints -join ' ')

            if ($haystack -notlike ('*{0}*' -f $Filter.Trim())) {
                continue
            }
        }

        [void] $list.Items.Add($topic.title)
    }
}

<#
.SYNOPSIS
    Renders one knowledge base topic.
#>
function Show-TkKnowledgeTopic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title
    )

    $catalog = Import-TkCatalog -Name 'network-knowledge'
    $topic   = $catalog.topics | Where-Object { $_.title -eq $Title } | Select-Object -First 1

    if (-not $topic) {
        return
    }

    $lines = @()
    $lines += $topic.title
    $lines += ('=' * $topic.title.Length)
    $lines += ''
    $lines += $topic.summary
    $lines += ''

    foreach ($paragraph in $topic.content) {
        $lines += $paragraph
        $lines += ''
    }

    if ($topic.keyPoints) {

        $lines += 'Key points'
        $lines += '----------'

        foreach ($point in $topic.keyPoints) {
            $lines += ('- ' + $point)
        }

        $lines += ''
    }

    if ($topic.troubleshooting) {

        $lines += 'Troubleshooting'
        $lines += '---------------'

        foreach ($step in $topic.troubleshooting) {
            $lines += ('- ' + $step)
        }
    }

    Set-TkOutput -ControlName 'KnowledgeContent' -Text ($lines -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# Vendor commands
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Fills the vendor selector and wires the section list.
#>
function Initialize-TkVendorCommands {
    [CmdletBinding()]
    param()

    $catalog = Import-TkCatalog -Name 'vendor-commands'

    if (-not $catalog) {
        return
    }

    $combo = Get-TkControl -Name 'VendorSelect'

    if ($combo) {

        foreach ($vendor in $catalog.vendors) {
            [void] $combo.Items.Add($vendor.name)
        }

        $combo.SelectedIndex = 0
        $combo.Add_SelectionChanged({ Update-TkVendorSections })
    }

    $list = Get-TkControl -Name 'VendorSectionList'

    if ($list) {
        $list.Add_SelectionChanged({ Show-TkVendorSection })
    }

    $search = Get-TkControl -Name 'VendorSearch'

    if ($search) {
        $search.Add_TextChanged({ Show-TkVendorSearchResult })
    }

    Update-TkVendorSections
}

<#
.SYNOPSIS
    Lists the sections of the selected vendor.
#>
function Update-TkVendorSections {
    [CmdletBinding()]
    param()

    $catalog = Import-TkCatalog -Name 'vendor-commands'
    $combo   = Get-TkControl -Name 'VendorSelect'
    $list    = Get-TkControl -Name 'VendorSectionList'

    if (-not $catalog -or -not $combo -or -not $list) {
        return
    }

    $vendor = $catalog.vendors | Where-Object { $_.name -eq [string] $combo.SelectedItem } | Select-Object -First 1

    if (-not $vendor) {
        return
    }

    $list.Items.Clear()

    foreach ($section in $vendor.sections) {
        [void] $list.Items.Add($section.name)
    }

    Set-TkOutput -ControlName 'VendorContent' -Text (
        ($vendor.name + [Environment]::NewLine +
         ('=' * $vendor.name.Length) + [Environment]::NewLine + [Environment]::NewLine +
         $vendor.description + [Environment]::NewLine + [Environment]::NewLine +
         'Pick a section on the left, or type in the search box to look across every vendor.')
    )
}

<#
.SYNOPSIS
    Renders the selected vendor section.
#>
function Show-TkVendorSection {
    [CmdletBinding()]
    param()

    $catalog = Import-TkCatalog -Name 'vendor-commands'
    $combo   = Get-TkControl -Name 'VendorSelect'
    $list    = Get-TkControl -Name 'VendorSectionList'

    if (-not $catalog -or -not $combo -or -not $list -or $null -eq $list.SelectedItem) {
        return
    }

    $vendor  = $catalog.vendors | Where-Object { $_.name -eq [string] $combo.SelectedItem } | Select-Object -First 1
    $section = $vendor.sections | Where-Object { $_.name -eq [string] $list.SelectedItem } | Select-Object -First 1

    if (-not $section) {
        return
    }

    $lines = @()
    $lines += ('{0} - {1}' -f $vendor.name, $section.name)
    $lines += ('-' * 70)
    $lines += ''

    foreach ($entry in $section.commands) {

        $lines += $entry.command
        $lines += ('    # ' + $entry.description)
        $lines += ''
    }

    Set-TkOutput -ControlName 'VendorContent' -Text ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Searches commands across every vendor.

.DESCRIPTION
    Cross vendor search is the point of this tab: "how do I see the MAC table
    here" has a different answer on each platform and they are worth seeing
    side by side.
#>
function Show-TkVendorSearchResult {
    [CmdletBinding()]
    param()

    $search = Get-TkControl -Name 'VendorSearch'

    if (-not $search -or [string]::IsNullOrWhiteSpace($search.Text)) {
        Update-TkVendorSections
        return
    }

    $term    = $search.Text.Trim()
    $catalog = Import-TkCatalog -Name 'vendor-commands'

    if (-not $catalog) {
        return
    }

    $lines = @()
    $lines += ('Results for "{0}" across every vendor' -f $term)
    $lines += ('-' * 70)
    $lines += ''

    $matchCount = 0

    foreach ($vendor in $catalog.vendors) {

        foreach ($section in $vendor.sections) {

            foreach ($entry in $section.commands) {

                $haystack = '{0} {1}' -f $entry.command, $entry.description

                if ($haystack -notlike ('*{0}*' -f $term)) {
                    continue
                }

                $matchCount++

                $lines += ('[{0} / {1}]' -f $vendor.name, $section.name)
                $lines += $entry.command
                $lines += ('    # ' + $entry.description)
                $lines += ''
            }
        }
    }

    if ($matchCount -eq 0) {
        $lines += 'No command matched.'
    }

    Set-TkOutput -ControlName 'VendorContent' -Text ($lines -join [Environment]::NewLine)
}
