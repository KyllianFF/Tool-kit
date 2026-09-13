<#
    Toolkit - Features / Proxy

    "The web works but Windows Update fails", or "the browser works but git
    does not", is very often a proxy question: Windows keeps three separate
    proxy settings and each program reads one of them.

      - the application setting (WinINET), read by browsers, Office and most
        applications, set in Settings, Network and internet, Proxy, or by
        policy;
      - the services setting (WinHTTP), read by Windows Update, BITS and the
        Defender and Intune agents, set with netsh winhttp;
      - the HTTP_PROXY and HTTPS_PROXY environment variables, read by command
        line tools such as git, curl, Python and Node.

    The application setting is decoded from the binary value the Settings page
    writes, the only place the automatic detection switch is kept. Reading is
    kept apart from checking that each proxy answers, which uses the network,
    and from the judgement, which is tested without either.
#>

<#
.SYNOPSIS
    Decodes a proxy setting stored as bytes.

.DESCRIPTION
    DefaultConnectionSettings (applications) and WinHttpSettings (services)
    share one layout: a version, a counter and flags, then counted strings
    for the proxy, the bypass list and, for applications only, the
    configuration script address. Flag 1 is direct, 2 a manual proxy, 4 a
    configuration script and 8 automatic detection.

.PARAMETER Bytes
    The registry value.

.OUTPUTS
    PSCustomObject with Flags, Direct, UseProxy, UseScript, AutoDetect,
    ProxyServer, Bypass and AutoConfigUrl, or $null when too short.
#>
function ConvertFrom-TkProxyBlob {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -lt 12) {
        return $null
    }

    $flags  = [BitConverter]::ToInt32($Bytes, 8)
    $texts  = New-Object System.Collections.Generic.List[string]
    $offset = 12

    while ($texts.Count -lt 3 -and $offset + 4 -le $Bytes.Length) {

        $length  = [BitConverter]::ToInt32($Bytes, $offset)
        $offset += 4

        # A value cut short keeps what was read before the cut.
        if ($length -lt 0 -or $offset + $length -gt $Bytes.Length) {
            break
        }

        $texts.Add([Text.Encoding]::UTF8.GetString($Bytes, $offset, $length).TrimEnd([char] 0))
        $offset += $length
    }

    return [pscustomobject] @{
        Flags         = $flags
        Direct        = (($flags -band 1) -ne 0)
        UseProxy      = (($flags -band 2) -ne 0)
        UseScript     = (($flags -band 4) -ne 0)
        AutoDetect    = (($flags -band 8) -ne 0)
        ProxyServer   = $(if ($texts.Count -gt 0) { $texts[0] } else { '' })
        Bypass        = $(if ($texts.Count -gt 1) { $texts[1] } else { '' })
        AutoConfigUrl = $(if ($texts.Count -gt 2) { $texts[2] } else { '' })
    }
}

<#
.SYNOPSIS
    Removes a user name and password from a proxy address.

.DESCRIPTION
    Environment variables are URLs and may carry credentials, as in
    http://user:secret@proxy:8080. They never reach a report.

.PARAMETER Text
    The proxy address.

.OUTPUTS
    System.String
#>
function Hide-TkProxyCredential {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    return ($Text -replace '^([a-z][a-z0-9+.-]*://)?[^@/]*@', '$1')
}

<#
.SYNOPSIS
    Splits a proxy setting into the addresses it names.

.DESCRIPTION
    Accepts the forms Windows and the tools use: proxy:8080, a list per
    scheme such as http=a:80;https=b:443, and a URL with or without
    credentials. Without a port, WinINET uses 80.

.PARAMETER Text
    The proxy setting.

.OUTPUTS
    PSCustomObject[] with Scheme, Host, Port and Address.
#>
function ConvertFrom-TkProxyServerList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $rows = foreach ($part in @($Text -split '[;\s]+' | Where-Object { $_ })) {

        $scheme  = ''
        $address = $part

        if ($address -match '^(?<scheme>[a-z]+)=(?<rest>.+)$') {
            $scheme  = $Matches['scheme']
            $address = $Matches['rest']
        }

        $address = (Hide-TkProxyCredential -Text $address) -replace '^[a-z][a-z0-9+.-]*://', '' -replace '/.*$', ''

        if ($address -match '^\[(?<name>[^\]]+)\](:(?<port>\d+))?$' -or $address -match '^(?<name>[^:\[\]]+)(:(?<port>\d+))?$') {

            $port = if ($Matches['port']) { [int] $Matches['port'] } else { 80 }

            if ($port -lt 1 -or $port -gt 65535) {
                continue
            }

            $name = $Matches['name']

            [pscustomobject] @{
                Scheme  = $scheme
                Host    = $name
                Port    = $port
                Address = $(if ($name.Contains(':')) { '[{0}]:{1}' -f $name, $port } else { '{0}:{1}' -f $name, $port })
            }
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Returns the address a proxy configuration script is fetched from.

.PARAMETER Url
    The AutoConfigURL value.

.OUTPUTS
    PSCustomObject with Scheme, Host, Port and Address, or $null for a
    script that is not fetched over HTTP.
#>
function Get-TkProxyScriptAddress {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Url
    )

    $uri = $null

    if (-not [uri]::TryCreate($Url, [UriKind]::Absolute, [ref] $uri) -or -not $uri.Host -or $uri.Scheme -notin @('http', 'https')) {
        return $null
    }

    return [pscustomobject] @{
        Scheme  = $uri.Scheme
        Host    = $uri.Host
        Port    = $uri.Port
        Address = ('{0}:{1}' -f $uri.Host, $uri.Port)
    }
}

<#
.SYNOPSIS
    Says whether a host name is this machine.

.PARAMETER Name
    The host name or address.
#>
function Test-TkLoopbackAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Name
    )

    return ($Name -match '^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|\[::1\])$')
}

<#
.SYNOPSIS
    Describes a decoded proxy setting in one line.

.DESCRIPTION
    In the order Windows tries them: automatic detection, then the
    configuration script, then the manual proxy.

.PARAMETER Setting
    Output of ConvertFrom-TkProxyBlob, or $null when the value was never set.

.OUTPUTS
    System.String
#>
function Format-TkProxyDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Setting
    )

    if (-not $Setting) {
        return 'Direct, never set'
    }

    $parts = @()

    if ($Setting.AutoDetect) {
        $parts += 'automatic detection'
    }

    if ($Setting.UseScript -and $Setting.AutoConfigUrl) {
        $parts += 'script {0}' -f $Setting.AutoConfigUrl
    }

    if ($Setting.UseProxy -and $Setting.ProxyServer) {
        $parts += 'proxy {0}{1}' -f $Setting.ProxyServer, $(if ($Setting.Bypass) { ', not for ' + $Setting.Bypass } else { '' })
    }

    if ($parts.Count -eq 0) {
        return 'Direct'
    }

    $text = $parts -join ', then '

    return ($text.Substring(0, 1).ToUpperInvariant() + $text.Substring(1))
}

<#
.SYNOPSIS
    Reads the three proxy settings Windows keeps.

.DESCRIPTION
    Reads the registry and the environment only; nothing goes out on the
    network.

.OUTPUTS
    PSCustomObject with Scope, MachineWide, User, Machine and Environment.
#>
function Get-TkProxySetting {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $settingsPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'

    $read = {
        param($path, $name)

        try {
            (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop).$name
        }
        catch {
            $null
        }
    }

    # ProxySettingsPerUser = 0 makes the application setting one for the whole
    # machine, kept under HKLM.
    $perUser     = & $read "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" 'ProxySettingsPerUser'
    $machineWide = ($null -ne $perUser -and [int] $perUser -eq 0)
    $root        = if ($machineWide) { 'HKLM:' } else { 'HKCU:' }

    $user = $null
    $blob = & $read "$root\$settingsPath\Connections" 'DefaultConnectionSettings'

    if ($blob) {
        $user = ConvertFrom-TkProxyBlob -Bytes ([byte[]] $blob)
    }

    # Before the Settings page first writes the binary value, only the plain
    # values exist, and they hold no automatic detection switch.
    if (-not $user) {

        $scriptUrl = [string] (& $read "$root\$settingsPath" 'AutoConfigURL')

        $user = [pscustomobject] @{
            Flags         = 0
            Direct        = $true
            UseProxy      = ([int] (& $read "$root\$settingsPath" 'ProxyEnable') -eq 1)
            UseScript     = [bool] $scriptUrl
            AutoDetect    = $false
            ProxyServer   = [string] (& $read "$root\$settingsPath" 'ProxyServer')
            Bypass        = [string] (& $read "$root\$settingsPath" 'ProxyOverride')
            AutoConfigUrl = $scriptUrl
        }
    }

    $machine = $null
    $winHttp = & $read "HKLM:\$settingsPath\Connections" 'WinHttpSettings'

    if ($winHttp) {
        $machine = ConvertFrom-TkProxyBlob -Bytes ([byte[]] $winHttp)
    }

    $environment = foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
        foreach ($target in @('Machine', 'User')) {

            $value = [Environment]::GetEnvironmentVariable($name, $target)

            if ($value) {
                [pscustomobject] @{
                    Name  = $name
                    Scope = $(if ($target -eq 'Machine') { 'all users' } else { 'this user' })
                    Value = Hide-TkProxyCredential -Text $value
                }
            }
        }
    }

    return [pscustomobject] @{
        Scope       = $(if ($machineWide) { 'all users, by policy' } else { 'this user' })
        MachineWide = $machineWide
        User        = $user
        Machine     = $machine
        Environment = @($environment)
    }
}

<#
.SYNOPSIS
    Checks that each proxy and configuration script answers, and what
    automatic detection finds.

.DESCRIPTION
    Opens a TCP connection to each address, which is enough to tell a proxy
    left over from another network from one that is there, and looks up the
    wpad name automatic detection asks for. Nothing is sent through a proxy.

.PARAMETER Setting
    Output of Get-TkProxySetting.

.PARAMETER TimeoutMilliseconds
    How long to wait for each connection.

.OUTPUTS
    PSCustomObject with Targets (Address, Open, ResponseMs), WpadChecked and
    WpadAddresses.
#>
function Invoke-TkProxyProbe {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Setting,

        [Parameter()]
        [ValidateRange(200, 10000)]
        [int] $TimeoutMilliseconds = 2000
    )

    $targets = @()

    if ($Setting.User -and $Setting.User.UseProxy -and $Setting.User.ProxyServer) {
        $targets += @(ConvertFrom-TkProxyServerList -Text $Setting.User.ProxyServer)
    }

    if ($Setting.User -and $Setting.User.UseScript -and $Setting.User.AutoConfigUrl) {
        $targets += @(Get-TkProxyScriptAddress -Url $Setting.User.AutoConfigUrl | Where-Object { $_ })
    }

    if ($Setting.Machine -and $Setting.Machine.UseProxy -and $Setting.Machine.ProxyServer) {
        $targets += @(ConvertFrom-TkProxyServerList -Text $Setting.Machine.ProxyServer)
    }

    foreach ($variable in @($Setting.Environment | Where-Object { $_ -and $_.Name -ne 'NO_PROXY' })) {
        $targets += @(ConvertFrom-TkProxyServerList -Text $variable.Value)
    }

    $results = foreach ($target in @($targets | Sort-Object -Property Address -Unique)) {

        $probe = Test-TkTcpPort -ComputerName $target.Host -Port $target.Port -TimeoutMilliseconds $TimeoutMilliseconds

        [pscustomobject] @{
            Address    = $target.Address
            Open       = [bool] $probe.Open
            ResponseMs = $probe.ResponseMs
        }
    }

    $wpad    = @()
    $checked = $false

    if ($Setting.User -and $Setting.User.AutoDetect -and (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue)) {

        $checked = $true

        try {
            $wpad = @(Resolve-DnsName -Name 'wpad' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                      Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress } |
                      ForEach-Object { [string] $_.IPAddress } | Sort-Object -Unique)
        }
        catch {
            # No wpad name is the usual answer, and it comes back as an error.
            $wpad = @()
        }
    }

    return [pscustomobject] @{
        Targets       = @($results)
        WpadChecked   = $checked
        WpadAddresses = $wpad
    }
}

<#
.SYNOPSIS
    Judges the proxy settings.

.PARAMETER Setting
    Output of Get-TkProxySetting.

.PARAMETER Probe
    Output of Invoke-TkProxyProbe, or $null when nothing was checked.

.OUTPUTS
    PSCustomObject[] with Severity, Heading, Detail, Note and RemediationId.
#>
function Get-TkProxyFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        $Setting,

        [Parameter()]
        $Probe
    )

    $findings = @()
    $finding  = {
        param($severity, $heading, $detail, $note, $remediation)
        [pscustomobject] @{ Severity = $severity; Heading = $heading; Detail = $detail; Note = $note; RemediationId = [string] $remediation }
    }

    # $true when every address of a setting answered, $false when one did
    # not, $null when none was checked.
    $answered = {
        param($addresses)

        if (-not $Probe) {
            return $null
        }

        $checked = @($Probe.Targets | Where-Object { $_.Address -in @($addresses) })

        if ($checked.Count -eq 0) {
            return $null
        }

        return (@($checked | Where-Object { -not $_.Open }).Count -eq 0)
    }

    $user    = $Setting.User
    $machine = $Setting.Machine

    $userProxy    = [bool] ($user -and $user.UseProxy -and $user.ProxyServer)
    $userScript   = [bool] ($user -and $user.UseScript -and $user.AutoConfigUrl)
    $machineProxy = [bool] ($machine -and $machine.UseProxy -and $machine.ProxyServer)
    $wpadFound    = [bool] ($Probe -and @($Probe.WpadAddresses).Count -gt 0)
    $variables    = @($Setting.Environment | Where-Object { $_ -and $_.Name -ne 'NO_PROXY' })

    if ($user -and -not $user.UseProxy -and $user.ProxyServer) {
        $findings += & $finding 'Info' 'A proxy is filled in but turned off' $user.ProxyServer `
            'Harmless while it stays off. Worth knowing if the switch is turned back on, by a person or a script.' ''
    }

    if (-not $userProxy -and -not $userScript -and -not $wpadFound -and -not $machineProxy -and $variables.Count -eq 0) {

        $findings += & $finding 'Pass' 'No proxy: applications, services and command line tools go straight out' `
            $(if ($user -and $user.AutoDetect) { 'Automatic detection is on and finds no proxy' } else { 'Every setting is direct' }) `
            'When a site still fails, the cause is further along: DNS, a firewall, or the site itself.' ''

        return $findings
    }

    # --- Applications ---------------------------------------------------------
    if ($userProxy) {

        $entries = @(ConvertFrom-TkProxyServerList -Text $user.ProxyServer)
        $scope   = 'For {0}{1}' -f $Setting.Scope, $(if ($user.Bypass) { '; not for ' + ($user.Bypass -replace ';', ', ') } else { '' })

        if (@($entries | Where-Object { Test-TkLoopbackAddress -Name $_.Host }).Count -gt 0) {
            $findings += & $finding 'Warning' ('Applications go through a program on this machine: {0}' -f $user.ProxyServer) $scope `
                'A proxy on the machine itself is a local program: a debugging tool such as Fiddler, a web filter or parental control, or adware. If nobody installed one on purpose, look up the program listening on that port in Network, Diagnostics.' 'open-proxy-settings'
        }
        elseif ((& $answered @($entries | ForEach-Object { $_.Address })) -eq $false) {
            $findings += & $finding 'Fail' ('Proxy {0} does not answer' -f $user.ProxyServer) $scope `
                'Browsers and most applications follow this setting and reach nothing. It is often left over from another network, such as a company proxy on a home connection: turn it off in Settings, Network and internet, Proxy.' 'open-proxy-settings'
        }
        else {
            $findings += & $finding 'Info' ('Applications go through proxy {0}' -f $user.ProxyServer) $scope `
                'Browsers, Office and most applications follow this setting.' ''
        }
    }

    if ($userScript) {

        $address = Get-TkProxyScriptAddress -Url $user.AutoConfigUrl

        if ($address -and (& $answered @($address.Address)) -eq $false) {
            $findings += & $finding 'Fail' 'The proxy configuration script does not answer' $user.AutoConfigUrl `
                'Windows waits for the script at each new connection, then goes direct: pages load slowly, or not at all on a network that only lets the proxy out. It is often left over from a company network.' 'open-proxy-settings'
        }
        else {
            $findings += & $finding 'Info' 'Applications follow a proxy configuration script' $user.AutoConfigUrl `
                'The script picks the proxy address by address, so one site can go direct while another goes through a proxy.' ''
        }
    }

    if ($wpadFound) {
        $findings += & $finding 'Info' 'Automatic detection finds a proxy on this network' ('wpad answers at {0}' -f (@($Probe.WpadAddresses) -join ', ')) `
            'Windows downloads its proxy settings from that address. Expected on a company network; on a home or public network it can send web traffic through someone else''s proxy, so turn automatic detection off there.' 'open-proxy-settings'
    }

    # --- Services -------------------------------------------------------------
    if ($machineProxy) {

        $addresses = @(ConvertFrom-TkProxyServerList -Text $machine.ProxyServer | ForEach-Object { $_.Address })

        if ((& $answered $addresses) -eq $false) {
            $findings += & $finding 'Fail' ('The services proxy {0} does not answer' -f $machine.ProxyServer) 'Machine setting (WinHTTP)' `
                'Windows Update, BITS, Defender and the Intune agent go through it and fail. If it is left over, reset it from an elevated prompt with netsh winhttp reset proxy.' ''
        }
        elseif (-not $userProxy -and -not $userScript) {
            $findings += & $finding 'Warning' ('Services go through proxy {0}, applications go direct' -f $machine.ProxyServer) 'Machine setting (WinHTTP)' `
                'Windows Update and the agents do not read the application setting. A services proxy nothing else uses is usually left over from another network or a removed security product; check it with netsh winhttp show proxy.' ''
        }
        else {
            $findings += & $finding 'Info' ('Services go through proxy {0}' -f $machine.ProxyServer) 'Machine setting (WinHTTP)' `
                'Windows Update, BITS, Defender and the Intune agent use it, whatever the applications do.' ''
        }
    }
    elseif ($userProxy -or $userScript) {
        $findings += & $finding 'Info' 'Services go direct' 'No machine setting (WinHTTP)' `
            'Windows Update, BITS and the agents do not read the application setting. On a network where only the proxy reaches the internet they fail while browsing works; copy a manual proxy across with netsh winhttp import proxy source=ie from an elevated prompt.' ''
    }

    # --- Command line tools ---------------------------------------------------
    foreach ($variable in $variables) {

        $state = & $answered @(ConvertFrom-TkProxyServerList -Text $variable.Value | ForEach-Object { $_.Address })

        $findings += & $finding $(if ($state -eq $false) { 'Warning' } else { 'Info' }) `
            ('{0} is set for {1}' -f $variable.Name, $variable.Scope) `
            ('{0}{1}' -f $variable.Value, $(if ($state -eq $false) { ', does not answer' } else { '' })) `
            'Read by command line tools such as git, curl, Python and Node, not by browsers. A value left over from another network makes those tools fail while the browser works.' ''
    }

    if ($Setting.MachineWide) {
        $findings += & $finding 'Info' 'The application proxy setting is shared by every user' 'Set by policy (ProxySettingsPerUser = 0)' `
            'A change made in one session applies to every user of the machine.' ''
    }

    return $findings
}
