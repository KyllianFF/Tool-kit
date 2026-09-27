<#
    Toolkit - Features / Microsoft 365

    "Outlook is disconnected", "Teams calls drop", "OneDrive stopped
    syncing": half the time the network lets the machine reach some of
    Microsoft 365 and not the rest, and the other half the apps on the
    machine are in a state nobody looked at. This page answers both.

    The connectivity test resolves and opens a TCP connection to each
    endpoint Microsoft publishes for a workload, checks that the TLS
    certificate of sign-in comes from Microsoft's own chain rather than from
    a proxy that inspects the traffic, and sends one STUN request to a Teams
    relay to see whether UDP 3478, the port Teams calls want, gets through.
    The apps and accounts reader only reads the registry, the file system and
    the installed packages. Nothing is changed; the related fixes are one
    click away and ask first, as every fix does.
#>

<#
.SYNOPSIS
    The endpoints to test, with the tenant name put in.

.PARAMETER Tenant
    The tenant name, contoso for contoso.sharepoint.com. Endpoints that need
    it are left out when it is empty.

.OUTPUTS
    PSCustomObject[] with Workload, Name, Impact, Host, Port and Note.
#>
function Get-TkM365Endpoint {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Tenant = ''
    )

    $catalog = Import-TkCatalog -Name 'm365-endpoints'
    $tenant  = $Tenant.Trim().ToLowerInvariant() -replace '\.sharepoint\.com$', '' -replace '\.onmicrosoft\.com$', ''

    $endpoints = foreach ($workload in $catalog.workloads) {
        foreach ($endpoint in $workload.endpoints) {

            $name = [string] $endpoint.host

            if ($name.Contains('{tenant}')) {
                if (-not $tenant) { continue }
                $name = $name.Replace('{tenant}', $tenant)
            }

            [pscustomobject] @{
                Workload = [string] $workload.id
                Name     = [string] $workload.name
                Impact   = [string] $workload.impact
                Host     = $name
                Port     = [int] $endpoint.port
                Note     = [string] $endpoint.note
            }
        }
    }

    return @($endpoints)
}

<#
.SYNOPSIS
    Says whether a tenant name is well formed.

.OUTPUTS
    System.Boolean
#>
function Test-TkM365TenantName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Tenant
    )

    $name = $Tenant.Trim().ToLowerInvariant() -replace '\.sharepoint\.com$', '' -replace '\.onmicrosoft\.com$', ''

    return ($name -eq '' -or $name -match '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
}

<#
.SYNOPSIS
    Judges each workload from the results of its endpoints.

.DESCRIPTION
    Pure. A workload whose every endpoint answered passes; one with some
    endpoints failing is a warning, since the app works in part and fails in
    ways that are hard to read; one with none answering fails. When a proxy is
    set, a direct connection that fails is expected and said so.

.PARAMETER Result
    Objects with Workload, Name, Impact, Host, Port, Resolved and Connected.

.PARAMETER ProxySet
    Whether the machine sends web traffic through a proxy.

.OUTPUTS
    PSCustomObject[] with Workload, Name, Severity, Heading, Detail and Note.
#>
function ConvertTo-TkM365Verdict {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Result = @(),
        [Parameter()] [bool] $ProxySet = $false
    )

    $verdicts = foreach ($group in ($Result | Where-Object { $_ } | Group-Object Workload)) {

        $rows   = @($group.Group)
        $failed = @($rows | Where-Object { -not $_.Connected })
        $name   = $rows[0].Name

        if ($failed.Count -eq 0) {
            [pscustomobject] @{ Workload = $group.Name; Name = $name; Severity = 'Pass'; Heading = ('{0}: reachable' -f $name)
                                Detail = ('{0} endpoint(s)' -f $rows.Count); Note = '' }
            continue
        }

        $unresolved = @($failed | Where-Object { -not $_.Resolved })
        $list       = (@($failed | ForEach-Object { '{0}:{1}' -f $_.Host, $_.Port })) -join ', '

        $cause = if ($unresolved.Count -eq $failed.Count) { 'The names do not resolve: the DNS server, or a DNS filter, does not answer for them.' }
                 elseif ($ProxySet) { 'A proxy is set on this machine: a direct connection may be refused by design while the apps go through the proxy. Check that the proxy lets these names through.' }
                 else { 'The names resolve but the connection is refused or times out: a firewall or a web filter blocks them.' }

        [pscustomobject] @{
            Workload = $group.Name
            Name     = $name
            Severity = $(if ($failed.Count -eq $rows.Count) { 'Fail' } else { 'Warning' })
            Heading  = $(if ($failed.Count -eq $rows.Count) { '{0}: not reachable' -f $name } else { '{0}: partly reachable' -f $name })
            Detail   = $list
            Note     = ('{0} {1}' -f $rows[0].Impact, $cause)
        }
    }

    return @($verdicts)
}

<#
.SYNOPSIS
    Judges the certificate chain a Microsoft endpoint presented.

.DESCRIPTION
    Pure. Microsoft 365 presents certificates that chain to a handful of
    public roots. Another root means something between the machine and
    Microsoft re-signed the traffic: a proxy that inspects TLS, which
    Microsoft asks to be bypassed for its endpoints, and which breaks
    certificate pinning in some apps.

.OUTPUTS
    PSCustomObject with Severity, Heading, Detail and Note.
#>
function ConvertTo-TkM365TlsVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter()] [AllowEmptyString()] [string] $Root = '',
        [Parameter()] [AllowEmptyString()] [string] $Issuer = '',
        [Parameter()] [string[]] $ExpectedRoot = @('DigiCert', 'Microsoft', 'Baltimore', 'GlobalSign')
    )

    if (-not $Root) {
        return [pscustomobject] @{ Severity = 'Info'; Heading = ('TLS to {0} could not be checked' -f $HostName); Detail = ''; Note = 'The connection did not complete, so the certificate was not seen.' }
    }

    $organisation = if ($Root -match '(?:^|,\s*)O=(?<o>[^,]+)') { $Matches['o'].Trim('"') } elseif ($Root -match 'CN=(?<cn>[^,]+)') { $Matches['cn'] } else { $Root }

    foreach ($expected in $ExpectedRoot) {
        if ($Root -match [regex]::Escape($expected)) {
            return [pscustomobject] @{ Severity = 'Pass'; Heading = 'No TLS inspection'; Detail = $organisation
                                       Note = ('{0} presented a certificate from Microsoft''s own chain.' -f $HostName) }
        }
    }

    return [pscustomobject] @{
        Severity = 'Warning'
        Heading  = 'The traffic to Microsoft 365 is inspected'
        Detail   = $organisation
        Note     = ('{0} presented a certificate signed by {1}, not by Microsoft''s chain: a proxy or a security product decrypts the traffic. Microsoft asks for its endpoints to be left out of TLS inspection; some apps refuse the re-signed certificate, and it slows Teams and OneDrive.' -f $HostName, $organisation)
    }
}

<#
.SYNOPSIS
    Reads the certificate chain an endpoint presents.

.OUTPUTS
    PSCustomObject with Root and Issuer, empty when the handshake failed.
#>
function Get-TkTlsChainRoot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter()] [int] $Port = 443
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $ssl    = $null

    try {
        if (-not $client.ConnectAsync($HostName, $Port).Wait(4000)) {
            return [pscustomobject] @{ Root = ''; Issuer = '' }
        }

        # Every certificate is accepted here, since the point is to see which
        # one is presented, including one a proxy made up.
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, { $true })
        $ssl.ReadTimeout = 4000
        $ssl.AuthenticateAsClient($HostName)

        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $chain       = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        [void] $chain.Build($certificate)

        $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject

        return [pscustomobject] @{ Root = [string] $root; Issuer = [string] $certificate.Issuer }
    }
    catch {
        return [pscustomobject] @{ Root = ''; Issuer = '' }
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        $client.Close()
    }
}

<#
.SYNOPSIS
    Builds a STUN binding request.

.DESCRIPTION
    Pure. RFC 5389: the binding request type, no attributes, the magic cookie
    and a transaction id.

.OUTPUTS
    System.Byte[]
#>
function New-TkStunRequest {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter()]
        [byte[]] $TransactionId
    )

    if (-not $TransactionId -or $TransactionId.Length -ne 12) {
        $TransactionId = New-Object byte[] 12
        (New-Object System.Random).NextBytes($TransactionId)
    }

    $request = New-Object byte[] 20
    $request[1] = 0x01
    $request[4] = 0x21; $request[5] = 0x12; $request[6] = 0xA4; $request[7] = 0x42
    [Array]::Copy($TransactionId, 0, $request, 8, 12)

    return , $request
}

<#
.SYNOPSIS
    Says whether a datagram is the success answer to a STUN request.

.OUTPUTS
    System.Boolean
#>
function Test-TkStunResponse {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowNull()] [byte[]] $Response,
        [Parameter(Mandatory)] [byte[]] $Request
    )

    if (-not $Response -or $Response.Length -lt 20) {
        return $false
    }

    # A binding success response, with the same cookie and transaction id.
    for ($i = 4; $i -lt 20; $i++) {
        if ($Response[$i] -ne $Request[$i]) { return $false }
    }

    return ($Response[0] -eq 0x01 -and $Response[1] -eq 0x01)
}

<#
.SYNOPSIS
    Sends one STUN request to a Teams relay over UDP.

.OUTPUTS
    PSCustomObject with Answered and Milliseconds.
#>
function Test-TkTeamsMediaPath {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter()] [int] $Port = 3478
    )

    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = 2500

    try {
        $request = New-TkStunRequest
        $clock   = [System.Diagnostics.Stopwatch]::StartNew()
        [void] $udp.Send($request, $request.Length, $HostName, $Port)

        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $reply  = $udp.Receive([ref] $remote)

        return [pscustomobject] @{ Answered = (Test-TkStunResponse -Response $reply -Request $request); Milliseconds = $clock.ElapsedMilliseconds }
    }
    catch {
        return [pscustomobject] @{ Answered = $false; Milliseconds = 0 }
    }
    finally {
        $udp.Close()
    }
}

<#
.SYNOPSIS
    Tests the connection to Microsoft 365 from this machine.

.PARAMETER Tenant
    The tenant name, for the SharePoint and OneDrive endpoints.

.OUTPUTS
    PSCustomObject with Results, Verdicts, Tls, Teams, ProxySet and Tenant.
#>
function Test-TkM365Connectivity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Tenant = ''
    )

    [void] (Import-TkCommandModule -Command @('Resolve-DnsName'))

    $catalog   = Import-TkCatalog -Name 'm365-endpoints'
    $endpoints = @(Get-TkM365Endpoint -Tenant $Tenant)

    $results = foreach ($endpoint in $endpoints) {

        $resolved = $false
        try {
            $resolved = [bool] @(Resolve-DnsName -Name $endpoint.Host -ErrorAction Stop | Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress }).Count
        }
        catch {
            $resolved = $false
        }

        $connected = $false
        $time      = 0
        if ($resolved) {
            $probe     = Test-TkTcpPort -ComputerName $endpoint.Host -Port $endpoint.Port -TimeoutMilliseconds 3000
            $connected = [bool] $probe.Open
            $time      = $probe.ResponseTime
        }

        $endpoint | Select-Object *, @{ Name = 'Resolved'; Expression = { $resolved } }, @{ Name = 'Connected'; Expression = { $connected } }, @{ Name = 'Milliseconds'; Expression = { $time } }
    }

    $proxy    = Get-TkProxySetting
    $proxySet = [bool] ($proxy -and (($proxy.User -and ($proxy.User.UseProxy -or $proxy.User.UseScript)) -or ($proxy.Machine -and $proxy.Machine.UseProxy)))

    $chain = Get-TkTlsChainRoot -HostName 'login.microsoftonline.com'
    $tls   = ConvertTo-TkM365TlsVerdict -HostName 'login.microsoftonline.com' -Root $chain.Root -Issuer $chain.Issuer -ExpectedRoot @($catalog.tlsRoots)

    $teams = Test-TkTeamsMediaPath -HostName ([string] $catalog.teamsRelay.host) -Port ([int] $catalog.teamsRelay.port)

    return [pscustomobject] @{
        Tenant   = $Tenant.Trim()
        Results  = @($results)
        Verdicts = @(ConvertTo-TkM365Verdict -Result @($results) -ProxySet $proxySet)
        Tls      = $tls
        Teams    = $teams
        ProxySet = $proxySet
    }
}

# ---------------------------------------------------------------------------
# Apps and accounts
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Names the Office update channel from the CDN address Click-to-Run uses.

.OUTPUTS
    System.String
#>
function Get-TkOfficeChannelName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $CdnBaseUrl = ''
    )

    $channels = @{
        '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current Channel'
        '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Channel (Preview)'
        '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise Channel'
        '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise Channel'
        'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Channel (Preview)'
        '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta Channel'
    }

    foreach ($id in $channels.Keys) {
        if ($CdnBaseUrl -match [regex]::Escape($id)) {
            return $channels[$id]
        }
    }

    return $(if ($CdnBaseUrl) { 'another channel' } else { '' })
}

<#
.SYNOPSIS
    Reads the state of the Microsoft 365 apps and accounts on this machine.

.DESCRIPTION
    Registry, files and installed packages only. The accounts listed are the
    ones Office and OneDrive keep for the account the toolkit runs as.

.OUTPUTS
    PSCustomObject with Office, Identities, OneDrive, Teams and Outlook.
#>
function Get-TkM365ClientState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $read = { param($path) try { Get-ItemProperty -LiteralPath $path -ErrorAction Stop } catch { $null } }

    # --- Office ------------------------------------------------------------
    $c2r = & $read 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $msi = & $read 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot'

    $office = [pscustomobject] @{
        Installed      = [bool] ($c2r -or $msi)
        ClickToRun     = [bool] $c2r
        Version        = [string] $(if ($c2r) { $c2r.VersionToReport } else { '' })
        Channel        = $(if ($c2r) { Get-TkOfficeChannelName -CdnBaseUrl ([string] $c2r.CDNBaseUrl) } else { '' })
        Products       = [string] $(if ($c2r) { $c2r.ProductReleaseIds } else { '' })
        Platform       = [string] $(if ($c2r) { $c2r.Platform } else { '' })
        UpdatesEnabled = $(if ($c2r -and $null -ne $c2r.PSObject.Properties['UpdatesEnabled']) { [string] $c2r.UpdatesEnabled } else { '' })
    }

    # --- Accounts Office knows -----------------------------------------------
    $identities = @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities' -ErrorAction SilentlyContinue | ForEach-Object {
        $item = & $read $_.PSPath
        if ($item -and $item.EmailAddress) {
            [pscustomobject] @{
                Email = [string] $item.EmailAddress
                Kind  = $(if ([string] $item.ProviderId -match 'AD') { 'Work or school' } elseif ([string] $item.ProviderId -match 'Live') { 'Personal' } else { [string] $item.ProviderId })
            }
        }
    } | Sort-Object Email -Unique)

    # --- OneDrive ----------------------------------------------------------
    $accounts = @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue | ForEach-Object {
        $item = & $read $_.PSPath
        if ($item -and $item.UserFolder) {
            [pscustomobject] @{
                Email    = [string] $item.UserEmail
                Folder   = [string] $item.UserFolder
                Business = ($_.PSChildName -like 'Business*')
            }
        }
    })

    $shell  = & $read 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    $backed = @()
    foreach ($pair in @(@('Desktop', 'Desktop'), @('Documents', 'Personal'), @('Pictures', 'My Pictures'))) {
        $path = if ($shell) { [Environment]::ExpandEnvironmentVariables([string] $shell.($pair[1])) } else { '' }
        foreach ($account in $accounts) {
            if ($path -and $account.Folder -and $path.StartsWith($account.Folder, [System.StringComparison]::OrdinalIgnoreCase)) {
                $backed += $pair[0]
            }
        }
    }

    $onedriveVersion = & $read 'HKCU:\Software\Microsoft\OneDrive'
    $oneDrive = [pscustomobject] @{
        Installed = [bool] ($onedriveVersion -or (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe')))
        Running   = [bool] (Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)
        Version   = [string] $(if ($onedriveVersion) { $onedriveVersion.Version } else { '' })
        Accounts  = @($accounts)
        BackedUp  = @($backed | Select-Object -Unique)
    }

    # --- Teams and Outlook -----------------------------------------------
    $packages = @(try { Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -in @('MSTeams', 'Microsoft.OutlookForWindows') } | Select-Object Name, Version } catch { @() })

    $teams = [pscustomobject] @{
        New     = [string] (@($packages | Where-Object Name -eq 'MSTeams') | Select-Object -First 1).Version
        Classic = [bool] (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Teams\current\Teams.exe'))
    }

    $outlook = [pscustomobject] @{
        New     = [string] (@($packages | Where-Object Name -eq 'Microsoft.OutlookForWindows') | Select-Object -First 1).Version
        Classic = [bool] (& $read 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE')
    }

    return [pscustomobject] @{ Office = $office; Identities = $identities; OneDrive = $oneDrive; Teams = $teams; Outlook = $outlook }
}

<#
.SYNOPSIS
    Judges the apps and accounts.

.DESCRIPTION
    Pure, so each case can be tested without Office on the machine.

.OUTPUTS
    PSCustomObject[] with Severity, Heading, Detail and Note.
#>
function ConvertTo-TkM365ClientFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $State
    )

    $finding = { param($severity, $heading, $detail, $note) [pscustomobject] @{ Severity = $severity; Heading = $heading; Detail = $detail; Note = $note } }

    $office = $State.Office

    if (-not $office.Installed) {
        & $finding 'Info' 'Microsoft 365 apps are not installed' '' 'Word, Excel and Outlook are not on this machine, or not installed from Microsoft 365.'
    }
    elseif (-not $office.ClickToRun) {
        & $finding 'Info' 'Office installed from an MSI' 'volume licence' 'A volume licence Office, not the Microsoft 365 apps: it activates with a key or KMS, not with a Microsoft 365 account.'
    }
    else {
        & $finding 'Pass' ('Microsoft 365 apps {0}' -f $office.Version) $office.Channel ('{0}, {1}.' -f $office.Products, $office.Platform)

        if ($office.UpdatesEnabled -eq 'False') {
            & $finding 'Warning' 'Office updates are turned off' '' 'The Click-to-Run configuration disables updates. On a managed machine updates may come another way (SCCM, Intune); otherwise Office falls behind on security fixes.'
        }
    }

    $identities = @($State.Identities)
    if ($identities.Count -eq 0) {
        if ($office.Installed) {
            & $finding 'Info' 'No account signed in to Office' '' 'Office has no account for this user yet: open Word or Outlook and sign in.'
        }
    }
    else {
        $work     = @($identities | Where-Object Kind -eq 'Work or school')
        $personal = @($identities | Where-Object Kind -eq 'Personal')
        & $finding 'Info' ('{0} account(s) signed in to Office' -f $identities.Count) ((@($identities | ForEach-Object { $_.Email })) -join ', ') ''

        if ($work.Count -gt 1) {
            & $finding 'Warning' 'Several work accounts in Office' ((@($work | ForEach-Object { $_.Email })) -join ', ') 'Office activates with one of them and may pick the wrong one, which shows as unlicensed or as the wrong mailbox. Sign out of the account that no longer applies, or reset the Office activation.'
        }
        if ($work.Count -ge 1 -and $personal.Count -ge 1) {
            & $finding 'Info' 'A personal account sits beside the work one' ((@($personal | ForEach-Object { $_.Email })) -join ', ') 'Files may be saved to the personal OneDrive by mistake.'
        }
    }

    $oneDrive = $State.OneDrive
    if (-not $oneDrive.Installed) {
        & $finding 'Info' 'OneDrive is not installed' '' ''
    }
    elseif (@($oneDrive.Accounts).Count -eq 0) {
        & $finding 'Info' 'OneDrive is not signed in' '' 'No OneDrive account is set up for this user, so nothing is synced.'
    }
    else {
        $running = if ($oneDrive.Running) { 'running' } else { 'not running' }
        & $finding $(if ($oneDrive.Running) { 'Pass' } else { 'Warning' }) ('OneDrive {0}' -f $running) ((@($oneDrive.Accounts | ForEach-Object { $_.Email })) -join ', ') $(if ($oneDrive.Running) { '' } else { 'Files are not synced while OneDrive is closed. Start it from the Start menu, or reset it if it closes again.' })

        $missing = @(@('Desktop', 'Documents', 'Pictures') | Where-Object { @($oneDrive.BackedUp) -notcontains $_ })
        if ($missing.Count -eq 0) {
            & $finding 'Pass' 'Desktop, Documents and Pictures are backed up by OneDrive' '' ''
        }
        elseif (@($oneDrive.Accounts | Where-Object Business).Count -gt 0) {
            & $finding 'Info' ('Not backed up by OneDrive: {0}' -f ($missing -join ', ')) '' 'These folders stay on the disk only. Folder backup in OneDrive settings moves them into OneDrive, so a lost or replaced PC loses nothing.'
        }
    }

    $teams = $State.Teams
    if ($teams.New) {
        & $finding 'Pass' ('Teams (new) {0}' -f $teams.New) '' ''
    }
    if ($teams.Classic) {
        & $finding 'Warning' 'Classic Teams is still installed' '' 'Microsoft retired classic Teams; it no longer receives updates and stops signing in. Remove it and use the new Teams.'
    }

    $outlook = $State.Outlook
    if ($outlook.New -and $outlook.Classic) {
        & $finding 'Info' 'Both the new and the classic Outlook are installed' $outlook.New 'Users can switch between them with the toggle in the title bar; some add-ins and PST files only work in the classic one.'
    }
}

<#
.SYNOPSIS
    Reads and judges the apps and accounts.

.OUTPUTS
    PSCustomObject with State and Findings.
#>
function Get-TkM365ClientReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $state = Get-TkM365ClientState

    return [pscustomobject] @{ State = $state; Findings = @(ConvertTo-TkM365ClientFinding -State $state) }
}
