<#
    Toolkit - Features / Incident triage collection

    In the first hour of an incident the state of a suspect machine has to be
    kept before it changes, in a form a CERT can trust and use. The
    investigations of the Audit page show that state; this file collects it:
    in order of volatility, each artefact as a file, every file hashed in a
    manifest dated in UTC that names the operator and the toolkit that
    collected it, the whole packed in one archive, and that archive
    optionally encrypted for the responder's certificate.

    What it does not do, on purpose: no memory image, no copy of LSASS, no
    credential extraction. Those are a forensic tool's work, and the
    signature of malware. The collection itself leaves traces on the machine
    (PowerShell's own events, Prefetch entries, the files it writes): the
    manifest says so. A step that fails is recorded and the next one runs.

    Encryption is CMS (EnvelopedCms), the format openssl and .NET both read,
    with no cryptography of the toolkit's own. One CMS message cannot hold an
    archive of hundreds of megabytes - .NET refuses to read back one past
    about 64 MB - so the archive is cut into 32 MB chunks, each its own CMS
    message, with an index that gives the SHA-256 of each chunk and of the
    archive they rebuild.
#>

# Chunks well under the size past which .NET cannot read a CMS message back.
$script:TkTriageChunkBytes = 33554432

<#
.SYNOPSIS
    The steps of a triage collection, most volatile first.

.DESCRIPTION
    A closed list. Each step writes its artefacts into the folder it is given
    and returns the files it wrote and a note. NeedsElevation steps still run
    without administrator rights, and say what they could not read.

.OUTPUTS
    PSCustomObject[] with Key, Title, Label, NeedsElevation, Partial and Collect.
#>
function Get-TkTriageStep {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $step = {
        param($key, $title, $label, $elevation, $partial, $collect)
        [pscustomobject] @{ Key = $key; Title = $title; Label = $label; NeedsElevation = $elevation; Partial = $partial; Collect = $collect }
    }

    return @(
        (& $step 'processes' 'Processes' 'Processes: command line, parent, owner, SHA-256 and signature' $true 'Other accounts'' command lines and owners are hidden without administrator rights.' {
            param($Folder)
            $all     = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
            $names   = @{}
            foreach ($process in $all) { $names[[int] $process.ProcessId] = [string] $process.Name }
            $hashes  = @{}
            $signers = @{}
            foreach ($path in @($all | ForEach-Object { [string] $_.ExecutablePath } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 800)) {
                $hashes[$path]  = try { (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { '' }
                $signed         = try { Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop } catch { $null }
                $signers[$path] = if ($signed) { '{0}{1}' -f $signed.Status, $(if ($signed.SignerCertificate) { ' ({0})' -f ($signed.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1') } else { '' }) } else { '' }
            }
            # Owners in one pass: GetOwner per process took a minute for three
            # hundred processes. Elevated, Get-Process names every owner;
            # otherwise the logon sessions name this account's, which is all
            # GetOwner would have answered.
            $owners = @{}
            if (Test-TkIsElevated) {
                try { foreach ($process in @(Get-Process -IncludeUserName -ErrorAction Stop)) { if ($process.UserName) { $owners[[int] $process.Id] = [string] $process.UserName } } } catch { $null = $_ }
            }
            if ($owners.Count -eq 0) {
                $users = @{}
                foreach ($link in @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction SilentlyContinue)) { $users[[string] $link.Dependent.LogonId] = '{0}\{1}' -f $link.Antecedent.Domain, $link.Antecedent.Name }
                foreach ($link in @(Get-CimInstance -ClassName Win32_SessionProcess -ErrorAction SilentlyContinue)) { $owners[[int] $link.Dependent.Handle] = $users[[string] $link.Antecedent.LogonId] }
            }
            $rows = foreach ($process in $all) {
                $path  = [string] $process.ExecutablePath
                [pscustomobject] @{
                    ProcessId = $process.ProcessId; ParentProcessId = $process.ParentProcessId; Parent = $names[[int] $process.ParentProcessId]
                    Name = $process.Name; Owner = [string] $owners[[int] $process.ProcessId]; SessionId = $process.SessionId
                    Created = $(if ($process.CreationDate) { ([datetime] $process.CreationDate).ToUniversalTime().ToString('o') } else { '' })
                    Path = $path; CommandLine = $process.CommandLine
                    Sha256 = $(if ($path) { $hashes[$path] } else { '' }); Signature = $(if ($path) { $signers[$path] } else { '' })
                }
            }
            @($rows) | Export-Csv -LiteralPath (Join-Path $Folder 'processes.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('processes.csv'); Note = '{0} process(es), {1} executable(s) hashed.' -f $all.Count, $hashes.Count }
        })

        (& $step 'connections' 'Connections' 'Network connections and listening ports' $false '' {
            param($Folder)
            $names = @{}
            foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[int] $process.Id] = $process.ProcessName }
            $tcp = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
                [pscustomobject] @{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort; State = [string] $_.State; ProcessId = $_.OwningProcess; Process = $names[[int] $_.OwningProcess]; Created = $(if ($_.CreationTime) { ([datetime] $_.CreationTime).ToUniversalTime().ToString('o') } else { '' }) }
            })
            $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject] @{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; ProcessId = $_.OwningProcess; Process = $names[[int] $_.OwningProcess] }
            })
            $tcp | Export-Csv -LiteralPath (Join-Path $Folder 'tcp.csv') -NoTypeInformation -Encoding UTF8
            $udp | Export-Csv -LiteralPath (Join-Path $Folder 'udp.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('tcp.csv', 'udp.csv'); Note = '{0} TCP connection(s), {1} UDP endpoint(s).' -f $tcp.Count, $udp.Count }
        })

        (& $step 'sessions' 'Logon sessions' 'Logon sessions and the users behind them' $true 'Other accounts'' sessions are hidden without administrator rights.' {
            param($Folder)
            $sessions = @{}
            foreach ($session in @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop)) { $sessions[[string] $session.LogonId] = $session }
            $rows = @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop | ForEach-Object {
                $id      = [string] $_.Dependent.LogonId
                $session = $sessions[$id]
                [pscustomobject] @{
                    User = '{0}\{1}' -f $_.Antecedent.Domain, $_.Antecedent.Name; LogonId = $id
                    LogonType = $(if ($session) { $session.LogonType } else { '' }); AuthenticationPackage = $(if ($session) { $session.AuthenticationPackage } else { '' })
                    Started = $(if ($session -and $session.StartTime) { ([datetime] $session.StartTime).ToUniversalTime().ToString('o') } else { '' })
                }
            })
            $rows | Export-Csv -LiteralPath (Join-Path $Folder 'sessions.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('sessions.csv'); Note = '{0} session(s).' -f $rows.Count }
        })

        (& $step 'dns-cache' 'DNS cache' 'DNS cache' $false '' {
            param($Folder)
            $rows = @(Get-DnsClientCache -ErrorAction Stop | Select-Object -Property Entry, RecordName, Type, Status, Section, TimeToLive, Data)
            $rows | Export-Csv -LiteralPath (Join-Path $Folder 'dns-cache.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('dns-cache.csv'); Note = '{0} record(s).' -f $rows.Count }
        })

        (& $step 'arp-cache' 'ARP cache' 'ARP and neighbour cache' $false '' {
            param($Folder)
            $rows = @(Get-NetNeighbor -ErrorAction Stop | Select-Object -Property InterfaceAlias, AddressFamily, IPAddress, LinkLayerAddress, @{ Name = 'State'; Expression = { [string] $_.State } })
            $rows | Export-Csv -LiteralPath (Join-Path $Folder 'arp-cache.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('arp-cache.csv'); Note = '{0} neighbour(s).' -f $rows.Count }
        })

        (& $step 'network' 'Network' 'Network configuration, routes, hosts file, mapped drives and shares' $false '' {
            param($Folder)
            $files = New-Object System.Collections.Generic.List[string]
            (& ipconfig.exe /all) | Set-Content -LiteralPath (Join-Path $Folder 'ipconfig.txt') -Encoding UTF8; $files.Add('ipconfig.txt')
            (& netsh.exe winhttp show proxy) | Set-Content -LiteralPath (Join-Path $Folder 'winhttp-proxy.txt') -Encoding UTF8; $files.Add('winhttp-proxy.txt')
            @(Get-NetRoute -ErrorAction SilentlyContinue | Select-Object -Property InterfaceAlias, AddressFamily, DestinationPrefix, NextHop, RouteMetric, @{ Name = 'Protocol'; Expression = { [string] $_.Protocol } }) |
                Export-Csv -LiteralPath (Join-Path $Folder 'routes.csv') -NoTypeInformation -Encoding UTF8; $files.Add('routes.csv')
            $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            if ([System.IO.File]::Exists($hosts)) { Copy-Item -LiteralPath $hosts -Destination (Join-Path $Folder 'hosts.txt'); $files.Add('hosts.txt') }
            try { @(Get-SmbMapping -ErrorAction Stop | Select-Object -Property LocalPath, RemotePath, Status) | Export-Csv -LiteralPath (Join-Path $Folder 'smb-mappings.csv') -NoTypeInformation -Encoding UTF8; $files.Add('smb-mappings.csv') } catch { $null = $_ }
            try { @(Get-SmbShare -ErrorAction Stop | Select-Object -Property Name, Path, Description, ScopeName, CurrentUsers) | Export-Csv -LiteralPath (Join-Path $Folder 'shares.csv') -NoTypeInformation -Encoding UTF8; $files.Add('shares.csv') } catch { $null = $_ }
            [pscustomobject] @{ Files = $files.ToArray(); Note = '{0} file(s).' -f $files.Count }
        })

        (& $step 'tasks' 'Scheduled tasks' 'Scheduled tasks, with their actions and accounts' $false '' {
            param($Folder)
            $rows = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
                $info = try { Get-ScheduledTaskInfo -InputObject $_ -ErrorAction Stop } catch { $null }
                [pscustomobject] @{
                    Path = $_.TaskPath; Name = $_.TaskName; State = [string] $_.State; Author = $_.Author; RunAs = $_.Principal.UserId
                    Actions = (@($_.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' | ')
                    Triggers = (@($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '' }) -join ', ')
                    LastRun = $(if ($info -and $info.LastRunTime) { ([datetime] $info.LastRunTime).ToUniversalTime().ToString('o') } else { '' })
                    LastResult = $(if ($info) { $info.LastTaskResult } else { '' })
                }
            })
            $rows | Export-Csv -LiteralPath (Join-Path $Folder 'scheduled-tasks.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('scheduled-tasks.csv'); Note = '{0} task(s).' -f $rows.Count }
        })

        (& $step 'services' 'Services and drivers' 'Services and kernel drivers' $false '' {
            param($Folder)
            $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object -Property Name, DisplayName, State, StartMode, PathName, StartName, ProcessId, Description)
            $drivers  = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue | Select-Object -Property Name, DisplayName, State, StartMode, PathName)
            $services | Export-Csv -LiteralPath (Join-Path $Folder 'services.csv') -NoTypeInformation -Encoding UTF8
            $drivers  | Export-Csv -LiteralPath (Join-Path $Folder 'drivers.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('services.csv', 'drivers.csv'); Note = '{0} service(s), {1} driver(s).' -f $services.Count, $drivers.Count }
        })

        (& $step 'autostarts' 'Autostarts' 'Autostarts and persistence' $false '' {
            param($Folder)
            $items = @(Get-TkPersistenceItem)
            ConvertTo-Json -InputObject $items -Depth 6 | Set-Content -LiteralPath (Join-Path $Folder 'autostarts.json') -Encoding UTF8
            [pscustomobject] @{ Files = @('autostarts.json'); Note = '{0} item(s).' -f $items.Count }
        })

        (& $step 'accounts' 'Accounts' 'Local accounts and privileged groups' $false '' {
            param($Folder)
            $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [pscustomobject] @{ Name = $_.Name; Enabled = $_.Enabled; Sid = [string] $_.SID; Description = $_.Description; LastLogon = $(if ($_.LastLogon) { ([datetime] $_.LastLogon).ToUniversalTime().ToString('o') } else { '' }); PasswordLastSet = $(if ($_.PasswordLastSet) { ([datetime] $_.PasswordLastSet).ToUniversalTime().ToString('o') } else { '' }); Source = [string] $_.PrincipalSource }
            })
            $members = @(foreach ($sid in @('S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-551', 'S-1-5-32-580')) {
                $group = try { Get-LocalGroup -SID $sid -ErrorAction Stop } catch { $null }
                if (-not $group) { continue }
                try { Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object { [pscustomobject] @{ Group = $group.Name; Member = $_.Name; Class = $_.ObjectClass; Source = [string] $_.PrincipalSource; Sid = [string] $_.SID } } }
                catch { [pscustomobject] @{ Group = $group.Name; Member = '(could not be listed: {0})' -f $_.Exception.Message; Class = ''; Source = ''; Sid = '' } }
            })
            $users   | Export-Csv -LiteralPath (Join-Path $Folder 'local-users.csv') -NoTypeInformation -Encoding UTF8
            $members | Export-Csv -LiteralPath (Join-Path $Folder 'privileged-groups.csv') -NoTypeInformation -Encoding UTF8
            [pscustomobject] @{ Files = @('local-users.csv', 'privileged-groups.csv'); Note = '{0} account(s), {1} membership(s).' -f $users.Count, $members.Count }
        })

        (& $step 'firewall' 'Firewall' 'Firewall profiles and rules' $false '' {
            param($Folder)
            $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogAllowed, LogBlocked)
            $profiles | Export-Csv -LiteralPath (Join-Path $Folder 'firewall-profiles.csv') -NoTypeInformation -Encoding UTF8
            (& netsh.exe advfirewall firewall show rule name=all verbose) | Set-Content -LiteralPath (Join-Path $Folder 'firewall-rules.txt') -Encoding UTF8
            [pscustomobject] @{ Files = @('firewall-profiles.csv', 'firewall-rules.txt'); Note = '{0} profile(s) off.' -f @($profiles | Where-Object { -not $_.Enabled }).Count }
        })

        (& $step 'defender' 'Defender' 'Microsoft Defender: detections, status and exclusions' $true 'The exclusions are hidden without administrator rights.' {
            param($Folder)
            $data = [ordered] @{
                Status     = $(try { Get-MpComputerStatus -ErrorAction Stop | Select-Object -Property AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime } catch { $_.Exception.Message })
                Detections = $(try { @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -Property ThreatID, InitialDetectionTime, LastThreatStatusChangeTime, ActionSuccess, ProcessName, DomainUser, Resources) } catch { @() })
                Threats    = $(try { @(Get-MpThreat -ErrorAction Stop | Select-Object -Property ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute, Resources) } catch { @() })
                Exclusions = $(try { $p = Get-MpPreference -ErrorAction Stop; [ordered] @{ Path = @($p.ExclusionPath); Process = @($p.ExclusionProcess); Extension = @($p.ExclusionExtension); IpAddress = @($p.ExclusionIpAddress) } } catch { $_.Exception.Message })
            }
            ConvertTo-Json -InputObject $data -Depth 6 | Set-Content -LiteralPath (Join-Path $Folder 'defender.json') -Encoding UTF8
            [pscustomobject] @{ Files = @('defender.json'); Note = '{0} detection(s).' -f @($data.Detections).Count }
        })

        (& $step 'extensions' 'Browser extensions' 'Browser extensions' $false '' {
            param($Folder)
            $items = @(Get-TkBrowserExtension)
            ConvertTo-Json -InputObject $items -Depth 6 | Set-Content -LiteralPath (Join-Path $Folder 'browser-extensions.json') -Encoding UTF8
            [pscustomobject] @{ Files = @('browser-extensions.json'); Note = '{0} extension(s).' -f $items.Count }
        })

        (& $step 'history' 'USB and RDP history' 'USB storage and Remote Desktop history' $false '' {
            param($Folder)
            $usb = @(Get-TkUsbHistory)
            $rdp = Get-TkRdpHistory
            ConvertTo-Json -InputObject $usb -Depth 6 | Set-Content -LiteralPath (Join-Path $Folder 'usb-history.json') -Encoding UTF8
            ConvertTo-Json -InputObject $rdp -Depth 6 | Set-Content -LiteralPath (Join-Path $Folder 'rdp-history.json') -Encoding UTF8
            [pscustomobject] @{ Files = @('usb-history.json', 'rdp-history.json'); Note = '{0} USB device(s).' -f $usb.Count }
        })

        (& $step 'event-logs' 'Event logs' 'Event logs, exported whole as .evtx' $true 'The Security log needs administrator rights.' {
            param($Folder)
            $logs = @('System', 'Application', 'Security', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
                      'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
                      'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
                      'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-Sysmon/Operational')
            # The API wevtutil epl uses, without a native command: Windows
            # PowerShell turns a native command's error output into an error
            # that stops the step, and the refused Security log has one.
            $session = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession
            $files   = New-Object System.Collections.Generic.List[string]
            $missing = New-Object System.Collections.Generic.List[string]
            foreach ($log in $logs) {
                $name = ($log -replace '[\\/ ]', '-') + '.evtx'
                try {
                    $session.ExportLog($log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*', [System.IO.Path]::Combine($Folder, $name))
                    $files.Add($name)
                }
                catch {
                    $missing.Add($log)
                }
            }
            [pscustomobject] @{ Files = $files.ToArray(); Note = '{0} log(s) exported{1}.' -f $files.Count, $(if ($missing.Count) { '; not exported (absent or not readable): {0}' -f ($missing -join ', ') } else { '' }) }
        })
    )
}

<#
.SYNOPSIS
    Starts a triage case: its folder at the destination, and its identity.

.DESCRIPTION
    The folder is named after the machine and the moment, in UTC, so two
    collections never meet. The reference is the operator's (an incident or
    ticket number) and is only written into the manifest.

.OUTPUTS
    PSCustomObject with Id, Folder, Reference, Started and OnSystemDrive.
#>
function New-TkTriageCase {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter()] [AllowEmptyString()] [string] $Reference = '',
        [Parameter()] [datetime] $Now = ([datetime]::UtcNow)
    )

    if (-not [System.IO.Directory]::Exists($Destination)) {
        throw ('{0} does not exist: choose a folder, preferably on removable media.' -f $Destination)
    }

    if ($Reference.Length -gt 120) {
        throw 'The reference is longer than 120 characters.'
    }

    $utc    = $Now.ToUniversalTime()
    $id     = 'triage-{0}-{1}' -f ($env:COMPUTERNAME -replace '[^A-Za-z0-9-]', '_'), $utc.ToString('yyyyMMddTHHmmssZ')
    $folder = [System.IO.Path]::Combine((Resolve-Path -LiteralPath $Destination).ProviderPath, $id)

    if (-not $PSCmdlet.ShouldProcess($folder, 'Create the triage folder')) {
        return $null
    }

    [void] [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($folder, 'artefacts'))

    $systemRoot = [System.IO.Path]::GetPathRoot($env:SystemRoot)
    $onSystem   = [string]::Equals([System.IO.Path]::GetPathRoot($folder), $systemRoot, [System.StringComparison]::OrdinalIgnoreCase)

    return [pscustomobject] @{
        Id            = $id
        Folder        = $folder
        Reference     = $Reference.Trim()
        Started       = $utc.ToString('o')
        OnSystemDrive = $onSystem
    }
}

<#
.SYNOPSIS
    Runs one step of a collection into its own folder of the case.

.DESCRIPTION
    Never throws: a step that fails is recorded with its error, and the
    collection goes on. A step that needs administrator rights still runs
    without them and is marked Partial, with what it could not read.

.OUTPUTS
    PSCustomObject with Key, Label, Started, Ended (UTC), Status (Done,
    Partial, Failed), Note, Folder, Ok and Text.
#>
function Invoke-TkTriageStep {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter()] [int] $Order = 0
    )

    $step = @(Get-TkTriageStep | Where-Object { $_.Key -eq $Key }) | Select-Object -First 1

    if (-not $step) {
        throw ('{0} is not a triage step.' -f $Key)
    }

    $relative = 'artefacts/{0:D2}-{1}' -f $Order, $Key
    $target   = [System.IO.Path]::Combine($Folder, 'artefacts', ('{0:D2}-{1}' -f $Order, $Key))
    [void] [System.IO.Directory]::CreateDirectory($target)

    $record = [pscustomobject] @{
        Key     = $step.Key
        Label   = $step.Label
        Started = [datetime]::UtcNow.ToString('o')
        Ended   = ''
        Status  = 'Done'
        Note    = ''
        Folder  = $relative
        Ok      = $true
        Text    = ''
    }

    try {
        $result      = & $step.Collect $target
        $record.Note = [string] $(if ($result) { $result.Note } else { '' })

        if ($step.NeedsElevation -and -not (Test-TkIsElevated)) {
            $record.Status = 'Partial'
            $record.Note   = ('{0} {1}' -f $record.Note, $step.Partial).Trim()
        }
    }
    catch {
        $record.Status = 'Failed'
        $record.Ok     = $false
        $record.Note   = $_.Exception.Message
    }

    $record.Ended = [datetime]::UtcNow.ToString('o')
    $record.Text  = $record.Note

    return $record
}

<#
.SYNOPSIS
    Every file of a folder, with its size and SHA-256, by relative path.

.OUTPUTS
    PSCustomObject[] with Path (forward slashes), Bytes and Sha256.
#>
function Get-TkTriageFileList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Exclude = @()
    )

    $root = (Resolve-Path -LiteralPath $Folder).ProviderPath.TrimEnd('\') + '\'

    return @(Get-ChildItem -LiteralPath $Folder -File -Recurse -Force | Sort-Object -Property FullName | ForEach-Object {
        $relative = $_.FullName.Substring($root.Length).Replace('\', '/')
        if ($Exclude -notcontains $relative) {
            [pscustomobject] @{ Path = $relative; Bytes = $_.Length; Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
        }
    })
}

<#
.SYNOPSIS
    What identifies the toolkit that collected: version, commit, where it
    came from, and the SHA-256 of that build when it is known.
#>
function Get-TkTriageToolkitIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $ctx    = Get-TkContext
    $source = ''
    $sha    = ''
    $how    = ''

    if ($ctx.EntryScript -and [System.IO.File]::Exists([string] $ctx.EntryScript)) {
        $source = [string] $ctx.EntryScript
        $sha    = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $how    = 'The file that ran, hashed by the collection.'
    }
    elseif ($ctx.SourceUri) {
        $source = [string] $ctx.SourceUri
        $sha    = [string] $ctx.SourceSha256
        $how    = if ($sha) { 'Downloaded and run only after this SHA-256 was checked.' } else { 'Downloaded without a pinned SHA-256: the build that ran cannot be proven.' }
    }
    else {
        $how = 'Neither the file nor the address the toolkit was started from is known: the build that ran cannot be proven.'
    }

    return [pscustomobject] @{ Version = [string] $ctx.Version; Commit = [string] $ctx.Commit; Source = $source; Sha256 = $sha; Proof = $how }
}

<#
.SYNOPSIS
    The manifest of a triage case.

.DESCRIPTION
    Pure. Dated in UTC; names the case, the machine, the operator, the
    toolkit, each step and each file with its SHA-256; says what the
    collection itself changed on the machine and what it does not collect.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
function New-TkTriageManifest {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Case,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Step,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $File,
        [Parameter(Mandatory)] [pscustomobject] $Toolkit,
        [Parameter()] [bool] $Elevated = $false,
        [Parameter()] [string] $Ended = ([datetime]::UtcNow.ToString('o'))
    )

    $os = Get-TkCimInstanceSafe -ClassName 'Win32_OperatingSystem'

    return [ordered] @{
        Schema        = 'toolkit-triage'
        SchemaVersion = '1.0'
        Case          = [ordered] @{ Id = $Case.Id; Reference = $Case.Reference }
        Started       = $Case.Started
        Ended         = $Ended
        Machine       = [ordered] @{
            Computer  = $env:COMPUTERNAME
            MachineId = Get-TkMachineId
            Os        = $(if ($os) { '{0} {1}' -f $os.Caption, $os.BuildNumber } else { '' })
            LastBoot  = $(if ($os -and $os.LastBootUpTime) { ([datetime] $os.LastBootUpTime).ToUniversalTime().ToString('o') } else { '' })
            TimeZone  = [System.TimeZoneInfo]::Local.Id
            UtcOffset = [System.TimeZoneInfo]::Local.GetUtcOffset([datetime]::Now).ToString()
        }
        Operator      = [ordered] @{ User = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME); Elevated = $Elevated }
        Toolkit       = $Toolkit
        Steps         = @($Step | ForEach-Object { [ordered] @{ Key = $_.Key; Label = $_.Label; Started = $_.Started; Ended = $_.Ended; Status = $_.Status; Note = $_.Note; Folder = $_.Folder } })
        Files         = @($File | ForEach-Object { [ordered] @{ Path = $_.Path; Bytes = $_.Bytes; Sha256 = $_.Sha256 } })
        Footprint     = 'The collection itself changed the machine a little: Windows PowerShell and the toolkit write their own events, Prefetch records the programs it ran (powershell, netsh, ipconfig), and the files of the case were written to the destination.'
        NotCollected  = 'No memory image, no copy of LSASS, no password or credential: out of scope by design.'
        Destination   = $(if ($Case.OnSystemDrive) { 'Written to the system drive: where the evidence lives. Removable media would have touched it less.' } else { 'Written outside the system drive.' })
    }
}

<#
.SYNOPSIS
    Reads the responder's certificate, and refuses one CMS cannot encrypt for.
#>
function Get-TkTriageCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    if (-not [System.IO.File]::Exists($Path)) {
        throw ('{0} does not exist.' -f $Path)
    }

    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.IO.File]::ReadAllBytes($Path))
    }
    catch {
        throw ('{0} is not a certificate (.cer, DER or PEM).' -f $Path)
    }

    if ($certificate.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1') {
        throw ('The certificate of {0} has a {1} key: the archive can only be encrypted for an RSA key.' -f ($certificate.Subject -replace '^CN=([^,]+).*$', '$1'), $certificate.PublicKey.Oid.FriendlyName)
    }

    if ($certificate.NotAfter -lt (Get-Date)) {
        throw ('The certificate of {0} expired on {1}.' -f ($certificate.Subject -replace '^CN=([^,]+).*$', '$1'), $certificate.NotAfter.ToString('yyyy-MM-dd'))
    }

    return $certificate
}

<#
.SYNOPSIS
    Encrypts an archive for a certificate, in CMS chunks with an index.

.DESCRIPTION
    Each chunk is a CMS EnvelopedCms message (AES-256) for the certificate,
    written to <archive>.p7m.001, .002...; each is read back and its
    recipient checked before the next. The index, <archive>.p7m.json, gives
    the SHA-256 of every chunk and of the archive they rebuild. openssl
    decrypts a chunk with: openssl cms -decrypt -inform DER -in <chunk>
    -recip <cert.pem> -inkey <key.pem>.

.OUTPUTS
    PSCustomObject with Index, Chunks and Sha256 (of the clear archive).
#>
function Protect-TkTriageArchive {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter()] [ValidateRange(1024, 33554432)] [int] $ChunkBytes = $script:TkTriageChunkBytes
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -AssemblyName System.Security
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Encrypt the archive')) {
        return $null
    }

    $sha    = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $chunks = New-Object System.Collections.Generic.List[object]
    $buffer = New-Object byte[] $ChunkBytes
    $stream = [System.IO.File]::OpenRead($Path)
    $aes    = New-Object System.Security.Cryptography.Oid('2.16.840.1.101.3.4.1.42')

    try {
        $number = 0
        while ($true) {
            $read = 0
            while ($read -lt $ChunkBytes) {
                $count = $stream.Read($buffer, $read, $ChunkBytes - $read)
                if ($count -le 0) { break }
                $read += $count
            }
            if ($read -le 0) { break }

            $number++
            $content = New-Object byte[] $read
            [System.Array]::Copy($buffer, $content, $read)

            $cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms((New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $content)), (New-Object System.Security.Cryptography.Pkcs.AlgorithmIdentifier($aes)))
            $cms.Encrypt((New-Object System.Security.Cryptography.Pkcs.CmsRecipient($Certificate)))
            $encoded = $cms.Encode()

            # Read back before going on: a chunk that cannot be decoded, or is
            # not for this certificate, is no use to the responder.
            $check = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
            $check.Decode($encoded)
            if ($check.RecipientInfos.Count -ne 1 -or [string] $check.RecipientInfos[0].RecipientIdentifier.Value.SerialNumber -ne $Certificate.SerialNumber) {
                throw ('Chunk {0} did not read back for the certificate.' -f $number)
            }

            $name = '{0}.p7m.{1:D3}' -f [System.IO.Path]::GetFileName($Path), $number
            [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($Path), $name), $encoded)
            $chunks.Add([pscustomobject] @{ File = $name; ClearBytes = $read; Sha256 = Get-TkBytesSha256 -Bytes $encoded })
        }
    }
    finally {
        $stream.Dispose()
    }

    $index = [ordered] @{
        Schema      = 'toolkit-triage-archive'
        Archive     = [System.IO.Path]::GetFileName($Path)
        Sha256      = $sha
        Algorithm   = 'CMS EnvelopedCms, AES-256-CBC, one message per chunk'
        ChunkBytes  = $ChunkBytes
        Recipient   = [ordered] @{ Subject = $Certificate.Subject; Thumbprint = $Certificate.Thumbprint; SerialNumber = $Certificate.SerialNumber; NotAfter = $Certificate.NotAfter.ToUniversalTime().ToString('o') }
        Chunks      = @($chunks | ForEach-Object { [ordered] @{ File = $_.File; ClearBytes = $_.ClearBytes; Sha256 = $_.Sha256 } })
        Rebuild     = 'Decrypt each chunk in order (openssl cms -decrypt -inform DER -in <chunk> -recip <cert.pem> -inkey <key.pem> >> archive.zip), then check the SHA-256 of the archive.'
    }

    $indexPath = '{0}.p7m.json' -f $Path
    [System.IO.File]::WriteAllText($indexPath, (ConvertTo-Json -InputObject $index -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

    return [pscustomobject] @{ Index = $indexPath; Chunks = @($chunks | ForEach-Object { $_.File }); Sha256 = $sha }
}

<#
.SYNOPSIS
    Rebuilds an encrypted triage archive, for the responder who holds the key.

.DESCRIPTION
    Decrypts each chunk listed in the index, in order, after checking its
    SHA-256, and checks the SHA-256 of the archive rebuilt. The key is taken
    from the certificate store (by thumbprint, the usual place for a SOC's
    key) or from a .pfx.

.OUTPUTS
    System.String, the path of the archive rebuilt.
#>
function Unprotect-TkTriageArchive {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Store')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Index,
        [Parameter(Mandatory)] [string] $OutFile,
        [Parameter(ParameterSetName = 'Store')] [string] $Thumbprint = '',
        [Parameter(Mandatory, ParameterSetName = 'Pfx')] [string] $PfxPath,
        [Parameter(ParameterSetName = 'Pfx')] [System.Security.SecureString] $Password,
        [Parameter(Mandatory, ParameterSetName = 'Certificate')] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -AssemblyName System.Security
    }

    $data   = Get-Content -LiteralPath $Index -Raw -Encoding UTF8 | ConvertFrom-Json
    $folder = [System.IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $Index).ProviderPath)

    if ([string] $data.Schema -ne 'toolkit-triage-archive') {
        throw ('{0} is not the index of an encrypted triage archive.' -f $Index)
    }

    $keys = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    switch ($PSCmdlet.ParameterSetName) {
        'Pfx'         { [void] $keys.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Password)) }
        'Certificate' { [void] $keys.Add($Certificate) }
        default {
            $wanted = if ($Thumbprint) { $Thumbprint } else { [string] $data.Recipient.Thumbprint }
            foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
                $found = Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $wanted -and $_.HasPrivateKey } | Select-Object -First 1
                if ($found) { [void] $keys.Add($found); break }
            }
            if ($keys.Count -eq 0) { throw ('No certificate with a private key and the thumbprint {0} in the stores of this account or machine.' -f $wanted) }
        }
    }

    if (-not $PSCmdlet.ShouldProcess($OutFile, 'Rebuild the archive')) {
        return $null
    }

    $output = [System.IO.File]::Create($OutFile)
    try {
        foreach ($chunk in @($data.Chunks)) {
            $bytes = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($folder, [string] $chunk.File))
            if ((Get-TkBytesSha256 -Bytes $bytes) -ne [string] $chunk.Sha256) {
                throw ('{0} is not the chunk the index lists: its SHA-256 differs.' -f $chunk.File)
            }
            $cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
            $cms.Decode($bytes)
            $cms.Decrypt($keys)
            $clear = $cms.ContentInfo.Content
            $output.Write($clear, 0, $clear.Length)
        }
    }
    finally {
        $output.Dispose()
    }

    if ((Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash -ne [string] $data.Sha256) {
        throw ('The archive rebuilt in {0} is not the one encrypted: its SHA-256 differs.' -f $OutFile)
    }

    return $OutFile
}

<#
.SYNOPSIS
    Ends a triage case: manifest, archive, encryption, journal.

.DESCRIPTION
    The manifest lists every file the steps wrote with its SHA-256, and its
    own SHA-256 goes beside it, in the journal and on screen, for the chain
    of custody. The case folder is packed into <case>.zip. With a
    certificate, the archive is encrypted in CMS chunks; the clear copy is
    removed only when asked, and only once every chunk has been read back.
    Encryption that fails keeps the clear archive and says why: the
    evidence is never lost to a wrong certificate.

.PARAMETER Toolkit
    What identifies the toolkit that collected, from Get-TkTriageToolkitIdentity.
    Read on the window's thread and handed over: a background runspace has
    no record of where the toolkit was launched from.

.OUTPUTS
    PSCustomObject with Folder, Manifest, ManifestSha256, Archive,
    ArchiveSha256, Encrypted, EncryptionError, Index, Chunks, ClearRemoved,
    Hashes, Steps (Key, Label, Status, Note), Failed and Partial.
#>
function Complete-TkTriageCase {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Case,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Step,
        [Parameter()] [AllowEmptyString()] [string] $CertificatePath = '',
        [Parameter()] [switch] $RemoveClear,
        [Parameter()] [AllowNull()] [pscustomobject] $Toolkit = $null,
        [Parameter()] [ValidateRange(1024, 33554432)] [int] $ChunkBytes = $script:TkTriageChunkBytes
    )

    if (-not $PSCmdlet.ShouldProcess($Case.Folder, 'Complete the triage case')) {
        return $null
    }

    # Read first: a wrong certificate is refused before anything is packed.
    $certificate = if ($CertificatePath) { Get-TkTriageCertificate -Path $CertificatePath } else { $null }
    $identity    = if ($Toolkit) { $Toolkit } else { Get-TkTriageToolkitIdentity }

    $files    = @(Get-TkTriageFileList -Folder $Case.Folder -Exclude @('manifest.json', 'manifest.sha256'))
    $manifest = New-TkTriageManifest -Case $Case -Step $Step -File $files -Toolkit $identity -Elevated ([bool] (Test-TkIsElevated))

    $manifestPath = [System.IO.Path]::Combine($Case.Folder, 'manifest.json')
    [System.IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $manifest -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($Case.Folder, 'manifest.sha256'), ('{0}  manifest.json{1}' -f $manifestSha, [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
    }

    $archive = '{0}.zip' -f $Case.Folder
    if ([System.IO.File]::Exists($archive)) { [System.IO.File]::Delete($archive) }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($Case.Folder, $archive, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $archiveSha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash

    $encrypted = $null
    $failure   = ''
    if ($certificate) {
        try {
            $encrypted = Protect-TkTriageArchive -Path $archive -Certificate $certificate -ChunkBytes $ChunkBytes -Confirm:$false
        }
        catch {
            $failure = 'The archive could not be encrypted, and was kept in clear: {0}' -f $_.Exception.Message
            Write-TkLog -Level Warning -Category 'Triage' -Message $failure
        }
    }

    $hashes = New-Object System.Collections.Generic.List[string]
    $hashes.Add(('{0}  {1}/manifest.json' -f $manifestSha, $Case.Id))
    $hashes.Add(('{0}  {1}' -f $archiveSha, [System.IO.Path]::GetFileName($archive)))
    if ($encrypted) {
        $base = [System.IO.Path]::GetDirectoryName($archive)
        foreach ($chunk in $encrypted.Chunks) { $hashes.Add(('{0}  {1}' -f (Get-FileHash -LiteralPath ([System.IO.Path]::Combine($base, $chunk)) -Algorithm SHA256).Hash, $chunk)) }
    }
    $summary = '{0}.sha256.txt' -f $Case.Folder
    [System.IO.File]::WriteAllText($summary, (($hashes -join [Environment]::NewLine) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))

    if ($encrypted -and $RemoveClear) {
        Remove-Item -LiteralPath $archive -Force
        Remove-Item -LiteralPath $Case.Folder -Recurse -Force
    }

    $failed  = @($Step | Where-Object { $_.Status -eq 'Failed' })
    $partial = @($Step | Where-Object { $_.Status -eq 'Partial' })
    $detail  = '{0}{1}: {2} step(s), {3} failed, {4} partial; manifest SHA-256 {5}; archive SHA-256 {6}{7}.' -f $Case.Id,
        $(if ($Case.Reference) { ' ({0})' -f $Case.Reference } else { '' }), @($Step).Count, $failed.Count, $partial.Count, $manifestSha, $archiveSha,
        $(if ($encrypted) { '; encrypted for {0}' -f ($certificate.Subject -replace '^CN=([^,]+).*$', '$1') } elseif ($failure) { '; {0}' -f $failure } else { '' })

    Write-TkLog -Level Information -Category 'Triage' -Message ('Triage collection: {0}' -f $detail)
    Add-TkJournalEntry -Name 'Triage collection' -Category 'Triage' -Success ($failed.Count -eq 0 -and -not $failure) -Detail $detail

    return [pscustomobject] @{
        Id              = $Case.Id
        Reference       = $Case.Reference
        Folder          = $Case.Folder
        OnSystemDrive   = [bool] $Case.OnSystemDrive
        Manifest        = $manifestPath
        ManifestSha256  = $manifestSha
        Archive         = $archive
        ArchiveSha256   = $archiveSha
        Encrypted       = [bool] $encrypted
        EncryptionError = $failure
        Index           = $(if ($encrypted) { $encrypted.Index } else { '' })
        Chunks          = $(if ($encrypted) { @($encrypted.Chunks) } else { @() })
        ClearRemoved    = [bool] ($encrypted -and $RemoveClear)
        Hashes          = $summary
        Steps           = @($Step | ForEach-Object { [pscustomobject] @{ Key = $_.Key; Label = $_.Label; Status = $_.Status; Note = $_.Note } })
        Failed          = $failed.Count
        Partial         = $partial.Count
    }
}

<#
.SYNOPSIS
    A whole triage collection, without a window.

.PARAMETER Step
    The keys of the steps to run; all of them when empty.

.OUTPUTS
    PSCustomObject, as Complete-TkTriageCase returns it.
#>
function Invoke-TkTriageCollection {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter()] [AllowEmptyString()] [string] $Reference = '',
        [Parameter()] [AllowEmptyCollection()] [string[]] $Step = @(),
        [Parameter()] [AllowEmptyString()] [string] $CertificatePath = '',
        [Parameter()] [switch] $RemoveClear,
        [Parameter()] [AllowNull()] [pscustomobject] $Toolkit = $null
    )

    $known  = @(Get-TkTriageStep | ForEach-Object { $_.Key })
    $chosen = @(Resolve-TkTriageStepChoice -Step $Step)

    # Read before anything is collected, so a wrong certificate fails at once.
    if ($CertificatePath) { $null = Get-TkTriageCertificate -Path $CertificatePath }

    if (-not $PSCmdlet.ShouldProcess($Destination, 'Collect a triage case')) {
        return $null
    }

    $case    = New-TkTriageCase -Destination $Destination -Reference $Reference -Confirm:$false
    $order   = 0
    $records = foreach ($key in $known) {
        $order++
        if ($chosen -notcontains $key) { continue }
        Write-TkLog -Level Information -Category 'Triage' -Message ('Collecting: {0}' -f $key)
        Invoke-TkTriageStep -Key $key -Folder $case.Folder -Order $order
    }

    return (Complete-TkTriageCase -Case $case -Step @($records) -CertificatePath $CertificatePath -RemoveClear:$RemoveClear -Toolkit $Toolkit -Confirm:$false)
}

<#
.SYNOPSIS
    The steps asked for, checked against the closed list, in its order.

.DESCRIPTION
    Pure. Keys may come one per value or several in one, separated by commas,
    semicolons or spaces. None asked for means every step.

.OUTPUTS
    System.String[]: the step keys, most volatile first.
#>
function Resolve-TkTriageStepChoice {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $Step = @()
    )

    $known   = @(Get-TkTriageStep | ForEach-Object { $_.Key })
    $chosen  = @($Step | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ })
    $unknown = @($chosen | Where-Object { $known -notcontains $_ })

    if ($unknown.Count -gt 0) {
        throw ('{0} is not a triage step. The steps are: {1}.' -f $unknown[0], ($known -join ', '))
    }

    if ($chosen.Count -eq 0) {
        return $known
    }

    return @($known | Where-Object { $chosen -contains $_ })
}

<#
.SYNOPSIS
    Collects a triage case without a window, and returns the result as JSON.

.DESCRIPTION
    For a responder working through a remote shell or an RMM: the case is
    collected into the destination as from the Audit page, and the result
    says where each file went and its SHA-256. Destination List returns the
    steps instead. The exit code, left in $LASTEXITCODE, is 0 when every
    step ran and the archive was encrypted as asked, 1 otherwise.

.OUTPUTS
    System.String: the JSON, or the full path of the file written.
#>
function Invoke-TkHeadlessTriage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter()] [AllowEmptyString()] [string] $Reference = '',
        [Parameter()] [AllowEmptyCollection()] [string[]] $Step = @(),
        [Parameter()] [AllowEmptyString()] [string] $CertificatePath = '',
        [Parameter()] [switch] $RemoveClear,
        [Parameter()] [AllowEmptyString()] [string] $OutFile = ''
    )

    if ($Destination -eq 'List') {

        $json     = ConvertTo-Json -InputObject @(Get-TkTriageStep | Select-Object -Property Key, Title, Label, NeedsElevation, Partial) -Depth 4
        $exitCode = 0
    }
    else {

        if ($RemoveClear -and -not $CertificatePath) {
            throw '-TriageRemoveClear removes the clear copy once it is encrypted: it needs -TriageCertificate.'
        }

        $context  = Get-TkContext
        $result   = Invoke-TkTriageCollection -Destination $Destination -Reference $Reference -Step $Step -CertificatePath $CertificatePath -RemoveClear:$RemoveClear -Confirm:$false
        $exitCode = if ($result.Failed -gt 0 -or $result.EncryptionError) { 1 } else { 0 }

        $document = [ordered] @{
            Schema        = 'toolkit-triage-result'
            SchemaVersion = '1.0'
            Computer      = $env:COMPUTERNAME
            MachineId     = Get-TkMachineId
            GeneratedAt   = [datetime]::UtcNow.ToString('o')
            Toolkit       = [ordered] @{ Version = [string] $context.Version; Commit = [string] $context.Commit }
            Elevated      = [bool] (Test-TkIsElevated)
            Outcome       = $(if ($exitCode -ne 0) { 'Failed' } elseif ($result.Partial -gt 0) { 'Partial' } else { 'Done' })
            ExitCode      = $exitCode
            Case          = $result
        }

        $json = ConvertTo-Json -InputObject (ConvertTo-TkPlainData -InputObject $document) -Depth 8
    }

    # Left for the caller, as for the headless actions: exit here would close
    # the console of someone who ran it by hand.
    Set-Variable -Name 'LASTEXITCODE' -Value $exitCode -Scope Global

    if (-not $OutFile) {
        return $json
    }

    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))

    return $path
}
