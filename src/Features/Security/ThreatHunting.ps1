<#
    Toolkit - Features / Threat hunting and exposure

    The four questions a security or infrastructure engineer asks about a
    machine that might be compromised, or might simply be exposed:

      1. What do the logs say happened. Failed logons, lockouts, services
         installed, logs cleared.
      2. What runs on its own. Every automatic start point, with the ones
         outside Windows separated from the ones inside it.
      3. What certificates does it hold, and which are about to expire or
         are signed with something nobody should still accept.
      4. What is actually reachable from the network, as opposed to what is
         merely listening.

    All four are read only. Nothing here changes the machine, which is what
    makes them safe to run first, on a system whose state you do not want to
    disturb.
#>

# ---------------------------------------------------------------------------
# 1. Event log triage
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns the security relevant events from the last few days.

.DESCRIPTION
    Reads the Security and System logs for the handful of event identifiers
    that are worth looking at first, and summarises rather than dumps. A raw
    export of ten thousand 4624s tells you nothing; "one account, 340 failed
    logons, from one workstation, overnight" tells you everything.

    Requires elevation: the Security log is not readable otherwise, and that
    is reported rather than silently returning nothing.

.PARAMETER Days
    How far back to look.

.PARAMETER MaxEvents
    Cap on the events read per identifier, so a busy domain controller does
    not take minutes.

.OUTPUTS
    PSCustomObject[] with Category, Count, Detail and Assessment.

.EXAMPLE
    Get-TkSecurityEventSummary -Days 7
#>
function Get-TkSecurityEventSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 90)]
        [int] $Days = 7,

        [Parameter()]
        [ValidateRange(100, 50000)]
        [int] $MaxEvents = 5000
    )

    if (-not (Assert-TkElevated -Operation 'Read the Security event log')) {
        return @()
    }

    $since   = (Get-Date).AddDays(-$Days)
    $results = @()

    $stopwatch = Start-TkOperation -Name ('Event triage over {0} days' -f $Days) -Category 'Hunting'

    # --- Failed logons ----------------------------------------------------
    $failed = Get-TkWinEvent -LogName 'Security' -Id 4625 -Since $since -MaxEvents $MaxEvents

    if ($failed.Count -gt 0) {

        # Grouped by account: a spread across many accounts from one source is
        # password spraying, many attempts on one account is brute force.
        $byAccount = $failed |
            ForEach-Object { $_.Properties[5].Value } |
            Where-Object { $_ } |
            Group-Object |
            Sort-Object -Property Count -Descending |
            Select-Object -First 5

        $detail = ($byAccount | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }) -join ', '

        $assessment = 'Normal background level for a workstation.'

        if ($failed.Count -gt 100 -and $byAccount.Count -eq 1) {
            $assessment = 'Concentrated on one account: consistent with brute force, or with a service running under stale credentials.'
        }
        elseif ($byAccount.Count -ge 4 -and $failed.Count -gt 50) {
            $assessment = 'Spread across several accounts: consistent with password spraying. Check the source addresses.'
        }
        elseif ($failed.Count -gt 500) {
            $assessment = 'Very high volume. Investigate before assuming it is a misconfigured service.'
        }

        $results += New-TkHuntFinding -Category 'Failed logons' -Count $failed.Count `
            -Detail ('Top accounts: {0}' -f $detail) -Assessment $assessment `
            -Severity $(if ($failed.Count -gt 100) { 'Warning' } else { 'Info' })
    }
    else {
        $results += New-TkHuntFinding -Category 'Failed logons' -Count 0 `
            -Detail 'None recorded.' -Assessment 'Nothing to look at.' -Severity 'Pass'
    }

    # --- Account lockouts -------------------------------------------------
    $lockouts = Get-TkWinEvent -LogName 'Security' -Id 4740 -Since $since -MaxEvents 500

    $results += New-TkHuntFinding -Category 'Account lockouts' -Count $lockouts.Count `
        -Detail $(if ($lockouts.Count) {
                     'Accounts: ' + ((@($lockouts | ForEach-Object { $_.Properties[0].Value }) |
                                      Select-Object -Unique) -join ', ')
                 } else { 'None recorded.' }) `
        -Assessment $(if ($lockouts.Count) {
                          'A lockout is either an attack or a stale credential in a mapped drive, a scheduled task or a phone. Find the source before resetting.'
                      } else { 'Nothing to look at.' }) `
        -Severity $(if ($lockouts.Count -gt 0) { 'Warning' } else { 'Pass' })

    # --- Services installed ----------------------------------------------
    # 7045 is one of the highest value events on Windows: most remote
    # execution frameworks install a service to get SYSTEM.
    $services = Get-TkWinEvent -LogName 'System' -Id 7045 -Since $since -MaxEvents 500

    $results += New-TkHuntFinding -Category 'Services installed' -Count $services.Count `
        -Detail $(if ($services.Count) {
                     ((@($services | ForEach-Object { $_.Properties[0].Value }) |
                       Select-Object -Unique -First 8) -join ', ')
                 } else { 'None recorded.' }) `
        -Assessment $(if ($services.Count) {
                          'Every one of these should match something you installed. A service with a random name, or one whose binary sits in a temporary folder, is how remote execution frameworks obtain SYSTEM.'
                      } else { 'Nothing to look at.' }) `
        -Severity $(if ($services.Count -gt 0) { 'Warning' } else { 'Pass' })

    # --- Log cleared ------------------------------------------------------
    $cleared = Get-TkWinEvent -LogName 'Security' -Id 1102 -Since $since -MaxEvents 100

    $results += New-TkHuntFinding -Category 'Security log cleared' -Count $cleared.Count `
        -Detail $(if ($cleared.Count) {
                     'Most recent: ' + ($cleared[0].TimeCreated).ToString('yyyy-MM-dd HH:mm')
                 } else { 'Never, within the window.' }) `
        -Assessment $(if ($cleared.Count) {
                          'The Security log was cleared. There is almost no legitimate reason for this on a workstation, and it is a standard anti forensic step.'
                      } else { 'Nothing to look at.' }) `
        -Severity $(if ($cleared.Count -gt 0) { 'Fail' } else { 'Pass' })

    # --- Remote interactive logons ---------------------------------------
    $remote = Get-TkWinEvent -LogName 'Security' -Id 4624 -Since $since -MaxEvents $MaxEvents |
              Where-Object { $_.Properties[8].Value -eq 10 }

    $remoteAccounts = @($remote | ForEach-Object { $_.Properties[5].Value } | Select-Object -Unique)

    $results += New-TkHuntFinding -Category 'Remote desktop logons' -Count @($remote).Count `
        -Detail $(if ($remoteAccounts.Count) { 'Accounts: ' + ($remoteAccounts -join ', ') }
                  else { 'None recorded.' }) `
        -Assessment $(if ($remoteAccounts.Count) {
                          'Confirm each account is expected to reach this machine over RDP.'
                      } else { 'Nothing to look at.' }) `
        -Severity 'Info'

    # --- Privileged group changes ----------------------------------------
    $groupChanges = @()
    $groupChanges += Get-TkWinEvent -LogName 'Security' -Id 4728 -Since $since -MaxEvents 200
    $groupChanges += Get-TkWinEvent -LogName 'Security' -Id 4732 -Since $since -MaxEvents 200

    $results += New-TkHuntFinding -Category 'Added to a privileged group' -Count $groupChanges.Count `
        -Detail $(if ($groupChanges.Count) { 'Review each one against a change request.' }
                  else { 'None recorded.' }) `
        -Assessment $(if ($groupChanges.Count) {
                          'Group membership changes are how access is escalated and kept. Each should map to a request.'
                      } else { 'Nothing to look at.' }) `
        -Severity $(if ($groupChanges.Count -gt 0) { 'Warning' } else { 'Pass' })

    # --- New local accounts ----------------------------------------------
    $newAccounts = Get-TkWinEvent -LogName 'Security' -Id 4720 -Since $since -MaxEvents 200

    $results += New-TkHuntFinding -Category 'Local accounts created' -Count $newAccounts.Count `
        -Detail $(if ($newAccounts.Count) {
                     ((@($newAccounts | ForEach-Object { $_.Properties[0].Value }) | Select-Object -Unique) -join ', ')
                 } else { 'None recorded.' }) `
        -Assessment $(if ($newAccounts.Count) {
                          'A new local account on a domain joined machine is unusual and is a common persistence step.'
                      } else { 'Nothing to look at.' }) `
        -Severity $(if ($newAccounts.Count -gt 0) { 'Warning' } else { 'Pass' })

    Stop-TkOperation -Name ('Event triage over {0} days' -f $Days) -Stopwatch $stopwatch -Category 'Hunting'

    return $results
}

<#
.SYNOPSIS
    Reads events of one identifier without throwing when there are none.

.DESCRIPTION
    Get-WinEvent treats an empty result as a terminating error, which would
    otherwise abort the whole triage the first time a machine happened to
    have no lockouts.

.OUTPUTS
    System.Diagnostics.Eventing.Reader.EventRecord[]
#>
function Get-TkWinEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $LogName,

        [Parameter(Mandatory)]
        [int] $Id,

        [Parameter(Mandatory)]
        [datetime] $Since,

        [Parameter()]
        [int] $MaxEvents = 1000
    )

    try {
        $filter = @{
            LogName   = $LogName
            Id        = $Id
            StartTime = $Since
        }

        return @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        # "No events were found" is the normal answer, not a failure.
        if ($_.Exception.Message -match 'No events|Aucun') {
            return @()
        }

        Write-TkLog -Level Debug -Category 'Hunting' -Message (
            'Could not read {0} event {1}: {2}' -f $LogName, $Id, $_.Exception.Message
        )

        return @()
    }
}

<#
.SYNOPSIS
    Builds a hunting finding.

.OUTPUTS
    PSCustomObject
#>
function New-TkHuntFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [int]    $Count,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Detail,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Assessment,

        [Parameter()]
        [ValidateSet('Pass', 'Info', 'Warning', 'Fail')]
        [string] $Severity = 'Info'
    )

    return [pscustomobject]@{
        Severity   = $Severity
        Category   = $Category
        Count      = $Count
        Detail     = $Detail
        Assessment = $Assessment
    }
}

# ---------------------------------------------------------------------------
# 2. Persistence
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Lists everything configured to start on its own.

.DESCRIPTION
    Walks the automatic start points that matter: the Run keys for both the
    machine and the user, the start-up folders, scheduled tasks outside the
    Microsoft namespace, services whose binary sits outside the Windows
    directory, and WMI permanent event consumers.

    The output separates what ships with Windows from what does not, because
    the whole skill in reading an autoruns list is ignoring the hundred
    entries that are supposed to be there.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkPersistenceItem {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $results   = @()
    $stopwatch = Start-TkOperation -Name 'Persistence sweep' -Category 'Hunting'

    # --- Run keys ---------------------------------------------------------
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($path in $runKeys) {

        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Ignore

        if (-not $item) {
            continue
        }

        foreach ($property in $item.PSObject.Properties) {

            if ($property.Name -like 'PS*') {
                continue
            }

            $results += New-TkPersistenceEntry -Kind 'Run key' -Name $property.Name `
                -Command ([string] $property.Value) -Location $path
        }
    }

    # --- Start-up folders -------------------------------------------------
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    )

    foreach ($folder in $startupFolders) {

        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) {
            continue
        }

        foreach ($file in (Get-ChildItem -LiteralPath $folder -File -ErrorAction Ignore)) {

            $results += New-TkPersistenceEntry -Kind 'Start-up folder' -Name $file.Name `
                -Command $file.FullName -Location $folder
        }
    }

    # --- Services with a binary outside Windows ---------------------------
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
                    Where-Object { $_.PathName }

        foreach ($service in $services) {

            $binary = ($service.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+).*$', '$1'

            # Everything under the Windows directory is assumed to be part of
            # the platform. That is where the noise is.
            if ($binary -like "$env:SystemRoot\*") {
                continue
            }

            $results += New-TkPersistenceEntry -Kind 'Service' -Name $service.Name `
                -Command $service.PathName -Location ('Start-up: {0}' -f $service.StartMode)
        }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Hunting' -Message (
            'Services could not be enumerated: {0}' -f $_.Exception.Message
        )
    }

    # --- Scheduled tasks outside the Microsoft namespace ------------------
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
                 Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }

        foreach ($task in $tasks) {

            $actions = @($task.Actions | ForEach-Object { $_.Execute }) -join '; '

            if (-not $actions) {
                continue
            }

            $results += New-TkPersistenceEntry -Kind 'Scheduled task' -Name $task.TaskName `
                -Command $actions -Location $task.TaskPath
        }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Hunting' -Message (
            'Scheduled tasks could not be enumerated: {0}' -f $_.Exception.Message
        )
    }

    # --- WMI permanent event subscriptions --------------------------------
    # Rare, and almost never legitimate on a workstation. It is a favourite
    # fileless persistence mechanism precisely because nobody looks here.
    try {
        $consumers = Get-CimInstance -Namespace 'root\subscription' `
                                     -ClassName '__EventConsumer' -ErrorAction Stop

        foreach ($consumer in $consumers) {

            $command = ''

            if ($consumer.PSObject.Properties.Name -contains 'CommandLineTemplate') {
                $command = $consumer.CommandLineTemplate
            }
            elseif ($consumer.PSObject.Properties.Name -contains 'ScriptText') {
                $command = $consumer.ScriptText
            }

            $results += New-TkPersistenceEntry -Kind 'WMI subscription' -Name $consumer.Name `
                -Command $command -Location 'root\subscription'
        }
    }
    catch {
        Write-TkLog -Level Debug -Category 'Hunting' -Message (
            'WMI subscriptions could not be read: {0}' -f $_.Exception.Message
        )
    }

    Stop-TkOperation -Name 'Persistence sweep' -Stopwatch $stopwatch -Category 'Hunting'

    Write-TkLog -Level Information -Category 'Hunting' -Message (
        '{0} automatic start point(s) found, {1} outside the Windows directory.' -f
            $results.Count, @($results | Where-Object { -not $_.InWindows }).Count
    )

    return ($results | Sort-Object -Property InWindows, Kind, Name)
}

<#
.SYNOPSIS
    Builds a persistence entry, classifying and signature checking it.

.DESCRIPTION
    The signature is the fastest triage signal available offline: an unsigned
    binary starting automatically from a user writable folder is worth a look,
    a Microsoft signed one under Program Files almost never is.

.OUTPUTS
    PSCustomObject
#>
function New-TkPersistenceEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Command,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Location
    )

    # Pull the executable out of a command line that may be quoted and may
    # carry arguments.
    $binary = $Command

    if ($binary -match '^"(?<path>[^"]+)"') {
        $binary = $Matches['path']
    }
    elseif ($binary -match '^(?<path>\S+\.(exe|dll|bat|cmd|ps1|vbs|js))') {
        $binary = $Matches['path']
    }

    $binary = [Environment]::ExpandEnvironmentVariables($binary)

    $signer     = ''
    $signature  = 'Not checked'
    $suspicious = @()

    if ($binary -and (Test-Path -LiteralPath $binary -PathType Leaf -ErrorAction Ignore)) {

        $authenticode = Get-TkFileSignature -Path $binary

        $signature = $authenticode.Status
        $signer    = $authenticode.Signer

        if ($authenticode.Status -ne 'Valid') {
            $suspicious += 'unsigned or untrusted'
        }
    }
    elseif ($binary) {
        $signature = 'File not found'
        $suspicious += 'the target does not exist'
    }

    # User writable locations are where an unprivileged foothold puts things.
    $userWritable = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC) |
                    Where-Object { $_ }

    foreach ($folder in $userWritable) {

        if ($binary -like "$folder*") {
            $suspicious += 'runs from a user writable folder'
            break
        }
    }

    if ($Command -match '(?i)-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-expression|iex\s|-w\s+hidden|-windowstyle\s+hidden') {
        $suspicious += 'the command line carries encoding or download markers'
    }

    $inWindows = ($binary -like "$env:SystemRoot\*")

    return [pscustomobject]@{
        Kind       = $Kind
        Name       = $Name
        Command    = $Command
        Location   = $Location
        Signature  = $signature
        Signer     = $signer
        InWindows  = $inWindows
        Concerns   = ($suspicious -join '; ')
        Suspicious = ($suspicious.Count -gt 0 -and -not $inWindows)
    }
}

# ---------------------------------------------------------------------------
# 3. Certificate inventory
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Inventories the certificates installed on this machine.

.DESCRIPTION
    Reads the machine and user personal stores and reports what is expiring,
    what is self signed, and what is signed with an algorithm or key size
    nobody should still accept.

    An expired internal certificate is the most common self inflicted outage
    there is, and it is always discovered by users rather than by monitoring.

.PARAMETER WarningDays
    How far ahead to treat an expiry as urgent.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkCertificateInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int] $WarningDays = 30
    )

    $stores = @(
        'Cert:\LocalMachine\My',
        'Cert:\LocalMachine\WebHosting',
        'Cert:\CurrentUser\My'
    )

    $results = @()

    foreach ($store in $stores) {

        if (-not (Test-Path -LiteralPath $store -ErrorAction Ignore)) {
            continue
        }

        foreach ($certificate in (Get-ChildItem -LiteralPath $store -ErrorAction Ignore)) {

            $daysRemaining = [int] ($certificate.NotAfter - (Get-Date)).TotalDays
            $concerns      = @()

            if ($daysRemaining -lt 0) {
                $concerns += 'expired'
            }
            elseif ($daysRemaining -le $WarningDays) {
                $concerns += 'expires within {0} days' -f $WarningDays
            }

            # SHA-1 signatures are collision vulnerable and rejected by every
            # current browser.
            if ($certificate.SignatureAlgorithm.FriendlyName -match 'sha1') {
                $concerns += 'SHA-1 signature'
            }

            $keySize = 0

            try {
                $keySize = $certificate.PublicKey.Key.KeySize
            }
            catch {
                $null = $_
            }

            if ($keySize -gt 0 -and $keySize -lt 2048 -and
                $certificate.PublicKey.Oid.FriendlyName -match 'RSA') {

                $concerns += 'RSA key below 2048 bits'
            }

            $selfSigned = ($certificate.Subject -eq $certificate.Issuer)

            $severity = 'Pass'

            if ($daysRemaining -lt 0) {
                $severity = 'Fail'
            }
            elseif ($concerns.Count -gt 0) {
                $severity = 'Warning'
            }

            $results += [pscustomobject]@{
                Severity      = $severity
                Store         = $store -replace '^Cert:\\', ''
                Subject       = $certificate.Subject
                Issuer        = $certificate.Issuer
                NotAfter      = $certificate.NotAfter
                DaysRemaining = $daysRemaining
                KeySize       = $keySize
                Algorithm     = $certificate.SignatureAlgorithm.FriendlyName
                SelfSigned    = $selfSigned
                HasPrivateKey = $certificate.HasPrivateKey
                Thumbprint    = $certificate.Thumbprint
                Concerns      = ($concerns -join '; ')
            }
        }
    }

    Write-TkLog -Level Information -Category 'Hunting' -Message (
        '{0} certificate(s) inventoried, {1} needing attention.' -f
            $results.Count, @($results | Where-Object { $_.Severity -ne 'Pass' }).Count
    )

    return ($results | Sort-Object -Property DaysRemaining)
}

<#
.SYNOPSIS
    Checks the certificate expiry of several endpoints at once.

.DESCRIPTION
    The monitoring nobody sets up. Feed it the list of internal services that
    matter and it reports which are about to lapse.

.PARAMETER Endpoint
    Hosts to check, each optionally with a port as host:port.

.OUTPUTS
    PSCustomObject[]

.EXAMPLE
    Test-TkEndpointCertificate -Endpoint 'intranet', 'dc01:636', 'vpn.example.com'
#>
function Test-TkEndpointCertificate {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Endpoint,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int] $WarningDays = 30
    )

    $results = @()

    foreach ($entry in $Endpoint) {

        $trimmed = $entry.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        $hostName = $trimmed
        $port     = 443

        # host:port, but not an IPv6 literal, which is full of colons.
        if ($trimmed -match '^(?<host>[^:\[\]]+):(?<port>\d{1,5})$') {
            $hostName = $Matches['host']
            $port     = [int] $Matches['port']
        }

        $certificate = Get-TkTlsCertificate -ComputerName $hostName -Port $port -TimeoutMilliseconds 6000

        if (-not $certificate.Subject) {

            $results += [pscustomobject]@{
                Severity      = 'Fail'
                Endpoint      = '{0}:{1}' -f $hostName, $port
                Subject       = ''
                NotAfter      = $null
                DaysRemaining = $null
                Protocol      = ''
                Verdict       = $certificate.Verdict
            }

            continue
        }

        $severity = 'Pass'

        if ($certificate.DaysRemaining -lt 0) {
            $severity = 'Fail'
        }
        elseif ($certificate.DaysRemaining -le $WarningDays) {
            $severity = 'Warning'
        }

        $results += [pscustomobject]@{
            Severity      = $severity
            Endpoint      = '{0}:{1}' -f $hostName, $port
            Subject       = $certificate.Subject
            NotAfter      = $certificate.NotAfter
            DaysRemaining = $certificate.DaysRemaining
            Protocol      = $certificate.Protocol
            Verdict       = $certificate.Verdict
        }
    }

    return ($results | Sort-Object -Property DaysRemaining)
}

# ---------------------------------------------------------------------------
# 4. Exposure
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reports what is actually reachable from the network.

.DESCRIPTION
    A listening socket is not the same as an exposed service. This joins the
    listening TCP ports to the enabled inbound allow rules in the firewall,
    and reports the intersection: the ports a packet from the network can
    actually reach.

    That difference is the whole point. A machine can listen on forty ports
    and expose three, and reading either list alone tells you the wrong thing.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkExposureReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $stopwatch = Start-TkOperation -Name 'Exposure analysis' -Category 'Hunting'

    $listening = Get-TkListeningPort

    # --- Firewall rules that let something in ----------------------------
    $allowedPorts   = @{}
    $allowsAnyPort  = $false
    $firewallUsable = $true

    try {
        $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop

        foreach ($rule in $rules) {

            $filter = $rule | Get-NetFirewallPortFilter -ErrorAction Ignore

            foreach ($portSpec in @($filter.LocalPort)) {

                if ($portSpec -eq 'Any') {
                    $allowsAnyPort = $true
                    continue
                }

                # A rule can carry a range or a comma separated list.
                foreach ($part in ($portSpec -split ',')) {

                    if ($part -match '^(?<low>\d+)-(?<high>\d+)$') {

                        for ($p = [int] $Matches['low']; $p -le [int] $Matches['high']; $p++) {
                            $allowedPorts[$p] = $rule.DisplayName
                        }
                    }
                    elseif ($part -match '^\d+$') {
                        $allowedPorts[[int] $part] = $rule.DisplayName
                    }
                }
            }
        }
    }
    catch {
        $firewallUsable = $false

        Write-TkLog -Level Warning -Category 'Hunting' -Message (
            'Firewall rules could not be read ({0}). Exposure cannot be determined, only what is listening.' -f
                $_.Exception.Message
        )
    }

    $results = @()

    foreach ($socket in $listening) {

        # A socket bound to loopback is unreachable from the network whatever
        # the firewall says, and that is the single most useful distinction
        # in this report.
        $loopbackOnly = ($socket.LocalAddress -in @('127.0.0.1', '::1'))

        $exposed = $false
        $reason  = ''

        if ($loopbackOnly) {
            $reason = 'Bound to loopback: not reachable from the network.'
        }
        elseif (-not $firewallUsable) {
            $reason = 'Firewall state unknown.'
        }
        elseif ($allowedPorts.ContainsKey($socket.Port)) {
            $exposed = $true
            $reason  = 'Allowed inbound by: {0}' -f $allowedPorts[$socket.Port]
        }
        elseif ($allowsAnyPort) {
            $exposed = $true
            $reason  = 'A rule allows any port inbound for this program.'
        }
        else {
            $reason = 'Listening, but no inbound allow rule matches this port.'
        }

        $severity = 'Info'

        if ($exposed) {

            $severity = 'Warning'

            # The ports that matter most when they are reachable.
            if ($socket.Port -in @(21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017)) {
                $severity = 'Fail'
            }
        }
        elseif ($loopbackOnly) {
            $severity = 'Pass'
        }

        $results += [pscustomobject]@{
            Severity    = $severity
            Port        = $socket.Port
            Service     = $socket.Service
            Address     = $socket.LocalAddress
            ProcessName = $socket.ProcessName
            Exposed     = $exposed
            Reason      = $reason
        }
    }

    Stop-TkOperation -Name 'Exposure analysis' -Stopwatch $stopwatch -Category 'Hunting'

    $exposedCount = @($results | Where-Object { $_.Exposed }).Count

    Write-TkLog -Level Information -Category 'Hunting' -Message (
        '{0} listening socket(s), {1} reachable from the network.' -f $results.Count, $exposedCount
    )

    return ($results | Sort-Object -Property @{ Expression = 'Exposed'; Descending = $true }, 'Port')
}
