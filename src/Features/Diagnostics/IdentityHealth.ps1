<#
    Toolkit - Features / Sign-in and management

    "I cannot sign in", "Outlook keeps asking for my password", "the policy
    never arrives": the answers are the join state of the device, its single
    sign-on token, the domain controller it can reach, the clock Kerberos
    depends on, and whether an MDM manages it.

    The readers run the tools Windows ships (dsregcmd, w32tm) and read the
    registry and the event logs, all as a standard user. The judgement is kept
    in ConvertTo-TkIdentityHealth, apart from the reading, so every case can be
    tested without a joined machine.

    Nothing here leaves the local network: the clock is only measured against
    the domain controller of a domain member.
#>

<#
.SYNOPSIS
    Reads the name and value pairs of dsregcmd /status.

.DESCRIPTION
    dsregcmd writes its field names in English whatever the display language,
    as "Name : Value" lines under boxed section headings. A name that appears
    in two sections keeps its first value.

.PARAMETER Line
    The output lines.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
function ConvertFrom-TkDsregStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Line
    )

    $values = [ordered] @{}

    foreach ($entry in $Line) {

        $match = [regex]::Match([string] $entry, '^\s*(?<key>[A-Za-z][A-Za-z0-9 \-]*?)\s*:\s*(?<value>.*?)\s*$')

        if ($match.Success -and -not $values.Contains($match.Groups['key'].Value)) {
            $values[$match.Groups['key'].Value] = $match.Groups['value'].Value
        }
    }

    return $values
}

<#
.SYNOPSIS
    Says whether a dsregcmd field reads YES.
#>
function Test-TkDsregYes {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        $Status,

        [Parameter(Mandatory)]
        [string] $Key
    )

    if ($null -eq $Status -or -not $Status.Contains($Key)) {
        return $false
    }

    return ([string] $Status[$Key] -match '^YES\b')
}

<#
.SYNOPSIS
    Names the join state of the device.

.DESCRIPTION
    From the combinations Microsoft documents for dsregcmd. Microsoft Entra
    registered is a property of the signed-in user rather than of the device,
    and is named only when the device has no join of its own.

.PARAMETER Status
    Output of ConvertFrom-TkDsregStatus.

.OUTPUTS
    System.String
#>
function Get-TkJoinType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        $Status
    )

    $entra      = Test-TkDsregYes -Status $Status -Key 'AzureAdJoined'
    $domain     = Test-TkDsregYes -Status $Status -Key 'DomainJoined'
    $enterprise = Test-TkDsregYes -Status $Status -Key 'EnterpriseJoined'

    if ($entra -and $domain)      { return 'Microsoft Entra hybrid joined' }
    if ($entra)                   { return 'Microsoft Entra joined' }
    if ($enterprise -and $domain) { return 'On-premises DRS joined' }
    if ($domain)                  { return 'Domain joined' }

    if (Test-TkDsregYes -Status $Status -Key 'WorkplaceJoined') {
        return 'Microsoft Entra registered'
    }

    return 'Not joined'
}

<#
.SYNOPSIS
    Reads a dsregcmd time, which is written in UTC.

.PARAMETER Text
    For example 2019-01-24 19:15:33.000 UTC.

.OUTPUTS
    System.DateTime in UTC, or $null.
#>
function ConvertFrom-TkDsregTime {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Text
    )

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal

    if ([datetime]::TryParseExact(($Text -replace '\s*UTC\s*$', ''), 'yyyy-MM-dd HH:mm:ss.fff',
                                  [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref] $parsed)) {
        return $parsed
    }

    return $null
}

<#
.SYNOPSIS
    Reads the clock offset from w32tm /stripchart output.

.DESCRIPTION
    The data line is "19:42:54, -05.6530458s". The separator of the decimals
    follows the display language on some systems, so a comma is accepted too.

.PARAMETER Line
    The output lines.

.OUTPUTS
    System.Double, the offset in seconds, or $null.
#>
function ConvertFrom-TkStripchartOffset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Line
    )

    foreach ($entry in @($Line)[-1..-(@($Line).Count)]) {

        $match = [regex]::Match([string] $entry, ',\s*(?<offset>[+-]?\d+(?:[.,]\d+)?)s\s*$')

        if ($match.Success) {
            return [double]::Parse(($match.Groups['offset'].Value -replace ',', '.'),
                                   [System.Globalization.CultureInfo]::InvariantCulture)
        }
    }

    return $null
}

<#
.SYNOPSIS
    Runs dsregcmd /status.

.OUTPUTS
    OrderedDictionary, or $null when the tool is missing or fails.
#>
function Get-TkDsregStatus {
    [CmdletBinding()]
    param()

    $tool = Join-Path -Path $env:SystemRoot -ChildPath 'System32\dsregcmd.exe'

    if (-not (Test-Path -LiteralPath $tool)) {
        return $null
    }

    try {
        $output = @(& $tool '/status' 2>&1 | ForEach-Object { [string] $_ })
        return (ConvertFrom-TkDsregStatus -Line $output)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Identity' -Message ('dsregcmd could not run: {0}' -f $_.Exception.Message)
        return $null
    }
}

<#
.SYNOPSIS
    Lists the MDM enrollments of the device, Intune among them.

.DESCRIPTION
    Each enrollment is a key under HKLM\SOFTWARE\Microsoft\Enrollments, which
    a standard user can read. Only the ones served by an MDM server count:
    Windows keeps other kinds of enrollment in the same place.

.OUTPUTS
    PSCustomObject[] with Upn, State and DiscoveryUrl.
#>
function Get-TkMdmEnrollment {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'

    if (-not (Test-Path -LiteralPath $root)) {
        return @()
    }

    $rows = foreach ($key in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {

        $values = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue

        if ([string] $values.ProviderID -eq 'MS DM Server') {

            [pscustomobject] @{
                Upn          = [string] $values.UPN
                State        = $values.EnrollmentState
                DiscoveryUrl = [string] $values.DiscoveryServiceFullURL
            }
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Counts the errors the MDM client logged recently.

.PARAMETER Days
    How far back to look.

.OUTPUTS
    PSCustomObject with Count, LastId and LastWhen.
#>
function Get-TkMdmSyncError {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 90)]
        [int] $Days = 7
    )

    $events = @()

    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
            Level     = 2
            StartTime = (Get-Date).AddDays(-$Days)
        } -MaxEvents 200 -ErrorAction Stop)
    }
    catch {
        $events = @()
    }

    $last = $events | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1

    return [pscustomobject] @{
        Count    = $events.Count
        LastId   = $(if ($last) { $last.Id } else { 0 })
        LastWhen = $(if ($last) { $last.TimeCreated } else { $null })
    }
}

<#
.SYNOPSIS
    Finds a domain controller for the domain of this computer.

.DESCRIPTION
    Through the directory API rather than nltest, whose messages are written
    in the display language.

.OUTPUTS
    PSCustomObject with Domain, Name, Site, Reachable and Error.
#>
function Get-TkDomainController {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue

        $domain     = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $controller = $domain.FindDomainController()

        return [pscustomobject] @{
            Domain    = $domain.Name
            Name      = $controller.Name
            Site      = $controller.SiteName
            Reachable = $true
            Error     = ''
        }
    }
    catch {
        $inner = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }

        return [pscustomobject] @{
            Domain    = ''
            Name      = ''
            Site      = ''
            Reachable = $false
            Error     = $inner
        }
    }
}

<#
.SYNOPSIS
    Says whether the domain publishes Microsoft Entra hybrid join settings.

.DESCRIPTION
    A device finds its tenant either in the registry, for a targeted rollout,
    or in the service connection point of the configuration partition, which
    any domain user can read. Without either, hybrid join is simply not in
    use and its failed discovery in dsregcmd is expected.

.OUTPUTS
    $true when the settings exist, $false when the domain has none, $null
    when the directory could not be read.
#>
function Get-TkHybridJoinConfiguration {
    [CmdletBinding()]
    param()

    if (Get-TkRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD' -Name 'TenantId') {
        return $true
    }

    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue

        $root          = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $configuration = [string] $root.Properties['configurationNamingContext'].Value

        if (-not $configuration) {
            return $null
        }

        # The fixed name Microsoft gives the device registration service
        # connection point.
        $path = 'LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,{0}' -f $configuration

        return [System.DirectoryServices.DirectoryEntry]::Exists($path)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Identity' -Message ('Hybrid join settings could not be read: {0}' -f $_.Exception.Message)
        return $null
    }
}

<#
.SYNOPSIS
    Measures the clock of this computer against another one.

.PARAMETER Computer
    A host name. Anything else is refused, since it reaches a command line.

.OUTPUTS
    System.Double, the offset in seconds, or $null.
#>
function Get-TkClockOffset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Computer
    )

    if ($Computer -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$') {
        return $null
    }

    try {
        $output = @(& w32tm.exe '/stripchart' ('/computer:{0}' -f $Computer) '/samples:1' '/dataonly' 2>&1 |
                    ForEach-Object { [string] $_ })

        return (ConvertFrom-TkStripchartOffset -Line $output)
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Builds one row of the sign-in and management report.
#>
function New-TkIdentityRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Severity,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $Value,
        [Parameter()] [AllowEmptyString()] [string] $Detail = '',
        [Parameter()] [AllowEmptyString()] [string] $RemediationId = ''
    )

    return [pscustomobject] @{
        Severity      = $Severity
        Kind          = $Kind
        Value         = $Value
        Detail        = $Detail
        RemediationId = $RemediationId
    }
}

<#
.SYNOPSIS
    Judges the readings of sign-in and management.

.PARAMETER Status
    Output of ConvertFrom-TkDsregStatus, or $null when dsregcmd could not run.

.PARAMETER DomainJoined
    Whether Windows reports the computer as part of a domain.

.PARAMETER Domain
    Output of Get-TkDomainController, for a domain member.

.PARAMETER SecureChannel
    $true, $false, or $null when it could not be tested.

.PARAMETER TimeService
    Object with Status, StartType and Server.

.PARAMETER ClockOffset
    Seconds against the domain controller, or $null.

.PARAMETER Enrollment
    Output of Get-TkMdmEnrollment.

.PARAMETER MdmErrors
    Output of Get-TkMdmSyncError.

.PARAMETER HybridConfigured
    Output of Get-TkHybridJoinConfiguration: $true when the domain publishes
    Microsoft Entra hybrid join settings, $false when it does not, $null when
    that could not be read.

.PARAMETER Now
    The current time in UTC, a parameter so tests do not depend on the clock.

.OUTPUTS
    PSCustomObject[] with Severity, Kind, Value, Detail and RemediationId.
#>
function ConvertTo-TkIdentityHealth {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] $Status,
        [Parameter()] [bool] $DomainJoined = $false,
        [Parameter()] $Domain,
        [Parameter()] $SecureChannel,
        [Parameter()] $TimeService,
        [Parameter()] $ClockOffset,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Enrollment = @(),
        [Parameter()] $MdmErrors,
        [Parameter()] $HybridConfigured,
        [Parameter()] [datetime] $Now = [datetime]::UtcNow
    )

    $rows     = @()
    $joinType = Get-TkJoinType -Status $Status
    $entra    = Test-TkDsregYes -Status $Status -Key 'AzureAdJoined'
    $field    = { param($key) if ($Status -and $Status.Contains($key)) { [string] $Status[$key] } else { '' } }

    # --- Join state -------------------------------------------------------
    if ($null -eq $Status) {
        $rows += New-TkIdentityRow -Severity 'Info' -Kind 'Join' -Value $(if ($DomainJoined) { 'Domain joined' } else { 'Not joined' }) `
                                   -Detail 'dsregcmd could not be read, so the Microsoft Entra state is unknown.'
    }
    else {
        $where = @((& $field 'TenantName'), (& $field 'DomainName')) | Where-Object { $_ }

        $rows += New-TkIdentityRow -Severity 'Info' -Kind 'Join' -Value $joinType `
                                   -Detail $(if ($where) { 'Tenant or domain: {0}.' -f ($where -join ', ') } else { 'Signed in with local or personal accounts only.' })
    }

    # --- Microsoft Entra device and single sign-on --------------------------
    if ($entra) {

        $authStatus = & $field 'DeviceAuthStatus'

        if ($authStatus -match '^SUCCESS') {
            $rows += New-TkIdentityRow -Severity 'Pass' -Kind 'Entra device' -Value 'Present and enabled' `
                                       -Detail 'Microsoft Entra ID recognises this device.'
        }
        elseif ($authStatus -match 'disabled or deleted') {
            $rows += New-TkIdentityRow -Severity 'Fail' -Kind 'Entra device' -Value 'Disabled or deleted' `
                                       -Detail 'The device object is disabled or deleted in Microsoft Entra ID. Work accounts cannot sign in until an administrator enables it again or the device joins again.'
        }
        elseif ($authStatus) {
            $rows += New-TkIdentityRow -Severity 'Warning' -Kind 'Entra device' -Value 'Not verified' `
                                       -Detail 'Microsoft Entra ID could not be reached to check the device. The check needs the network under the system account.'
        }

        if (Test-TkDsregYes -Status $Status -Key 'AzureAdPrt') {

            $updated = ConvertFrom-TkDsregTime -Text (& $field 'AzureAdPrtUpdateTime')
            $hours   = if ($updated) { [math]::Round(($Now - $updated).TotalHours, 1) } else { $null }

            if ($null -ne $hours -and $hours -gt 24) {
                $rows += New-TkIdentityRow -Severity 'Warning' -Kind 'Single sign-on' -Value ('Token not renewed for {0} hours' -f [math]::Round($hours)) `
                                           -Detail 'The primary refresh token renews about every four hours while the user is signed in and online. A token this old points at a network, proxy or conditional access problem.'
            }
            else {
                $rows += New-TkIdentityRow -Severity 'Pass' -Kind 'Single sign-on' -Value 'Primary refresh token present' `
                                           -Detail $(if ($null -ne $hours) { 'Renewed {0} hours ago.' -f $hours } else { 'Present for the signed-in user.' })
            }
        }
        else {
            $reason = @((& $field 'Attempt Status'), (& $field 'Server Error Description')) | Where-Object { $_ }

            $rows += New-TkIdentityRow -Severity 'Fail' -Kind 'Single sign-on' -Value 'No primary refresh token' `
                                       -Detail ('Microsoft 365 and other work apps will keep asking for the password. Sign out and in again with the work account; if it persists, the last attempt says why.{0}' -f
                                                $(if ($reason) { ' Last attempt: {0}.' -f ($reason -join ' - ') } else { '' })) `
                                       -RemediationId 'open-work-access'
        }

        $rows += New-TkIdentityRow -Severity $(if (Test-TkDsregYes -Status $Status -Key 'NgcSet') { 'Pass' } else { 'Info' }) `
                                   -Kind 'Windows Hello' `
                                   -Value $(if (Test-TkDsregYes -Status $Status -Key 'NgcSet') { 'Set up' } else { 'Not set up' }) `
                                   -Detail 'Windows Hello for Business replaces the password at sign-in for this user.'
    }

    # --- Hybrid join failing ------------------------------------------------
    # Every domain member runs the automatic device join task, so dsregcmd
    # records a failed discovery on a domain that never set up Microsoft
    # Entra hybrid join. That is the normal state of an on-premises domain,
    # not a fault: no work or school account is expected there. Only a domain
    # that publishes the join settings, or a failure past discovery, is
    # worth a warning.
    if ($DomainJoined -and -not $entra -and (& $field 'Error Phase')) {

        $phase = & $field 'Error Phase'
        $code  = & $field 'Client ErrorCode'

        $notSetUp = $HybridConfigured -ne $true -and (
                        $HybridConfigured -eq $false -or
                        $code -match '0x801c001d' -or
                        (& $field 'AD Configuration Test') -match '^FAIL' -or
                        ($phase -match '^discover' -and -not (& $field 'TenantName') -and -not (& $field 'TenantId'))
                    )

        if ($notSetUp) {
            $rows += New-TkIdentityRow -Severity 'Info' -Kind 'Hybrid join' -Value 'Not set up for this domain' `
                                       -Detail ('Windows looked for Microsoft Entra hybrid join settings in the domain and found none{0}. That is expected for a domain that does not use Microsoft Entra ID: nothing to fix, and no work or school account is needed.' -f
                                                $(if ($code) { ' (client error {0})' -f $code } else { '' }))
        }
        else {
            $rows += New-TkIdentityRow -Severity 'Warning' -Kind 'Hybrid join' -Value ('Failing at the {0} phase' -f $phase) `
                                       -Detail ('The domain is set up for Microsoft Entra hybrid join, but this device did not join. Client error {0}. {1} Microsoft lists the codes at https://aka.ms/aadjerrors.' -f
                                                $code, (& $field 'Server Message')).Trim()
        }
    }

    # --- Domain -------------------------------------------------------------
    if ($DomainJoined) {

        if ($Domain -and $Domain.Reachable) {
            $rows += New-TkIdentityRow -Severity 'Pass' -Kind 'Domain controller' -Value $Domain.Name `
                                       -Detail ('Domain {0}, site {1}.' -f $Domain.Domain, $Domain.Site)
        }
        else {
            $rows += New-TkIdentityRow -Severity 'Fail' -Kind 'Domain controller' -Value 'None reachable' `
                                       -Detail ('No domain controller answered, so sign-in uses cached credentials and group policy does not apply. Check the VPN, the network, and that DNS points at the domain DNS servers.{0}' -f
                                                $(if ($Domain.Error) { ' ' + $Domain.Error } else { '' }))
        }

        $rows += New-TkIdentityRow -Kind 'Secure channel' `
                                   -Severity $(if ($SecureChannel -eq $false) { 'Fail' } elseif ($null -eq $SecureChannel) { 'Info' } else { 'Pass' }) `
                                   -Value $(if ($null -eq $SecureChannel) { 'Not tested' } elseif ($SecureChannel) { 'Healthy' } else { 'Broken' }) `
                                   -Detail $(if ($SecureChannel -eq $false) {
                                                 'The computer password no longer matches the directory, so domain sign-in fails. Repair it from an elevated console with Test-ComputerSecureChannel -Repair.'
                                             }
                                             elseif ($null -eq $SecureChannel) { 'Testing it needs Windows PowerShell and a reachable domain controller.' }
                                             else { 'The computer account and the directory agree.' })
    }

    # --- Time ---------------------------------------------------------------
    if ($TimeService) {

        if ($DomainJoined) {

            $offset = if ($null -ne $ClockOffset) { [math]::Abs([double] $ClockOffset) } else { $null }

            $severity = if ($null -ne $offset -and $offset -gt 300) { 'Fail' }
                        elseif (($null -ne $offset -and $offset -gt 60) -or [string] $TimeService.Status -ne 'Running') { 'Warning' }
                        else { 'Pass' }

            $rows += New-TkIdentityRow -Severity $severity -Kind 'Clock' `
                                       -Value $(if ($null -ne $ClockOffset) { '{0:+0.00;-0.00} s from the domain controller' -f [double] $ClockOffset } else { 'Offset not measured' }) `
                                       -Detail ('Time service {0}. Kerberos refuses sign-in when the clock is more than five minutes out.' -f ([string] $TimeService.Status).ToLowerInvariant()) `
                                       -RemediationId $(if ($severity -ne 'Pass') { 'open-date-time' } else { '' })
        }
        else {
            $rows += New-TkIdentityRow -Severity 'Info' -Kind 'Clock' -Value ('Time service {0}' -f ([string] $TimeService.Status).ToLowerInvariant()) `
                                       -Detail ('Source: {0}. Outside a domain, Windows starts the service when it needs to synchronise.' -f $(if ($TimeService.Server) { $TimeService.Server } else { 'not set' }))
        }
    }

    # --- Device management --------------------------------------------------
    $enrolled = @($Enrollment | Where-Object { $_ })

    if ($enrolled.Count -gt 0) {

        $upn = @($enrolled | ForEach-Object { $_.Upn } | Where-Object { $_ }) | Select-Object -First 1

        $rows += New-TkIdentityRow -Severity 'Pass' -Kind 'Device management' -Value 'Enrolled in an MDM' `
                                   -Detail $(if ($upn) { 'Enrolled by {0}.' -f $upn } else { 'Enrolled by the device.' })

        if ($MdmErrors -and $MdmErrors.Count -gt 0) {
            $rows += New-TkIdentityRow -Severity 'Warning' -Kind 'Device management' -Value ('{0} MDM error(s) in 7 days' -f $MdmErrors.Count) `
                                       -Detail ('Last: event {0}. The MDM client log is under Applications and Services Logs, DeviceManagement-Enterprise-Diagnostics-Provider, Admin. Sync again from Access work or school.' -f $MdmErrors.LastId) `
                                       -RemediationId 'open-work-access'
        }
    }
    elseif ($entra -and (& $field 'MdmUrl')) {
        $rows += New-TkIdentityRow -Severity 'Warning' -Kind 'Device management' -Value 'Not enrolled' `
                                   -Detail 'The tenant enrolls devices automatically, but this one is not enrolled. The user may be out of the MDM scope, or enrollment failed.' `
                                   -RemediationId 'open-work-access'
    }
    else {
        $rows += New-TkIdentityRow -Severity 'Info' -Kind 'Device management' -Value 'Not enrolled' `
                                   -Detail 'No MDM, such as Intune, manages this device.'
    }

    return $rows
}

<#
.SYNOPSIS
    Reads and judges sign-in and management.

.OUTPUTS
    PSCustomObject[], as built by ConvertTo-TkIdentityHealth.
#>
function Get-TkIdentityHealth {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $status       = Get-TkDsregStatus
    $computer     = Get-TkCimInstanceSafe -ClassName 'Win32_ComputerSystem'
    $domainJoined = [bool] $computer.PartOfDomain

    $domain  = $null
    $channel = $null
    $offset  = $null
    $hybrid  = $null

    if ($domainJoined) {

        $domain = Get-TkDomainController

        try {
            $channel = Test-ComputerSecureChannel -ErrorAction Stop
        }
        catch {
            $channel = $null
        }

        if ($domain.Reachable) {
            $offset = Get-TkClockOffset -Computer $domain.Name
            $hybrid = Get-TkHybridJoinConfiguration
        }
    }

    $service    = Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue
    $parameters = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue

    $time = [pscustomobject] @{
        Status    = $(if ($service) { [string] $service.Status } else { 'missing' })
        StartType = $(if ($service) { [string] $service.StartType } else { '' })
        Server    = [string] $parameters.NtpServer
    }

    return @(ConvertTo-TkIdentityHealth -Status $status -DomainJoined $domainJoined -Domain $domain `
                                        -SecureChannel $channel -TimeService $time -ClockOffset $offset `
                                        -Enrollment @(Get-TkMdmEnrollment) -MdmErrors (Get-TkMdmSyncError -Days 7) `
                                        -HybridConfigured $hybrid)
}
