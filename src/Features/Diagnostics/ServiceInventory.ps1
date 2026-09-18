<#
    Toolkit - Features / Diagnostics / Services

    An operational view of the Windows services: how each one starts, the
    account it runs as, and whether the ones set to start automatically actually
    did. Read only.

    This is the operational counterpart to the persistence hunt on the threat
    hunting page: that one looks for a service that should not be there, this one
    answers "is the service that should be running actually running, and as
    whom".
#>

<#
.SYNOPSIS
    Reduces a Win32_Service instance to the fields an operator reads.

.DESCRIPTION
    Normalises the start mode and the log-on account, and marks a service that
    runs as a named account (anything other than the three built-in service
    accounts), since those depend on a password that can expire.

.PARAMETER Service
    A Win32_Service instance, or an object with the same properties.

.OUTPUTS
    PSCustomObject with Name, DisplayName, State, StartMode, DelayedAutoStart,
    Account, Path, Running and NamedAccount.
#>
function ConvertFrom-TkServiceCim {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $Service
    )

    $account = [string] $Service.StartName

    # The three built-in service identities; anything else is a named account.
    $builtin = @('LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService', 'NT AUTHORITY\System', '')

    return [pscustomobject] @{
        Name             = [string] $Service.Name
        DisplayName      = [string] $Service.DisplayName
        State            = [string] $Service.State
        StartMode        = [string] $Service.StartMode
        DelayedAutoStart = [bool]   $Service.DelayedAutoStart
        Account          = $account
        Path             = [string] $Service.PathName
        Running          = ([string] $Service.State -eq 'Running')
        NamedAccount     = ($account -notin $builtin)
    }
}

<#
.SYNOPSIS
    Lists the Windows services, normalised.

.OUTPUTS
    PSCustomObject[] as ConvertFrom-TkServiceCim returns, by display name.
#>
function Get-TkServiceInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $services = @(Get-TkCimInstanceSafe -ClassName 'Win32_Service' -All)

    $result = foreach ($service in $services) {
        ConvertFrom-TkServiceCim -Service $service
    }

    return @($result | Sort-Object -Property DisplayName)
}

<#
.SYNOPSIS
    Judges the services the way an operator would.

.DESCRIPTION
    Flags a service set to start automatically that is not running, which is the
    operational problem worth seeing; and notes the services that run as a named
    account, whose password can expire. A delayed auto-start service that is
    stopped is left as information, since it may simply not have started yet.

.PARAMETER Services
    The services from Get-TkServiceInventory.

.OUTPUTS
    PSCustomObject[] with Severity, Heading and Note.
#>
function Get-TkServiceFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [pscustomobject[]] $Services
    )

    $findings = New-Object System.Collections.Generic.List[pscustomobject]
    $add = { param($s, $h, $n) $findings.Add([pscustomobject] @{ Severity = $s; Heading = $h; Note = $n }) }

    $autoStopped = @($Services | Where-Object { $_.StartMode -eq 'Auto' -and -not $_.Running })
    foreach ($service in @($autoStopped | Where-Object { -not $_.DelayedAutoStart })) {
        & $add 'Warning' ('"{0}" is set to start automatically but is stopped' -f $service.DisplayName) $service.Name
    }
    foreach ($service in @($autoStopped | Where-Object { $_.DelayedAutoStart })) {
        & $add 'Info' ('"{0}" (delayed auto-start) is stopped' -f $service.DisplayName) 'A delayed-start service may simply not have started yet.'
    }

    $named = @($Services | Where-Object { $_.NamedAccount })
    if ($named.Count -gt 0) {
        & $add 'Info' ('{0} service(s) run as a named account' -f $named.Count) 'Their password can expire; note them before a password change.'
    }

    if ($findings.Count -eq 0) {
        & $add 'Pass' 'Every automatic service is running' ''
    }

    return @($findings)
}
