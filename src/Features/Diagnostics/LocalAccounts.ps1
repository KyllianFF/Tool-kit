<#
    Toolkit - Features / Diagnostics / Local accounts

    The local users and groups on this machine: who can sign in, whose password
    never expires or is not required, and who is a local administrator. Read
    only; nothing is created, changed or removed.
#>

<#
.SYNOPSIS
    Lists the local user accounts, normalised.

.DESCRIPTION
    Reads the local users through Get-LocalUser and reduces each to the fields
    that matter for a review, including whether it is the built-in Administrator
    or Guest (told from the last part of the SID, not the name, which can be
    renamed).

.OUTPUTS
    PSCustomObject[] with Name, Enabled, Description, LastLogon, PasswordLastSet,
    PasswordExpires, PasswordRequired, Sid, IsBuiltinAdministrator and
    IsBuiltinGuest.
#>
function Get-TkLocalUserInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    if (-not (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
        return @()
    }

    try {
        $users = @(Get-LocalUser -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Diagnostics' -Message ('Local users could not be read: {0}' -f $_.Exception.Message)
        return @()
    }

    $result = foreach ($user in $users) {

        $sid = [string] $user.SID.Value

        [pscustomobject] @{
            Name                    = $user.Name
            Enabled                 = [bool] $user.Enabled
            Description             = $user.Description
            LastLogon               = $user.LastLogon
            PasswordLastSet         = $user.PasswordLastSet
            PasswordExpires         = $user.PasswordExpires
            PasswordRequired        = [bool] $user.PasswordRequired
            Sid                     = $sid
            IsBuiltinAdministrator  = $sid -match '-500$'
            IsBuiltinGuest          = $sid -match '-501$'
        }
    }

    return @($result | Sort-Object -Property Name)
}

<#
.SYNOPSIS
    Lists the members of the local Administrators group.

.DESCRIPTION
    Reads the group by its well-known SID (S-1-5-32-544) rather than its name,
    which is localised, so it works on a machine in any language.

.OUTPUTS
    PSCustomObject[] with Name, Sid and ObjectClass.
#>
function Get-TkLocalAdministrator {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    if (-not (Get-Command -Name 'Get-LocalGroupMember' -ErrorAction SilentlyContinue)) {
        return @()
    }

    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Diagnostics' -Message ('The Administrators group could not be read: {0}' -f $_.Exception.Message)
        return @()
    }

    $result = foreach ($member in $members) {
        [pscustomobject] @{
            Name        = $member.Name
            Sid         = [string] $member.SID.Value
            ObjectClass = $member.ObjectClass
        }
    }

    return @($result)
}

<#
.SYNOPSIS
    Lists the local groups and how many members each has.

.OUTPUTS
    PSCustomObject[] with Name, Description and MemberCount.
#>
function Get-TkLocalGroupInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    if (-not (Get-Command -Name 'Get-LocalGroup' -ErrorAction SilentlyContinue)) {
        return @()
    }

    try {
        $groups = @(Get-LocalGroup -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Diagnostics' -Message ('Local groups could not be read: {0}' -f $_.Exception.Message)
        return @()
    }

    $result = foreach ($group in $groups) {

        $count = 0
        try {
            $count = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop).Count
        }
        catch {
            $count = -1
        }

        [pscustomobject] @{
            Name        = $group.Name
            Description = $group.Description
            MemberCount = $count
        }
    }

    return @($result | Where-Object { $_.MemberCount -ne 0 } | Sort-Object -Property @{ Expression = 'MemberCount'; Descending = $true }, Name)
}

<#
.SYNOPSIS
    Judges the local accounts against the usual review points.

.DESCRIPTION
    Turns the inventory into findings a review looks for: the built-in Guest
    enabled, more than a couple of local administrators, an enabled account whose
    password is not required or never expires, and an enabled account that has
    not signed in for a long time. The reference time is a parameter so the stale
    check is testable.

.PARAMETER Users
    The users from Get-TkLocalUserInventory.

.PARAMETER AdminMembers
    The Administrators members from Get-TkLocalAdministrator.

.PARAMETER Now
    The reference time for the stale-account check.

.OUTPUTS
    PSCustomObject[] with Severity, Heading and Note.
#>
function Get-TkLocalAccountFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [pscustomobject[]] $Users,

        [Parameter()]
        [AllowNull()]
        [pscustomobject[]] $AdminMembers,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $findings = New-Object System.Collections.Generic.List[pscustomobject]

    $add = {
        param($severity, $heading, $note)
        $findings.Add([pscustomobject] @{ Severity = $severity; Heading = $heading; Note = $note })
    }

    $enabled = @($Users | Where-Object { $_.Enabled })

    # The built-in Guest.
    $guest = @($Users | Where-Object { $_.IsBuiltinGuest }) | Select-Object -First 1
    if ($guest) {
        if ($guest.Enabled) {
            & $add 'Fail' ('The Guest account "{0}" is enabled' -f $guest.Name) 'The built-in Guest account should stay disabled.'
        }
        else {
            & $add 'Pass' ('The Guest account "{0}" is disabled' -f $guest.Name) ''
        }
    }

    # The built-in Administrator.
    $builtinAdmin = @($Users | Where-Object { $_.IsBuiltinAdministrator }) | Select-Object -First 1
    if ($builtinAdmin -and $builtinAdmin.Enabled) {
        & $add 'Info' ('The built-in Administrator "{0}" is enabled' -f $builtinAdmin.Name) 'Preferably it stays disabled, with named admin accounts used instead.'
    }

    # Local administrators.
    $adminCount = @($AdminMembers).Count
    if ($adminCount -gt 0) {
        $severity = if ($adminCount -gt 3) { 'Warning' } else { 'Info' }
        & $add $severity ('{0} local administrator(s)' -f $adminCount) ((@($AdminMembers | ForEach-Object { $_.Name })) -join ', ')
    }

    # Password not required, on an enabled account.
    foreach ($user in @($enabled | Where-Object { -not $_.PasswordRequired })) {
        & $add 'Warning' ('"{0}" needs no password' -f $user.Name) 'An enabled account with no password required is a weak point.'
    }

    # Password never expires, on an enabled account (informational).
    foreach ($user in @($enabled | Where-Object { $null -eq $_.PasswordExpires -and -not $_.IsBuiltinGuest })) {
        & $add 'Info' ('"{0}" has a password that never expires' -f $user.Name) ''
    }

    # Stale enabled account.
    foreach ($user in @($enabled | Where-Object { $_.LastLogon -and $_.LastLogon -lt $Now.AddDays(-90) })) {
        & $add 'Info' ('"{0}" has not signed in for over 90 days' -f $user.Name) ('Last sign-in {0}.' -f $user.LastLogon.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture))
    }

    return @($findings)
}
