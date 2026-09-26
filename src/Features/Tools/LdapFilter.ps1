<#
    Toolkit - Features / LDAP filter builder

    The Active Directory search filter, built rather than remembered. Pick the
    kind of object, write the conditions one per line as "attribute operator
    value", and choose whether all or any of them must hold; the tool composes
    the RFC 4515 filter, escaping the values, and writes the Get-ADObject and
    dsquery commands that use it.

    Common jobs come as presets that drop a ready condition in: the disabled
    accounts, the passwords that never expire, the members of a group, the ones
    that never signed in. The matching-rule OIDs those need are filled in, so a
    bit test on userAccountControl does not have to be typed by hand.
#>

<#
.SYNOPSIS
    The object kinds the builder scopes a search to.

.DESCRIPTION
    Parts are the objectCategory and objectClass clauses that pin a search to
    that kind. Cmdlet is the Active Directory cmdlet that fits it best.

.OUTPUTS
    PSCustomObject[] with Name, Parts and Cmdlet.
#>
function Get-TkLdapObjectClass {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'Any';                 Parts = @();                                                   Cmdlet = 'Get-ADObject' }
        [pscustomobject] @{ Name = 'Users';               Parts = @('(objectCategory=person)', '(objectClass=user)');    Cmdlet = 'Get-ADUser' }
        [pscustomobject] @{ Name = 'Groups';              Parts = @('(objectCategory=group)');                           Cmdlet = 'Get-ADGroup' }
        [pscustomobject] @{ Name = 'Computers';           Parts = @('(objectCategory=computer)');                        Cmdlet = 'Get-ADComputer' }
        [pscustomobject] @{ Name = 'Contacts';            Parts = @('(objectCategory=contact)');                         Cmdlet = 'Get-ADObject' }
        [pscustomobject] @{ Name = 'Organizational units'; Parts = @('(objectCategory=organizationalUnit)');             Cmdlet = 'Get-ADOrganizationalUnit' }
        [pscustomobject] @{ Name = 'Printers';            Parts = @('(objectCategory=printQueue)');                      Cmdlet = 'Get-ADObject' }
    )
}

<#
.SYNOPSIS
    Ready conditions for the jobs that come up often.

.DESCRIPTION
    Each preset is a raw filter clause dropped straight into the conditions.
    The ones that test a bit of userAccountControl carry the matching-rule OID
    (1.2.840.113556.1.4.803) that AD needs; a couple carry a DN to edit.

.OUTPUTS
    PSCustomObject[] with Name and Clause.
#>
function Get-TkLdapPreset {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'Enabled accounts';           Clause = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' }
        [pscustomobject] @{ Name = 'Disabled accounts';          Clause = '(userAccountControl:1.2.840.113556.1.4.803:=2)' }
        [pscustomobject] @{ Name = 'Password never expires';     Clause = '(userAccountControl:1.2.840.113556.1.4.803:=65536)' }
        [pscustomobject] @{ Name = 'Password not required';      Clause = '(userAccountControl:1.2.840.113556.1.4.803:=32)' }
        [pscustomobject] @{ Name = 'Smartcard required';         Clause = '(userAccountControl:1.2.840.113556.1.4.803:=262144)' }
        [pscustomobject] @{ Name = 'Trusted for delegation';     Clause = '(userAccountControl:1.2.840.113556.1.4.803:=524288)' }
        [pscustomobject] @{ Name = 'Kerberos DES only';          Clause = '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' }
        [pscustomobject] @{ Name = 'Account locked out';         Clause = '(lockoutTime>=1)' }
        [pscustomobject] @{ Name = 'Must change password';       Clause = '(pwdLastSet=0)' }
        [pscustomobject] @{ Name = 'Never signed in';            Clause = '(!(lastLogonTimestamp=*))' }
        [pscustomobject] @{ Name = 'Has an e-mail';              Clause = '(mail=*)' }
        [pscustomobject] @{ Name = 'Member of a group (edit DN)'; Clause = '(memberOf=CN=Group,OU=Groups,DC=example,DC=com)' }
        [pscustomobject] @{ Name = 'Member of a group, nested (edit DN)'; Clause = '(memberOf:1.2.840.113556.1.4.1941:=CN=Group,OU=Groups,DC=example,DC=com)' }
    )
}

<#
.SYNOPSIS
    Escapes an LDAP filter value, keeping * so wildcards still work.

.OUTPUTS
    System.String
#>
function Protect-TkLdapValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    # The backslash first, so the ones added next are not escaped again.
    $escaped = $Value -replace '\\', '\5c'
    $escaped = $escaped -replace '\(', '\28'
    $escaped = $escaped -replace '\)', '\29'
    $escaped = $escaped -replace "`0", '\00'

    return $escaped
}

<#
.SYNOPSIS
    Turns one "attribute operator value" line into an LDAP clause.

.DESCRIPTION
    Operators: = (equals or, with *, a wildcard or presence), != (not equal),
    <= and >= (ordering, as AD reads them), ~= (approximate). A line already
    written as a raw clause, starting with "(", is passed through untouched. A
    blank line, or one starting with #, is ignored.

.OUTPUTS
    System.String, or $null when the line is blank, a comment or unparseable.
#>
function ConvertTo-TkLdapCondition {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Line
    )

    $text = $Line.Trim()

    if ($text.Length -eq 0 -or $text.StartsWith('#')) {
        return $null
    }

    # An advanced user can paste a whole clause; take it as written.
    if ($text.StartsWith('(')) {
        return $text
    }

    if ($text -notmatch '^(?<attr>[A-Za-z0-9.;-]+)\s*(?<op>!=|<=|>=|~=|=)\s*(?<val>.*)$') {
        return $null
    }

    $attr = $Matches['attr']
    $op   = $Matches['op']
    $val  = $Matches['val'].Trim()

    switch ($op) {
        '='  { if ($val -eq '*') { '({0}=*)' -f $attr } else { '({0}={1})' -f $attr, (Protect-TkLdapValue -Value $val) } }
        '!=' { '(!({0}={1}))' -f $attr, (Protect-TkLdapValue -Value $val) }
        '<=' { '({0}<={1})' -f $attr, (Protect-TkLdapValue -Value $val) }
        '>=' { '({0}>={1})' -f $attr, (Protect-TkLdapValue -Value $val) }
        '~=' { '({0}~={1})' -f $attr, (Protect-TkLdapValue -Value $val) }
    }
}

<#
.SYNOPSIS
    Composes the full LDAP filter from its parsed parts.

.PARAMETER Conditions
    The clauses already parsed from the conditions text.

.PARAMETER Match
    All (every condition must hold, AND) or Any (at least one, OR).

.PARAMETER ObjectParts
    The objectCategory and objectClass clauses that scope the kind.

.PARAMETER Negate
    Wrap the whole filter in (!...).

.OUTPUTS
    System.String
#>
function Build-TkLdapFilter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Conditions = @(),

        [Parameter()]
        [ValidateSet('All', 'Any')]
        [string] $Match = 'All',

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ObjectParts = @(),

        [Parameter()]
        [switch] $Negate
    )

    $conds  = @($Conditions | Where-Object { $_ })
    $object = @($ObjectParts | Where-Object { $_ })

    if ($conds.Count -eq 0 -and $object.Count -eq 0) {
        return '(objectClass=*)'
    }

    if ($Match -eq 'All') {

        # Everything is ANDed, so the object clauses and the conditions flatten
        # into one group rather than a group inside a group.
        $all    = @($object) + @($conds)
        $joined = -join $all
        $body   = if ($all.Count -gt 1) { '(&{0})' -f $joined } else { $joined }
    }
    else {

        $group = if ($conds.Count -gt 1) { '(|{0})' -f (-join $conds) } elseif ($conds.Count -eq 1) { $conds[0] } else { '' }
        $all   = @($object) + @($group | Where-Object { $_ })
        $body  = if ($all.Count -gt 1) { '(&{0})' -f (-join $all) } elseif ($all.Count -eq 1) { $all[0] } else { '(objectClass=*)' }
    }

    if ($Negate) {
        $body = '(!{0})' -f $body
    }

    return $body
}

<#
.SYNOPSIS
    Builds the filter and the commands that run it.

.PARAMETER Conditions
    The conditions text, one per line.

.PARAMETER ObjectClass
    A name from Get-TkLdapObjectClass.

.PARAMETER Match
    All or Any.

.PARAMETER Negate
    Wrap the whole filter in (!...).

.OUTPUTS
    System.String[]
#>
function Format-TkLdapReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Conditions,

        [Parameter()]
        [string] $ObjectClass = 'Any',

        [Parameter()]
        [ValidateSet('All', 'Any')]
        [string] $Match = 'All',

        [Parameter()]
        [switch] $Negate
    )

    $object = @(Get-TkLdapObjectClass) | Where-Object { $_.Name -eq $ObjectClass } | Select-Object -First 1

    if (-not $object) {
        $object = @(Get-TkLdapObjectClass)[0]
    }

    $clauses = New-Object System.Collections.Generic.List[string]
    $invalid = New-Object System.Collections.Generic.List[string]
    $number  = 0

    foreach ($line in ($Conditions -split '\r?\n')) {

        $number++
        $trimmed = $line.Trim()

        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
            continue
        }

        $clause = ConvertTo-TkLdapCondition -Line $line

        if ($clause) {
            $clauses.Add($clause)
        }
        else {
            $invalid.Add(('L{0,-3} not "attribute operator value": {1}' -f $number, $trimmed))
        }
    }

    $filter = Build-TkLdapFilter -Conditions $clauses.ToArray() -Match $Match -ObjectParts $object.Parts -Negate:$Negate

    # A single quote in the filter has to be doubled to sit in a PowerShell
    # single-quoted string.
    $psFilter = $filter -replace "'", "''"

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add('LDAP filter:')
    $lines.Add(('  {0}' -f $filter))
    $lines.Add('')
    $lines.Add('PowerShell (ActiveDirectory module):')
    $lines.Add(('  Get-ADObject -LDAPFilter ''{0}'' -Properties *' -f $psFilter))

    if ($object.Cmdlet -ne 'Get-ADObject') {
        $lines.Add(('  {0} -LDAPFilter ''{1}''' -f $object.Cmdlet, $psFilter))
    }

    $lines.Add('')
    $lines.Add('Command line:')
    $lines.Add(('  dsquery * -limit 0 -filter "{0}"' -f $filter))

    if ($invalid.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Ignored lines:')
        foreach ($bad in $invalid) { $lines.Add(('  {0}' -f $bad)) }
    }

    return $lines.ToArray()
}
