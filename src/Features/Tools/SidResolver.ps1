<#
    Toolkit - Features / SID resolver

    A security identifier read both ways: a pasted SID named and taken apart into
    its authority, its domain and its RID, and an account name turned back into
    its SID. The well-known SIDs and the domain RIDs are named offline; a local
    or reachable-domain account is translated by Windows. It reuses the naming
    the SDDL decoder already does and adds the reverse direction and the
    structure.

    Read on the machine. Translating an account name asks the local SAM or the
    domain, so a domain account does not resolve on a stand-alone machine, which
    is said rather than guessed at.
#>

<#
.SYNOPSIS
    Names the identifier authority of a SID.

.OUTPUTS
    System.String
#>
function Get-TkSidAuthorityName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Authority
    )

    $names = @{
        '0'  = 'Null Authority'
        '1'  = 'World Authority'
        '2'  = 'Local Authority'
        '3'  = 'Creator Authority'
        '4'  = 'Non-unique Authority'
        '5'  = 'NT Authority'
        '9'  = 'Resource Manager Authority'
        '15' = 'Application Package Authority'
        '16' = 'Mandatory Label Authority'
        '18' = 'Asserted Identity Authority'
    }

    if ($names.ContainsKey($Authority)) { return $names[$Authority] }
    return ''
}

<#
.SYNOPSIS
    Breaks a SID into its revision, authority, sub-authorities, domain and RID.

.OUTPUTS
    PSCustomObject, or null when the text is not a SID.
#>
function Get-TkSidStructure {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Sid
    )

    if ($Sid -notmatch '^S-\d+-\d+(-\d+)*$') {
        return $null
    }

    $parts = $Sid -split '-'
    # parts[0] = S, [1] = revision, [2] = authority, [3..] = sub-authorities.

    $rid    = ''
    $domain = ''

    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(?<rid>\d+)$') {
        $rid    = $Matches['rid']
        $domain = $Sid -replace '-\d+$', ''
    }

    return [pscustomobject] @{
        Revision       = $parts[1]
        Authority      = $parts[2]
        AuthorityName  = (Get-TkSidAuthorityName -Authority $parts[2])
        SubAuthorities = @($parts[3..($parts.Count - 1)])
        Domain         = $domain
        Rid            = $rid
    }
}

<#
.SYNOPSIS
    Maps the common well-known account names to their SID, in English.

.DESCRIPTION
    Windows names these accounts in its own language, so "Everyone" does not
    resolve on a French machine where it is "Tout le monde". This lets the
    English names, the ones written in scripts and documentation, resolve
    offline whatever the language of the machine.

.OUTPUTS
    System.Collections.Hashtable keyed by the lower-case name.
#>
function Get-TkWellKnownNameSid {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'everyone'                 = 'S-1-1-0'
        'anonymous'                = 'S-1-5-7'
        'anonymous logon'          = 'S-1-5-7'
        'authenticated users'      = 'S-1-5-11'
        'interactive'              = 'S-1-5-4'
        'network'                  = 'S-1-5-2'
        'batch'                    = 'S-1-5-3'
        'service'                  = 'S-1-5-6'
        'system'                   = 'S-1-5-18'
        'local system'             = 'S-1-5-18'
        'local service'            = 'S-1-5-19'
        'network service'          = 'S-1-5-20'
        'creator owner'            = 'S-1-3-0'
        'creator group'            = 'S-1-3-1'
        'administrators'           = 'S-1-5-32-544'
        'users'                    = 'S-1-5-32-545'
        'guests'                   = 'S-1-5-32-546'
        'power users'              = 'S-1-5-32-547'
        'account operators'        = 'S-1-5-32-548'
        'server operators'         = 'S-1-5-32-549'
        'print operators'          = 'S-1-5-32-550'
        'backup operators'         = 'S-1-5-32-551'
        'remote desktop users'     = 'S-1-5-32-555'
        'event log readers'        = 'S-1-5-32-573'
        'remote management users'  = 'S-1-5-32-580'
    }
}

<#
.SYNOPSIS
    Translates an account name to its SID, or throws when it cannot be resolved.

.DESCRIPTION
    A well-known English name is mapped offline; anything else, a local account
    or a reachable-domain account, is translated by Windows in its own language.

.OUTPUTS
    System.String
#>
function ConvertTo-TkAccountSid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Account
    )

    $name = $Account.Trim()
    $key  = ($name -replace '^(BUILTIN|NT AUTHORITY)\\', '').ToLowerInvariant()

    $wellKnown = Get-TkWellKnownNameSid
    if ($wellKnown.ContainsKey($key)) {
        return $wellKnown[$key]
    }

    $ntAccount = New-Object System.Security.Principal.NTAccount($name)
    return $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

<#
.SYNOPSIS
    Resolves a pasted SID or account name, whichever it is.

.OUTPUTS
    PSCustomObject with Kind and the fields for that kind.
#>
function Get-TkSidReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $value = $Text.Trim()

    if (-not $value) {
        return [pscustomobject] @{ Kind = 'Empty' }
    }

    if ($value -match '^S-\d+-') {

        return [pscustomobject] @{
            Kind      = 'Sid'
            Sid       = $value
            Name      = (Get-TkSidFriendlyName -Sid $value)
            Structure = (Get-TkSidStructure -Sid $value)
        }
    }

    try {
        $sid = ConvertTo-TkAccountSid -Account $value
    }
    catch {
        return [pscustomobject] @{ Kind = 'Unresolved'; Account = $value }
    }

    return [pscustomobject] @{
        Kind    = 'Account'
        Account = $value
        Sid     = $sid
        Name    = (Get-TkSidFriendlyName -Sid $sid)
    }
}

<#
.SYNOPSIS
    Writes the SID resolution as lines of text.

.OUTPUTS
    System.String[]
#>
function Format-TkSidReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $report = Get-TkSidReport -Text $Text
    $lines  = New-Object System.Collections.Generic.List[string]

    switch ($report.Kind) {

        'Empty' {
            $lines.Add('Paste a SID (S-1-5-...) or an account name (DOMAIN\User) to resolve it.')
        }

        'Unresolved' {
            $lines.Add(('"{0}" could not be resolved to a SID.' -f $report.Account))
            $lines.Add('It is not a local account, and the machine reached no domain that knows it. On a stand-alone machine a domain account cannot be translated.')
        }

        'Account' {
            $lines.Add(('Account: {0}' -f $report.Account))
            $lines.Add(('SID:     {0}' -f $report.Sid))
            if ($report.Name) { $lines.Add(('Name:    {0}' -f $report.Name)) }
        }

        'Sid' {
            $lines.Add(('SID:  {0}' -f $report.Sid))
            $lines.Add(('Name: {0}' -f $(if ($report.Name) { $report.Name } else { 'not known and not resolvable on this machine' })))

            if ($report.Structure) {

                $structure = $report.Structure
                $lines.Add('')
                $lines.Add(('Revision:  {0}' -f $structure.Revision))
                $lines.Add(('Authority: {0}{1}' -f $structure.Authority, $(if ($structure.AuthorityName) { ' (' + $structure.AuthorityName + ')' } else { '' })))

                if ($structure.Domain) {
                    $lines.Add(('Domain:    {0}' -f $structure.Domain))
                    $lines.Add(('RID:       {0}' -f $structure.Rid))
                }
                else {
                    $lines.Add(('Sub-authorities: {0}' -f (@($structure.SubAuthorities) -join ', ')))
                }
            }
        }
    }

    return $lines.ToArray()
}
