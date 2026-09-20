<#
    Toolkit - Features / Administration decoders

    Reading and building the strings a Windows administrator meets but rarely
    remembers by heart: SDDL security descriptors, the bit fields of an Active
    Directory account, numbers in every base and as a bitmask, data sizes and
    transfer times, and the robocopy and schtasks command lines.

    Everything here is pure text work. Nothing is read from the machine, sent
    or run: a descriptor or a flag value is decoded on its own, which is what
    lets the tests cover it without a domain, elevation or a network.
#>

# ---------------------------------------------------------------------------
# SDDL: security descriptor strings
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Names a security identifier, well known ones by hand and the rest by asking
    Windows.

.DESCRIPTION
    The well known SIDs and the domain relative ones (a S-1-5-21 domain SID
    followed by a known RID, such as 512 for Domain Admins) are named from a
    table, so they read the same on any machine and without a domain. Anything
    left is translated through Windows as a last resort, which resolves local
    and reachable domain accounts and is allowed to fail quietly.

.PARAMETER Sid
    The SID, as its S-1-... string.

.OUTPUTS
    System.String, empty when nothing is known.
#>
function Get-TkSidFriendlyName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Sid
    )

    $wellKnown = @{
        'S-1-0-0'      = 'Nobody'
        'S-1-1-0'      = 'Everyone'
        'S-1-2-0'      = 'Local'
        'S-1-3-0'      = 'Creator Owner'
        'S-1-3-1'      = 'Creator Group'
        'S-1-3-4'      = 'Owner Rights'
        'S-1-5-1'      = 'Dialup'
        'S-1-5-2'      = 'Network'
        'S-1-5-3'      = 'Batch'
        'S-1-5-4'      = 'Interactive'
        'S-1-5-6'      = 'Service'
        'S-1-5-7'      = 'Anonymous'
        'S-1-5-9'      = 'Enterprise Domain Controllers'
        'S-1-5-10'     = 'Principal Self'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-12'     = 'Restricted Code'
        'S-1-5-13'     = 'Terminal Server User'
        'S-1-5-14'     = 'Remote Interactive Logon'
        'S-1-5-15'     = 'This Organization'
        'S-1-5-17'     = 'IIS_USRS'
        'S-1-5-18'     = 'Local System'
        'S-1-5-19'     = 'Local Service'
        'S-1-5-20'     = 'Network Service'
        'S-1-5-113'    = 'Local account'
        'S-1-5-114'    = 'Local account and member of Administrators'
        'S-1-5-32-544' = 'Administrators'
        'S-1-5-32-545' = 'Users'
        'S-1-5-32-546' = 'Guests'
        'S-1-5-32-547' = 'Power Users'
        'S-1-5-32-548' = 'Account Operators'
        'S-1-5-32-549' = 'Server Operators'
        'S-1-5-32-550' = 'Print Operators'
        'S-1-5-32-551' = 'Backup Operators'
        'S-1-5-32-552' = 'Replicator'
        'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'
        'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-32-556' = 'Network Configuration Operators'
        'S-1-5-32-558' = 'Performance Monitor Users'
        'S-1-5-32-559' = 'Performance Log Users'
        'S-1-5-32-568' = 'IIS_IUSRS'
        'S-1-5-32-569' = 'Cryptographic Operators'
        'S-1-5-32-573' = 'Event Log Readers'
        'S-1-5-32-574' = 'Certificate Service DCOM Access'
        'S-1-5-32-578' = 'Hyper-V Administrators'
        'S-1-5-32-579' = 'Access Control Assistance Operators'
        'S-1-5-32-580' = 'Remote Management Users'
        'S-1-15-2-1'   = 'All Application Packages'
        'S-1-15-2-2'   = 'All Restricted Application Packages'
        'S-1-16-0'     = 'Untrusted Mandatory Level'
        'S-1-16-4096'  = 'Low Mandatory Level'
        'S-1-16-8192'  = 'Medium Mandatory Level'
        'S-1-16-8448'  = 'Medium Plus Mandatory Level'
        'S-1-16-12288' = 'High Mandatory Level'
        'S-1-16-16384' = 'System Mandatory Level'
    }

    if ($wellKnown.ContainsKey($Sid)) {
        return $wellKnown[$Sid]
    }

    # A domain relative SID: S-1-5-21-<domain>-<RID>. The RID names the account.
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(?<rid>\d+)$') {

        $rid = [int] $Matches['rid']

        $ridNames = @{
            500 = 'Administrator'
            501 = 'Guest'
            502 = 'krbtgt'
            512 = 'Domain Admins'
            513 = 'Domain Users'
            514 = 'Domain Guests'
            515 = 'Domain Computers'
            516 = 'Domain Controllers'
            517 = 'Cert Publishers'
            518 = 'Schema Admins'
            519 = 'Enterprise Admins'
            520 = 'Group Policy Creator Owners'
            521 = 'Read-only Domain Controllers'
            522 = 'Cloneable Domain Controllers'
            525 = 'Protected Users'
            526 = 'Key Admins'
            527 = 'Enterprise Key Admins'
            498 = 'Enterprise Read-only Domain Controllers'
        }

        if ($ridNames.ContainsKey($rid)) {
            return $ridNames[$rid]
        }
    }

    # Last resort: let Windows translate a local or reachable domain account.
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return ''
    }
}

<#
.SYNOPSIS
    Describes the access rights an access mask carries.

.DESCRIPTION
    The generic rights and the standard rights sit in the high bits and mean
    the same on every object. The low sixteen bits are object specific, so the
    caller says what kind of object it is (a file, a registry key, a directory
    service object or a service) and those bits are read from that object's
    table. Whole named rights (Full control, Read...) are recognised before the
    single bits they contain, so the result reads the way the SDDL tokens do.

.PARAMETER Mask
    The access mask.

.PARAMETER Context
    The object the mask applies to: File, Registry, Directory, Service or
    Generic. Generic leaves the low bits as hexadecimal.

.OUTPUTS
    System.String[]
#>
function Get-TkAccessMaskRight {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [long] $Mask,

        [Parameter()]
        [ValidateSet('File', 'Registry', 'Directory', 'Service', 'Generic')]
        [string] $Context = 'Generic'
    )

    # The order matters: whole named rights come before the single bits they
    # contain, so the greedy pass below reads them the way SDDL tokens do. Bits
    # are kept as 64-bit values so the high generic bit (0x80000000) stays
    # positive on Windows PowerShell, where a 32-bit literal would go negative.
    $table = New-Object System.Collections.Generic.List[object]

    $add = { param($bits, $label) $table.Add([pscustomobject] @{ Bits = ([long] $bits) -band 0xFFFFFFFFL; Label = $label }) }

    # Generic rights (0x1000_0000 and up).
    & $add 0x10000000 'Generic all'
    & $add 0x80000000 'Generic read'
    & $add 0x40000000 'Generic write'
    & $add 0x20000000 'Generic execute'
    & $add 0x02000000 'Maximum allowed'
    & $add 0x01000000 'Access system security'

    # The object specific low bits, whole rights first.
    switch ($Context) {

        'File' {
            & $add 0x001F01FF 'Full control'
            & $add 0x001200A9 'Read and execute'
            & $add 0x00120089 'Read'
            & $add 0x00120116 'Write'
            & $add 0x00000001 'Read data / list directory'
            & $add 0x00000002 'Write data / add file'
            & $add 0x00000004 'Append data / add subdirectory'
            & $add 0x00000008 'Read extended attributes'
            & $add 0x00000010 'Write extended attributes'
            & $add 0x00000020 'Execute / traverse'
            & $add 0x00000040 'Delete subfolders and files'
            & $add 0x00000080 'Read attributes'
            & $add 0x00000100 'Write attributes'
        }

        'Registry' {
            & $add 0x000F003F 'Full control'
            & $add 0x00020019 'Read'
            & $add 0x00000001 'Query value'
            & $add 0x00000002 'Set value'
            & $add 0x00000004 'Create subkey'
            & $add 0x00000008 'Enumerate subkeys'
            & $add 0x00000010 'Notify'
            & $add 0x00000020 'Create link'
        }

        'Directory' {
            & $add 0x00000001 'Create child'
            & $add 0x00000002 'Delete child'
            & $add 0x00000004 'List contents'
            & $add 0x00000008 'Write self / validated write'
            & $add 0x00000010 'Read property'
            & $add 0x00000020 'Write property'
            & $add 0x00000040 'Delete tree'
            & $add 0x00000080 'List object'
            & $add 0x00000100 'Control access / extended right'
        }

        'Service' {
            & $add 0x000F01FF 'Full control'
            & $add 0x00000001 'Query config'
            & $add 0x00000002 'Change config'
            & $add 0x00000004 'Query status'
            & $add 0x00000008 'Enumerate dependents'
            & $add 0x00000010 'Start'
            & $add 0x00000020 'Stop'
            & $add 0x00000040 'Pause and continue'
            & $add 0x00000080 'Interrogate'
            & $add 0x00000100 'User-defined control'
        }
    }

    # Standard rights, common to every object.
    & $add 0x00100000 'Synchronize'
    & $add 0x00080000 'Write owner'
    & $add 0x00040000 'Write DAC'
    & $add 0x00020000 'Read control'
    & $add 0x00010000 'Delete'

    $names     = New-Object System.Collections.Generic.List[string]
    $remaining = $Mask -band 0xFFFFFFFFL

    foreach ($entry in $table) {
        if ($entry.Bits -ne 0 -and ($remaining -band $entry.Bits) -eq $entry.Bits) {
            $names.Add($entry.Label)
            $remaining = $remaining -band (-bnot $entry.Bits)
        }
    }

    if ($remaining -ne 0) {
        $names.Add(('other bits 0x{0:X8}' -f $remaining))
    }

    if ($names.Count -eq 0) {
        $names.Add('none')
    }

    return $names.ToArray()
}

<#
.SYNOPSIS
    Names an SDDL ACE type.
#>
function Get-TkAceTypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.AceQualifier] $Qualifier,

        [Parameter()]
        [switch] $Audit
    )

    if ($Audit) {
        return 'Audit'
    }

    switch ($Qualifier) {
        'AccessAllowed' { return 'Allow' }
        'AccessDenied'  { return 'Deny' }
        'SystemAudit'   { return 'Audit' }
        'SystemAlarm'   { return 'Alarm' }
        default         { return [string] $Qualifier }
    }
}

<#
.SYNOPSIS
    Names the inheritance and audit flags of an ACE.

.OUTPUTS
    System.String[]
#>
function Get-TkAceFlagName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.AceFlags] $Flags
    )

    $value = [int] $Flags
    $names = New-Object System.Collections.Generic.List[string]

    # The AceFlags bit values, low bit first.
    $map = @(
        @{ Bit = 1;   Text = 'Object inherit' }
        @{ Bit = 2;   Text = 'Container inherit' }
        @{ Bit = 4;   Text = 'No propagate' }
        @{ Bit = 8;   Text = 'Inherit only' }
        @{ Bit = 16;  Text = 'Inherited' }
        @{ Bit = 64;  Text = 'Audit success' }
        @{ Bit = 128; Text = 'Audit failure' }
    )

    foreach ($entry in $map) {
        if (($value -band $entry.Bit) -eq $entry.Bit) {
            $names.Add($entry.Text)
        }
    }

    return $names.ToArray()
}

<#
.SYNOPSIS
    Reads an SDDL security descriptor string into its parts.

.DESCRIPTION
    Windows itself parses the string, so every ACE type and flag it knows is
    accepted, and the same result comes out on Windows PowerShell 5.1 and
    PowerShell 7. The owner and group SIDs are named, and each ACE is broken
    into its type, its flags, the rights of its access mask and its trustee.
    The rights are read for the object kind passed in, since the low bits of a
    mask mean different things on a file and on a directory object.

.PARAMETER Text
    The descriptor, such as O:BAG:BAD:(A;;FA;;;SY)(A;;FR;;;BU).

.PARAMETER Context
    The object the descriptor protects, for the access mask: File, Registry,
    Directory, Service or Generic.

.OUTPUTS
    PSCustomObject with Owner, Group, Control, Dacl and Sacl.
#>
function ConvertFrom-TkSddl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter()]
        [ValidateSet('File', 'Registry', 'Directory', 'Service', 'Generic')]
        [string] $Context = 'Generic'
    )

    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Text.Trim())

    $named = {
        param($sid)
        if ($null -eq $sid) { return $null }
        $value    = $sid.Value
        $friendly = Get-TkSidFriendlyName -Sid $value
        [pscustomobject] @{ Sid = $value; Name = $friendly }
    }

    $readAcl = {
        param($acl)

        if ($null -eq $acl) {
            return @()
        }

        $entries = New-Object System.Collections.Generic.List[object]

        foreach ($ace in $acl) {

            $isAudit = $ace.AceType -in @([System.Security.AccessControl.AceType]::SystemAudit, [System.Security.AccessControl.AceType]::SystemAuditObject)
            $isDeny  = $ace.AceType -in @([System.Security.AccessControl.AceType]::AccessDenied, [System.Security.AccessControl.AceType]::AccessDeniedObject)

            $type = if ($isAudit) { 'Audit' } elseif ($isDeny) { 'Deny' } else { 'Allow' }

            $mask   = ([long] $ace.AccessMask) -band 0xFFFFFFFFL
            $rights = @(Get-TkAccessMaskRight -Mask $mask -Context $Context)

            $entries.Add([pscustomobject] @{
                Type      = $type
                Flags     = @(Get-TkAceFlagName -Flags $ace.AceFlags)
                Mask      = $mask
                Rights    = $rights
                Trustee   = (& $named $ace.SecurityIdentifier)
                ObjectAce = ($ace -is [System.Security.AccessControl.ObjectAce])
            })
        }

        return $entries.ToArray()
    }

    $controlValue = [int] $descriptor.ControlFlags
    $control      = New-Object System.Collections.Generic.List[string]

    $controlMap = @(
        @{ Bit = 1024; Text = 'DACL auto-inherited' }
        @{ Bit = 2048; Text = 'SACL auto-inherited' }
        @{ Bit = 4096; Text = 'DACL protected' }
        @{ Bit = 8192; Text = 'SACL protected' }
    )

    foreach ($entry in $controlMap) {
        if (($controlValue -band $entry.Bit) -eq $entry.Bit) {
            $control.Add($entry.Text)
        }
    }

    return [pscustomobject] @{
        Owner   = (& $named $descriptor.Owner)
        Group   = (& $named $descriptor.Group)
        Control = $control.ToArray()
        Dacl    = (& $readAcl $descriptor.DiscretionaryAcl)
        Sacl    = (& $readAcl $descriptor.SystemAcl)
        Context = $Context
    }
}

<#
.SYNOPSIS
    Lays out a decoded SDDL descriptor for the panel.

.OUTPUTS
    System.String[]
#>
function Format-TkSddl {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Descriptor
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $trustee = {
        param($t)
        if ($null -eq $t) { return '(none)' }
        if ($t.Name)      { return ('{0}  [{1}]' -f $t.Name, $t.Sid) }
        return $t.Sid
    }

    $lines.Add(('Read as       {0} object' -f $Descriptor.Context.ToLowerInvariant()))
    $lines.Add(('Owner         {0}' -f (& $trustee $Descriptor.Owner)))
    $lines.Add(('Group         {0}' -f (& $trustee $Descriptor.Group)))

    if (@($Descriptor.Control).Count -gt 0) {
        $lines.Add(('Control       {0}' -f (@($Descriptor.Control) -join ', ')))
    }

    $section = {
        param($title, $aces)

        $lines.Add('')

        if (@($aces).Count -eq 0) {
            $lines.Add(('{0}: empty' -f $title))
            return
        }

        $lines.Add(('{0}: {1} entr{2}' -f $title, @($aces).Count, $(if (@($aces).Count -eq 1) { 'y' } else { 'ies' })))

        $number = 0
        foreach ($ace in $aces) {
            $number++
            $flags = if (@($ace.Flags).Count -gt 0) { ' (' + (@($ace.Flags) -join ', ') + ')' } else { '' }
            $lines.Add(('  {0}. {1}{2} to {3}' -f $number, $ace.Type, $flags, (& $trustee $ace.Trustee)))
            $lines.Add(('     Mask 0x{0:X8}: {1}' -f $ace.Mask, (@($ace.Rights) -join ', ')))
        }
    }

    & $section 'DACL (who may do what)' $Descriptor.Dacl
    & $section 'SACL (what is audited)' $Descriptor.Sacl

    return $lines.ToArray()
}

# ---------------------------------------------------------------------------
# Active Directory bit fields
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    The bit definitions of an Active Directory attribute that holds flags.

.DESCRIPTION
    userAccountControl, groupType and msDS-SupportedEncryptionTypes are each a
    number whose bits are separate settings. The tables come from Microsoft's
    documentation, with the value, a short name and a plain description.

.PARAMETER Attribute
    userAccountControl, groupType or supportedEncryptionTypes.

.OUTPUTS
    PSCustomObject[] with Value, Name and Description, low bit first.
#>
function Get-TkAdFlagDefinition {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('userAccountControl', 'groupType', 'supportedEncryptionTypes')]
        [string] $Attribute
    )

    # The 0x80000000 entries are read as a negative Int32 by Windows PowerShell,
    # which [uint32] then refuses; masking through a 64-bit value keeps them.
    $flag = {
        param($value, $name, $description)
        [pscustomobject] @{ Value = [uint32] (([long] $value) -band 0xFFFFFFFFL); Name = $name; Description = $description }
    }

    switch ($Attribute) {

        'userAccountControl' {
            return @(
                (& $flag 0x00000001 'SCRIPT' 'The logon script runs.')
                (& $flag 0x00000002 'ACCOUNTDISABLE' 'The account is disabled.')
                (& $flag 0x00000008 'HOMEDIR_REQUIRED' 'A home folder is required.')
                (& $flag 0x00000010 'LOCKOUT' 'The account is locked out.')
                (& $flag 0x00000020 'PASSWD_NOTREQD' 'No password is required.')
                (& $flag 0x00000040 'PASSWD_CANT_CHANGE' 'The user cannot change the password (a permission, shown for completeness).')
                (& $flag 0x00000080 'ENCRYPTED_TEXT_PWD_ALLOWED' 'The password may be stored with reversible encryption.')
                (& $flag 0x00000100 'TEMP_DUPLICATE_ACCOUNT' 'A local account for a user whose main account is in another domain.')
                (& $flag 0x00000200 'NORMAL_ACCOUNT' 'A typical user account.')
                (& $flag 0x00000800 'INTERDOMAIN_TRUST_ACCOUNT' 'A trust account for a trusting domain.')
                (& $flag 0x00001000 'WORKSTATION_TRUST_ACCOUNT' 'A computer account for a member workstation or server.')
                (& $flag 0x00002000 'SERVER_TRUST_ACCOUNT' 'A computer account for a domain controller.')
                (& $flag 0x00010000 'DONT_EXPIRE_PASSWORD' 'The password never expires.')
                (& $flag 0x00020000 'MNS_LOGON_ACCOUNT' 'A majority node set logon account.')
                (& $flag 0x00040000 'SMARTCARD_REQUIRED' 'A smart card is required to sign in.')
                (& $flag 0x00080000 'TRUSTED_FOR_DELEGATION' 'Trusted for Kerberos delegation (unconstrained).')
                (& $flag 0x00100000 'NOT_DELEGATED' 'The account cannot be delegated, even to a trusted service.')
                (& $flag 0x00200000 'USE_DES_KEY_ONLY' 'Restricted to DES encryption for keys (legacy, weak).')
                (& $flag 0x00400000 'DONT_REQ_PREAUTH' 'Kerberos pre-authentication is not required (AS-REP roasting risk).')
                (& $flag 0x00800000 'PASSWORD_EXPIRED' 'The password has expired.')
                (& $flag 0x01000000 'TRUSTED_TO_AUTH_FOR_DELEGATION' 'Enabled for constrained delegation with protocol transition.')
                (& $flag 0x04000000 'PARTIAL_SECRETS_ACCOUNT' 'A read-only domain controller account.')
            )
        }

        'groupType' {
            return @(
                (& $flag 0x00000001 'SYSTEM' 'A group created by the system.')
                (& $flag 0x00000002 'GLOBAL' 'Global scope.')
                (& $flag 0x00000004 'DOMAIN_LOCAL' 'Domain local scope.')
                (& $flag 0x00000008 'UNIVERSAL' 'Universal scope.')
                (& $flag 0x00000010 'APP_BASIC' 'An APP_BASIC group for Authorization Manager.')
                (& $flag 0x00000020 'APP_QUERY' 'An APP_QUERY group for Authorization Manager.')
                (& $flag 0x80000000 'SECURITY_ENABLED' 'A security group; without this bit it is a distribution group.')
            )
        }

        'supportedEncryptionTypes' {
            return @(
                (& $flag 0x00000001 'DES_CBC_CRC' 'DES-CBC-CRC (legacy, disabled by default).')
                (& $flag 0x00000002 'DES_CBC_MD5' 'DES-CBC-MD5 (legacy, disabled by default).')
                (& $flag 0x00000004 'RC4_HMAC' 'RC4-HMAC (legacy, kept only for transition).')
                (& $flag 0x00000008 'AES128_CTS_HMAC_SHA1_96' 'AES128-CTS-HMAC-SHA1-96.')
                (& $flag 0x00000010 'AES256_CTS_HMAC_SHA1_96' 'AES256-CTS-HMAC-SHA1-96.')
                (& $flag 0x00000020 'AES256_CTS_HMAC_SHA1_96_SK' 'AES256 session key.')
                (& $flag 0x00010000 'FAST_SUPPORTED' 'Kerberos armoring (FAST) is supported.')
                (& $flag 0x00020000 'COMPOUND_IDENTITY_SUPPORTED' 'Compound identity is supported.')
                (& $flag 0x00040000 'CLAIMS_SUPPORTED' 'Claims are supported.')
                (& $flag 0x00080000 'RESOURCE_SID_COMPRESSION_DISABLED' 'Resource SID compression is disabled.')
                (& $flag 0x80000000 'USE_DEFAULT' 'Use the Windows default encryption types.')
            )
        }
    }
}

<#
.SYNOPSIS
    Breaks an Active Directory flag value into the bits it sets.

.DESCRIPTION
    The value is matched against the attribute's bit table. Each known bit is
    reported as set or clear, any bit set that the table does not know is listed
    on its own, and a few plain-language notes are added for the states that
    matter most (an account disabled, a password that never expires, only RC4
    left on).

.PARAMETER Attribute
    userAccountControl, groupType or supportedEncryptionTypes.

.PARAMETER Value
    The number held in the attribute.

.OUTPUTS
    PSCustomObject with Attribute, Value, Hex, Flags and Notes.
#>
function ConvertFrom-TkAdFlags {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('userAccountControl', 'groupType', 'supportedEncryptionTypes')]
        [string] $Attribute,

        [Parameter(Mandatory)]
        [uint32] $Value
    )

    $definitions = @(Get-TkAdFlagDefinition -Attribute $Attribute)
    $known       = 0
    $flags       = New-Object System.Collections.Generic.List[object]

    foreach ($definition in $definitions) {
        $set = ($Value -band $definition.Value) -eq $definition.Value -and $definition.Value -ne 0
        if ($set) { $known = $known -bor $definition.Value }
        $flags.Add([pscustomobject] @{
            Value       = $definition.Value
            Name        = $definition.Name
            Description = $definition.Description
            Set         = $set
        })
    }

    $unknown = $Value -band (-bnot $known)
    $notes   = New-Object System.Collections.Generic.List[string]

    switch ($Attribute) {

        'userAccountControl' {
            if (($Value -band 0x2) -eq 0x2) { $notes.Add('The account is disabled.') } else { $notes.Add('The account is enabled.') }
            if (($Value -band 0x10000) -eq 0x10000) { $notes.Add('The password never expires.') }
            if (($Value -band 0x400000) -eq 0x400000) { $notes.Add('Pre-authentication is off: the account can be AS-REP roasted.') }
            if (($Value -band 0x80000) -eq 0x80000) { $notes.Add('Unconstrained delegation is a high-value target; review it.') }
            if (($Value -band 0x20) -eq 0x20) { $notes.Add('No password is required, which is rarely wanted.') }
        }

        'groupType' {
            $scope = switch ($true) {
                (($Value -band 0x2) -eq 0x2) { 'global'; break }
                (($Value -band 0x4) -eq 0x4) { 'domain local'; break }
                (($Value -band 0x8) -eq 0x8) { 'universal'; break }
                default { 'no scope set' }
            }
            # 0x80000000 written as a decimal, since as a 32-bit hex literal it
            # would be read as a negative Int32 on Windows PowerShell.
            $kind = if (($Value -band 2147483648) -eq 2147483648) { 'security' } else { 'distribution' }
            $notes.Add(('A {0} group with {1} scope.' -f $kind, $scope))
        }

        'supportedEncryptionTypes' {
            if ($Value -eq 0) {
                $notes.Add('Zero: the KDC falls back to its default, historically RC4. Set AES explicitly.')
            }
            else {
                $aes = ($Value -band 0x18) -ne 0
                $rc4 = ($Value -band 0x4) -eq 0x4
                $des = ($Value -band 0x3) -ne 0
                if ($aes -and -not $rc4 -and -not $des) { $notes.Add('AES only: the hardened state once the transition is done.') }
                if ($rc4 -and $aes) { $notes.Add('RC4 and AES: a transition value, still allowing weak RC4.') }
                if ($rc4 -and -not $aes) { $notes.Add('RC4 without AES: weak, upgrade to AES.') }
                if ($des) { $notes.Add('DES is enabled, which is broken; remove it.') }
            }
        }
    }

    return [pscustomobject] @{
        Attribute = $Attribute
        Value     = $Value
        Hex       = '0x{0:X}' -f $Value
        Flags     = $flags.ToArray()
        Unknown   = $unknown
        Notes     = $notes.ToArray()
    }
}

<#
.SYNOPSIS
    Lays out a decoded Active Directory flag value for the panel.

.OUTPUTS
    System.String[]
#>
function Format-TkAdFlags {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('{0} = {1} ({2})' -f $Report.Attribute, $Report.Value, $Report.Hex))
    $lines.Add('')

    $set = @($Report.Flags | Where-Object { $_.Set })

    if ($set.Count -eq 0) {
        $lines.Add('No known bit is set.')
    }
    else {
        $lines.Add('Bits set:')
        foreach ($flag in $set) {
            $lines.Add(('  0x{0:X8}  {1} - {2}' -f $flag.Value, $flag.Name, $flag.Description))
        }
    }

    if ($Report.Unknown -ne 0) {
        $lines.Add('')
        $lines.Add(('Unrecognised bits: 0x{0:X8}' -f $Report.Unknown))
    }

    if (@($Report.Notes).Count -gt 0) {
        $lines.Add('')
        foreach ($note in $Report.Notes) {
            $lines.Add(('Note: {0}' -f $note))
        }
    }

    return $lines.ToArray()
}

# ---------------------------------------------------------------------------
# Numbers: bases and bitmasks
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads a number written in any base.

.DESCRIPTION
    A 0x, 0b or 0o prefix sets the base; otherwise the base passed in is used,
    ten by default. Spaces and underscores are grouping and are ignored. The
    result is a non-negative big integer, so a 64-bit mask fits without loss.

.PARAMETER Text
    The number, such as 0xFF, 0b1010, 493 or 755.

.PARAMETER Base
    The base to read a number with no prefix: 2, 8, 10 or 16.

.OUTPUTS
    System.Numerics.BigInteger, or throws when the text is not a number.
#>
function ConvertFrom-TkNumberText {
    [CmdletBinding()]
    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter()]
        [ValidateSet(2, 8, 10, 16)]
        [int] $Base = 10
    )

    $clean = ($Text -replace '[\s_]', '').Trim()

    if (-not $clean) {
        throw 'Type a number.'
    }

    $radix  = $Base
    $digits = $clean

    if ($clean -match '^0[xX](?<d>.+)$')      { $radix = 16; $digits = $Matches['d'] }
    elseif ($clean -match '^0[bB](?<d>.+)$')  { $radix = 2;  $digits = $Matches['d'] }
    elseif ($clean -match '^0[oO](?<d>.+)$')  { $radix = 8;  $digits = $Matches['d'] }

    $alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'.Substring(0, $radix)
    $value    = [System.Numerics.BigInteger]::Zero
    $radixBig = [System.Numerics.BigInteger] $radix

    foreach ($character in $digits.ToCharArray()) {
        $index = $alphabet.IndexOf([char]::ToLowerInvariant($character))
        if ($index -lt 0) {
            throw ('"{0}" is not a base-{1} digit.' -f $character, $radix)
        }
        $value = ($value * $radixBig) + $index
    }

    return $value
}

<#
.SYNOPSIS
    Writes a big integer in binary, in groups of four bits.
#>
function Format-TkBinaryGrouped {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Numerics.BigInteger] $Value
    )

    if ($Value -eq 0) { return '0' }

    $bits = ''
    $n    = $Value
    $two  = [System.Numerics.BigInteger] 2

    while ($n -gt 0) {
        $bits = [string] ($n % $two) + $bits
        $n    = [System.Numerics.BigInteger]::Divide($n, $two)
    }

    # Pad to a multiple of four, then group.
    while ($bits.Length % 4 -ne 0) { $bits = '0' + $bits }

    $groups = for ($i = 0; $i -lt $bits.Length; $i += 4) { $bits.Substring($i, 4) }
    return ($groups -join ' ')
}

<#
.SYNOPSIS
    Shows a number in every base and lists the bits it sets.

.PARAMETER Value
    A non-negative big integer.

.OUTPUTS
    PSCustomObject with Decimal, Hex, Octal, Binary, Bits and Signed forms.
#>
function Get-TkNumberReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Numerics.BigInteger] $Value
    )

    $hex = $Value.ToString('X').TrimStart('0')
    if (-not $hex) { $hex = '0' }

    # Octal by repeated division.
    $octal = ''
    $n     = $Value
    $eight = [System.Numerics.BigInteger] 8
    if ($n -eq 0) { $octal = '0' }
    while ($n -gt 0) {
        $octal = [string] ($n % $eight) + $octal
        $n     = [System.Numerics.BigInteger]::Divide($n, $eight)
    }

    $bits = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt 64; $i++) {
        if (($Value -band ([System.Numerics.BigInteger]::Pow(2, $i))) -ne 0) {
            $bits.Add($i)
        }
    }

    $signed = $null
    if ($Value -le [uint32]::MaxValue) {
        $asInt32 = [int32] ([uint32] $Value)
        if ($asInt32 -lt 0) { $signed = '{0} as a signed 32-bit integer' -f $asInt32 }
    }

    return [pscustomobject] @{
        Decimal = $Value.ToString()
        Hex     = '0x' + $hex
        Octal   = '0o' + $octal
        Binary  = '0b' + (Format-TkBinaryGrouped -Value $Value)
        Bits    = $bits.ToArray()
        Signed  = $signed
    }
}

<#
.SYNOPSIS
    Lays out a number report for the panel.

.OUTPUTS
    System.String[]
#>
function Format-TkNumberReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Decimal   {0}' -f $Report.Decimal))
    $lines.Add(('Hex       {0}' -f $Report.Hex))
    $lines.Add(('Octal     {0}' -f $Report.Octal))
    $lines.Add(('Binary    {0}' -f $Report.Binary))

    if (@($Report.Bits).Count -gt 0) {
        $bitList = @($Report.Bits | ForEach-Object { 'bit {0} ({1})' -f $_, ([System.Numerics.BigInteger]::Pow(2, $_)).ToString() })
        $lines.Add(('Bits set  {0}' -f ($bitList -join ', ')))
    }
    else {
        $lines.Add('Bits set  none')
    }

    if ($Report.Signed) {
        $lines.Add(('Signed    {0}' -f $Report.Signed))
    }

    return $lines.ToArray()
}

# ---------------------------------------------------------------------------
# Data sizes and transfer times
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads a data size or a rate into a count of bits.

.DESCRIPTION
    Understands decimal units (KB, MB, GB, TB, kb, Mb...) as powers of a
    thousand and binary units (KiB, MiB, GiB...) as powers of 1024, and tells a
    byte (B, capital) from a bit (b, small) as the networking world writes them.
    A rate may end in /s, which is ignored here since a rate and a size are the
    same count of bits per unit.

.PARAMETER Text
    The size or rate, such as 1.5 GB, 500 MiB, 100 Mbps or 940 Mb/s.

.OUTPUTS
    PSCustomObject with Bits, Bytes and IsBits, or throws when unreadable.
#>
function ConvertFrom-TkDataSizeText {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    $clean = ($Text -replace '/s|ps$', '').Trim()

    if ($clean -notmatch '^(?<number>[0-9]+(?:[.,][0-9]+)?)\s*(?<unit>[KMGTPE]?i?[Bb])?$') {
        throw ('"{0}" is not a size. Write something like 1.5 GB, 500 MiB or 100 Mb.' -f $Text)
    }

    $number = [double]::Parse(($Matches['number'] -replace ',', '.'), [System.Globalization.CultureInfo]::InvariantCulture)
    $unit   = $Matches['unit']
    if (-not $unit) { $unit = 'B' }

    $isBits = $unit.EndsWith('b')
    $binary = $unit.Contains('i')
    $prefix = ($unit -replace 'i?[Bb]$', '')

    $powers = @{ '' = 0; 'K' = 1; 'M' = 2; 'G' = 3; 'T' = 4; 'P' = 5; 'E' = 6 }
    $step   = if ($binary) { 1024 } else { 1000 }
    $factor = [Math]::Pow($step, $powers[$prefix])

    $units = $number * $factor
    $bits  = if ($isBits) { $units } else { $units * 8 }

    return [pscustomobject] @{
        Bits   = $bits
        Bytes  = $bits / 8
        IsBits = $isBits
    }
}

<#
.SYNOPSIS
    Writes a byte count in both decimal and binary units.

.OUTPUTS
    System.String
#>
function Format-TkByteCountBoth {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [double] $Bytes
    )

    $pick = {
        param($value, $step, $names)
        $index = 0
        $v     = [double] $value
        while ($v -ge $step -and $index -lt ($names.Count - 1)) {
            $v = $v / $step
            $index++
        }
        [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.###} {1}', $v, $names[$index])
    }

    $decimal = & $pick $Bytes 1000 @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $binary  = & $pick $Bytes 1024 @('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB')

    if ($decimal -eq $binary) { return $decimal }
    return ('{0}  ({1})' -f $decimal, $binary)
}

<#
.SYNOPSIS
    Writes a duration in seconds as days, hours, minutes and seconds.
#>
function Format-TkDuration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [double] $Seconds
    )

    if ($Seconds -lt 1) {
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.###} s', $Seconds)
    }

    $span  = [TimeSpan]::FromSeconds([Math]::Round($Seconds))
    $parts = New-Object System.Collections.Generic.List[string]

    if ($span.Days -gt 0)    { $parts.Add(('{0} d' -f $span.Days)) }
    if ($span.Hours -gt 0)   { $parts.Add(('{0} h' -f $span.Hours)) }
    if ($span.Minutes -gt 0) { $parts.Add(('{0} min' -f $span.Minutes)) }
    if ($span.Seconds -gt 0) { $parts.Add(('{0} s' -f $span.Seconds)) }

    if ($parts.Count -eq 0) { return '0 s' }
    return ($parts -join ' ')
}

<#
.SYNOPSIS
    Works out how long a transfer of a given size takes at a given rate.

.DESCRIPTION
    The size and the rate are read on their own scales, so a size in bytes and a
    link in bits per second are compared correctly. Ninety percent of the link
    is offered too, since a real transfer rarely reaches the full advertised
    rate.

.PARAMETER SizeText
    The amount to move, such as 25 GB.

.PARAMETER RateText
    The link speed, such as 100 Mbps or 50 MB/s.

.OUTPUTS
    PSCustomObject with Bytes, BitsPerSecond, Seconds and RealisticSeconds.
#>
function Get-TkTransferReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $SizeText,

        [Parameter(Mandatory)]
        [string] $RateText
    )

    $size = ConvertFrom-TkDataSizeText -Text $SizeText
    $rate = ConvertFrom-TkDataSizeText -Text $RateText

    if ($rate.Bits -le 0) {
        throw 'The rate must be more than zero.'
    }

    $seconds = $size.Bits / $rate.Bits

    return [pscustomobject] @{
        Bytes            = $size.Bytes
        BitsPerSecond    = $rate.Bits
        Seconds          = $seconds
        RealisticSeconds = $seconds / 0.9
    }
}

<#
.SYNOPSIS
    Lays out a transfer estimate for the panel.

.OUTPUTS
    System.String[]
#>
function Format-TkTransferReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Report
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Size      {0}' -f (Format-TkByteCountBoth -Bytes $Report.Bytes)))
    $lines.Add(('Rate      {0} per second' -f (Format-TkByteCountBoth -Bytes ($Report.BitsPerSecond / 8))))
    $lines.Add('')
    $lines.Add(('At the full rate      {0}' -f (Format-TkDuration -Seconds $Report.Seconds)))
    $lines.Add(('At 90% of the rate    {0}' -f (Format-TkDuration -Seconds $Report.RealisticSeconds)))

    return $lines.ToArray()
}

# ---------------------------------------------------------------------------
# Robocopy
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Builds a robocopy command line from its parts.

.DESCRIPTION
    Paths with a space are quoted. Mirror and copy-subdirectories are exclusive,
    so mirror wins when both are asked. The retry and wait counts default to
    robocopy's own million retries and thirty-second wait unless given, which is
    the first thing most people cut down.

.PARAMETER Source
    The source folder.

.PARAMETER Destination
    The destination folder.

.PARAMETER Options
    A hashtable of switches: Mirror, Subdirectories, EmptyDirectories,
    Restartable, Backup, CopyAll, ExcludeOlder, ExcludeChanged, Purge,
    Move, ListOnly, NoProgress, Threads, Retries, Wait, ExcludeFiles,
    ExcludeDirs, Log.

.OUTPUTS
    System.String
#>
function Build-TkRobocopyCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter(Mandatory)]
        [string] $Destination,

        [Parameter()]
        [hashtable] $Options = @{}
    )

    $quote = {
        param($path)
        $p = ([string] $path).Trim()
        if ($p -match '\s') { return '"{0}"' -f $p.TrimEnd('\') } else { return $p }
    }

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('robocopy')
    $parts.Add((& $quote $Source))
    $parts.Add((& $quote $Destination))

    if ($Options.Mirror) {
        $parts.Add('/MIR')
    }
    else {
        if ($Options.EmptyDirectories) { $parts.Add('/E') }
        elseif ($Options.Subdirectories) { $parts.Add('/S') }
        if ($Options.Purge) { $parts.Add('/PURGE') }
    }

    if ($Options.CopyAll)     { $parts.Add('/COPYALL') }
    if ($Options.Restartable) { $parts.Add('/Z') }
    if ($Options.Backup)      { $parts.Add('/ZB') }
    if ($Options.Move)        { $parts.Add('/MOVE') }
    if ($Options.ExcludeOlder)   { $parts.Add('/XO') }
    if ($Options.ExcludeChanged) { $parts.Add('/XC') }

    if ($Options.ContainsKey('Threads') -and $Options.Threads) {
        $parts.Add('/MT:{0}' -f [int] $Options.Threads)
    }

    if ($Options.ContainsKey('Retries')) {
        $parts.Add('/R:{0}' -f [int] $Options.Retries)
    }

    if ($Options.ContainsKey('Wait')) {
        $parts.Add('/W:{0}' -f [int] $Options.Wait)
    }

    if ($Options.ExcludeFiles) {
        foreach ($file in @($Options.ExcludeFiles)) {
            if (([string] $file).Trim()) {
                $parts.Add('/XF')
                $parts.Add((& $quote $file))
            }
        }
    }

    if ($Options.ExcludeDirs) {
        foreach ($dir in @($Options.ExcludeDirs)) {
            if (([string] $dir).Trim()) {
                $parts.Add('/XD')
                $parts.Add((& $quote $dir))
            }
        }
    }

    if ($Options.ListOnly) { $parts.Add('/L') }

    if ($Options.Log) {
        $parts.Add('/LOG:{0}' -f (& $quote $Options.Log))
        $parts.Add('/TEE')
    }

    if ($Options.NoProgress) { $parts.Add('/NP') }

    return ($parts -join ' ')
}

<#
.SYNOPSIS
    Reads a robocopy exit code.

.DESCRIPTION
    The exit code is a bitmask, not a rank: bit 0 (1) means files were copied,
    bit 1 (2) that extra files are in the destination, bit 2 (4) a mismatch, bit
    3 (8) that some files failed, bit 4 (16) a fatal error. Anything below eight
    is a success; eight or more means at least one failure.

.PARAMETER Code
    The exit code, 0 to 31.

.OUTPUTS
    PSCustomObject with Code, Success, Meanings.
#>
function ConvertFrom-TkRobocopyExitCode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $Code
    )

    $bits = @(
        @{ Bit = 1;  Text = 'Files were copied.' }
        @{ Bit = 2;  Text = 'Extra files or folders are in the destination that are not in the source.' }
        @{ Bit = 4;  Text = 'Some files differ and were not overwritten (a mismatch).' }
        @{ Bit = 8;  Text = 'Some files or folders could not be copied (a copy error).' }
        @{ Bit = 16; Text = 'A fatal error: robocopy could not start, wrong arguments or no access.' }
    )

    $meanings = New-Object System.Collections.Generic.List[string]

    if ($Code -eq 0) {
        $meanings.Add('Nothing to do: the destination already matched the source.')
    }

    foreach ($entry in $bits) {
        if (($Code -band $entry.Bit) -eq $entry.Bit) {
            $meanings.Add($entry.Text)
        }
    }

    return [pscustomobject] @{
        Code     = $Code
        Success  = ($Code -lt 8)
        Meanings = $meanings.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Builds a schtasks /create command line from its parts.

.DESCRIPTION
    The task name and the program to run are quoted. The schedule type decides
    which of the other fields make sense, so only the ones that apply are added:
    a start time for a minute, hourly, daily, weekly, monthly or once schedule,
    a day for a weekly or monthly one. HIGHEST run level maps to "run with the
    highest privileges", and /f overwrites a task of the same name.

.PARAMETER Name
    The task name, /tn.

.PARAMETER Run
    The program or command, /tr.

.PARAMETER Schedule
    MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE.

.PARAMETER Options
    A hashtable: Modifier, StartTime, StartDate, Day, RunAs, HighestPrivileges,
    Force.

.OUTPUTS
    System.String
#>
function Build-TkSchtasksCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Run,

        [Parameter(Mandatory)]
        [ValidateSet('MINUTE', 'HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY', 'ONCE', 'ONSTART', 'ONLOGON', 'ONIDLE')]
        [string] $Schedule,

        [Parameter()]
        [hashtable] $Options = @{}
    )

    $quote = {
        param($text)
        '"{0}"' -f (([string] $text).Trim() -replace '"', '')
    }

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('schtasks /create')
    $parts.Add('/tn {0}' -f (& $quote $Name))
    $parts.Add('/tr {0}' -f (& $quote $Run))
    $parts.Add('/sc {0}' -f $Schedule)

    if ($Options.ContainsKey('Modifier') -and ([string] $Options.Modifier).Trim()) {
        $parts.Add('/mo {0}' -f ([string] $Options.Modifier).Trim())
    }

    $takesDay  = $Schedule -in @('WEEKLY', 'MONTHLY')
    $takesTime = $Schedule -in @('MINUTE', 'HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY', 'ONCE')

    if ($takesDay -and $Options.Day -and ([string] $Options.Day).Trim()) {
        $parts.Add('/d {0}' -f ([string] $Options.Day).Trim().ToUpperInvariant())
    }

    if ($takesTime -and $Options.StartTime -and ([string] $Options.StartTime).Trim()) {
        $parts.Add('/st {0}' -f ([string] $Options.StartTime).Trim())
    }

    if ($Options.StartDate -and ([string] $Options.StartDate).Trim()) {
        $parts.Add('/sd {0}' -f ([string] $Options.StartDate).Trim())
    }

    if ($Options.RunAs -and ([string] $Options.RunAs).Trim()) {
        $parts.Add('/ru {0}' -f (& $quote $Options.RunAs))
    }

    if ($Options.HighestPrivileges) {
        $parts.Add('/rl HIGHEST')
    }

    if ($Options.Force) {
        $parts.Add('/f')
    }

    return ($parts -join ' ')
}

# ---------------------------------------------------------------------------
# dsacls: delegating control on directory objects
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    The delegation tasks the dsacls builder offers, and how each maps to a
    dsacls rights string.

.DESCRIPTION
    Each preset knows the dsacls permission letters it needs and where the
    object type belongs in the rights string, since that differs by task: for
    create and delete the type is the child object to make, for a property or an
    extended right it is the class the entry is inherited to. The Build script
    turns a chosen object type into the finished rights string, the part that
    follows the trustee and a colon.

.OUTPUTS
    PSCustomObject[] with Label, Description, UsesObjectType, DefaultInheritance
    and a Build script.
#>
function Get-TkDsaclsPreset {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $preset = {
        param($label, $description, $usesType, $inheritance, $build)
        [pscustomobject] @{
            Label             = $label
            Description       = $description
            UsesObjectType    = [bool] $usesType
            DefaultInheritance = $inheritance
            Build             = $build
        }
    }

    # The object type is dropped in with a leading class where it belongs, and
    # left out entirely when "all objects" (an empty type) is chosen.
    return @(
        (& $preset 'Full control' 'Full control of the OU and everything in it.' $false 'T' { param($type) 'GA' })

        (& $preset 'Create and delete child objects' 'Create and delete objects of a type in the OU, such as user accounts.' $true 'T' {
            param($type)
            if ($type) { 'CCDC;{0}' -f $type } else { 'CCDC' }
        })

        (& $preset 'Reset passwords' 'Reset the password of user accounts (the Reset Password right).' $true 'S' {
            param($type)
            $class = if ($type) { $type } else { 'user' }
            'CA;Reset Password;{0}' -f $class
        })

        (& $preset 'Read all properties' 'Read every property of the objects.' $true 'S' {
            param($type)
            'RP;;{0}' -f $type
        })

        (& $preset 'Write all properties' 'Change every property of the objects.' $true 'S' {
            param($type)
            'WP;;{0}' -f $type
        })

        (& $preset 'Read and write all properties' 'Read and change every property of the objects.' $true 'S' {
            param($type)
            'RPWP;;{0}' -f $type
        })

        (& $preset 'Manage group membership' 'Add and remove members of groups (write the member property).' $false 'S' {
            param($type)
            'WP;member;group'
        })

        (& $preset 'Custom' 'Type the dsacls rights yourself, such as CCDC;computer or WPRP;member;group.' $false '' { param($type) '' })
    )
}

<#
.SYNOPSIS
    Builds a dsacls command line that delegates control on a directory object.

.DESCRIPTION
    dsacls sets the permissions on an Active Directory object such as an OU. The
    object's distinguished name is quoted, the trustee and its rights follow
    /G to grant or /D to deny, and /I sets how far the grant reaches: this object
    and all children (T), child objects only (S), or this object and its
    immediate children (P). The rights string is passed in ready made, from a
    preset or typed by hand.

.PARAMETER ObjectDn
    The distinguished name of the object, such as OU=Sales,DC=contoso,DC=com.

.PARAMETER Trustee
    Who is granted the rights: DOMAIN\Group, a UPN, or a distinguished name.

.PARAMETER Rights
    The dsacls rights string after the colon, such as GA or CA;Reset Password;user.

.PARAMETER Inheritance
    T, S or P, or empty for this object only.

.PARAMETER Deny
    Deny the rights (/D) instead of granting them (/G).

.OUTPUTS
    System.String
#>
function Build-TkDsaclsCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $ObjectDn,

        [Parameter(Mandatory)]
        [string] $Trustee,

        [Parameter(Mandatory)]
        [string] $Rights,

        [Parameter()]
        [ValidateSet('', 'T', 'S', 'P')]
        [string] $Inheritance = '',

        [Parameter()]
        [switch] $Deny
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('dsacls')
    $parts.Add('"{0}"' -f $ObjectDn.Trim())

    if ($Inheritance) {
        $parts.Add('/I:{0}' -f $Inheritance)
    }

    $parts.Add($(if ($Deny) { '/D' } else { '/G' }))
    $parts.Add(('"{0}:{1}"' -f $Trustee.Trim(), $Rights.Trim()))

    return ($parts -join ' ')
}

<#
.SYNOPSIS
    The permission presets for the icacls builder: a label and its simple right.

.OUTPUTS
    PSCustomObject[] with Label and Right.
#>
function Get-TkIcaclsPermission {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $permission = {
        param($label, $right)
        [pscustomobject] @{ Label = $label; Right = $right }
    }

    return @(
        (& $permission 'Full control'   'F')
        (& $permission 'Modify'         'M')
        (& $permission 'Read & execute' 'RX')
        (& $permission 'Read'           'R')
        (& $permission 'Write'          'W')
        (& $permission 'Custom'         '')
    )
}

<#
.SYNOPSIS
    Builds an icacls command line that sets NTFS permissions on a path.

.DESCRIPTION
    icacls edits the access control list of a file or folder. A grant or a deny
    is written as "trustee:(inheritance)(rights)", where the inheritance flags,
    such as (OI)(CI) for this folder, its subfolders and its files, decide what a
    folder's entry applies to. Reset restores inheritance from the parent, and
    remove strips the trustee's entries. /T applies the change through the tree
    that already exists, /C carries on past an error, and /Q stays quiet.

.PARAMETER Path
    The file or folder, quoted in the command.

.PARAMETER Action
    Grant, Deny, Remove or Reset.

.PARAMETER Trustee
    Who the entry is for: DOMAIN\User, a UPN or a SID. Not used by Reset.

.PARAMETER Permission
    The simple right, such as F, M, RX, R or W, or a specific list in parentheses.

.PARAMETER Inheritance
    The inheritance flags, such as (OI)(CI), or empty for this folder only.

.PARAMETER Recurse
    Apply through the existing tree (/T).

.PARAMETER ContinueOnError
    Carry on past a failure (/C).

.PARAMETER Quiet
    Suppress the success messages (/Q).

.OUTPUTS
    System.String
#>
function Build-TkIcaclsCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [ValidateSet('Grant', 'Deny', 'Remove', 'Reset')]
        [string] $Action = 'Grant',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Trustee = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Permission = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Inheritance = '',

        [Parameter()]
        [switch] $Recurse,

        [Parameter()]
        [switch] $ContinueOnError,

        [Parameter()]
        [switch] $Quiet
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('icacls')
    $parts.Add('"{0}"' -f $Path.Trim())

    switch ($Action) {

        'Reset'  { $parts.Add('/reset') }

        'Remove' { $parts.Add('/remove "{0}"' -f $Trustee.Trim()) }

        default  {
            $flag = if ($Action -eq 'Deny') { '/deny' } else { '/grant' }
            $parts.Add(('{0} "{1}:{2}{3}"' -f $flag, $Trustee.Trim(), $Inheritance, $Permission))
        }
    }

    if ($Recurse)         { $parts.Add('/T') }
    if ($ContinueOnError) { $parts.Add('/C') }
    if ($Quiet)           { $parts.Add('/Q') }

    return ($parts -join ' ')
}

# ---------------------------------------------------------------------------
# JSON and YAML
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Removes the whitespace between the tokens of a JSON text.

.DESCRIPTION
    Walks the characters so that spaces inside a string are kept and only the
    layout between tokens is dropped. It is the mirror of Format-TkJsonText and,
    like it, never re-reads the document, so numbers and dates stay exactly as
    written.

.PARAMETER Json
    A valid JSON text.

.OUTPUTS
    System.String
#>
function Compress-TkJsonText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Json
    )

    $builder  = New-Object System.Text.StringBuilder
    $inString = $false
    $escaped  = $false

    foreach ($character in $Json.ToCharArray()) {

        if ($inString) {
            [void] $builder.Append($character)
            if ($escaped) { $escaped = $false }
            elseif ($character -eq '\') { $escaped = $true }
            elseif ($character -eq '"') { $inString = $false }
            continue
        }

        if ($character -eq '"') {
            $inString = $true
            [void] $builder.Append($character)
            continue
        }

        if ([char]::IsWhiteSpace($character)) {
            continue
        }

        [void] $builder.Append($character)
    }

    return $builder.ToString()
}

<#
.SYNOPSIS
    Says whether a text is valid JSON, and why not when it is not.

.OUTPUTS
    PSCustomObject with Valid and Error.
#>
function Test-TkJsonText {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Json
    )

    if (-not $Json.Trim()) {
        return [pscustomobject] @{ Valid = $false; Error = 'The text is empty.' }
    }

    try {
        $null = ConvertFrom-Json -InputObject $Json -ErrorAction Stop
        return [pscustomobject] @{ Valid = $true; Error = '' }
    }
    catch {
        return [pscustomobject] @{ Valid = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Turns an object read from JSON into YAML.

.DESCRIPTION
    Walks the object graph, writing mappings and sequences with two-space
    indentation and quoting scalars only when YAML would otherwise misread them,
    through ConvertTo-TkYamlScalar. An empty mapping is written {} and an empty
    sequence [].

.PARAMETER InputObject
    The object, as ConvertFrom-Json returns it.

.PARAMETER Indent
    The current depth, for the recursion.

.OUTPUTS
    System.String
#>
function ConvertTo-TkYamlFromObject {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [int] $Indent = 0
    )

    $pad   = '  ' * $Indent
    $lines = New-Object System.Collections.Generic.List[string]

    $isMap = $InputObject -is [System.Management.Automation.PSCustomObject] -or $InputObject -is [hashtable]
    $isSeq = $InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]

    if ($isMap) {

        $properties = if ($InputObject -is [hashtable]) {
            $InputObject.Keys | ForEach-Object { [pscustomobject] @{ Name = $_; Value = $InputObject[$_] } }
        }
        else {
            $InputObject.PSObject.Properties | ForEach-Object { [pscustomobject] @{ Name = $_.Name; Value = $_.Value } }
        }

        $properties = @($properties)
        if ($properties.Count -eq 0) { return '{}' }

        foreach ($property in $properties) {
            $key      = ConvertTo-TkYamlScalar -Value ([string] $property.Name)
            $childMap = $property.Value -is [System.Management.Automation.PSCustomObject] -or $property.Value -is [hashtable]
            $childSeq = $property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string]
            $hasChild = ($childMap -and @($property.Value.PSObject.Properties).Count -gt 0) -or ($childSeq -and @($property.Value).Count -gt 0)

            if ($hasChild) {
                $lines.Add(('{0}{1}:' -f $pad, $key))
                $lines.Add((ConvertTo-TkYamlFromObject -InputObject $property.Value -Indent ($Indent + 1)))
            }
            else {
                $lines.Add(('{0}{1}: {2}' -f $pad, $key, (ConvertTo-TkYamlFromObject -InputObject $property.Value -Indent $Indent)))
            }
        }

        return ($lines -join [Environment]::NewLine)
    }

    if ($isSeq) {

        $items = @($InputObject)
        if ($items.Count -eq 0) { return '[]' }

        foreach ($item in $items) {
            $childMap = $item -is [System.Management.Automation.PSCustomObject] -or $item -is [hashtable]
            $childSeq = $item -is [System.Collections.IEnumerable] -and $item -isnot [string]

            if (($childMap -and @($item.PSObject.Properties).Count -gt 0) -or ($childSeq -and @($item).Count -gt 0)) {
                # A nested block under the dash, indented one deeper and with the
                # leading pad of its first line replaced by the dash.
                $block = ConvertTo-TkYamlFromObject -InputObject $item -Indent ($Indent + 1)
                $first = ($block -split "`n", 2)[0].TrimStart()
                $lines.Add(('{0}- {1}' -f $pad, $first))
                $rest = ($block -split "`n", 2)
                if ($rest.Count -gt 1) { $lines.Add($rest[1].TrimEnd()) }
            }
            else {
                $lines.Add(('{0}- {1}' -f $pad, (ConvertTo-TkYamlFromObject -InputObject $item -Indent $Indent)))
            }
        }

        return ($lines -join [Environment]::NewLine)
    }

    # A scalar.
    return ConvertTo-TkYamlScalar -Value $InputObject
}

<#
.SYNOPSIS
    Converts a JSON text, then, on the operation, formats, minifies, validates
    or turns it into YAML or CSV.

.PARAMETER Json
    The JSON text.

.PARAMETER Operation
    Format, Minify, Validate, Yaml or Csv.

.OUTPUTS
    System.String
#>
function Convert-TkJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Json,

        [Parameter(Mandatory)]
        [ValidateSet('Format', 'Minify', 'Validate', 'Yaml', 'Csv')]
        [string] $Operation
    )

    if ($Operation -eq 'Validate') {
        $test = Test-TkJsonText -Json $Json
        if ($test.Valid) { return 'Valid JSON.' }
        return 'Not valid JSON: {0}' -f $test.Error
    }

    $test = Test-TkJsonText -Json $Json
    if (-not $test.Valid) {
        return 'Not valid JSON: {0}' -f $test.Error
    }

    switch ($Operation) {

        'Format' { return Format-TkJsonText -Json $Json }
        'Minify' { return Compress-TkJsonText -Json $Json }

        'Yaml' {
            $object = ConvertFrom-Json -InputObject $Json
            return ConvertTo-TkYamlFromObject -InputObject $object
        }

        'Csv' {
            $object = ConvertFrom-Json -InputObject $Json
            $rows   = @($object)

            if ($rows.Count -eq 0 -or ($rows | Where-Object { $_ -isnot [System.Management.Automation.PSCustomObject] })) {
                return 'CSV needs a JSON array of flat objects, such as [ { "name": "a", "id": 1 }, ... ].'
            }

            return (($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine)
        }
    }
}
