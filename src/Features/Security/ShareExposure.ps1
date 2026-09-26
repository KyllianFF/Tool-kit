<#
    Toolkit - Features / Shared folders

    What this PC shares on the network, and who can reach it. A folder shared
    years ago "to pass a file" and left with Everyone on it is one of the most
    common ways data leaves a workstation, and nothing in Windows reminds
    anyone it is there.

    Access over the network is the stricter of two layers: the permissions of
    the share, and the NTFS permissions of the folder behind it. A share that
    grants Everyone full control is only held back by NTFS; when both let a
    broad group write, anyone on the network in that group can.

    Everything is read by security identifier, never by account name, which
    Windows translates ("Tout le monde" is Everyone): the same code judges a
    French and an English machine. Read only, and readable by a standard user.
#>

<#
.SYNOPSIS
    Names a security identifier that stands for many people, or returns nothing.

.DESCRIPTION
    The groups that make a share reach beyond named accounts: everyone,
    anonymous connections, every authenticated user, every local or domain
    user, guests. On a workgroup PC the local group ending in 513 ("None")
    holds every local account.

.OUTPUTS
    System.String, or $null for a SID that is not one of these.
#>
function Get-TkBroadSidName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Sid
    )

    switch -Regex ($Sid) {
        '^S-1-1-0$'                       { return 'Everyone' }
        '^S-1-5-7$'                       { return 'Anonymous' }
        '^S-1-5-2$'                       { return 'Network' }
        '^S-1-5-11$'                      { return 'Authenticated Users' }
        '^S-1-5-32-545$'                  { return 'Users' }
        '^S-1-5-32-546$'                  { return 'Guests' }
        '^S-1-5-21-\d+-\d+-\d+-513$'      { return 'Domain Users' }
        '^S-1-5-21-\d+-\d+-\d+-514$'      { return 'Domain Guests' }
        '^S-1-5-21-\d+-\d+-\d+-515$'      { return 'Domain Computers' }
    }

    return $null
}

<#
.SYNOPSIS
    Names any security identifier for display: the account, or the group.
#>
function Get-TkShareSidName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Sid
    )

    $broad = Get-TkBroadSidName -Sid $Sid

    if ($broad) {
        return $broad
    }

    # A person or a group someone created: its own name, as Windows has it.
    # A built-in group: its English name, the same on every machine rather
    # than "BUILTIN\Administrateurs" beside "Everyone".
    $account = $Sid -match '^S-1-5-21-\d+-\d+-\d+-(?<rid>\d+)$' -and [int] $Matches['rid'] -ge 1000

    if (-not $account) {
        $name = Get-TkSidFriendlyName -Sid $Sid
        if ($name -and $name -ne $Sid) { return $name }
    }

    try {
        return ([System.Security.Principal.SecurityIdentifier] $Sid).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $Sid
    }
}

<#
.SYNOPSIS
    Reads the entries of a share's security descriptor.

.DESCRIPTION
    Get-SmbShare returns the share permissions as SDDL. Each entry is turned
    into the right Windows shows for it (Full, Change, Read) and into two
    plain answers: can it write, can it read.

.PARAMETER Sddl
    The share's SecurityDescriptor.

.OUTPUTS
    PSCustomObject[] with Sid, Allow, Mask, Rights, CanWrite and CanRead.
#>
function ConvertFrom-TkShareSddl {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Sddl
    )

    if ([string]::IsNullOrWhiteSpace($Sddl)) {
        return @()
    }

    try {
        $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    }
    catch {
        return @()
    }

    $genericAll   = 0x10000000
    $genericWrite = 0x40000000
    $genericRead  = 0x80000000
    $fullFile     = 0x1F01FF
    $writeBits    = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000   # write data, append, delete, write DAC, write owner
    $readBits     = 0x1                                                     # read data

    $rules = New-Object System.Collections.Generic.List[object]

    foreach ($ace in @($descriptor.DiscretionaryAcl)) {

        if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
            continue
        }

        $mask = [long] $ace.AccessMask -band 0xFFFFFFFFL

        $full     = (($mask -band $genericAll) -ne 0) -or (($mask -band $fullFile) -eq $fullFile)
        $canWrite = $full -or (($mask -band $genericWrite) -ne 0) -or (($mask -band $writeBits) -ne 0)
        $canRead  = $full -or $canWrite -or (($mask -band $genericRead) -ne 0) -or (($mask -band $readBits) -ne 0)

        $rights = if ($full) { 'Full' } elseif ($canWrite) { 'Change' } elseif ($canRead) { 'Read' } else { 'Special' }

        $rules.Add([pscustomobject] @{
            Sid      = $ace.SecurityIdentifier.Value
            Allow    = ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed)
            Mask     = $mask
            Rights   = $rights
            CanWrite = $canWrite
            CanRead  = $canRead
        })
    }

    return @($rules.ToArray())
}

<#
.SYNOPSIS
    Lists the broad groups the NTFS permissions of a folder let write or read.

.DESCRIPTION
    Rules inherited by the folder's content count too: a group that may only
    create files inside the folder can still drop one there.

.OUTPUTS
    PSCustomObject with Readable (whether the permissions could be read),
    Write and Read (the broad groups, by name).
#>
function Get-TkNtfsBroadAccess {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    try {
        $acl   = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    }
    catch {
        return [pscustomobject] @{ Readable = $false; Write = @(); Read = @() }
    }

    $write = New-Object System.Collections.Generic.List[string]
    $read  = New-Object System.Collections.Generic.List[string]

    # Write data or create files, append or create folders, delete, change
    # permissions or owner, and the generic rights inheritable entries carry.
    $writeBits = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    $readBits  = 0x1 -bor 0x10000000 -bor 0x80000000

    foreach ($rule in $rules) {

        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }

        $name = Get-TkBroadSidName -Sid $rule.IdentityReference.Value

        if (-not $name) {
            continue
        }

        $bits = [long] $rule.FileSystemRights -band 0xFFFFFFFFL

        if (($bits -band $writeBits) -ne 0 -and -not $write.Contains($name)) { $write.Add($name) }
        if (($bits -band $readBits)  -ne 0 -and -not $read.Contains($name))  { $read.Add($name) }
    }

    return [pscustomobject] @{ Readable = $true; Write = @($write.ToArray()); Read = @($read.ToArray()) }
}

<#
.SYNOPSIS
    Judges one share from what its two layers let broad groups do.

.DESCRIPTION
    Pure, so each case is tested on its own:

      - a default administrative share: information only;
      - a broad group can write through both layers: fail, anyone in it can;
      - a broad group can write through the share, and NTFS could not be read
        or holds it back: warning, one layer is all that stops it;
      - a broad group can read through both layers: warning;
      - a hidden share of someone's own making: warning, since a $ only hides
        it from browsing, not from anyone who types its name;
      - otherwise: shared with named accounts only.

.OUTPUTS
    PSCustomObject with Severity, Heading and Note.
#>
function Get-TkShareVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [switch] $DefaultAdmin,
        [Parameter()] [AllowEmptyCollection()] [string[]] $ShareWrite = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $ShareRead  = @(),
        [Parameter()] [bool] $NtfsReadable = $true,
        [Parameter()] [AllowEmptyCollection()] [string[]] $NtfsWrite  = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $NtfsRead   = @()
    )

    $verdict = { param($severity, $heading, $note) [pscustomobject] @{ Severity = $severity; Heading = $heading; Note = $note } }

    if ($DefaultAdmin) {
        return (& $verdict 'Info' 'Default administrative share' 'Created by Windows and reachable only by administrators.')
    }

    $bothWrite = @($ShareWrite | Where-Object { $NtfsWrite -contains $_ })

    if ($bothWrite.Count -gt 0) {
        return (& $verdict 'Fail' ('{0} can write here over the network' -f ($bothWrite -join ', ')) `
            'Both the share and the folder let this group change files, so anyone on the network in it can add, change or delete them: the way a ransomware on another PC reaches this one.')
    }

    $bothRead = @($ShareRead | Where-Object { $NtfsRead -contains $_ })

    if ($ShareWrite.Count -gt 0) {
        $held = if ($NtfsReadable) { 'The folder''s NTFS permissions are all that hold them back.' } else { 'The folder''s NTFS permissions could not be read to see whether they hold them back.' }
        if ($bothRead.Count -gt 0) {
            $held += ' {0} can already read what the folder holds.' -f ($bothRead -join ', ')
        }
        return (& $verdict 'Warning' ('The share lets {0} change files' -f ($ShareWrite -join ', ')) $held)
    }

    if ($bothRead.Count -gt 0) {
        return (& $verdict 'Warning' ('{0} can read this over the network' -f ($bothRead -join ', ')) `
            'Anyone on the network in this group can open and copy what the folder holds.')
    }

    if ($Name.EndsWith('$')) {
        return (& $verdict 'Warning' 'Hidden share' 'The $ hides it from network browsing, not from anyone who types its name. Check it is still needed.')
    }

    return (& $verdict 'Pass' 'Shared with named accounts only' '')
}

<#
.SYNOPSIS
    Reads what this PC shares and who can reach each share.

.OUTPUTS
    PSCustomObject with ServerRunning and Shares (Name, Path, Kind,
    DefaultAdmin, Encrypted, Permissions, ShareWrite, ShareRead,
    NtfsReadable, NtfsWrite, Severity, Heading, Note).
#>
function Get-TkShareExposure {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $running = $false

    try {
        $running = (Get-Service -Name 'LanmanServer' -ErrorAction Stop).Status -eq 'Running'
    }
    catch {
        $null = $_
    }

    $shares = @()

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Hunting' -Message ('Could not list the SMB shares: {0}' -f $_.Exception.Message)
    }

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($share in $shares) {

        $name         = [string] $share.Name
        $path         = [string] $share.Path
        $defaultAdmin = [bool] $share.Special -and ($name -match '^([A-Za-z]\$|ADMIN\$|IPC\$|PRINT\$)$')

        $rules = @(ConvertFrom-TkShareSddl -Sddl ([string] $share.SecurityDescriptor))
        $allow = @($rules | Where-Object { $_.Allow })

        $shareWrite = @($allow | Where-Object { $_.CanWrite } | ForEach-Object { Get-TkBroadSidName -Sid $_.Sid } | Where-Object { $_ } | Select-Object -Unique)
        $shareRead  = @($allow | Where-Object { $_.CanRead }  | ForEach-Object { Get-TkBroadSidName -Sid $_.Sid } | Where-Object { $_ } | Select-Object -Unique)

        $permissions = @($allow | ForEach-Object { '{0}: {1}' -f (Get-TkShareSidName -Sid $_.Sid), $_.Rights })

        $ntfs = [pscustomobject] @{ Readable = $true; Write = @(); Read = @() }

        if (-not $defaultAdmin -and $path -and ($shareWrite.Count -gt 0 -or $shareRead.Count -gt 0)) {
            $ntfs = Get-TkNtfsBroadAccess -Path $path
        }

        $verdict = Get-TkShareVerdict -Name $name -DefaultAdmin:$defaultAdmin `
                                      -ShareWrite $shareWrite -ShareRead $shareRead `
                                      -NtfsReadable $ntfs.Readable -NtfsWrite $ntfs.Write -NtfsRead $ntfs.Read

        $kind = switch ([string] $share.ShareType) {
            'FileSystemDirectory' { 'Folder' }
            'PrintQueue'          { 'Printer' }
            'Ipc'                 { 'Inter-process' }
            'InterprocessCommunication' { 'Inter-process' }
            default               { [string] $share.ShareType }
        }

        $result.Add([pscustomobject] @{
            Name         = $name
            Path         = $path
            Kind         = $kind
            DefaultAdmin = $defaultAdmin
            Encrypted    = [bool] $share.EncryptData
            Permissions  = $permissions
            ShareWrite   = $shareWrite
            ShareRead    = $shareRead
            NtfsReadable = $ntfs.Readable
            NtfsWrite    = @($ntfs.Write)
            Severity     = $verdict.Severity
            Heading      = $verdict.Heading
            Note         = $verdict.Note
        })
    }

    return [pscustomobject] @{
        ServerRunning = $running
        Shares        = @($result.ToArray())
    }
}
