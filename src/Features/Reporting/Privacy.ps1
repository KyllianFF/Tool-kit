<#
    Toolkit - Features / Reporting: privacy of exports

    A report, a support bundle or an intervention report leaves the machine:
    to a vendor, a forum, a colleague or a provider. What it says about the
    machine is the point; who uses it, what it is called and where it sits on
    the network usually is not. This replaces those values, in the final text
    of an export, by stable pseudonyms: the same value gets the same alias
    everywhere in one export, so the report stays readable (USER-1 is the same
    account in every section) without naming anyone.

    Levels:
      None      nothing is replaced, as before.
      Personal  the names of this computer and of its accounts, profile
                folders, e-mail addresses, account SIDs and hardware serial
                numbers.
      Strict    also IP and MAC addresses, the names of the saved Wi-Fi
                networks and the domain names of this machine.

    The replacement works from patterns and from the values this machine is
    known by. It reduces what an export discloses; it cannot promise that
    nothing identifying is left, so the interface says "reduced", never
    "anonymous". Built-in account names and special addresses (loopback,
    APIPA, masks) are kept: they name nobody and they carry diagnostic
    meaning. The table from the aliases back to the real values stays on this
    PC, encrypted with DPAPI for this Windows account, so an answer about
    "PC-1" can still be matched.
#>

<#
.SYNOPSIS
    Names that are never replaced: built-in accounts and profile folders, and generic account names.

.DESCRIPTION
    A generic name (admin, test, support, scan) names nobody, and it is also
    an ordinary word: replaced everywhere, it would turn Test-NetConnection
    or a "throughput test" in a log into an alias.

.OUTPUTS
    System.String[]
#>
function Get-TkPrivacyKeptName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'Administrator', 'Administrateur', 'Administrador', ('Administrat' + [char] 0x00F6 + 'r'), 'Guest', ('Invit' + [char] 0x00E9), 'Invitado', 'Gast',
        'DefaultAccount', 'WDAGUtilityAccount', 'defaultuser0', 'defaultuser100000', 'Public', 'Default', 'Default User', 'All Users',
        'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'Users', 'Everyone', 'Administrators',
        'admin', 'user', 'utilisateur', 'test', 'demo', 'support', 'helpdesk', 'tech', 'technicien', 'scan', 'scanner', 'backup', 'sauvegarde',
        'service', 'install', 'setup', 'maintenance', 'kiosk', 'temp', 'owner', 'home', 'office', 'lab'
    )
}

<#
.SYNOPSIS
    The values this machine is known by: its names, accounts, serial numbers and networks.

.DESCRIPTION
    Read once per export. The Wi-Fi networks and the domains are only read
    for the strict level. Every source is optional: what cannot be read is
    left out, and the patterns still apply.

.OUTPUTS
    PSCustomObject with Computers, Users, Serials, Domains and Networks.
#>
function Get-TkRedactionSeed {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('Personal', 'Strict')]
        [string] $Level = 'Personal'
    )

    $cim = { param($class, $filter) try { if ($filter) { @(Get-CimInstance -ClassName $class -Filter $filter -ErrorAction Stop) } else { @(Get-CimInstance -ClassName $class -ErrorAction Stop) } } catch { @() } }

    $computers = @($env:COMPUTERNAME, $(try { [System.Net.Dns]::GetHostName() } catch { '' }))

    $users = New-Object System.Collections.Generic.List[string]
    $users.Add([string] $env:USERNAME)
    foreach ($folder in @(Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($env:SystemDrive + '\', 'Users')) -Directory -ErrorAction SilentlyContinue)) { $users.Add($folder.Name) }
    foreach ($account in (& $cim 'Win32_UserAccount' 'LocalAccount=True')) {
        $users.Add([string] $account.Name)
        if ($account.FullName) { $users.Add([string] $account.FullName) }
    }

    $serials = New-Object System.Collections.Generic.List[string]
    foreach ($item in (& $cim 'Win32_BIOS' '')) { $serials.Add([string] $item.SerialNumber) }
    foreach ($item in (& $cim 'Win32_BaseBoard' '')) { $serials.Add([string] $item.SerialNumber) }
    foreach ($item in (& $cim 'Win32_SystemEnclosure' '')) { $serials.Add([string] $item.SerialNumber); $serials.Add([string] $item.SMBIOSAssetTag) }
    foreach ($item in (& $cim 'Win32_ComputerSystemProduct' '')) { $serials.Add([string] $item.IdentifyingNumber); $serials.Add([string] $item.UUID) }
    foreach ($item in (& $cim 'Win32_DiskDrive' '')) { $serials.Add([string] $item.SerialNumber) }

    $domains  = New-Object System.Collections.Generic.List[string]
    $networks = New-Object System.Collections.Generic.List[string]

    if ($Level -eq 'Strict') {
        $domains.Add([string] $env:USERDNSDOMAIN)
        if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { $domains.Add([string] $env:USERDOMAIN) }
        foreach ($system in (& $cim 'Win32_ComputerSystem' '')) { if ($system.PartOfDomain) { $domains.Add([string] $system.Domain) } }
        try { $domains.Add([string] (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction Stop).Domain) } catch { $null = $_ }

        foreach ($name in @(Get-TkSavedWifiName)) { $networks.Add($name) }
    }

    return (ConvertTo-TkRedactionSeed -Computers $computers -Users @($users.ToArray()) -Serials @($serials.ToArray()) -Domains @($domains.ToArray()) -Networks @($networks.ToArray()))
}

<#
.SYNOPSIS
    Cleans the raw seed values: trims them, drops placeholders, built-in names and duplicates.

.DESCRIPTION
    Pure. A value shorter than three characters, or one a vendor writes
    instead of a real serial ("To be filled by O.E.M."), would replace
    ordinary words, so it is left out.

.OUTPUTS
    PSCustomObject with Computers, Users, Serials, Domains and Networks.
#>
function ConvertTo-TkRedactionSeed {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [string[]] $Computers = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [string[]] $Users = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [string[]] $Serials = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [string[]] $Domains = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [string[]] $Networks = @()
    )

    $kept        = @(Get-TkPrivacyKeptName)
    $placeholder = '(?i)^(to be filled.*|default string|system serial number|chassis serial number|base board serial number|serial number|none|n/?a|not specified|not applicable|o\.?e\.?m\.?|0+|x+|f+|1234567890?|[0-9a-f]{8}-0{4}-0{4}-0{4}-0{12}|0{8}-0{4}-0{4}-0{4}-0{12}|f{8}-f{4}-f{4}-f{4}-f{12})$'

    $clean = {
        param($values, [switch] $Serial)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        @(foreach ($value in @($values)) {
            $text = ([string] $value).Trim().TrimEnd('.')
            if ($text.Length -lt 3) { continue }
            if ($kept -contains $text) { continue }
            if ($Serial -and $text -match $placeholder) { continue }
            if ($seen.Add($text)) { $text }
        })
    }

    return [pscustomobject] @{
        Computers = @(& $clean $Computers)
        Users     = @(& $clean $Users)
        Serials   = @(& $clean $Serials -Serial)
        Domains   = @(& $clean $Domains)
        Networks  = @(& $clean $Networks)
    }
}

<#
.SYNOPSIS
    The names of the Wi-Fi networks this PC remembers, for the strict level.

.OUTPUTS
    System.String[]
#>
function Get-TkSavedWifiName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    try {
        if (-not (Initialize-TkWlanApi)) { return @() }
        $failure    = 0
        $interfaces = @(ConvertFrom-TkWlanInterfaceList -Bytes ([TkWlanApi]::EnumInterfaces([ref] $failure)))
        return @(foreach ($interface in $interfaces) {
            $failure = 0
            @(ConvertFrom-TkWlanProfileList -Bytes ([TkWlanApi]::GetProfileList($interface.Guid, [ref] $failure))) | ForEach-Object { [string] $_.Name }
        })
    }
    catch {
        return @()
    }
}

<#
.SYNOPSIS
    Starts the pseudonymisation of one export.

.DESCRIPTION
    The known values get their aliases first, in a fixed order, so the same
    machine gives the same aliases in every export of the same level: this
    computer is PC-1, its first account USER-1. Values found by pattern get
    the next free alias as they are met.

.PARAMETER Seed
    The values to replace, from Get-TkRedactionSeed. Read when not given.

.OUTPUTS
    PSCustomObject: the session, to pass to Protect-TkText.
#>
function New-TkRedactionSession {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Personal', 'Strict')]
        [string] $Level,

        [Parameter()]
        [AllowNull()]
        [object] $Seed = $null
    )

    if (-not $Seed) { $Seed = Get-TkRedactionSeed -Level $Level }

    $session = [pscustomobject] @{
        Level    = $Level
        Entries  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
        Counters = @{}
        Known    = New-Object System.Collections.Generic.List[object]
        Replaced = 0
    }

    $groups = @(
        @{ Values = $Seed.Computers; Kind = 'PC' }
        @{ Values = $Seed.Users;     Kind = 'USER' }
        @{ Values = $Seed.Serials;   Kind = 'SERIAL' }
    )
    if ($Level -eq 'Strict') {
        $groups += @{ Values = $Seed.Domains;  Kind = 'DOMAIN' }
        $groups += @{ Values = $Seed.Networks; Kind = 'WIFI' }
    }

    foreach ($group in $groups) {
        foreach ($value in @($group.Values | Where-Object { $_ })) {
            [void] (Get-TkPseudonym -Session $session -Value $value -Kind $group.Kind -Silent)
            $session.Known.Add([pscustomobject] @{ Value = [string] $value; Kind = $group.Kind })
        }
    }

    return $session
}

<#
.SYNOPSIS
    The alias of a value in a session, assigned on first use.

.PARAMETER Silent
    Assigns without counting a replacement: for the aliases given up front.

.OUTPUTS
    System.String
#>
function Get-TkPseudonym {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Session,
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter()] [switch] $Silent
    )

    $key = '{0}|{1}' -f $Kind, $Value
    if (-not $Session.Entries.ContainsKey($key)) {
        $number = 1 + [int] $Session.Counters[$Kind]
        $Session.Counters[$Kind] = $number
        $Session.Entries[$key] = [pscustomobject] @{ Alias = '{0}-{1}' -f $Kind, $number; Value = $Value; Kind = $Kind; Used = $false }
    }

    $entry = $Session.Entries[$key]
    if (-not $Silent) { $entry.Used = $true; $Session.Replaced++ }
    return $entry.Alias
}

<#
.SYNOPSIS
    Says whether an IPv4 address names nobody: loopback, APIPA, multicast, broadcast, a mask.

.OUTPUTS
    System.Boolean
#>
function Test-TkNeutralIPv4 {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [byte[]] $Octet
    )

    # 224 and above: multicast, reserved, the broadcast address and every
    # subnet mask (255.x.x.x); 0 the unspecified; 127 loopback; 169.254 APIPA.
    if ($Octet[0] -eq 0 -or $Octet[0] -eq 127 -or $Octet[0] -ge 224) { return $true }
    return ($Octet[0] -eq 169 -and $Octet[1] -eq 254)
}

<#
.SYNOPSIS
    Replaces, in a text, what the session's level covers.

.DESCRIPTION
    Pure apart from the session it updates. Works on the final text of an
    export, whatever its form: JSON (with its doubled backslashes), HTML,
    CSV or plain text. The aliases hold only letters, digits and dashes, so
    replacing never breaks the quoting of the format around them.

.OUTPUTS
    System.String
#>
function Protect-TkText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [pscustomobject] $Session
    )

    if (-not $Text) { return $Text }

    # Each evaluator runs at once, inside Replace, so it reads the loop
    # variables of the current pass directly.
    $result = $Text
    $edge   = '[\p{L}\p{Nd}_]'

    # --- E-mail addresses first: whole, before a domain inside them is replaced
    $result = [regex]::Replace($result, '(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,24}(?![A-Z0-9-])', {
        param($m)
        if ($m.Value -like '*@example.invalid') { return $m.Value }
        (Get-TkPseudonym -Session $Session -Value $m.Value -Kind 'EMAIL') + '@example.invalid'
    })

    # --- The values this machine is known by, the longest first ------------
    $known = @($Session.Known | Where-Object { $_.Kind -ne 'DOMAIN' } | Sort-Object -Property @{ Expression = { $_.Value.Length }; Descending = $true })
    foreach ($item in $known) {
        $pattern = '(?i)(?<!{0}){1}(?!{0})' -f $edge, [regex]::Escape($item.Value)
        $kind    = $item.Kind
        $value   = $item.Value
        $result  = [regex]::Replace($result, $pattern, { param($m) $null = $m; Get-TkPseudonym -Session $Session -Value $value -Kind $kind })
    }

    # --- Domains, with the host names under them --------------------------
    foreach ($item in @($Session.Known | Where-Object { $_.Kind -eq 'DOMAIN' } | Sort-Object -Property @{ Expression = { $_.Value.Length }; Descending = $true })) {
        $value   = $item.Value
        $pattern = '(?i)(?<![\p{{L}}\p{{Nd}}_.-])((?:[A-Za-z0-9-]+\.)*){0}(?![\p{{L}}\p{{Nd}}_-])' -f [regex]::Escape($value)
        $result  = [regex]::Replace($result, $pattern, {
            param($m)
            $prefix = $m.Groups[1].Value
            $domain = Get-TkPseudonym -Session $Session -Value $value -Kind 'DOMAIN'
            if (-not $prefix -or $prefix -match '^(PC|USER|HOST)-\d+\.$') { return $prefix + $domain }
            return (Get-TkPseudonym -Session $Session -Value $prefix.TrimEnd('.') -Kind 'HOST') + '.' + $domain
        })
    }

    # --- Profile folders: C:\Users\<name>, also with JSON's doubled backslashes
    $kept   = @(Get-TkPrivacyKeptName)
    $result = [regex]::Replace($result, '(?i)([A-Z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/))([^\\/"''<>|:*?\r\n]+)', {
        param($m)
        $name = $m.Groups[2].Value
        if ($kept -contains $name -or $name -match '^USER-\d+$') { return $m.Value }
        return $m.Groups[1].Value + (Get-TkPseudonym -Session $Session -Value $name -Kind 'USER')
    })

    # --- Account SIDs: the domain or machine part, the RID kept -------------
    $result = [regex]::Replace($result, 'S-1-5-21-(\d+-\d+-\d+)((?:-\d+)?)', {
        param($m)
        'S-1-5-21-{0}{1}' -f (Get-TkPseudonym -Session $Session -Value $m.Groups[1].Value -Kind 'SID'), $m.Groups[2].Value
    })

    if ($Session.Level -ne 'Strict') { return $result }

    # --- MAC addresses: the maker's part (OUI) kept ---------------------------
    $result = [regex]::Replace($result, '(?i)(?<![0-9a-f:-])([0-9a-f]{2})([:-])([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})(?![0-9a-f:-])', {
        param($m)
        $first = [Convert]::ToByte($m.Groups[1].Value, 16)
        $flat  = ($m.Value -replace '[:-]', '').ToUpperInvariant()
        if (($first -band 1) -eq 1 -or $flat -eq '000000000000' -or $flat -eq 'FFFFFFFFFFFF') { return $m.Value }
        $number = (Get-TkPseudonym -Session $Session -Value $flat -Kind 'MAC').Substring(4)
        return ('MAC-{0}-{1}' -f $flat.Substring(0, 6), $number)
    })

    # --- IPv4 addresses ---------------------------------------------------------
    $result = [regex]::Replace($result, '(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])', {
        param($m)
        $parts = @($m.Value -split '\.')
        foreach ($part in $parts) { if ([int] $part -gt 255) { return $m.Value } }

        # Ending in .0: a network address, or a version number such as 5.1.0.0.
        if ([int] $parts[3] -eq 0) { return $m.Value }
        $octet = [byte[]] @($parts | ForEach-Object { [byte] $_ })
        if (Test-TkNeutralIPv4 -Octet $octet) { return $m.Value }
        $private = $octet[0] -eq 10 -or ($octet[0] -eq 172 -and $octet[1] -ge 16 -and $octet[1] -le 31) -or
                   ($octet[0] -eq 192 -and $octet[1] -eq 168) -or ($octet[0] -eq 100 -and $octet[1] -ge 64 -and $octet[1] -le 127)
        Get-TkPseudonym -Session $Session -Value $m.Value -Kind $(if ($private) { 'PRIVATE-IP' } else { 'PUBLIC-IP' })
    })

    # --- IPv6 addresses ---------------------------------------------------------
    $result = [regex]::Replace($result, '(?i)(?<![0-9a-f:.\w])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(%[0-9a-z]+)?(?![0-9a-f:\w])', {
        param($m)
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($m.Groups[1].Value, [ref] $address)) { return $m.Value }
        if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $m.Value }
        if ($address.Equals([System.Net.IPAddress]::IPv6Any) -or $address.Equals([System.Net.IPAddress]::IPv6Loopback)) { return $m.Value }
        Get-TkPseudonym -Session $Session -Value $address.ToString() -Kind 'IPV6'
    })

    return $result
}

<#
.SYNOPSIS
    Encrypts or decrypts bytes for this Windows account (DPAPI).

.OUTPUTS
    System.Byte[]
#>
function Protect-TkUserData {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter()] [switch] $Decrypt
    )

    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        Add-Type -AssemblyName System.Security
    }

    $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    if ($Decrypt) { return , [System.Security.Cryptography.ProtectedData]::Unprotect($Bytes, $null, $scope) }
    return , [System.Security.Cryptography.ProtectedData]::Protect($Bytes, $null, $scope)
}

<#
.SYNOPSIS
    The folder of the tables from aliases back to real values.

.OUTPUTS
    System.String
#>
function Get-TkPrivacyFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return [System.IO.Path]::Combine((Get-TkContext).DataRoot, 'privacy')
}

<#
.SYNOPSIS
    Saves the aliases one export used, encrypted for this Windows account.

.OUTPUTS
    System.String, the path of the table, or empty when nothing was replaced.
#>
function Save-TkRedactionMap {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Session,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter()] [string] $Folder = (Get-TkPrivacyFolder)
    )

    $used = @($Session.Entries.Values | Where-Object { $_.Used })
    if ($used.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($Folder, 'Save the pseudonym table')) { return '' }

    $table = [ordered] @{
        Schema  = 'toolkit-privacy-map'
        Label   = $Label
        Level   = $Session.Level
        Created = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        Entries = @($used | ForEach-Object { [ordered] @{ Alias = $_.Alias; Value = $_.Value; Kind = $_.Kind } })
    }

    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    $name = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ($Label -replace '[^A-Za-z0-9-]+', '-').Trim('-')
    $path = [System.IO.Path]::Combine($Folder, $name + '.map')

    # Two exports in the same second: the second table must not replace the first.
    for ($number = 2; [System.IO.File]::Exists($path); $number++) { $path = [System.IO.Path]::Combine($Folder, ('{0}-{1}.map' -f $name, $number)) }
    $data = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $table -Depth 4))
    [System.IO.File]::WriteAllBytes($path, (Protect-TkUserData -Bytes $data))
    return $path
}

<#
.SYNOPSIS
    Finds what an alias stood for, in the tables of this PC, the newest first.

.OUTPUTS
    PSCustomObject[] with Alias, Value, Kind, Export and Created.
#>
function Find-TkPseudonym {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Alias,
        [Parameter()] [string] $Folder = (Get-TkPrivacyFolder),
        [Parameter()] [int] $Maximum = 10
    )

    $wanted = $Alias.Trim()
    if ($wanted -match '^(EMAIL-\d+)@example\.invalid$') { $wanted = $Matches[1] }
    if ($wanted -match '^MAC-[0-9A-F]{6}-(\d+)$') { $wanted = 'MAC-' + $Matches[1] }

    $found = New-Object System.Collections.Generic.List[object]
    foreach ($file in @(Get-ChildItem -LiteralPath $Folder -Filter '*.map' -File -ErrorAction SilentlyContinue | Sort-Object -Property Name -Descending)) {
        try {
            $table = [System.Text.Encoding]::UTF8.GetString((Protect-TkUserData -Bytes ([System.IO.File]::ReadAllBytes($file.FullName)) -Decrypt)) | ConvertFrom-Json
        }
        catch {
            continue
        }
        foreach ($entry in @($table.Entries)) {
            if ([string] $entry.Alias -eq $wanted) {
                $found.Add([pscustomobject] @{ Alias = [string] $entry.Alias; Value = [string] $entry.Value; Kind = [string] $entry.Kind; Export = [string] $table.Label; Created = [string] $table.Created })
            }
        }
        if ($found.Count -ge $Maximum) { break }
    }

    return @($found.ToArray())
}

<#
.SYNOPSIS
    Pseudonymises the text of one export at a level, and keeps its table.

.OUTPUTS
    PSCustomObject with Text, Level, Replaced and MapPath.
#>
function Protect-TkExportText {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [ValidateSet('None', 'Personal', 'Strict')] [string] $Level,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter()] [AllowNull()] [object] $Seed = $null,
        [Parameter()] [string] $Folder = (Get-TkPrivacyFolder)
    )

    if ($Level -eq 'None') {
        return [pscustomobject] @{ Text = $Text; Level = $Level; Replaced = 0; MapPath = '' }
    }

    $session = New-TkRedactionSession -Level $Level -Seed $Seed
    $text    = Protect-TkText -Text $Text -Session $session
    $map     = Save-TkRedactionMap -Session $session -Label $Label -Folder $Folder -Confirm:$false

    return [pscustomobject] @{ Text = $text; Level = $Level; Replaced = $session.Replaced; MapPath = $map }
}

<#
.SYNOPSIS
    Pseudonymises every text file of a folder with one session, before it is packed.

.OUTPUTS
    PSCustomObject with Level, Replaced and MapPath.
#>
function Protect-TkExportFolder {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [ValidateSet('None', 'Personal', 'Strict')] [string] $Level,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter()] [AllowNull()] [object] $Seed = $null,
        [Parameter()] [string] $Folder = (Get-TkPrivacyFolder)
    )

    if ($Level -eq 'None' -or -not $PSCmdlet.ShouldProcess($Path, 'Pseudonymise the export')) {
        return [pscustomobject] @{ Level = $Level; Replaced = 0; MapPath = '' }
    }

    $session = New-TkRedactionSession -Level $Level -Seed $Seed
    $utf8    = New-Object System.Text.UTF8Encoding($false)

    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Recurse | Where-Object { $_.Extension -match '^\.(txt|log|json|csv|html?|xml)$' })) {
        $text = [System.IO.File]::ReadAllText($file.FullName)
        [System.IO.File]::WriteAllText($file.FullName, (Protect-TkText -Text $text -Session $session), $utf8)
    }

    $map = Save-TkRedactionMap -Session $session -Label $Label -Folder $Folder -Confirm:$false
    return [pscustomobject] @{ Level = $Level; Replaced = $session.Replaced; MapPath = $map }
}

<#
.SYNOPSIS
    The name an export file takes for this computer: its name, or PC-1 when pseudonymised.

.OUTPUTS
    System.String
#>
function Get-TkExportComputerName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('None', 'Personal', 'Strict')] [string] $Level
    )

    if ($Level -eq 'None') { return $env:COMPUTERNAME }
    return 'PC-1'
}

<#
.SYNOPSIS
    The sentence an export's status adds about its privacy.

.OUTPUTS
    System.String
#>
function Format-TkPrivacyNote {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [object] $Result
    )

    if (-not $Result -or $Result.Level -eq 'None') { return '' }
    if ($null -eq $Result.Replaced) {
        return (' Reduced ({0}): names and identifiers replaced by aliases; the table stays on this PC (Settings, Privacy of exports).' -f $Result.Level.ToLowerInvariant())
    }
    return (' Reduced ({0}): {1} value(s) replaced by aliases; the table stays on this PC (Settings, Privacy of exports).' -f $Result.Level.ToLowerInvariant(), $Result.Replaced)
}

<#
.SYNOPSIS
    The privacy level chosen for exports in Settings: None, Personal or Strict.

.OUTPUTS
    System.String
#>
function Get-TkExportPrivacyLevel {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $value = [string] (Get-TkContext).Settings['ExportPrivacy']
    if ($value -in @('Personal', 'Strict')) { return $value }
    return 'None'
}

<#
.SYNOPSIS
    What a level replaces on this machine, for the settings page.

.OUTPUTS
    System.String[], one line per kind.
#>
function Get-TkPrivacyPreview {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [ValidateSet('None', 'Personal', 'Strict')] [string] $Level,
        [Parameter()] [AllowNull()] [object] $Seed = $null
    )

    if ($Level -eq 'None') { return @('Nothing is replaced: exports say what the screens say.') }

    $session = New-TkRedactionSession -Level $Level -Seed $Seed
    $labels  = [ordered] @{ PC = 'This computer'; USER = 'Accounts'; SERIAL = 'Serial numbers'; DOMAIN = 'Domains'; WIFI = 'Wi-Fi networks' }
    $lines   = foreach ($kind in $labels.Keys) {
        $items = @($session.Known | Where-Object Kind -eq $kind)
        if ($items.Count -eq 0) { continue }
        $pairs = @($items | Select-Object -First 6 | ForEach-Object { '{0} as {1}' -f $_.Value, (Get-TkPseudonym -Session $session -Value $_.Value -Kind $kind -Silent) })
        $more  = if ($items.Count -gt 6) { ' and {0} more' -f ($items.Count - 6) } else { '' }
        '{0}: {1}{2}' -f $labels[$kind], ($pairs -join ', '), $more
    }

    $patterns = 'Found in the text: profile folders, e-mail addresses (as EMAIL-n@example.invalid) and account SIDs (the machine or domain part replaced, the RID kept)'
    if ($Level -eq 'Strict') { $patterns += ', IP addresses (PRIVATE-IP-n, PUBLIC-IP-n, IPV6-n), MAC addresses (the maker part kept) and the host names of the domains' }
    return @(@($lines) + ($patterns + '.'))
}
