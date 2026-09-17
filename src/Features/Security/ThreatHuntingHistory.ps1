<#
    Toolkit - Features / Security / Threat hunting history

    Four more read-only investigations for the threat hunting page, each
    answering a question an incident asks: what was plugged in, who connected
    with Remote Desktop and where this machine connected to, what browser
    extensions are installed and what they can reach, and what Windows Defender
    has caught.

    Everything here reads: the registry, event logs and files on disk are
    examined, nothing is written or removed. What needs administrator rights to
    read (device timestamps, the Security and Terminal Services logs) is read
    where it can be and left blank where it cannot, rather than failing.
#>

# ---------------------------------------------------------------------------
# Shared: FILETIME
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads a Windows FILETIME from its eight little-endian bytes.

.PARAMETER Bytes
    The raw bytes, as a registry REG_BINARY value holds them.

.OUTPUTS
    System.DateTime in UTC, or $null when the bytes are missing or zero.
#>
function ConvertFrom-TkFileTimeBytes {
    [CmdletBinding()]
    [OutputType([System.Nullable[datetime]])]
    param(
        [Parameter()]
        [AllowNull()]
        [byte[]] $Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -lt 8) {
        return $null
    }

    $ticks = [System.BitConverter]::ToInt64($Bytes, 0)

    if ($ticks -le 0) {
        return $null
    }

    try {
        return [datetime]::FromFileTimeUtc($ticks)
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# 1. USB device history
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads the vendor, product and revision out of a USBSTOR key name.

.DESCRIPTION
    A USBSTOR device key is named like Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00.
    The underscores stand for spaces the original strings could not hold.

.PARAMETER KeyName
    The device key name.

.OUTPUTS
    PSCustomObject with Vendor, Product and Revision.
#>
function ConvertFrom-TkUsbStorId {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $KeyName
    )

    $clean = { param($text) if ($text) { ($text -replace '_', ' ').Trim() } else { '' } }

    $vendor = ''
    $product = ''
    $revision = ''

    if ($KeyName -match 'Ven_(?<v>.*?)(?:&|$)')  { $vendor   = & $clean $Matches['v'] }
    if ($KeyName -match 'Prod_(?<p>.*?)(?:&Rev_|$)') { $product = & $clean $Matches['p'] }
    if ($KeyName -match 'Rev_(?<r>.*)$')          { $revision = & $clean $Matches['r'] }

    return [pscustomobject] @{
        Vendor   = $vendor
        Product  = $product
        Revision = $revision
    }
}

<#
.SYNOPSIS
    Lists the USB mass-storage devices that have been connected to this machine.

.DESCRIPTION
    Reads HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR, where Windows keeps a
    record of every USB storage device ever attached, with its friendly name and
    serial. The first-connected, last-connected and last-removed times live in a
    Properties subkey that only administrators can read, so they are filled in
    when elevated and left blank otherwise.

.OUTPUTS
    PSCustomObject[] with Vendor, Product, Serial, FriendlyName, FirstConnected,
    LastConnected and LastRemoved.
#>
function Get-TkUsbHistory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $records = New-Object System.Collections.Generic.List[pscustomobject]

    # The property GUID that holds the connect and remove timestamps, and the
    # value names for first install, last arrival and last removal.
    $timeGuid = '{83da6326-97a6-4088-9453-a1923f573b29}'
    $timeKeys = @{ FirstConnected = '0064'; LastConnected = '0066'; LastRemoved = '0067' }

    try {
        $base = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Enum\USBSTOR')
    }
    catch {
        $base = $null
    }

    if ($null -eq $base) {
        return @()
    }

    try {
        foreach ($deviceName in $base.GetSubKeyNames()) {

            $device = $base.OpenSubKey($deviceName)
            if ($null -eq $device) { continue }

            $id = ConvertFrom-TkUsbStorId -KeyName $deviceName

            foreach ($serial in $device.GetSubKeyNames()) {

                $instance = $device.OpenSubKey($serial)
                if ($null -eq $instance) { continue }

                $friendly = [string] $instance.GetValue('FriendlyName')

                $times = @{}
                foreach ($name in $timeKeys.Keys) {
                    $times[$name] = $null
                    try {
                        $timeKey = $instance.OpenSubKey(('Properties\{0}\{1}' -f $timeGuid, $timeKeys[$name]))
                        if ($timeKey) {
                            $bytes = $timeKey.GetValue('')
                            if ($bytes -is [byte[]]) {
                                $times[$name] = ConvertFrom-TkFileTimeBytes -Bytes $bytes
                            }
                        }
                    }
                    catch {
                        # Access to the timestamps needs administrator rights.
                        $times[$name] = $null
                    }
                }

                # The serial ends in &0 for the interface; the device serial is
                # the part before it.
                $cleanSerial = ($serial -split '&')[0]

                $records.Add([pscustomobject] @{
                    Vendor         = $id.Vendor
                    Product        = $id.Product
                    Revision       = $id.Revision
                    Serial         = $cleanSerial
                    FriendlyName   = $friendly
                    FirstConnected = $times.FirstConnected
                    LastConnected  = $times.LastConnected
                    LastRemoved    = $times.LastRemoved
                })
            }
        }
    }
    catch {
        Write-TkLog -Level Debug -Category 'Hunting' -Message ('USB history read failed: {0}' -f $_.Exception.Message)
    }

    # Newest last-connected first, then by name.
    return @($records | Sort-Object -Property @{ Expression = { $_.LastConnected }; Descending = $true }, Product)
}

# ---------------------------------------------------------------------------
# 2. Remote Desktop history
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads an incoming Remote Desktop authentication event (1149).

.DESCRIPTION
    Event 1149 of the RemoteConnectionManager operational log is written when a
    Remote Desktop connection authenticates, and carries the user, the domain
    and the source network address in its first three properties.

.PARAMETER LogEvent
    An object with TimeCreated and a Properties array, as Get-WinEvent returns.

.OUTPUTS
    PSCustomObject with Time, User, Domain and SourceIp.
#>
function ConvertFrom-TkRdpLogonEvent {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $LogEvent
    )

    $values = @($LogEvent.Properties | ForEach-Object { [string] $_.Value })

    return [pscustomobject] @{
        Time     = $LogEvent.TimeCreated
        User     = if ($values.Count -gt 0) { $values[0] } else { '' }
        Domain   = if ($values.Count -gt 1) { $values[1] } else { '' }
        SourceIp = if ($values.Count -gt 2) { $values[2] } else { '' }
    }
}

<#
.SYNOPSIS
    Gathers Remote Desktop history, both incoming and outgoing.

.DESCRIPTION
    Incoming connections come from the Terminal Services RemoteConnectionManager
    log (event 1149), which needs administrator rights to read; outgoing ones
    come from the current user's own registry, the servers this account has
    connected to with the Remote Desktop client, which needs no rights at all.

.PARAMETER Days
    How far back to read the incoming connection log.

.OUTPUTS
    PSCustomObject with Incoming and Outgoing.
#>
function Get-TkRdpHistory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [int] $Days = 30
    )

    # --- Incoming ---------------------------------------------------------
    $incoming = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($logEvent in @(Get-TkWinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149 -Since (Get-Date).AddDays(-$Days))) {
        try {
            $incoming.Add((ConvertFrom-TkRdpLogonEvent -LogEvent $logEvent))
        }
        catch {
            continue
        }
    }

    # --- Outgoing ---------------------------------------------------------
    $outgoing = New-Object System.Collections.Generic.List[pscustomobject]

    try {
        $serversKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Terminal Server Client\Servers')

        if ($serversKey) {
            foreach ($server in $serversKey.GetSubKeyNames()) {
                $entry = $serversKey.OpenSubKey($server)
                $hint  = if ($entry) { [string] $entry.GetValue('UsernameHint') } else { '' }
                $outgoing.Add([pscustomobject] @{ Server = $server; UsernameHint = $hint })
            }
        }
    }
    catch {
        Write-TkLog -Level Debug -Category 'Hunting' -Message ('RDP outgoing read failed: {0}' -f $_.Exception.Message)
    }

    return [pscustomobject] @{
        Incoming = @($incoming | Sort-Object -Property Time -Descending)
        Outgoing = @($outgoing | Sort-Object -Property Server)
    }
}

# ---------------------------------------------------------------------------
# 3. Browser extensions
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Picks out the permissions of a browser extension that reach the most.

.DESCRIPTION
    Not every permission is worth a second look; these are the ones that let an
    extension read the pages you visit, watch your traffic, talk to a program on
    the machine, or read your cookies and history. Host permissions that match
    every site are treated the same way.

.PARAMETER Permissions
    The extension's permissions, host permissions included.

.OUTPUTS
    System.String[] of short reasons, empty when none stand out.
#>
function Get-TkExtensionPermissionRisk {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [string[]] $Permissions
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    $known = @{
        'tabs'                   = 'reads the pages you open'
        'webRequest'             = 'watches your web traffic'
        'webRequestBlocking'     = 'can block or change your web traffic'
        'declarativeNetRequest'  = 'can block or change your web traffic'
        'nativeMessaging'        = 'talks to a program installed on the machine'
        'cookies'                = 'reads your cookies'
        'history'                = 'reads your browsing history'
        'debugger'               = 'can attach to pages like a debugger'
        'management'             = 'can manage other extensions'
        'proxy'                  = 'can change your proxy'
        'downloads'              = 'can start downloads'
        'clipboardRead'          = 'reads the clipboard'
        'bookmarks'              = 'reads your bookmarks'
        'privacy'                = 'can change privacy settings'
    }

    foreach ($permission in @($Permissions)) {

        if (-not $permission) { continue }

        if ($known.ContainsKey($permission)) {
            $reasons.Add($known[$permission])
        }
        elseif ($permission -match '^(<all_urls>|https?://\*/|\*://\*/|https?://\*\.?\*/)') {
            $reasons.Add('can read and change every website you visit')
        }
    }

    return @($reasons | Select-Object -Unique)
}

<#
.SYNOPSIS
    Turns a Chromium extension manifest into a record.

.DESCRIPTION
    Reads the name, version and permissions from a parsed manifest.json.
    Manifest v3 keeps host permissions in their own list, and a name may be a
    __MSG_key__ placeholder resolved from the locale messages, which are passed
    in when available.

.PARAMETER Manifest
    The parsed manifest object.

.PARAMETER LocaleMessages
    The parsed messages.json for the default locale, or $null.

.OUTPUTS
    PSCustomObject with Name, Version and Permissions.
#>
function ConvertFrom-TkChromeExtensionManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $Manifest,

        [Parameter()]
        [AllowNull()]
        [object] $LocaleMessages
    )

    $name = [string] $Manifest.name

    if ($name -match '^__MSG_(?<key>.+)__$' -and $LocaleMessages) {
        $key = $Matches['key']
        $message = $LocaleMessages.$key
        if ($message -and $message.message) {
            $name = [string] $message.message
        }
    }

    $permissions = New-Object System.Collections.Generic.List[string]
    foreach ($group in @('permissions', 'host_permissions', 'optional_permissions')) {
        if ($Manifest.PSObject.Properties[$group]) {
            foreach ($value in @($Manifest.$group)) {
                if ($value -is [string]) { $permissions.Add($value) }
            }
        }
    }

    return [pscustomobject] @{
        Name        = $name
        Version     = [string] $Manifest.version
        Permissions = @($permissions)
    }
}

<#
.SYNOPSIS
    Turns a Firefox add-on entry into a record, or nothing for a built-in one.

.PARAMETER Addon
    One entry of the addons array from extensions.json.

.OUTPUTS
    PSCustomObject with Name, Version, Enabled and Permissions, or $null.
#>
function ConvertFrom-TkFirefoxExtension {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $Addon
    )

    if ([string] $Addon.type -ne 'extension') {
        return $null
    }

    # Built-in and system add-ons are not user-installed.
    if ([string] $Addon.location -in @('app-builtin', 'app-system-defaults', 'app-system-addons')) {
        return $null
    }

    $name = if ($Addon.defaultLocale -and $Addon.defaultLocale.name) { [string] $Addon.defaultLocale.name } else { [string] $Addon.id }

    $permissions = New-Object System.Collections.Generic.List[string]
    if ($Addon.userPermissions) {
        foreach ($group in @('permissions', 'origins')) {
            foreach ($value in @($Addon.userPermissions.$group)) {
                if ($value -is [string]) { $permissions.Add($value) }
            }
        }
    }

    return [pscustomobject] @{
        Name        = $name
        Id          = [string] $Addon.id
        Version     = [string] $Addon.version
        Enabled     = -not [bool] $Addon.userDisabled
        Permissions = @($permissions)
    }
}

<#
.SYNOPSIS
    Names a well-known browser extension from its store id.

.DESCRIPTION
    The extension id is the folder name, which stays readable even when the
    manifest inside cannot be read, so a short list of the most common ids lets
    an extension be named when its manifest is locked.

.PARAMETER Id
    The extension id.

.OUTPUTS
    System.String, empty when the id is not in the list.
#>
function Get-TkKnownExtensionName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Id
    )

    $map = @{
        'cjpalhdlnbpafiamejdnhcphjbkeiagm' = 'uBlock Origin'
        'ddkjiahejlhfcafbddmgiahcphecmpfh' = 'uBlock Origin Lite'
        'nngceckbapebfimnlniiiahkandclblb' = 'Bitwarden'
        'jbkfoedolllekgbhcbcoahefnbanhhlh' = 'Bitwarden'
        'aeblfdkhhhdcdjpifhhbdiojplfjncoa' = '1Password'
        'dppgmdbiimibapkepcbdbmkaabgiofem' = '1Password'
        'hdokiejnpimakedhajhdlcegeplioahd' = 'LastPass'
        'fdjamakpfbbddfjaooikfcpapjohcfmg' = 'Dashlane'
        'oboonakemofpalcgghocfoadofidjkkk' = 'KeePassXC-Browser'
        'nkbihfbeogaeaoehlefnkodbefgpgknn' = 'MetaMask'
        'bhghoamapcdpbohphigoooaddinpkbai' = 'Authenticator'
        'gighmmpiobklfepjocnamgkkbiglidom' = 'AdBlock'
        'cfhdojbkjhnklbpkdaibdccddilifddb' = 'Adblock Plus'
        'efaidnbmnnnibpcajpcglclefindmkaj' = 'Adobe Acrobat'
        'ghbmnnjooekpmoecnnnilnnbdlolhkhi' = 'Google Docs Offline'
        'nmmhkkegccagdldgiimedpiccmgmieda' = 'Google Wallet'
        'lpcaedmchfhocbbapmcbpinfpgnhiddi' = 'Google Keep'
        'aapbdbdomjkkjkaonfhkkikfgjllcleb' = 'Google Translate'
        'pkedcjkdefgpdelpbcmbmeomcjbeemfm' = 'Google Cast'
        'eimadpbcbfnmbkopoojfekhnkhdbieeh' = 'Dark Reader'
        'fmkadmapgofadopljbjfkapdkoienihi' = 'React Developer Tools'
        'lmhkpmbekcpmknklioeibfkpmmfibljd' = 'Redux DevTools'
        'dhdgffkkebhmkfjojejmpbldmpobfkfo' = 'Tampermonkey'
        'kbfnbcaeplbcioakkpcpgfkobkghlhen' = 'Grammarly'
        'bmnlcjabgnpnenekpadlanbbkooimhnj' = 'Honey'
        'neebplgakaahbhdphmkckjjcegoiijjo' = 'Keepa'
        'oombnmpbbhbakfpfgdflaajkhicgfaam' = 'ESET'
        'nkapkmklnmidbbgjaipbgpcnbomnaakc' = 'ESET'
    }

    if ($map.ContainsKey($Id)) {
        return $map[$Id]
    }

    return ''
}

<#
.SYNOPSIS
    Lists the extensions installed in the browsers on this machine.

.DESCRIPTION
    Reads the extension folders of the Chromium browsers (Chrome, Edge, Brave)
    and the extensions.json of Firefox, for the current user. The base folders
    are parameters so the list can be tested against a sample tree; by default
    they are the current user's own.

    A security product such as ESET, or the browser itself while it runs, can
    refuse to let another process read the profile files even when the account
    owns them. The extension id and its version folder stay readable, so those
    extensions are still listed, named from the built-in list where possible and
    marked as not fully read rather than dropped.

.PARAMETER LocalAppData
    The local application data folder (Chromium browsers).

.PARAMETER AppData
    The roaming application data folder (Firefox).

.OUTPUTS
    PSCustomObject[] with Browser, Profile, Id, Name, Version, Enabled,
    Readable, Permissions and RiskyPermissions.
#>
function Get-TkBrowserExtension {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA,
        [Parameter()] [string] $AppData      = $env:APPDATA
    )

    $records = New-Object System.Collections.Generic.List[pscustomobject]

    $readJson = {
        param($path)
        try {
            if (Test-Path -LiteralPath $path) {
                return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
            }
        }
        catch {
            # A missing or malformed manifest is simply skipped.
            Write-TkLog -Level Debug -Category 'Hunting' -Message ('Could not read {0}: {1}' -f $path, $_.Exception.Message)
        }
        return $null
    }

    # --- Chromium browsers ------------------------------------------------
    $chromium = @(
        [pscustomobject] @{ Browser = 'Chrome'; Root = (Join-Path $LocalAppData 'Google\Chrome\User Data') }
        [pscustomobject] @{ Browser = 'Edge';   Root = (Join-Path $LocalAppData 'Microsoft\Edge\User Data') }
        [pscustomobject] @{ Browser = 'Brave';  Root = (Join-Path $LocalAppData 'BraveSoftware\Brave-Browser\User Data') }
    )

    foreach ($browser in $chromium) {

        if (-not (Test-Path -LiteralPath $browser.Root)) { continue }

        $profiles = @(Get-ChildItem -LiteralPath $browser.Root -Directory -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })

        foreach ($browserProfile in $profiles) {

            $extRoot = Join-Path $browserProfile.FullName 'Extensions'
            if (-not (Test-Path -LiteralPath $extRoot)) { continue }

            foreach ($extDir in @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) {

                # The newest installed version folder holds the live manifest.
                $versionDir = @(Get-ChildItem -LiteralPath $extDir.FullName -Directory -ErrorAction SilentlyContinue |
                                Sort-Object -Property Name -Descending | Select-Object -First 1)

                if ($versionDir.Count -eq 0) { continue }

                # The version folder is named <version>_<build>, so the version
                # is readable from its name even when the manifest is not.
                $folderVersion = $versionDir[0].Name -replace '_[0-9]+$', ''
                $manifest      = & $readJson (Join-Path $versionDir[0].FullName 'manifest.json')

                if ($null -ne $manifest) {

                    $messages = $null
                    if ([string] $manifest.default_locale) {
                        $messages = & $readJson (Join-Path $versionDir[0].FullName ('_locales\{0}\messages.json' -f $manifest.default_locale))
                    }

                    $info = ConvertFrom-TkChromeExtensionManifest -Manifest $manifest -LocaleMessages $messages

                    $records.Add([pscustomobject] @{
                        Browser          = $browser.Browser
                        Profile          = $browserProfile.Name
                        Id               = $extDir.Name
                        Name             = if ($info.Name) { $info.Name } else { $extDir.Name }
                        Version          = if ($info.Version) { $info.Version } else { $folderVersion }
                        Enabled          = $true
                        Readable         = $true
                        Permissions      = $info.Permissions
                        RiskyPermissions = @(Get-TkExtensionPermissionRisk -Permissions $info.Permissions)
                    })
                }
                else {

                    # The manifest could not be read: name it from the built-in
                    # list where the id is known, and mark it not fully read.
                    $known = Get-TkKnownExtensionName -Id $extDir.Name

                    $records.Add([pscustomobject] @{
                        Browser          = $browser.Browser
                        Profile          = $browserProfile.Name
                        Id               = $extDir.Name
                        Name             = if ($known) { $known } else { $extDir.Name }
                        Version          = $folderVersion
                        Enabled          = $true
                        Readable         = $false
                        Permissions      = @()
                        RiskyPermissions = @()
                    })
                }
            }
        }
    }

    # --- Firefox ----------------------------------------------------------
    $firefoxProfiles = Join-Path $AppData 'Mozilla\Firefox\Profiles'

    if (Test-Path -LiteralPath $firefoxProfiles) {

        foreach ($firefoxProfile in @(Get-ChildItem -LiteralPath $firefoxProfiles -Directory -ErrorAction SilentlyContinue)) {

            $data = & $readJson (Join-Path $firefoxProfile.FullName 'extensions.json')
            if ($null -eq $data -or -not $data.addons) { continue }

            foreach ($addon in @($data.addons)) {

                $info = ConvertFrom-TkFirefoxExtension -Addon $addon
                if ($null -eq $info) { continue }

                $records.Add([pscustomobject] @{
                    Browser          = 'Firefox'
                    Profile          = $firefoxProfile.Name
                    Id               = $info.Id
                    Name             = $info.Name
                    Version          = $info.Version
                    Enabled          = $info.Enabled
                    Readable         = $true
                    Permissions      = $info.Permissions
                    RiskyPermissions = @(Get-TkExtensionPermissionRisk -Permissions $info.Permissions)
                })
            }
        }
    }

    return @($records | Sort-Object -Property Browser, Name)
}

# ---------------------------------------------------------------------------
# 4. Windows Defender detection history
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Names a Windows Defender threat severity.

.PARAMETER Value
    The SeverityID of a threat.

.OUTPUTS
    PSCustomObject with Name and Severity (the toolkit's own Pass/Info/Warning/Fail).
#>
function Get-TkDefenderSeverityName {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [int] $Value
    )

    switch ($Value) {
        1       { return [pscustomobject] @{ Name = 'Low';      Severity = 'Info' } }
        2       { return [pscustomobject] @{ Name = 'Moderate'; Severity = 'Warning' } }
        4       { return [pscustomobject] @{ Name = 'High';     Severity = 'Fail' } }
        5       { return [pscustomobject] @{ Name = 'Severe';   Severity = 'Fail' } }
        default { return [pscustomobject] @{ Name = 'Unknown';  Severity = 'Info' } }
    }
}

<#
.SYNOPSIS
    Turns a Defender detection into a record, naming the threat from the catalog.

.PARAMETER Detection
    A Get-MpThreatDetection object.

.PARAMETER Catalog
    A hashtable of ThreatID to the threat, as built from Get-MpThreat.

.OUTPUTS
    PSCustomObject with Time, ThreatName, SeverityName, Severity, Resources and Action.
#>
function ConvertFrom-TkDefenderDetection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $Detection,

        [Parameter()]
        [AllowNull()]
        [hashtable] $Catalog
    )

    $threat = if ($Catalog -and $Catalog.ContainsKey([string] $Detection.ThreatID)) { $Catalog[[string] $Detection.ThreatID] } else { $null }

    $name     = if ($threat -and $threat.ThreatName) { [string] $threat.ThreatName } elseif ($Detection.PSObject.Properties['ThreatName']) { [string] $Detection.ThreatName } else { ('Threat {0}' -f $Detection.ThreatID) }
    $severity = Get-TkDefenderSeverityName -Value $(if ($threat) { [int] $threat.SeverityID } else { 0 })

    # Resources look like "file:_C:\path" or "containerfile:_...".
    $resources = @(@($Detection.Resources) | ForEach-Object { ([string] $_) -replace '^[a-z]+:_', '' } | Where-Object { $_ })

    $action = switch ([int] $Detection.CleaningActionID) {
        1       { 'Clean' }
        2       { 'Quarantine' }
        3       { 'Remove' }
        6       { 'Allow' }
        8       { 'User defined' }
        9       { 'No action' }
        10      { 'Block' }
        default { 'Unknown' }
    }

    return [pscustomobject] @{
        Time         = $Detection.InitialDetectionTime
        ThreatName   = $name
        SeverityName = $severity.Name
        Severity     = $severity.Severity
        Resources    = $resources
        Action       = $action
        Cleaned      = [bool] $Detection.ActionSuccess
    }
}

<#
.SYNOPSIS
    Reads the Windows Defender detection history.

.DESCRIPTION
    Uses the Defender cmdlets when they are present, joining each detection to
    the threat catalog for its name and severity. On a machine without Defender,
    or where the cmdlets are unavailable, it returns nothing rather than failing.

.PARAMETER Days
    Only detections newer than this are kept.

.OUTPUTS
    PSCustomObject[] as ConvertFrom-TkDefenderDetection returns.
#>
function Get-TkDefenderDetectionHistory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [int] $Days = 90
    )

    if (-not (Get-Command -Name 'Get-MpThreatDetection' -ErrorAction SilentlyContinue)) {
        return @()
    }

    try {
        $detections = @(Get-MpThreatDetection -ErrorAction Stop)
    }
    catch {
        Write-TkLog -Level Debug -Category 'Hunting' -Message ('Defender history read failed: {0}' -f $_.Exception.Message)
        return @()
    }

    $catalog = @{}
    try {
        foreach ($threat in @(Get-MpThreat -ErrorAction Stop)) {
            $catalog[[string] $threat.ThreatID] = $threat
        }
    }
    catch {
        # Without the catalog, detections still show by their threat id.
        Write-TkLog -Level Debug -Category 'Hunting' -Message ('Defender threat catalog read failed: {0}' -f $_.Exception.Message)
    }

    $since = (Get-Date).AddDays(-$Days)

    $records = foreach ($detection in $detections) {
        if ($detection.InitialDetectionTime -and $detection.InitialDetectionTime -lt $since) { continue }
        ConvertFrom-TkDefenderDetection -Detection $detection -Catalog $catalog
    }

    return @($records | Sort-Object -Property Time -Descending)
}
