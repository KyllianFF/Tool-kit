<#
    Toolkit - Features / Saved Wi-Fi networks

    Every Wi-Fi network a PC has joined stays in its list, and the PC keeps
    looking for it. An open network it joins by itself is the classic trap:
    anyone can start a hotspot with the same name at a station or a cafe and
    the PC connects to it, traffic and all. WEP falls in minutes, TKIP is
    retired, and a hidden network makes the PC call its name out wherever it
    goes.

    This reads the saved profiles through the Wi-Fi API, as XML, so the
    security, the cipher and whether the PC joins by itself come from
    structured fields rather than from translated netsh output. The key is
    never read: Windows returns it encrypted unless explicitly asked, and
    nothing here asks. Read only.
#>

<#
.SYNOPSIS
    Reads the WLAN_PROFILE_INFO_LIST the Wi-Fi API returns.

.OUTPUTS
    PSCustomObject[] with Name, GroupPolicy and PerUser.
#>
function ConvertFrom-TkWlanProfileList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [byte[]] $Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -lt 8) {
        return @()
    }

    $count = [BitConverter]::ToInt32($Bytes, 0)
    $items = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $count; $i++) {

        $offset = 8 + (516 * $i)

        if ($offset + 516 -gt $Bytes.Length) {
            break
        }

        $flags = [BitConverter]::ToInt32($Bytes, $offset + 512)

        $items.Add([pscustomobject] @{
            Name        = ([Text.Encoding]::Unicode.GetString($Bytes, $offset, 512) -split "`0")[0]
            GroupPolicy = ($flags -band 1) -ne 0
            PerUser     = ($flags -band 2) -ne 0
        })
    }

    return @($items.ToArray())
}

<#
.SYNOPSIS
    Reads the parts of a Wi-Fi profile that say how safe it is.

.DESCRIPTION
    Pure: the profile XML in, its settings out. The element names are those of
    the WLANProfile schema, so a French and an English Windows read the same.

.OUTPUTS
    PSCustomObject with Name, Ssid, Authentication, Encryption, OneX,
    AutoConnect, Hidden and Security (a readable label), or $null when the
    text is not a profile.
#>
function ConvertFrom-TkWlanProfileXml {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Xml
    )

    try {
        $document = [xml] $Xml
    }
    catch {
        return $null
    }

    $wlan = $document.WLANProfile

    if ($null -eq $wlan) {
        return $null
    }

    $auth = $wlan.MSM.security.authEncryption

    $authentication = [string] $auth.authentication
    $encryption     = [string] $auth.encryption
    $oneX           = [string] $auth.useOneX -eq 'true'

    $label = switch -Regex ($authentication) {
        '^open$'                  { if ($encryption -eq 'WEP') { 'WEP' } else { 'Open' }; break }
        '^shared$'                { 'WEP (shared key)'; break }
        '^WPAPSK$'                { 'WPA-Personal'; break }
        '^WPA$'                   { 'WPA-Enterprise'; break }
        '^WPA2PSK$'               { 'WPA2-Personal'; break }
        '^WPA2$'                  { 'WPA2-Enterprise'; break }
        '^WPA3SAE$'               { 'WPA3-Personal'; break }
        '^WPA3(ENT|ENT192)?$'     { 'WPA3-Enterprise'; break }
        '^OWE$'                   { 'Enhanced Open (OWE)'; break }
        default                   { $authentication }
    }

    return [pscustomobject] @{
        Name           = [string] $wlan.name
        Ssid           = [string] $wlan.SSIDConfig.SSID.name
        Authentication = $authentication
        Encryption     = $encryption
        OneX           = $oneX
        AutoConnect    = ([string] $wlan.connectionMode) -ne 'manual'
        Hidden         = ([string] $wlan.SSIDConfig.nonBroadcast) -eq 'true'
        Security       = if ($encryption -and $encryption -ne 'none' -and $label -notmatch 'WEP') { '{0}, {1}' -f $label, $encryption } else { $label }
    }
}

<#
.SYNOPSIS
    Judges one saved network.

.DESCRIPTION
    Pure. Each weakness adds a note; the verdict takes the worst of them:

      - WEP: fail, it is broken;
      - open and joined by itself: fail, a look-alike hotspot is joined too;
      - open, joined by hand: warning, the traffic is readable;
      - WPA (the first one) or TKIP: warning, both are retired;
      - hidden: warning, the PC asks for it by name everywhere.

    Enhanced Open (OWE) is encrypted without a password and passes.

.OUTPUTS
    PSCustomObject with Severity, Heading, Note and Action.
#>
function Get-TkWifiProfileVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Network
    )

    $issues = New-Object System.Collections.Generic.List[object]
    $issue  = { param($severity, $heading, $note) $issues.Add([pscustomobject] @{ Severity = $severity; Heading = $heading; Note = $note }) }

    $open = $Network.Authentication -eq 'open' -and $Network.Encryption -eq 'none' -and -not $Network.OneX

    if ($Network.Encryption -eq 'WEP' -or $Network.Authentication -eq 'shared') {
        & $issue 'Fail' 'WEP, which is broken' 'A WEP key is recovered in minutes from the traffic alone. Move the network to WPA2 or WPA3.'
    }

    if ($open -and $Network.AutoConnect) {
        & $issue 'Fail' 'Open network joined automatically' 'Anyone can start a hotspot with this name and the PC joins it by itself, with everything it sends. Turn off "Connect automatically", or forget the network.'
    }
    elseif ($open) {
        & $issue 'Warning' 'Open network' 'Nothing is encrypted on the air: what the PC sends there is readable nearby unless the site or a VPN encrypts it.'
    }

    if ($Network.Authentication -in @('WPA', 'WPAPSK') -or $Network.Encryption -eq 'TKIP') {
        & $issue 'Warning' 'Retired security (WPA or TKIP)' 'Both are deprecated and weaker than WPA2 with AES; recent Windows builds warn about them. Move the network to WPA2 or WPA3.'
    }

    if ($Network.Hidden) {
        & $issue 'Warning' 'Hidden network' 'The PC calls this name out wherever it goes to find it, which gives the name away and lets a look-alike answer. A hidden name is not a protection; broadcasting it is safer.'
    }

    $order = @('Fail', 'Warning', 'Info', 'Pass')

    if ($issues.Count -eq 0) {
        return [pscustomobject] @{ Severity = 'Pass'; Heading = 'Protected'; Note = ''; Action = '' }
    }

    $worst = @($issues | Sort-Object { $order.IndexOf($_.Severity) })[0]

    return [pscustomobject] @{
        Severity = $worst.Severity
        Heading  = $worst.Heading
        Note     = (@($issues | ForEach-Object { $_.Note }) -join ' ')
        Action   = 'Forget it if it is no longer used: Settings, Network and internet, Wi-Fi, Manage known networks, or netsh wlan delete profile name="{0}".' -f $Network.Name
    }
}

<#
.SYNOPSIS
    Reads and judges every saved Wi-Fi network.

.OUTPUTS
    PSCustomObject with Available (a Wi-Fi adapter and API), Reason, and
    Profiles (the profile fields plus GroupPolicy, Severity, Heading, Note
    and Action), worst first.
#>
function Get-TkWifiProfileAudit {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $none = { param($reason) [pscustomobject] @{ Available = $false; Reason = $reason; Profiles = @() } }

    if (-not (Initialize-TkWlanApi)) {
        return (& $none 'The Wi-Fi API could not be loaded.')
    }

    $error1     = 0
    $interfaces = @(ConvertFrom-TkWlanInterfaceList -Bytes ([TkWlanApi]::EnumInterfaces([ref] $error1)))

    if ($interfaces.Count -eq 0) {
        return (& $none 'This PC has no Wi-Fi adapter, or the WLAN AutoConfig service is stopped.')
    }

    $seen    = New-Object System.Collections.Generic.HashSet[string]
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($interface in $interfaces) {

        $error2 = 0
        $list   = @(ConvertFrom-TkWlanProfileList -Bytes ([TkWlanApi]::GetProfileList($interface.Guid, [ref] $error2)))

        foreach ($entry in $list) {

            if (-not $seen.Add($entry.Name)) {
                continue
            }

            $error3 = 0
            $xml    = [TkWlanApi]::GetProfileXml($interface.Guid, $entry.Name, [ref] $error3)
            $parsed = if ($xml) { ConvertFrom-TkWlanProfileXml -Xml $xml } else { $null }

            if (-not $parsed) {
                continue
            }

            $verdict = Get-TkWifiProfileVerdict -Network $parsed

            $results.Add([pscustomobject] @{
                Name        = $parsed.Name
                Ssid        = $parsed.Ssid
                Security    = $parsed.Security
                AutoConnect = $parsed.AutoConnect
                Hidden      = $parsed.Hidden
                GroupPolicy = $entry.GroupPolicy
                Severity    = $verdict.Severity
                Heading     = $verdict.Heading
                Note        = $verdict.Note
                Action      = if ($entry.GroupPolicy) { 'Pushed by your organisation''s policy: ask its administrators.' } else { $verdict.Action }
            })
        }
    }

    $order = @('Fail', 'Warning', 'Info', 'Pass')

    return [pscustomobject] @{
        Available = $true
        Reason    = ''
        Profiles  = @($results.ToArray() | Sort-Object @{ Expression = { $order.IndexOf($_.Severity) } }, Name)
    }
}
