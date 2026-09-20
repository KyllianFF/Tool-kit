<#
    Toolkit - Features / User-Agent parser

    The User-Agent line a browser or a tool sends with every request, taken
    apart into the four things a log reader wants from it: the browser and its
    version, the layout engine, the operating system, and whether it came from a
    desktop, a phone, a tablet or a bot. It is a string of loose conventions,
    not a format, so the reading is by known patterns, most specific first: an
    Edge line contains the word Chrome, a Chrome line contains Safari, so the
    order they are tested in is what makes the answer right.

    The string is read as text on the machine; nothing is requested.
#>

<#
.SYNOPSIS
    Returns the first of an ordered set of patterns to match, with its version.

.DESCRIPTION
    The rules are an ordered dictionary of label to a regex that captures a
    version in a group named v. The order is the whole of the logic: the caller
    lists the specific before the general.

.OUTPUTS
    PSCustomObject with Name and Version, or null.
#>
function Get-TkUserAgentMatch {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Rule
    )

    foreach ($name in $Rule.Keys) {

        $match = [regex]::Match($Text, $Rule[$name])
        if ($match.Success) {
            $version = if ($match.Groups['v'].Success) { $match.Groups['v'].Value.Replace('_', '.') } else { '' }
            return [pscustomobject] @{ Name = $name; Version = $version }
        }
    }

    return $null
}

<#
.SYNOPSIS
    Parses a User-Agent string into browser, engine, OS and device.

.PARAMETER Text
    The User-Agent line.

.OUTPUTS
    PSCustomObject.
#>
function Get-TkUserAgentInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $ua = $Text.Trim()

    # --- Tools and bots, tested before browsers ---------------------------
    $agentRule = [ordered] @{
        'curl'            = 'curl/(?<v>[\d.]+)'
        'Wget'            = 'Wget/(?<v>[\d.]+)'
        'PowerShell'      = 'WindowsPowerShell/(?<v>[\d.]+)|PowerShell/(?<v>[\d.]+)'
        'Python requests' = 'python-requests/(?<v>[\d.]+)'
        'Go http client'  = 'Go-http-client/(?<v>[\d.]+)'
        'Googlebot'       = 'Googlebot/(?<v>[\d.]+)'
        'Bingbot'         = 'bingbot/(?<v>[\d.]+)'
        'DuckDuckBot'     = 'DuckDuckBot/(?<v>[\d.]+)'
        'Yandex bot'      = 'YandexBot/(?<v>[\d.]+)'
        'Applebot'        = 'Applebot/(?<v>[\d.]+)'
    }

    $agent = Get-TkUserAgentMatch -Text $ua -Rule $agentRule

    if ($agent) {
        return [pscustomobject] @{
            Raw           = $ua
            Browser       = $agent.Name
            BrowserVersion = $agent.Version
            Engine        = ''
            EngineVersion = ''
            Os            = (Get-TkUserAgentOs -Text $ua).Name
            OsVersion     = (Get-TkUserAgentOs -Text $ua).Version
            Device        = if ($ua -match 'bot|crawler|spider') { 'Bot' } else { 'Tool' }
        }
    }

    # --- Browsers, specific before general --------------------------------
    $browserRule = [ordered] @{
        'Edge'             = 'Edg(?:e|A|iOS)?/(?<v>[\d.]+)'
        'Opera'            = '(?:OPR|Opera)/(?<v>[\d.]+)'
        'Samsung Internet' = 'SamsungBrowser/(?<v>[\d.]+)'
        'Yandex Browser'   = 'YaBrowser/(?<v>[\d.]+)'
        'Vivaldi'          = 'Vivaldi/(?<v>[\d.]+)'
        'Firefox'          = '(?:Firefox|FxiOS)/(?<v>[\d.]+)'
        'Chrome'           = '(?:Chrome|CriOS|Chromium)/(?<v>[\d.]+)'
        'Internet Explorer' = 'MSIE (?<v>[\d.]+)|Trident/.*rv:(?<v>[\d.]+)'
        'Safari'           = 'Version/(?<v>[\d.]+).*Safari'
    }

    $browser = Get-TkUserAgentMatch -Text $ua -Rule $browserRule

    # --- Engine -----------------------------------------------------------
    $engine     = ''
    $engineVer  = ''
    $chromium   = @('Edge', 'Opera', 'Samsung Internet', 'Yandex Browser', 'Vivaldi', 'Chrome')

    if ($ua -match 'AppleWebKit/(?<v>[\d.]+)') {
        $engineVer = $matches['v']
        $engine    = if ($browser -and $chromium -contains $browser.Name) { 'Blink' } else { 'WebKit' }
    }
    elseif ($ua -match 'Trident/(?<v>[\d.]+)') { $engine = 'Trident'; $engineVer = $matches['v'] }
    elseif ($ua -match 'Gecko/\d' -or ($browser -and $browser.Name -eq 'Firefox')) {
        $engine = 'Gecko'
        if ($ua -match 'rv:(?<v>[\d.]+)') { $engineVer = $matches['v'] }
    }
    elseif ($ua -match 'Presto/(?<v>[\d.]+)') { $engine = 'Presto'; $engineVer = $matches['v'] }

    $os = Get-TkUserAgentOs -Text $ua

    $device = if ($ua -match 'bot|crawler|spider') { 'Bot' }
              elseif ($ua -match 'iPad|Tablet') { 'Tablet' }
              elseif ($ua -match 'Mobi|iPhone|iPod|Windows Phone') { 'Mobile' }
              else { 'Desktop' }

    return [pscustomobject] @{
        Raw            = $ua
        Browser        = if ($browser) { $browser.Name } else { '' }
        BrowserVersion = if ($browser) { $browser.Version } else { '' }
        Engine         = $engine
        EngineVersion  = $engineVer
        Os             = $os.Name
        OsVersion      = $os.Version
        Device         = $device
    }
}

<#
.SYNOPSIS
    Reads the operating system out of a User-Agent string.

.OUTPUTS
    PSCustomObject with Name and Version.
#>
function Get-TkUserAgentOs {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Text
    )

    # Windows first, then Android before Linux (an Android line also says Linux),
    # iOS before macOS, macOS before the bare Linux.
    if ($Text -match 'Windows NT (?<v>[\d.]+)') {
        $version = switch ($matches['v']) {
            '10.0' { '10 or 11' }
            '6.3'  { '8.1' }
            '6.2'  { '8' }
            '6.1'  { '7' }
            '6.0'  { 'Vista' }
            '5.1'  { 'XP' }
            default { $matches['v'] }
        }
        return [pscustomobject] @{ Name = 'Windows'; Version = $version }
    }

    if ($Text -match 'Windows Phone (?:OS )?(?<v>[\d.]+)') { return [pscustomobject] @{ Name = 'Windows Phone'; Version = $matches['v'] } }
    if ($Text -match 'Android (?<v>[\d.]+)')               { return [pscustomobject] @{ Name = 'Android'; Version = $matches['v'] } }
    if ($Text -match '(?:iPhone|iPad|iPod)(?: CPU)?(?:.*?OS) (?<v>[\d_]+)') { return [pscustomobject] @{ Name = 'iOS'; Version = $matches['v'].Replace('_', '.') } }
    if ($Text -match 'CrOS \S+ (?<v>[\d.]+)')              { return [pscustomobject] @{ Name = 'ChromeOS'; Version = $matches['v'] } }
    if ($Text -match 'Mac OS X (?<v>[\d_]+)')              { return [pscustomobject] @{ Name = 'macOS'; Version = $matches['v'].Replace('_', '.') } }
    if ($Text -match 'Mac OS X')                           { return [pscustomobject] @{ Name = 'macOS'; Version = '' } }
    if ($Text -match 'Linux')                              { return [pscustomobject] @{ Name = 'Linux'; Version = '' } }

    return [pscustomobject] @{ Name = ''; Version = '' }
}

<#
.SYNOPSIS
    Writes the parsed User-Agent as lines of text.

.OUTPUTS
    System.String[]
#>
function Format-TkUserAgentReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste a User-Agent string to take it apart.')
    }

    $info  = Get-TkUserAgentInfo -Text $Text
    $lines = New-Object System.Collections.Generic.List[string]

    $pair = {
        param($label, $name, $version)
        $value = if ($name) { ($name + $(if ($version) { ' ' + $version } else { '' })) } else { 'not recognised' }
        '{0,-9} {1}' -f $label, $value
    }

    $lines.Add((& $pair 'Browser:' $info.Browser $info.BrowserVersion))
    $lines.Add((& $pair 'Engine:'  $info.Engine  $info.EngineVersion))
    $lines.Add((& $pair 'OS:'      $info.Os      $info.OsVersion))
    $lines.Add(('Device:   {0}' -f $info.Device))

    return $lines.ToArray()
}
