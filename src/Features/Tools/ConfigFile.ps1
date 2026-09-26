<#
    Toolkit - Features / INI and .env parser

    The config file someone pasted from a server, a container or a ticket, to
    see what is actually in it. It reads an INI file (sections, key = value,
    ; and # comments) or a .env file (KEY=VALUE, an optional export, quotes,
    # comments), lays it out section by section, and masks the values that look
    like secrets so the readout does not carry a password on.

    It also points out the things that quietly break a config: a key repeated
    in a section, a key sitting above the first section, a line that is neither
    a comment nor a key = value. Read on the machine; nothing is sent anywhere.
#>

<#
.SYNOPSIS
    Guesses whether a config text is INI or .env.

.DESCRIPTION
    A section header, [like-this] on its own line, is the one thing only INI
    has. With none present the text is treated as a flat .env.

.OUTPUTS
    System.String: 'Ini' or 'Env'.
#>
function Get-TkConfigFormat {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    foreach ($line in ($Text -split '\r?\n')) {

        if ($line -match '^\s*\[[^\]]+\]\s*$') {
            return 'Ini'
        }
    }

    return 'Env'
}

<#
.SYNOPSIS
    Says whether a key names something that should be treated as a secret.
#>
function Test-TkConfigSensitiveKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Key
    )

    return [bool] ($Key -match '(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|credential|connection[_-]?string|conn[_-]?str)')
}

<#
.SYNOPSIS
    Masks a value, keeping just enough of the ends to recognise it.

.OUTPUTS
    System.String
#>
function Protect-TkConfigValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $length = $Value.Length

    if ($length -eq 0) {
        return ''
    }

    if ($length -le 8) {
        return ('*' * [math]::Max(4, $length))
    }

    return $Value.Substring(0, 2) + ('*' * [math]::Min(12, $length - 4)) + $Value.Substring($length - 2)
}

<#
.SYNOPSIS
    Parses an INI or .env text into one record per line.

.PARAMETER Text
    The config to read.

.PARAMETER Format
    Auto (detect), Ini or Env. Auto is the default.

.OUTPUTS
    PSCustomObject[] with LineNumber, Kind (Section, Pair, Comment, Blank,
    Invalid), Section, Key, Value, Quoted, Exported and Sensitive.
#>
function ConvertFrom-TkConfigText {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [ValidateSet('Auto', 'Ini', 'Env')]
        [string] $Format = 'Auto'
    )

    if ($Format -eq 'Auto') {
        $Format = Get-TkConfigFormat -Text $Text
    }

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    $section = ''
    $number  = 0

    $record = {
        param($kind, $key, $value, $quoted, $exported, $sensitive, $raw)
        [pscustomobject] @{
            LineNumber = $number
            Kind       = $kind
            Section    = $section
            Key        = $key
            Value      = $value
            Quoted     = [bool] $quoted
            Exported   = [bool] $exported
            Sensitive  = [bool] $sensitive
            Raw        = $raw
        }
    }

    foreach ($raw in ($Text -split '\r?\n')) {

        $number++
        $trim = $raw.Trim()

        if ($trim.Length -eq 0) {
            $entries.Add((& $record 'Blank' $null $null $false $false $false $raw))
            continue
        }

        # A comment: ';' is INI only, '#' is used by both.
        if ($trim[0] -eq ';' -or $trim[0] -eq '#') {
            $entries.Add((& $record 'Comment' $null $trim $false $false $false $raw))
            continue
        }

        # A section header, INI only.
        if ($Format -eq 'Ini' -and $trim -match '^\[(?<name>[^\]]+)\]$') {
            $section = $Matches['name'].Trim()
            $entries.Add((& $record 'Section' $null $section $false $false $false $raw))
            continue
        }

        # A .env line may lead with "export".
        $work     = $trim
        $exported = $false

        if ($Format -eq 'Env' -and $work -match '^(?i:export)\s+(?<rest>.+)$') {
            $exported = $true
            $work     = $Matches['rest']
        }

        # The separator: INI accepts '=' or ':', .env only '='. The earliest
        # of the accepted separators splits the line, so a value can contain
        # the other character.
        $separator = -1

        if ($Format -eq 'Ini') {

            $positions = @($work.IndexOf('='), $work.IndexOf(':')) | Where-Object { $_ -ge 0 }

            if ($positions.Count -gt 0) {
                $separator = ($positions | Measure-Object -Minimum).Minimum
            }
        }
        else {
            $separator = $work.IndexOf('=')
        }

        if ($separator -lt 1) {
            $entries.Add((& $record 'Invalid' $null $trim $false $exported $false $raw))
            continue
        }

        $key   = $work.Substring(0, $separator).Trim()
        $value = $work.Substring($separator + 1).Trim()
        $quoted = $false

        if ($value.Length -ge 2 -and
            (($value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') -or
             ($value[0] -eq "'" -and $value[$value.Length - 1] -eq "'"))) {

            $quoted = $true
            $value  = $value.Substring(1, $value.Length - 2)
        }
        else {
            # An unquoted value ends at an inline comment (space then ; or #).
            $inline = [regex]::Match($value, '\s+[;#].*$')

            if ($inline.Success) {
                $value = $value.Substring(0, $inline.Index)
            }

            $value = $value.TrimEnd()
        }

        $entries.Add((& $record 'Pair' $key $value $quoted $exported (Test-TkConfigSensitiveKey -Key $key) $raw))
    }

    return @($entries)
}

<#
.SYNOPSIS
    Reads an INI or .env text and writes it back grouped and masked.

.PARAMETER Text
    The config to read.

.PARAMETER Format
    Auto (detect), Ini or Env.

.PARAMETER Reveal
    Show the sensitive values instead of masking them.

.OUTPUTS
    System.String[]
#>
function Format-TkConfigReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [ValidateSet('Auto', 'Ini', 'Env')]
        [string] $Format = 'Auto',

        [Parameter()]
        [switch] $Reveal
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste an INI or a .env file to read it, grouped by section and with the secrets masked.')
    }

    $resolved = if ($Format -eq 'Auto') { Get-TkConfigFormat -Text $Text } else { $Format }
    $entries  = @(ConvertFrom-TkConfigText -Text $Text -Format $resolved)
    $pairs    = @($entries | Where-Object { $_.Kind -eq 'Pair' })
    $sections = @($pairs | ForEach-Object { $_.Section } | Sort-Object -Unique)

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Detected format: {0}' -f $(if ($resolved -eq 'Ini') { 'INI' } else { '.env' })))

    if ($resolved -eq 'Ini') {
        $lines.Add(('{0} key(s) in {1} section(s).' -f $pairs.Count, @($sections | Where-Object { $_ -ne '' }).Count))
    }
    else {
        $lines.Add(('{0} key(s).' -f $pairs.Count))
    }

    $lines.Add('')

    # The sections in the order they first appear, '' (before any header) first.
    $order = New-Object System.Collections.Generic.List[string]

    foreach ($pair in $pairs) {
        if (-not $order.Contains($pair.Section)) {
            $order.Add($pair.Section)
        }
    }

    foreach ($name in $order) {

        if ($name -ne '') {
            $lines.Add(('[{0}]' -f $name))
        }
        elseif ($resolved -eq 'Ini' -and $order.Count -gt 1) {
            $lines.Add('(no section)')
        }

        foreach ($pair in ($pairs | Where-Object { $_.Section -eq $name })) {

            $shown = if ($pair.Sensitive -and -not $Reveal) { Protect-TkConfigValue -Value $pair.Value } else { $pair.Value }
            $lines.Add(('  {0} = {1}' -f $pair.Key, $shown))
        }

        $lines.Add('')
    }

    # The things that quietly break a config.
    $notes = New-Object System.Collections.Generic.List[string]

    $duplicates = $pairs | Group-Object { '{0}//{1}' -f $_.Section, $_.Key } | Where-Object { $_.Count -gt 1 }

    foreach ($group in $duplicates) {
        $last = $group.Group | Select-Object -Last 1
        $where = if ($last.Section -ne '') { "in [$($last.Section)]" } else { 'at the top level' }
        $notes.Add(('L{0,-4} duplicate key ''{1}'' {2} ({3} times; the last value wins)' -f $last.LineNumber, $last.Key, $where, $group.Count))
    }

    foreach ($pair in ($pairs | Where-Object { $resolved -eq 'Ini' -and $_.Section -eq '' })) {
        $notes.Add(('L{0,-4} key ''{1}'' sits above the first [section]' -f $pair.LineNumber, $pair.Key))
    }

    foreach ($bad in ($entries | Where-Object { $_.Kind -eq 'Invalid' })) {
        $notes.Add(('L{0,-4} not a comment or a key {1} value: ''{2}''' -f $bad.LineNumber, $(if ($resolved -eq 'Ini') { '=/:' } else { '=' }), $bad.Value))
    }

    if ($notes.Count -gt 0) {
        $lines.Add('Notes:')
        foreach ($note in $notes) { $lines.Add(('  {0}' -f $note)) }
        $lines.Add('')
    }

    if (-not $Reveal -and @($pairs | Where-Object { $_.Sensitive }).Count -gt 0) {
        $lines.Add('Sensitive values are masked. Tick "Reveal secret values" to show them.')
    }

    return $lines.ToArray()
}

<#
.SYNOPSIS
    Reads an INI or .env text and writes it back as JSON.

.DESCRIPTION
    INI becomes an object of sections, each an object of its keys; keys above
    the first section sit at the top level. A .env becomes one flat object.
    A repeated key keeps its last value, as a parser would.

.PARAMETER Reveal
    Put the real sensitive values in, instead of the masked ones.

.OUTPUTS
    System.String
#>
function ConvertTo-TkConfigJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [ValidateSet('Auto', 'Ini', 'Env')]
        [string] $Format = 'Auto',

        [Parameter()]
        [switch] $Reveal
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return '{}'
    }

    $resolved = if ($Format -eq 'Auto') { Get-TkConfigFormat -Text $Text } else { $Format }
    $pairs    = @(ConvertFrom-TkConfigText -Text $Text -Format $resolved | Where-Object { $_.Kind -eq 'Pair' })

    $root = [ordered] @{}

    foreach ($pair in $pairs) {

        $value = if ($pair.Sensitive -and -not $Reveal) { Protect-TkConfigValue -Value $pair.Value } else { $pair.Value }

        if ($resolved -eq 'Ini' -and $pair.Section -ne '') {

            if (-not ($root.Contains($pair.Section)) -or -not ($root[$pair.Section] -is [System.Collections.Specialized.OrderedDictionary])) {
                $root[$pair.Section] = [ordered] @{}
            }

            $root[$pair.Section][$pair.Key] = $value
        }
        else {
            $root[$pair.Key] = $value
        }
    }

    return ($root | ConvertTo-Json -Depth 10)
}
