<#
    Toolkit - Features / Calculators

    The small tools of the job, each one a function the Tools page calls and
    the tests assert: random ports, Unix permissions, regular expressions,
    timestamps and text encodings.

    None of them changes the machine. The port generator reads which ports
    are in use and which ranges Windows reserves, so what it suggests can
    actually be opened here.
#>

# ---------------------------------------------------------------------------
# Random ports
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Reads the port ranges Windows reserves and will not let a program open.

.DESCRIPTION
    Hyper-V, WSL and Docker reserve whole blocks of ports; a service told to
    listen inside one fails with an access denied that says nothing about a
    reservation. netsh prints them under headings written in the display
    language, so only the lines made of two numbers are read.

.PARAMETER Text
    The output of netsh interface ipv4 show excludedportrange.

.OUTPUTS
    PSCustomObject[] with Start and End.
#>
function ConvertFrom-TkExcludedPortRange {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $rows = foreach ($line in ($Text -split "`r?`n")) {

        if ($line -match '^\s*(?<start>\d{1,5})\s+(?<end>\d{1,5})\s*\*?\s*$') {

            $start = [int] $Matches['start']
            $end   = [int] $Matches['end']

            if ($start -ge 1 -and $end -le 65535 -and $start -le $end) {
                [pscustomobject] @{ Start = $start; End = $end }
            }
        }
    }

    return @($rows)
}

<#
.SYNOPSIS
    Lists the ports this machine cannot hand to a new listener.

.DESCRIPTION
    The TCP ports listening, the UDP ports bound, and the TCP ranges Windows
    reserves.

.OUTPUTS
    System.Int32[]
#>
function Get-TkPortInUse {
    [CmdletBinding()]
    [OutputType([int[]])]
    param()

    $ports = New-Object System.Collections.Generic.List[int]

    try {
        foreach ($connection in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
            $ports.Add([int] $connection.LocalPort)
        }
    }
    catch {
        $null = $_
    }

    try {
        foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
            $ports.Add([int] $endpoint.LocalPort)
        }
    }
    catch {
        $null = $_
    }

    try {
        $text = (& netsh.exe interface ipv4 show excludedportrange protocol=tcp 2>$null) -join "`n"

        foreach ($range in @(ConvertFrom-TkExcludedPortRange -Text $text)) {
            for ($port = $range.Start; $port -le $range.End; $port++) {
                $ports.Add($port)
            }
        }
    }
    catch {
        $null = $_
    }

    return @($ports | Sort-Object -Unique)
}

<#
.SYNOPSIS
    Draws random ports from a range, leaving out the ones to avoid.

.DESCRIPTION
    Drawn with the cryptographic generator the password tools use. The ports
    are distinct. When fewer ports are free than asked for, every free one is
    returned rather than an endless draw.

.PARAMETER Minimum
    First port of the range.

.PARAMETER Maximum
    Last port of the range.

.PARAMETER Count
    How many ports.

.PARAMETER Exclude
    Ports to leave out, such as those in use.

.PARAMETER SkipKnownServices
    Also leaves out the ports of well-known services, such as 3389 or 8080.

.OUTPUTS
    System.Int32[], in the order drawn.
#>
function Get-TkRandomPort {
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter()] [ValidateRange(1, 65535)] [int] $Minimum = 49152,
        [Parameter()] [ValidateRange(1, 65535)] [int] $Maximum = 65535,
        [Parameter()] [ValidateRange(1, 1000)] [int] $Count = 5,
        [Parameter()] [AllowEmptyCollection()] [int[]] $Exclude = @(),
        [Parameter()] [switch] $SkipKnownServices
    )

    if ($Maximum -lt $Minimum) {
        throw ('The range ends at {0}, before it starts at {1}.' -f $Maximum, $Minimum)
    }

    $excluded = New-Object 'System.Collections.Generic.HashSet[int]'

    foreach ($port in $Exclude) {
        [void] $excluded.Add($port)
    }

    $size   = $Maximum - $Minimum + 1
    $chosen = New-Object System.Collections.Generic.List[int]

    $usable = {
        param($port)
        -not $excluded.Contains($port) -and -not ($SkipKnownServices -and (Get-TkWellKnownService -Port $port))
    }

    # Drawing at random stays fast while most of the range is free. A range
    # that is small or mostly taken is shuffled instead, so the draw ends.
    $inRange = @($Exclude | Where-Object { $_ -ge $Minimum -and $_ -le $Maximum } | Sort-Object -Unique).Count

    if (($size - $inRange) -ge ($Count * 4)) {

        $attempts = 0

        while ($chosen.Count -lt $Count -and $attempts -lt ($size * 4)) {

            $attempts++
            $port = $Minimum + (Get-TkRandomInteger -MaxExclusive $size)

            if ((& $usable $port) -and -not $chosen.Contains($port)) {
                $chosen.Add($port)
            }
        }
    }

    if ($chosen.Count -lt $Count) {

        $free = New-Object System.Collections.Generic.List[int]

        for ($port = $Minimum; $port -le $Maximum; $port++) {
            if ((& $usable $port) -and -not $chosen.Contains($port)) {
                $free.Add($port)
            }
        }

        # A partial Fisher-Yates shuffle: each place takes one of the ports
        # not placed yet, uniformly.
        $wanted = [math]::Min($Count - $chosen.Count, $free.Count)

        for ($index = 0; $index -lt $wanted; $index++) {

            $swap = $index + (Get-TkRandomInteger -MaxExclusive ($free.Count - $index))

            $held         = $free[$index]
            $free[$index] = $free[$swap]
            $free[$swap]  = $held

            $chosen.Add($free[$index])
        }
    }

    return $chosen.ToArray()
}

# ---------------------------------------------------------------------------
# Unix permissions
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Describes a Unix mode in every form it is written.

.PARAMETER Bits
    The mode, 0 to 7777 in octal (4095).

.OUTPUTS
    PSCustomObject with Bits, Octal, Symbolic, Listing, NumericCommand,
    SymbolicCommand, Owner, Group, Others, SetUid, SetGid and Sticky.
#>
function ConvertTo-TkUnixMode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 4095)]
        [int] $Bits
    )

    $triplet = {
        param($shift, $special, $letter)

        $read    = [bool] ($Bits -band (4 -shl $shift))
        $write   = [bool] ($Bits -band (2 -shl $shift))
        $execute = [bool] ($Bits -band (1 -shl $shift))
        $flag    = [bool] ($Bits -band $special)

        # s or t replaces x when the special bit is set with execute, S or T
        # when it is set without: ls writes it that way.
        $third = if ($flag -and $execute) { $letter } elseif ($flag) { $letter.ToUpperInvariant() } elseif ($execute) { 'x' } else { '-' }

        [pscustomobject] @{
            Read     = $read
            Write    = $write
            Execute  = $execute
            Text     = ('{0}{1}{2}' -f $(if ($read) { 'r' } else { '-' }), $(if ($write) { 'w' } else { '-' }), $third)
            Letters  = (@($(if ($read) { 'r' }), $(if ($write) { 'w' }), $(if ($execute) { 'x' }), $(if ($flag) { $letter })) | Where-Object { $_ }) -join ''
        }
    }

    $owner  = & $triplet 6 2048 's'
    $group  = & $triplet 3 1024 's'
    $others = & $triplet 0 512 't'

    $octal = [Convert]::ToString($Bits, 8)
    $octal = if ($Bits -ge 512) { $octal.PadLeft(4, '0') } else { $octal.PadLeft(3, '0') }

    $symbolic = '{0}{1}{2}' -f $owner.Text, $group.Text, $others.Text

    return [pscustomobject] @{
        Bits            = $Bits
        Octal           = $octal
        Symbolic        = $symbolic
        Listing         = '-' + $symbolic
        NumericCommand  = ('chmod {0} file' -f $octal)
        SymbolicCommand = ('chmod u={0},g={1},o={2} file' -f $owner.Letters, $group.Letters, $others.Letters)
        Owner           = $owner
        Group           = $group
        Others          = $others
        SetUid          = [bool] ($Bits -band 2048)
        SetGid          = [bool] ($Bits -band 1024)
        Sticky          = [bool] ($Bits -band 512)
    }
}

<#
.SYNOPSIS
    Reads a mode typed in octal or in symbolic form.

.DESCRIPTION
    Octal: one to four digits, 755 or 0755 or 4755. Symbolic: the nine
    characters of ls, rwxr-xr-x, with an optional file type in front such as
    drwxrwxrwt. Letters are read as ls writes them, in lower case, with S and
    T for a special bit without execute.

.PARAMETER Text
    What was typed.

.OUTPUTS
    System.Int32, or $null when it is not a mode.
#>
function ConvertFrom-TkUnixModeText {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $clean = $Text.Trim()

    if ($clean -cmatch '^[0-7]{1,4}$') {
        return [Convert]::ToInt32($clean, 8)
    }

    if ($clean -cnotmatch '^[-dlcbps]?[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]$') {
        return $null
    }

    $mode = $clean.Substring($clean.Length - 9)
    $bits = 0

    if ($mode[0] -ceq 'r') { $bits += 256 }
    if ($mode[1] -ceq 'w') { $bits += 128 }

    switch -CaseSensitive ([string] $mode[2]) {
        'x' { $bits += 64 }
        's' { $bits += 64 + 2048 }
        'S' { $bits += 2048 }
    }

    if ($mode[3] -ceq 'r') { $bits += 32 }
    if ($mode[4] -ceq 'w') { $bits += 16 }

    switch -CaseSensitive ([string] $mode[5]) {
        'x' { $bits += 8 }
        's' { $bits += 8 + 1024 }
        'S' { $bits += 1024 }
    }

    if ($mode[6] -ceq 'r') { $bits += 4 }
    if ($mode[7] -ceq 'w') { $bits += 2 }

    switch -CaseSensitive ([string] $mode[8]) {
        'x' { $bits += 1 }
        't' { $bits += 1 + 512 }
        'T' { $bits += 512 }
    }

    return $bits
}

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Runs a regular expression against a text and reports every match.

.DESCRIPTION
    The .NET flavour, the one -match and -replace use. A time limit stops a
    pattern that backtracks without end, such as (a+)+$ on a long line,
    instead of freezing the window.

.PARAMETER Pattern
    The regular expression.

.PARAMETER Text
    The text to search.

.PARAMETER IgnoreCase
    Case insensitive.

.PARAMETER Multiline
    ^ and $ match at each line.

.PARAMETER Singleline
    The dot matches new lines too.

.PARAMETER Replace
    Also applies Replacement to the whole text.

.PARAMETER Replacement
    The replacement, with $1 or ${name} for a group.

.PARAMETER MaxMatches
    How many matches to report at most.

.PARAMETER TimeoutMilliseconds
    How long a match may run.

.OUTPUTS
    PSCustomObject with Valid, Error, TimedOut, Matches, Truncated and
    Replaced.
#>
function Test-TkRegularExpression {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Pattern,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter()] [switch] $IgnoreCase,
        [Parameter()] [switch] $Multiline,
        [Parameter()] [switch] $Singleline,
        [Parameter()] [switch] $Replace,
        [Parameter()] [AllowEmptyString()] [string] $Replacement = '',
        [Parameter()] [ValidateRange(1, 5000)] [int] $MaxMatches = 500,
        [Parameter()] [ValidateRange(50, 10000)] [int] $TimeoutMilliseconds = 2000
    )

    $result = [pscustomobject] @{
        Valid     = $false
        Error     = ''
        TimedOut  = $false
        Matches   = @()
        Truncated = $false
        Replaced  = $null
    }

    if (-not $Pattern) {
        $result.Error = 'Type a pattern.'
        return $result
    }

    $options = [System.Text.RegularExpressions.RegexOptions]::None

    if ($IgnoreCase) { $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    if ($Multiline)  { $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::Multiline }
    if ($Singleline) { $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::Singleline }

    $innermost = {
        param($exception)
        while ($exception.InnerException) { $exception = $exception.InnerException }
        $exception
    }

    try {
        $regex = New-Object System.Text.RegularExpressions.Regex($Pattern, $options, [TimeSpan]::FromMilliseconds($TimeoutMilliseconds))
    }
    catch {
        $result.Error = (& $innermost $_.Exception).Message
        return $result
    }

    $result.Valid = $true
    $found        = New-Object System.Collections.Generic.List[object]

    try {
        $match = $regex.Match($Text)

        while ($match.Success) {

            if ($found.Count -ge $MaxMatches) {
                $result.Truncated = $true
                break
            }

            $groups = for ($number = 1; $number -lt $match.Groups.Count; $number++) {

                $group = $match.Groups[$number]

                [pscustomobject] @{
                    Name    = $regex.GroupNameFromNumber($number)
                    Success = $group.Success
                    Index   = $group.Index
                    Value   = $group.Value
                }
            }

            $found.Add([pscustomobject] @{
                Index  = $match.Index
                Length = $match.Length
                Line   = ($Text.Substring(0, $match.Index) -split "`n").Count
                Value  = $match.Value
                Groups = @($groups)
            })

            $match = $match.NextMatch()
        }

        if ($Replace) {
            $result.Replaced = $regex.Replace($Text, $Replacement)
        }
    }
    catch {
        $inner = & $innermost $_.Exception

        if ($inner -is [System.Text.RegularExpressions.RegexMatchTimeoutException]) {
            $result.TimedOut = $true
        }
        else {
            $result.Error = $inner.Message
        }
    }

    $result.Matches = $found.ToArray()

    return $result
}

<#
.SYNOPSIS
    Lists the regular expression tokens shown beside the tester.

.DESCRIPTION
    The .NET flavour, the one -match, -replace, Select-String and the tester
    use. Insert is what a double-click puts into the pattern, or into the
    replacement when Target says so. Ready-made patterns carry an Example they
    match whole, which the tests check.

.OUTPUTS
    PSCustomObject[] with Section, Token, Insert, Target, Description and Example.
#>
function Get-TkRegexCheatSheet {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $entry = {
        param($section, $token, $description, $insert, $example, $target)

        [pscustomobject] @{
            Section     = $section
            Token       = $token
            Insert      = $(if ($insert) { $insert } else { $token })
            Target      = $(if ($target) { $target } else { 'Pattern' })
            Description = $description
            Example     = $example
        }
    }

    $characters = 'Characters'
    $anchors    = 'Anchors'
    $repeats    = 'Repeats'
    $groups     = 'Groups and alternatives'
    $around     = 'Lookaround'
    $options    = 'Inline options'
    $replace    = 'Replacement'
    $ready      = 'Ready-made patterns'

    return @(
        (& $entry $characters '.'       'Any character but a new line')
        (& $entry $characters '\d'      'A digit; \D anything but a digit')
        (& $entry $characters '\w'      'A letter, digit or underscore; \W the opposite')
        (& $entry $characters '\s'      'A space, tab or new line; \S the opposite')
        (& $entry $characters '[abc]'   'One of the characters listed')
        (& $entry $characters '[^abc]'  'Any character but those listed')
        (& $entry $characters '[a-z0-9]' 'One character in the ranges')
        (& $entry $characters '\.'      'A dot itself: escape . * + ? ( ) [ ] { } | ^ $ \ this way')
        (& $entry $characters '\t \n'   'A tab, a new line; \r a carriage return' '\n')
        (& $entry $characters '\p{L}'   'A letter in any language, accents included')
        (& $entry $anchors    '^'       'The start of the text, or of each line with the option')
        (& $entry $anchors    '$'       'The end of the text, or of each line with the option')
        (& $entry $anchors    '\b'      'A word boundary: \bcat\b finds cat, not category')
        (& $entry $anchors    '\A \z'   'The very start and end of the text, whatever the options' '\A')
        (& $entry $repeats    '*'       'Zero or more times')
        (& $entry $repeats    '+'       'One or more times')
        (& $entry $repeats    '?'       'Zero or one time: optional')
        (& $entry $repeats    '{3}'     'Exactly 3 times')
        (& $entry $repeats    '{2,5}'   'From 2 to 5 times; {2,} at least 2')
        (& $entry $repeats    '+?'      'As few times as possible: *? and ?? work the same way')
        (& $entry $groups     '(...)'   'A group, numbered from 1 in the results' '()')
        (& $entry $groups     '(?<name>...)' 'A named group' '(?<name>)')
        (& $entry $groups     '(?:...)' 'Groups without capturing' '(?:)')
        (& $entry $groups     'a|b'     'Either side' '|')
        (& $entry $groups     '\1'      'The same text as group 1 again; \k<name> for a named group')
        (& $entry $around     '(?=...)'  'Followed by, without taking it' '(?=)')
        (& $entry $around     '(?!...)'  'Not followed by' '(?!)')
        (& $entry $around     '(?<=...)' 'Preceded by, without taking it' '(?<=)')
        (& $entry $around     '(?<!...)' 'Not preceded by' '(?<!)')
        (& $entry $options    '(?i)'    'Ignore case from here on')
        (& $entry $options    '(?m)'    '^ and $ match at each line')
        (& $entry $options    '(?s)'    'The dot matches new lines')
        (& $entry $options    '(?x)'    'Spaces ignored and # starts a comment, for a long pattern')
        (& $entry $replace    '$1'      'Group 1 in the replacement' '$1' $null 'Replacement')
        (& $entry $replace    '${name}' 'A named group in the replacement' '${name}' $null 'Replacement')
        (& $entry $replace    '$0'      'The whole match' '$0' $null 'Replacement')
        (& $entry $replace    '$$'      'A dollar sign itself' '$$' $null 'Replacement')
        (& $entry $ready      'IPv4 address' 'Four numbers from 0 to 255' '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b' '192.168.1.254')
        (& $entry $ready      'MAC address'  'Six pairs separated by : or -' '\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b' '00:1A:2B:3C:4D:5E')
        (& $entry $ready      'E-mail address' 'A practical match, not every address RFC 5322 allows' '\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b' 'jane.doe@example.com')
        (& $entry $ready      'Host name'    'A fully qualified name, labels of up to 63 characters' '\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b' 'srv01.corp.example.com')
        (& $entry $ready      'URL'          'An http or https link up to a space or a quote' 'https?://[^\s"''<>]+' 'https://example.com/path?id=42')
        (& $entry $ready      'ISO date'     'A year, month and day: 2026-09-14' '\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b' '2026-09-14')
        (& $entry $ready      'GUID'         'Braces are left out, add \{ and \} around it for them' '\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b' '3f2504e0-4f89-41d3-9a0c-0305e82c3301')
        (& $entry $ready      'Windows SID'  'A security identifier' '\bS-1-\d+(?:-\d+)+\b' 'S-1-5-21-3623811015-3361044348-30300820-1013')
        (& $entry $ready      'Windows path' 'A drive letter path' '[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*' 'C:\Windows\System32\drivers\etc\hosts')
        (& $entry $ready      'Log severity' 'The lines worth reading first in a log' '\b(?:ERROR|WARN(?:ING)?|FATAL|CRITICAL)\b' 'WARNING')
    )
}

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Says how long ago, or in how long, a moment is.

.PARAMETER Utc
    The moment, in UTC.

.PARAMETER Now
    The current time.

.OUTPUTS
    System.String
#>
function Format-TkRelativeTime {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [datetime] $Utc,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $span    = $Now.ToUniversalTime() - $Utc
    $seconds = [math]::Abs($span.TotalSeconds)

    if ($seconds -lt 60) {
        return 'now'
    }

    $amount = if ($seconds -lt 3600) { '{0} minute(s)' -f [int] [math]::Floor($seconds / 60) }
              elseif ($seconds -lt 86400) { '{0} hour(s)' -f [int] [math]::Floor($seconds / 3600) }
              elseif ($seconds -lt 86400 * 365.25) { '{0} day(s)' -f [int] [math]::Floor($seconds / 86400) }
              else { '{0} year(s)' -f [int] [math]::Floor($seconds / (86400 * 365.25)) }

    if ($span.TotalSeconds -ge 0) {
        return ('{0} ago' -f $amount)
    }

    return ('in {0}' -f $amount)
}

<#
.SYNOPSIS
    Reads a timestamp or a date, and writes it in every form.

.DESCRIPTION
    A number is read as Unix seconds, Unix milliseconds, a Windows FILETIME
    (the lastLogonTimestamp, pwdLastSet or accountExpires of an Active
    Directory account), or Unix microseconds or nanoseconds: the first reading
    that lands between 1980 and 2200 is kept, and the others are listed. 0 and
    the largest 64-bit number are the never of Active Directory.

.PARAMETER Text
    A number, a date, or now.

.PARAMETER Now
    The current time.

.OUTPUTS
    PSCustomObject with Valid, Kind, Utc, Local, Iso, UnixSeconds,
    UnixMilliseconds, FileTime, Relative, Note and Alternatives.
#>
function ConvertFrom-TkTimestamp {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $clean        = $Text.Trim()
    $utc          = $null
    $kind         = ''
    $note         = ''
    $alternatives = @()

    if (-not $clean -or $clean -eq 'now') {
        $utc  = $Now.ToUniversalTime()
        $kind = 'Now'
    }
    elseif ($clean -match '^-?\d+$') {

        $number = 0L

        if (-not [long]::TryParse($clean, [ref] $number)) {
            return [pscustomobject] @{ Valid = $false; Note = 'The number is larger than a 64-bit timestamp.' }
        }

        if ($number -eq 0 -or $number -eq [long]::MaxValue) {

            $note = if ($number -eq 0) {
                        'In Active Directory 0 means never set: a lastLogonTimestamp of 0 is an account that never signed in, and a pwdLastSet of 0 a password to change at the next sign-in. As Unix time it is 1970-01-01.'
                    }
                    else {
                        'In Active Directory this value means never: an accountExpires set to it is an account that does not expire.'
                    }

            if ($number -eq [long]::MaxValue) {
                return [pscustomobject] @{ Valid = $true; Kind = 'Never'; Utc = $null; Local = $null; Iso = ''; UnixSeconds = $null; UnixMilliseconds = $null; FileTime = $number; Relative = ''; Note = $note; Alternatives = @() }
            }
        }

        $candidates = New-Object System.Collections.Generic.List[object]

        $try = {
            param($label, $convert)

            try {
                $candidates.Add([pscustomobject] @{ Kind = $label; Utc = (& $convert) })
            }
            catch {
                $null = $_
            }
        }

        & $try 'Unix time, seconds' { [DateTimeOffset]::FromUnixTimeSeconds($number).UtcDateTime }
        & $try 'Unix time, milliseconds' { [DateTimeOffset]::FromUnixTimeMilliseconds($number).UtcDateTime }
        & $try 'Windows FILETIME (Active Directory timestamps)' { [DateTime]::FromFileTimeUtc($number) }
        & $try 'Unix time, microseconds' { [DateTimeOffset]::FromUnixTimeMilliseconds([long] [math]::Floor($number / 1000)).UtcDateTime }
        & $try 'Unix time, nanoseconds' { [DateTimeOffset]::FromUnixTimeMilliseconds([long] [math]::Floor($number / 1000000)).UtcDateTime }

        if ($candidates.Count -eq 0) {
            return [pscustomobject] @{ Valid = $false; Note = 'No timestamp format gives a date for this number.' }
        }

        $plausible = @($candidates | Where-Object { $_.Utc.Year -ge 1980 -and $_.Utc.Year -le 2200 })
        $chosen    = if ($plausible.Count -gt 0) { $plausible[0] } else { $candidates[0] }

        $utc          = $chosen.Utc
        $kind         = $chosen.Kind
        $alternatives = @($plausible | Where-Object { $_ -ne $chosen })
    }
    else {

        $parsed = [DateTimeOffset]::MinValue

        if ([DateTimeOffset]::TryParse($clean, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref] $parsed) -or
            [DateTimeOffset]::TryParse($clean, [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref] $parsed)) {

            $utc  = $parsed.UtcDateTime
            $kind = 'Date'
        }
        else {
            return [pscustomobject] @{ Valid = $false; Note = 'Not a date or a timestamp.' }
        }
    }

    $invariant = [Globalization.CultureInfo]::InvariantCulture
    $offset    = New-Object DateTimeOffset([datetime]::SpecifyKind($utc, [DateTimeKind]::Utc))

    return [pscustomobject] @{
        Valid            = $true
        Kind             = $kind
        Utc              = $utc
        Local            = $utc.ToLocalTime()
        Iso              = $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $invariant)
        UnixSeconds      = $offset.ToUnixTimeSeconds()
        UnixMilliseconds = $offset.ToUnixTimeMilliseconds()
        FileTime         = $(if ($utc.Year -ge 1601) { $utc.ToFileTimeUtc() } else { $null })
        Relative         = Format-TkRelativeTime -Utc $utc -Now $Now
        Note             = $note
        Alternatives     = $alternatives
    }
}

# ---------------------------------------------------------------------------
# Text encodings
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Decodes Base64, and the URL safe variant a JWT uses.

.PARAMETER Text
    The Base64 text.

.OUTPUTS
    System.Byte[]
#>
function ConvertFrom-TkBase64Text {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $clean = ($Text -replace '\s', '').Replace('-', '+').Replace('_', '/')

    switch ($clean.Length % 4) {
        1 { throw 'This is not valid Base64: its length is wrong.' }
        2 { $clean += '==' }
        3 { $clean += '=' }
    }

    try {
        $bytes = [Convert]::FromBase64String($clean)
    }
    catch {
        throw 'This is not valid Base64.'
    }

    return , $bytes
}

<#
.SYNOPSIS
    Indents a JSON text, keeping its order and its values as written.

.DESCRIPTION
    ConvertTo-Json indents differently in Windows PowerShell 5.1 and in
    PowerShell 7, and reading the text first would turn dates into DateTime
    in PowerShell 7. Walking the characters keeps the document as it was
    sent, only laid out.

.PARAMETER Json
    A valid JSON text.

.OUTPUTS
    System.String
#>
function Format-TkJsonText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Json
    )

    $builder  = New-Object System.Text.StringBuilder
    $depth    = 0
    $inString = $false
    $escaped  = $false
    $newLine  = { param($level) [void] $builder.Append("`n").Append('  ' * $level) }

    for ($index = 0; $index -lt $Json.Length; $index++) {

        $character = $Json[$index]

        if ($inString) {

            [void] $builder.Append($character)

            if ($escaped) { $escaped = $false }
            elseif ($character -eq '\') { $escaped = $true }
            elseif ($character -eq '"') { $inString = $false }

            continue
        }

        switch -CaseSensitive ([string] $character) {

            '"' {
                $inString = $true
                [void] $builder.Append($character)
            }

            { $_ -eq '{' -or $_ -eq '[' } {

                # An empty object or array stays on one line.
                $next = $index + 1
                while ($next -lt $Json.Length -and [char]::IsWhiteSpace($Json[$next])) { $next++ }

                if ($next -lt $Json.Length -and ($Json[$next] -eq '}' -or $Json[$next] -eq ']')) {
                    [void] $builder.Append($character).Append($Json[$next])
                    $index = $next
                }
                else {
                    $depth++
                    [void] $builder.Append($character)
                    & $newLine $depth
                }
            }

            { $_ -eq '}' -or $_ -eq ']' } {
                $depth = [math]::Max(0, $depth - 1)
                & $newLine $depth
                [void] $builder.Append($character)
            }

            ',' {
                [void] $builder.Append($character)
                & $newLine $depth
            }

            ':' {
                [void] $builder.Append(': ')
            }

            default {
                if (-not [char]::IsWhiteSpace($character)) {
                    [void] $builder.Append($character)
                }
            }
        }
    }

    return $builder.ToString()
}

<#
.SYNOPSIS
    Decodes a JSON Web Token without checking its signature.

.PARAMETER Token
    The token.

.PARAMETER Now
    The current time, to say whether it has expired.

.OUTPUTS
    PSCustomObject with Header, Payload, HeaderText, PayloadText, Signed,
    Times and Expired.
#>
function ConvertFrom-TkJwt {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Token,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $parts = $Token.Trim() -split '\.'

    if ($parts.Count -lt 2 -or -not $parts[0] -or -not $parts[1]) {
        throw 'A JWT has three parts separated by dots: a header, a payload and a signature.'
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false)

    try {
        $headerText  = $utf8.GetString((ConvertFrom-TkBase64Text -Text $parts[0]))
        $payloadText = $utf8.GetString((ConvertFrom-TkBase64Text -Text $parts[1]))
        $header      = $headerText | ConvertFrom-Json
        $payload     = $payloadText | ConvertFrom-Json
    }
    catch {
        throw 'This does not decode as a JWT: its header or its payload is not Base64 encoded JSON.'
    }

    $names = @{ exp = 'Expires'; nbf = 'Not before'; iat = 'Issued' }
    $times = @()
    $expired = $null

    foreach ($claim in @('iat', 'nbf', 'exp')) {

        $seconds = 0L

        if ($payload.PSObject.Properties[$claim] -and [long]::TryParse([string] $payload.$claim, [ref] $seconds)) {

            $when   = [DateTimeOffset]::FromUnixTimeSeconds($seconds).UtcDateTime
            $times += [pscustomobject] @{ Claim = $claim; Name = $names[$claim]; Utc = $when }

            if ($claim -eq 'exp') {
                $expired = ($when -lt $Now.ToUniversalTime())
            }
        }
    }

    return [pscustomobject] @{
        Header      = $header
        Payload     = $payload
        HeaderText  = Format-TkJsonText -Json $headerText
        PayloadText = Format-TkJsonText -Json $payloadText
        Signed      = ($parts.Count -ge 3 -and [bool] $parts[2])
        Times   = $times
        Expired = $expired
    }
}

<#
.SYNOPSIS
    Encodes or decodes text.

.PARAMETER Text
    The text.

.PARAMETER Operation
    What to do with it. Text is read and written as UTF-8.

.OUTPUTS
    System.String
#>
function Convert-TkText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [ValidateSet('Base64Encode', 'Base64Decode', 'UrlEncode', 'UrlDecode', 'HtmlEncode', 'HtmlDecode', 'HexEncode', 'HexDecode', 'JwtDecode')]
        [string] $Operation
    )

    $utf8 = New-Object System.Text.UTF8Encoding($false)

    switch ($Operation) {

        'Base64Encode' { return [Convert]::ToBase64String($utf8.GetBytes($Text)) }
        'Base64Decode' { return $utf8.GetString((ConvertFrom-TkBase64Text -Text $Text)) }
        'UrlEncode'    { return [Uri]::EscapeDataString($Text) }
        'UrlDecode'    { return [System.Net.WebUtility]::UrlDecode($Text) }
        'HtmlEncode'   { return [System.Net.WebUtility]::HtmlEncode($Text) }
        'HtmlDecode'   { return [System.Net.WebUtility]::HtmlDecode($Text) }
        'HexEncode'    { return (@($utf8.GetBytes($Text) | ForEach-Object { '{0:x2}' -f $_ }) -join '') }

        'HexDecode' {

            $clean = ($Text -replace '0[xX]', '') -replace '[\s:\-,]', ''

            if ($clean.Length % 2 -ne 0 -or $clean -notmatch '^[0-9A-Fa-f]*$') {
                throw 'This is not hexadecimal: it needs pairs of the digits 0-9 and a-f.'
            }

            $bytes = New-Object byte[] ($clean.Length / 2)

            for ($index = 0; $index -lt $bytes.Length; $index++) {
                $bytes[$index] = [Convert]::ToByte($clean.Substring($index * 2, 2), 16)
            }

            return $utf8.GetString($bytes)
        }

        'JwtDecode' {

            $token = ConvertFrom-TkJwt -Token $Text
            $lines = New-Object System.Collections.Generic.List[string]

            $lines.Add('Header')
            $lines.Add(($token.HeaderText -replace "`n", [Environment]::NewLine))
            $lines.Add('')
            $lines.Add('Payload')
            $lines.Add(($token.PayloadText -replace "`n", [Environment]::NewLine))

            if (@($token.Times).Count -gt 0) {

                $lines.Add('')

                foreach ($time in $token.Times) {
                    $lines.Add(('{0,-11} {1} UTC ({2})' -f $time.Name, $time.Utc.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture), (Format-TkRelativeTime -Utc $time.Utc)))
                }
            }

            $lines.Add('')
            $lines.Add('The signature is not checked: anyone can write a token that decodes like this one. Only the service that issued it can say whether it is genuine.')

            return ($lines -join [Environment]::NewLine)
        }
    }
}
