<#
    Toolkit - Features / Text and data tools

    UUIDs, the NATO phonetic alphabet, URLs, Safe Links, text differences and
    phone numbers: what a technician pastes into a web site to decode, often a
    site that keeps what it is given. Everything here runs on this machine and
    opens nothing.

    Pure functions, called by the Tools page and asserted by the tests.
#>

# ---------------------------------------------------------------------------
# UUIDs
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Generates UUIDs, random (version 4) or ordered by time (version 7).

.DESCRIPTION
    Version 7 starts with the Unix time in milliseconds, so keys generated with
    it arrive in order in a database index; the rest is random. Both are drawn
    from the cryptographic random generator, and the version and variant bits
    are set as RFC 9562 asks.

.PARAMETER Version
    4 or 7.

.PARAMETER Count
    How many.

.PARAMETER Now
    The time written into a version 7 UUID.

.OUTPUTS
    System.String[], in the standard lower case form.
#>
function New-TkUuid {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()] [ValidateSet(4, 7)] [int] $Version = 4,
        [Parameter()] [ValidateRange(1, 1000)] [int] $Count = 1,
        [Parameter()] [datetime] $Now = [datetime]::UtcNow
    )

    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $utc    = [datetime]::SpecifyKind($Now.ToUniversalTime(), [DateTimeKind]::Utc)
    $millis = ([DateTimeOffset] $utc).ToUnixTimeMilliseconds()

    try {
        $rows = for ($index = 0; $index -lt $Count; $index++) {

            $bytes = New-Object byte[] 16
            $random.GetBytes($bytes)

            if ($Version -eq 7) {
                for ($position = 0; $position -lt 6; $position++) {
                    $bytes[$position] = [byte] (($millis -shr (8 * (5 - $position))) -band 0xFF)
                }
            }

            $bytes[6] = [byte] (($bytes[6] -band 0x0F) -bor ($Version -shl 4))
            $bytes[8] = [byte] (($bytes[8] -band 0x3F) -bor 0x80)

            $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })

            '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)
        }
    }
    finally {
        $random.Dispose()
    }

    return @($rows)
}

<#
.SYNOPSIS
    Lists the ways a UUID is written.

.OUTPUTS
    PSCustomObject[] with Label and Format.
#>
function Get-TkUuidFormatChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Standard, lower case';    Format = 'Standard' }
        [pscustomobject] @{ Label = 'Upper case';              Format = 'Uppercase' }
        [pscustomobject] @{ Label = 'Braces, as the registry'; Format = 'Braces' }
        [pscustomobject] @{ Label = 'No hyphens';              Format = 'Compact' }
        [pscustomobject] @{ Label = 'URN';                     Format = 'Urn' }
    )
}

<#
.SYNOPSIS
    Writes a UUID in one of its forms.

.PARAMETER Uuid
    A UUID in the standard form.

.PARAMETER Format
    Standard, Uppercase, Braces, Compact or Urn.

.OUTPUTS
    System.String
#>
function Format-TkUuid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Uuid,
        [Parameter()] [ValidateSet('Standard', 'Uppercase', 'Braces', 'Compact', 'Urn')] [string] $Format = 'Standard'
    )

    $value = $Uuid.ToLowerInvariant()

    switch ($Format) {
        'Uppercase' { return $value.ToUpperInvariant() }
        'Braces'    { return ('{{{0}}}' -f $value.ToUpperInvariant()) }
        'Compact'   { return ($value -replace '-', '') }
        'Urn'       { return ('urn:uuid:{0}' -f $value) }
    }

    return $value
}

<#
.SYNOPSIS
    Reads what a UUID says about itself.

.DESCRIPTION
    The version tells how it was made; versions 1, 6 and 7 carry the time they
    were made, and version 1 the MAC address of the machine, or a random
    stand-in for it.

.PARAMETER Text
    A UUID or GUID, with or without hyphens, braces or urn:uuid:.

.OUTPUTS
    PSCustomObject with Valid, Uuid, Version, VersionName, Variant, Time, Node
    and Note.
#>
function ConvertFrom-TkUuid {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $clean = ($Text.Trim() -replace '^(?i)urn:uuid:', '') -replace '[{}]', ''

    if ($clean -notmatch '^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$') {
        return [pscustomobject] @{ Valid = $false; Note = 'A UUID is 32 hexadecimal digits, usually written 8-4-4-4-12.' }
    }

    $hex  = ($clean -replace '-', '').ToLowerInvariant()
    $uuid = '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)

    if ($hex -eq ('0' * 32) -or $hex -eq ('f' * 32)) {
        return [pscustomobject] @{
            Valid = $true; Uuid = $uuid; Version = 0
            VersionName = $(if ($hex -eq ('0' * 32)) { 'the nil UUID, all zeros' } else { 'the max UUID, all ones' })
            Variant = ''; Time = $null; Node = ''; Note = 'A placeholder value rather than an identifier.'
        }
    }

    $version = [Convert]::ToInt32($hex.Substring(12, 1), 16)
    $marker  = [Convert]::ToInt32($hex.Substring(16, 1), 16)

    $variant = if (($marker -band 0x8) -eq 0) { 'NCS, reserved for backward compatibility' }
               elseif (($marker -band 0xC) -eq 0x8) { 'RFC 9562' }
               elseif (($marker -band 0xE) -eq 0xC) { 'Microsoft, reserved for backward compatibility' }
               else { 'reserved for the future' }

    $names = @{
        1 = 'time and MAC address'; 2 = 'DCE security'; 3 = 'name based, MD5'; 4 = 'random'
        5 = 'name based, SHA-1'; 6 = 'time, reordered for sorting'; 7 = 'Unix time and random'; 8 = 'custom'
    }

    $time = $null
    $node = ''

    if ($variant -eq 'RFC 9562') {

        # Gregorian epoch of versions 1 and 6, counted in 100 nanosecond steps.
        $gregorian = [datetime]::new(1582, 10, 15, 0, 0, 0, [DateTimeKind]::Utc)

        switch ($version) {
            1 {
                $time = $gregorian.AddTicks([Convert]::ToInt64($hex.Substring(13, 3) + $hex.Substring(8, 4) + $hex.Substring(0, 8), 16))
                $node = (($hex.Substring(20, 12) -split '(..)' | Where-Object { $_ }) -join ':').ToUpperInvariant()
            }
            6 {
                $time = $gregorian.AddTicks([Convert]::ToInt64($hex.Substring(0, 12) + $hex.Substring(13, 3), 16))
            }
            7 {
                $time = [DateTimeOffset]::FromUnixTimeMilliseconds([Convert]::ToInt64($hex.Substring(0, 12), 16)).UtcDateTime
            }
        }
    }

    return [pscustomobject] @{
        Valid       = $true
        Uuid        = $uuid
        Version     = $version
        VersionName = $(if ($names.ContainsKey($version)) { 'version {0}, {1}' -f $version, $names[$version] } else { 'version {0}, not defined' -f $version })
        Variant     = $variant
        Time        = $time
        Node        = $node
        Note        = 'Windows stores the first three groups of a GUID byte-reversed in memory and in some registry values; the text form is the same everywhere.'
    }
}

# ---------------------------------------------------------------------------
# NATO phonetic alphabet
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Spells a text out with the NATO phonetic alphabet.

.PARAMETER Text
    What to spell out: a serial number, a licence key, a password to dictate.

.PARAMETER MarkCase
    Says Capital before an upper case letter, for a password where it matters.

.OUTPUTS
    PSCustomObject[] with Character, Spoken and Kind.
#>
function ConvertTo-TkNatoAlphabet {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter()] [switch] $MarkCase
    )

    $letters = @('Alfa', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot', 'Golf', 'Hotel', 'India', 'Juliett', 'Kilo', 'Lima', 'Mike',
                 'November', 'Oscar', 'Papa', 'Quebec', 'Romeo', 'Sierra', 'Tango', 'Uniform', 'Victor', 'Whiskey', 'X-ray', 'Yankee', 'Zulu')
    $digits  = @('Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine')

    $symbols = @{
        ' ' = 'Space'; '-' = 'Dash'; '_' = 'Underscore'; '.' = 'Dot'; ',' = 'Comma'; '@' = 'At sign'; '/' = 'Slash'
        '\' = 'Backslash'; ':' = 'Colon'; ';' = 'Semicolon'; '!' = 'Exclamation mark'; '?' = 'Question mark'; '#' = 'Hash'
        '$' = 'Dollar sign'; '%' = 'Percent sign'; '&' = 'Ampersand'; '*' = 'Asterisk'; '+' = 'Plus sign'; '=' = 'Equals sign'
        '(' = 'Open parenthesis'; ')' = 'Close parenthesis'; '[' = 'Open square bracket'; ']' = 'Close square bracket'
        '{' = 'Open curly brace'; '}' = 'Close curly brace'; '<' = 'Less than sign'; '>' = 'Greater than sign'
        '"' = 'Double quote'; "'" = 'Single quote'; '^' = 'Caret'; '~' = 'Tilde'; '|' = 'Vertical bar'; '`' = 'Backtick'
    }

    $rows = foreach ($character in $Text.ToCharArray()) {

        $value = [string] $character
        $base  = $value.Normalize([Text.NormalizationForm]::FormD)[0]

        if ([string] $base -cmatch '^[A-Za-z]$') {

            $spoken = $letters[[int] [char]::ToUpperInvariant($base) - 65]

            if ($MarkCase -and [char]::IsUpper($base)) {
                $spoken = 'Capital {0}' -f $spoken
            }

            if ($base -cne $character) {
                $spoken = '{0} (with an accent)' -f $spoken
            }

            [pscustomobject] @{ Character = $value; Spoken = $spoken; Kind = 'Letter' }
        }
        elseif ($value -match '^[0-9]$') {
            [pscustomobject] @{ Character = $value; Spoken = $digits[[int] $value]; Kind = 'Digit' }
        }
        elseif ($symbols.ContainsKey($value)) {
            [pscustomobject] @{ Character = $value; Spoken = $symbols[$value]; Kind = 'Symbol' }
        }
        else {
            [pscustomobject] @{ Character = $value; Spoken = ('U+{0:X4}' -f [int] $character); Kind = 'Other' }
        }
    }

    return @($rows)
}

# ---------------------------------------------------------------------------
# URLs and Safe Links
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Takes a URL apart.

.DESCRIPTION
    Every part decoded, the host as DNS resolves it, and the tricks a phishing
    link relies on named: a user name before @ that looks like the site, a
    host written with look-alike letters, an address instead of a name, a
    password in clear, a site without encryption.

.PARAMETER Url
    The link. Without a scheme, https is assumed.

.OUTPUTS
    PSCustomObject with Valid, SchemeAssumed, Scheme, User, HasPassword, Host,
    AsciiHost, UnicodeHost, HostType, Port, IsDefaultPort, Path, Segments,
    Query, Fragment, Origin, Warnings and Note.
#>
function Get-TkUrlPart {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Url
    )

    $clean   = $Url.Trim()
    $assumed = $false

    if (-not $clean) {
        return [pscustomobject] @{ Valid = $false; Note = 'Paste a link.' }
    }

    if ($clean -notmatch '^[A-Za-z][A-Za-z0-9+.\-]*:') {
        $clean   = 'https://' + $clean
        $assumed = $true
    }

    $uri = $null

    if (-not [Uri]::TryCreate($clean, [UriKind]::Absolute, [ref] $uri)) {
        return [pscustomobject] @{ Valid = $false; Note = 'This is not a link that can be read.' }
    }

    $decode = {
        param($value)
        try { [Uri]::UnescapeDataString(($value -replace '\+', ' ')) } catch { $value }
    }

    # The query and the fragment are read from the text as written: the .NET
    # Framework Uri of Windows PowerShell 5.1 rewrites some escapes, and the
    # value of a parameter is often itself an escaped link.
    $rawQuery    = [regex]::Match($clean, '^[^?#]*\?(?<query>[^#]*)').Groups['query'].Value
    $rawFragment = [regex]::Match($clean, '#(?<fragment>.*)$').Groups['fragment'].Value

    $query = New-Object System.Collections.Generic.List[object]

    if ($rawQuery) {

        foreach ($pair in ($rawQuery -split '&')) {

            if (-not $pair) { continue }

            $parts = $pair -split '=', 2

            $query.Add([pscustomobject] @{
                Name  = & $decode $parts[0]
                Value = $(if ($parts.Count -gt 1) { & $decode $parts[1] } else { $null })
            })
        }
    }

    $user        = ''
    $hasPassword = $false

    if ($uri.UserInfo) {
        $credentials = $uri.UserInfo -split ':', 2
        $user        = & $decode $credentials[0]
        $hasPassword = $credentials.Count -gt 1
    }

    $hostName    = $uri.Host
    $asciiHost   = $hostName
    $unicodeHost = $hostName
    $hostType    = [string] $uri.HostNameType

    if ($uri.HostNameType -eq [UriHostNameType]::Dns) {
        try {
            $idn         = New-Object System.Globalization.IdnMapping
            $asciiHost   = $idn.GetAscii($hostName)
            $unicodeHost = $idn.GetUnicode($asciiHost)
        }
        catch {
            $null = $_
        }
    }

    $warnings = New-Object System.Collections.Generic.List[string]

    if ($user) {
        $warnings.Add(('The part before @ ("{0}") is a user name, not the site: this link goes to {1}.' -f $user, $asciiHost))
    }

    if ($hasPassword) {
        $warnings.Add('The link carries a password in clear: anyone who sees the link has it.')
    }

    if ($asciiHost -ne $unicodeHost -or $asciiHost -match '(^|\.)xn--') {
        $warnings.Add(('The name is written with accented or non-Latin letters ({0} for DNS): check that it is not imitating a known site.' -f $asciiHost))
    }

    if ($uri.HostNameType -in @([UriHostNameType]::IPv4, [UriHostNameType]::IPv6)) {
        $warnings.Add('The site is an IP address rather than a name, which legitimate links rarely use.')
    }

    if ($uri.Scheme -eq 'http') {
        $warnings.Add('Not encrypted: what is sent through this link can be read on the way.')
    }

    return [pscustomobject] @{
        Valid         = $true
        SchemeAssumed = $assumed
        Scheme        = $uri.Scheme
        User          = $user
        HasPassword   = $hasPassword
        Host          = $hostName
        AsciiHost     = $asciiHost
        UnicodeHost   = $unicodeHost
        HostType      = $hostType
        Port          = $uri.Port
        IsDefaultPort = $uri.IsDefaultPort
        Path          = [Uri]::UnescapeDataString($uri.AbsolutePath)
        Segments      = @($uri.Segments | ForEach-Object { [Uri]::UnescapeDataString($_.TrimEnd('/')) } | Where-Object { $_ })
        Query         = $query.ToArray()
        Fragment      = $(if ($rawFragment) { [Uri]::UnescapeDataString($rawFragment) } else { '' })
        Origin        = $uri.GetLeftPart([UriPartial]::Authority)
        Warnings      = $warnings.ToArray()
        Note          = $(if ($assumed) { 'No scheme was given, so https was assumed.' } else { '' })
    }
}

<#
.SYNOPSIS
    Decodes the Safe Links in a link or a whole e-mail.

.DESCRIPTION
    Microsoft Defender for Office 365 rewrites the links of e-mails and Teams
    messages so they are checked when clicked. The destination is in the url
    parameter, and the data parameter names the mailbox the message was sent
    to. A link wrapped twice, when a message is forwarded, is unwrapped to
    the end.

.PARAMETER Text
    A Safe Links URL, or any text holding some.

.OUTPUTS
    PSCustomObject[] with Original, Destination, Host, Recipient and Layers.
#>
function ConvertFrom-TkSafeLink {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $wrapper = 'https?://(?:[a-z0-9\-]+\.)*safelinks\.protection\.(?:outlook\.com|office365\.us|outlook\.cn)/|https?://statics\.teams\.cdn\.office\.net/evergreen-assets/safelinks/'
    $found   = [regex]::Matches($Text, ('(?:{0})[^\s"''<>]*' -f $wrapper), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $rows = foreach ($match in $found) {

        $original    = $match.Value.TrimEnd('.', ',', ';', ')', ']')
        $destination = $original
        $recipient   = ''
        $layers      = 0

        while ($destination -match ('^(?:{0})' -f $wrapper) -and $layers -lt 10) {

            $parts = Get-TkUrlPart -Url $destination
            $inner = @($parts.Query | Where-Object { $_.Name -eq 'url' }) | Select-Object -First 1

            if (-not $parts.Valid -or -not $inner -or -not $inner.Value) {
                break
            }

            $data = @($parts.Query | Where-Object { $_.Name -eq 'data' }) | Select-Object -First 1

            if (-not $recipient -and $data -and $data.Value) {
                $recipient = @($data.Value -split '\|' | Where-Object { $_ -match '^[^@\s|]+@[^@\s|]+\.[^@\s|]+$' }) | Select-Object -First 1
            }

            $destination = $inner.Value
            $layers++
        }

        if ($layers -eq 0) { continue }

        $target = Get-TkUrlPart -Url $destination

        [pscustomobject] @{
            Original    = $original
            Destination = $destination
            Host        = $(if ($target.Valid) { $target.AsciiHost } else { '' })
            Recipient   = [string] $recipient
            Layers      = $layers
            Warnings    = $(if ($target.Valid) { @($target.Warnings) } else { @() })
        }
    }

    return @($rows)
}

# ---------------------------------------------------------------------------
# Text differences
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Compiles the line comparison, once per session.

.DESCRIPTION
    Myers' algorithm, the one diff and git use, walks the texts in steps that
    grow with the number of changes rather than with their size. Written in
    C# because a PowerShell loop over two configuration files of a few
    thousand lines takes seconds where this takes milliseconds.
#>
function Initialize-TkTextDiffType {
    [CmdletBinding()]
    param()

    if ('TkTextDiff' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System.Collections.Generic;

public static class TkTextDiff
{
    // The edit script from a to b, as operations of three integers: the kind
    // (0 same, 1 removed from a, 2 added from b), the line in a and the line
    // in b, -1 where the line is not in that text. Null past maxEdits.
    public static List<int[]> Compare(string[] a, string[] b, int maxEdits)
    {
        int n = a.Length, m = b.Length, max = n + m;
        var operations = new List<int[]>();

        if (max == 0)
        {
            return operations;
        }

        int offset = max + 1;
        int[] v = new int[2 * max + 3];
        var trace = new List<int[]>();
        int found = -1;

        for (int d = 0; d <= max && found < 0; d++)
        {
            if (d > maxEdits)
            {
                return null;
            }

            int[] step = new int[2 * d + 1];

            for (int k = -d; k <= d; k += 2)
            {
                int x = (k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1]))
                    ? v[offset + k + 1]
                    : v[offset + k - 1] + 1;

                int y = x - k;

                while (x < n && y < m && a[x] == b[y])
                {
                    x++;
                    y++;
                }

                v[offset + k] = x;
                step[k + d] = x;

                if (x >= n && y >= m)
                {
                    found = d;
                    break;
                }
            }

            trace.Add(step);
        }

        int bx = n, by = m;

        for (int d = found; d > 0; d--)
        {
            int[] previous = trace[d - 1];
            int k = bx - by;

            bool down = k == -d || (k != d && previous[k - 1 + d - 1] < previous[k + 1 + d - 1]);
            int previousK = down ? k + 1 : k - 1;
            int previousX = previous[previousK + d - 1];
            int previousY = previousX - previousK;

            while (bx > previousX && by > previousY)
            {
                operations.Add(new int[] { 0, bx - 1, by - 1 });
                bx--;
                by--;
            }

            if (down)
            {
                operations.Add(new int[] { 2, -1, by - 1 });
            }
            else
            {
                operations.Add(new int[] { 1, bx - 1, -1 });
            }

            bx = previousX;
            by = previousY;
        }

        while (bx > 0 && by > 0)
        {
            operations.Add(new int[] { 0, bx - 1, by - 1 });
            bx--;
            by--;
        }

        operations.Reverse();
        return operations;
    }
}
'@
}

<#
.SYNOPSIS
    Compares two texts line by line.

.PARAMETER Before
    The first text.

.PARAMETER After
    The second text.

.PARAMETER IgnoreCase
    Lines that differ only by case are the same.

.PARAMETER IgnoreWhitespace
    Lines that differ only by spaces and tabs are the same.

.PARAMETER MaxEdits
    Where to give up on texts with almost nothing in common.

.OUTPUTS
    PSCustomObject with Rows (Kind Same, Removed or Added, Text, Before,
    After), Added, Removed, Same and Identical.
#>
function Compare-TkText {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Before,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $After,
        [Parameter()] [switch] $IgnoreCase,
        [Parameter()] [switch] $IgnoreWhitespace,
        [Parameter()] [ValidateRange(1, 1000000)] [int] $MaxEdits = 20000
    )

    Initialize-TkTextDiffType

    [string[]] $linesBefore = @()
    [string[]] $linesAfter  = @()

    if ($Before.Length -gt 0) { $linesBefore = $Before -split "`r?`n" }
    if ($After.Length -gt 0)  { $linesAfter  = $After -split "`r?`n" }

    $normalise = {
        param($line)
        $key = $line
        if ($IgnoreWhitespace) { $key = ($key -replace '\s+', ' ').Trim() }
        if ($IgnoreCase) { $key = $key.ToLowerInvariant() }
        $key
    }

    [string[]] $keysBefore = $linesBefore
    [string[]] $keysAfter  = $linesAfter

    if ($IgnoreCase -or $IgnoreWhitespace) {
        $keysBefore = @(foreach ($line in $linesBefore) { & $normalise $line })
        $keysAfter  = @(foreach ($line in $linesAfter) { & $normalise $line })
    }

    $operations = [TkTextDiff]::Compare($keysBefore, $keysAfter, $MaxEdits)

    if ($null -eq $operations) {
        throw 'The two texts differ in too many places to compare line by line.'
    }

    $rows = foreach ($operation in $operations) {

        switch ($operation[0]) {
            0 { [pscustomobject] @{ Kind = 'Same';    Text = $linesAfter[$operation[2]];  Before = $operation[1] + 1; After = $operation[2] + 1 } }
            1 { [pscustomobject] @{ Kind = 'Removed'; Text = $linesBefore[$operation[1]]; Before = $operation[1] + 1; After = $null } }
            2 { [pscustomobject] @{ Kind = 'Added';   Text = $linesAfter[$operation[2]];  Before = $null;             After = $operation[2] + 1 } }
        }
    }

    $rows    = @($rows)
    $added   = @($rows | Where-Object { $_.Kind -eq 'Added' }).Count
    $removed = @($rows | Where-Object { $_.Kind -eq 'Removed' }).Count

    return [pscustomobject] @{
        Rows      = $rows
        Added     = $added
        Removed   = $removed
        Same      = $rows.Count - $added - $removed
        Identical = ($added + $removed) -eq 0
    }
}

<#
.SYNOPSIS
    Keeps the changes and a few lines around each, as diff -u does.

.PARAMETER Rows
    The rows of Compare-TkText.

.PARAMETER Context
    How many unchanged lines to keep around a change.

.OUTPUTS
    PSCustomObject[], the rows kept, with a Gap row for each run left out.
#>
function Get-TkDiffView {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows,
        [Parameter()] [ValidateRange(0, 1000)] [int] $Context = 3
    )

    $count = $Rows.Count
    $keep  = New-Object bool[] $count

    for ($index = 0; $index -lt $count; $index++) {

        if ($Rows[$index].Kind -ne 'Same') {
            for ($near = [math]::Max(0, $index - $Context); $near -le [math]::Min($count - 1, $index + $Context); $near++) {
                $keep[$near] = $true
            }
        }
    }

    $view = New-Object System.Collections.Generic.List[object]
    $gap  = 0

    $addGap = {
        if ($gap -gt 0) {
            $view.Add([pscustomobject] @{ Kind = 'Gap'; Text = ('{0} unchanged line(s)' -f $gap); Before = $null; After = $null })
        }
    }

    for ($index = 0; $index -lt $count; $index++) {

        if ($keep[$index]) {
            . $addGap
            $gap = 0
            $view.Add($Rows[$index])
        }
        else {
            $gap++
        }
    }

    . $addGap

    return $view.ToArray()
}

<#
.SYNOPSIS
    Writes the kept rows of a comparison as text, one line per row.

.PARAMETER View
    What Get-TkDiffView returns.

.OUTPUTS
    System.String
#>
function Format-TkDiffText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $View
    )

    $lines = foreach ($row in $View) {
        switch ($row.Kind) {
            'Added'   { '+ {0}' -f $row.Text }
            'Removed' { '- {0}' -f $row.Text }
            'Gap'     { '... {0}' -f $row.Text }
            default   { '  {0}' -f $row.Text }
        }
    }

    return (@($lines) -join [Environment]::NewLine)
}

# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Lists the countries whose numbers the formatter knows.

.DESCRIPTION
    Code is the country calling code, Trunk the prefix dialled before a
    national number and dropped after the country code, Lengths the number
    of digits after the country code, and Formats how those digits are
    grouped, the first pattern that fits winning.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkPhoneCountry {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $country = {
        param($iso, $name, $code, $trunk, $lengths, $formats)
        [pscustomobject] @{ Iso = $iso; Name = $name; Code = $code; Trunk = $trunk; Lengths = @($lengths); Formats = @($formats) }
    }

    $group = {
        param($pattern, $sizes)
        [pscustomobject] @{ Pattern = $pattern; Sizes = @($sizes) }
    }

    return @(
        (& $country 'FR' 'France'                   '33'  '0' @(9)         @((& $group '.' @(1, 2, 2, 2, 2))))
        (& $country 'BE' 'Belgium'                  '32'  '0' @(8, 9)      @((& $group '^4\d{8}$' @(3, 2, 2, 2)), (& $group '^[2349]\d{7}$' @(1, 3, 2, 2)), (& $group '^\d{8}$' @(2, 2, 2, 2))))
        (& $country 'CH' 'Switzerland'              '41'  '0' @(9)         @((& $group '.' @(2, 3, 2, 2))))
        (& $country 'LU' 'Luxembourg'               '352' ''  @(6..11)     @())
        (& $country 'MC' 'Monaco'                   '377' ''  @(8, 9)      @((& $group '^\d{8}$' @(2, 2, 2, 2)), (& $group '^\d{9}$' @(1, 2, 2, 2, 2))))
        (& $country 'DE' 'Germany'                  '49'  '0' @(6..13)     @())
        (& $country 'AT' 'Austria'                  '43'  '0' @(4..13)     @())
        (& $country 'NL' 'Netherlands'              '31'  '0' @(9)         @((& $group '^6' @(1, 8)), (& $group '.' @(2, 3, 4))))
        (& $country 'GB' 'United Kingdom'           '44'  '0' @(9, 10)     @((& $group '^2\d{9}$' @(2, 4, 4)), (& $group '^\d{10}$' @(4, 6))))
        (& $country 'IE' 'Ireland'                  '353' '0' @(7, 8, 9)   @())
        (& $country 'ES' 'Spain'                    '34'  ''  @(9)         @((& $group '.' @(3, 3, 3))))
        (& $country 'PT' 'Portugal'                 '351' ''  @(9)         @((& $group '.' @(3, 3, 3))))
        (& $country 'IT' 'Italy'                    '39'  ''  @(6..11)     @())
        (& $country 'PL' 'Poland'                   '48'  ''  @(9)         @((& $group '.' @(3, 3, 3))))
        (& $country 'US' 'United States or Canada'  '1'   '1' @(10)        @((& $group '.' @(3, 3, 4))))
        (& $country 'MA' 'Morocco'                  '212' '0' @(9)         @((& $group '.' @(1, 2, 2, 2, 2))))
        (& $country 'DZ' 'Algeria'                  '213' '0' @(8, 9)      @((& $group '^\d{9}$' @(3, 2, 2, 2)), (& $group '^\d{8}$' @(2, 2, 2, 2))))
        (& $country 'TN' 'Tunisia'                  '216' ''  @(8)         @((& $group '.' @(2, 3, 3))))
        (& $country 'SN' 'Senegal'                  '221' ''  @(9)         @((& $group '.' @(2, 3, 2, 2))))
        (& $country 'CI' "Cote d'Ivoire"            '225' ''  @(10)        @((& $group '.' @(2, 2, 2, 2, 2))))
        (& $country 'RE' 'Reunion or Mayotte'       '262' '0' @(9)         @((& $group '.' @(3, 2, 2, 2))))
        (& $country 'GP' 'Guadeloupe'               '590' '0' @(9)         @((& $group '.' @(3, 2, 2, 2))))
        (& $country 'GF' 'French Guiana'            '594' '0' @(9)         @((& $group '.' @(3, 2, 2, 2))))
        (& $country 'MQ' 'Martinique'               '596' '0' @(9)         @((& $group '.' @(3, 2, 2, 2))))
        (& $country 'AU' 'Australia'                '61'  '0' @(9)         @((& $group '^4' @(3, 3, 3)), (& $group '.' @(1, 4, 4))))
    )
}

<#
.SYNOPSIS
    Reads a phone number written in any form and writes it in the standard ones.

.PARAMETER Text
    The number: 06 12 34 56 78, +33 (0)6 12 34 56 78, 0033 6..., with an
    optional extension.

.PARAMETER DefaultCountry
    The country of a number written without a country code, by ISO code.

.OUTPUTS
    PSCustomObject with Valid, Country, Iso, CountryCode, NationalNumber,
    E164, International, National, Rfc3966, Type, Extension and Note.
#>
function ConvertFrom-TkPhoneNumber {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter()] [string] $DefaultCountry = 'FR'
    )

    $invalid = {
        param($note)
        [pscustomobject] @{ Valid = $false; Note = $note }
    }

    $countries = @(Get-TkPhoneCountry)
    $raw       = $Text.Trim()

    if (-not $raw) {
        return (& $invalid 'Type a phone number.')
    }

    $extension = ''
    $trailing  = [regex]::Match($raw, '(?i)\s*(?:ext\.?|extension|poste|x|#)\s*(\d{1,6})\s*$')

    if ($trailing.Success -and $trailing.Index -gt 0) {
        $extension = $trailing.Groups[1].Value
        $raw       = $raw.Substring(0, $trailing.Index)
    }

    # +33 (0)6...: the 0 in brackets is the trunk prefix, dialled from inside
    # the country only.
    $raw     = $raw -replace '\(\s*0\s*\)', ''
    $compact = $raw -replace '[\s.\-()/]', ''

    if ($compact -notmatch '^(\+|00)?\d+$') {
        return (& $invalid 'A phone number holds digits, spaces, dots, dashes and brackets, with a leading + or 00 before the country code.')
    }

    $country = $null
    $nsn     = ''

    if ($compact -match '^(?:\+|00)(\d+)$') {

        $digits = $Matches[1]

        foreach ($size in @(3, 2, 1)) {

            if ($digits.Length -gt $size) {

                $candidate = $countries | Where-Object { $_.Code -eq $digits.Substring(0, $size) } | Select-Object -First 1

                if ($candidate) {
                    $country = $candidate
                    $nsn     = $digits.Substring($size)
                    break
                }
            }
        }

        if (-not $country) {

            # The zones of the ITU plan: 1 and 7 take one digit, these two
            # digits, and every other code three.
            $twoDigit = @('20', '27', '30', '31', '32', '33', '34', '36', '39', '40', '41', '43', '44', '45', '46', '47', '48', '49',
                          '51', '52', '53', '54', '55', '56', '57', '58', '60', '61', '62', '63', '64', '65', '66',
                          '81', '82', '84', '86', '90', '91', '92', '93', '94', '95', '98')

            $code = if ($digits[0] -in @([char] '1', [char] '7')) { $digits.Substring(0, 1) }
                    elseif ($digits.Length -ge 2 -and $twoDigit -contains $digits.Substring(0, 2)) { $digits.Substring(0, 2) }
                    else { $digits.Substring(0, [math]::Min(3, $digits.Length)) }

            if ($digits.Length -lt 8 -or $digits.Length -gt 15) {
                return (& $invalid 'An international number has 8 to 15 digits, the country code included.')
            }

            $rest = $digits.Substring($code.Length)

            return [pscustomobject] @{
                Valid          = $true
                Country        = ''
                Iso            = ''
                CountryCode    = $code
                NationalNumber = $rest
                E164           = '+' + $digits
                International  = '+{0} {1}' -f $code, $rest
                National       = ''
                Rfc3966        = 'tel:+{0}-{1}' -f $code, $rest
                Type           = ''
                Extension      = $extension
                Note           = ('The formatter does not know the numbering of +{0}, so the number is not grouped.' -f $code)
            }
        }
    }
    else {

        $country = $countries | Where-Object { $_.Iso -eq $DefaultCountry } | Select-Object -First 1

        if (-not $country) {
            return (& $invalid ('No country is known by the code {0}.' -f $DefaultCountry))
        }

        $nsn = $compact
    }

    # A trunk prefix is not part of the number after the country code, whether
    # it came from a national number or was written after +33 by mistake.
    if ($country.Trunk -and $nsn.StartsWith($country.Trunk) -and $country.Lengths -contains ($nsn.Length - $country.Trunk.Length) -and
        ($country.Lengths -notcontains $nsn.Length -or $compact -notmatch '^(\+|00)')) {
        $nsn = $nsn.Substring($country.Trunk.Length)
    }

    if ($country.Lengths -notcontains $nsn.Length) {

        $lengths    = @($country.Lengths)
        $lengthText = if ($lengths.Count -eq 1) { [string] $lengths[0] }
                      elseif (($lengths[-1] - $lengths[0] + 1) -eq $lengths.Count) { '{0} to {1}' -f $lengths[0], $lengths[-1] }
                      else { $lengths -join ' or ' }

        return (& $invalid ('A number in {0} has {1} digits after +{2}; this one has {3}.' -f $country.Name, $lengthText, $country.Code, $nsn.Length))
    }

    $sizes = @()

    foreach ($format in $country.Formats) {
        if ($nsn -match $format.Pattern) {
            $sizes = @($format.Sizes)
            break
        }
    }

    $parts = @($nsn)

    if ($sizes.Count -gt 0 -and ($sizes | Measure-Object -Sum).Sum -eq $nsn.Length) {

        $parts    = @()
        $position = 0

        foreach ($size in $sizes) {
            $parts    += $nsn.Substring($position, $size)
            $position += $size
        }
    }

    $grouped  = $parts -join ' '
    $national = if ($country.Iso -eq 'US' -and $parts.Count -eq 3) { '({0}) {1}-{2}' -f $parts[0], $parts[1], $parts[2] }
                elseif ($country.Trunk -and $country.Iso -ne 'US') { $country.Trunk + $grouped }
                else { $grouped }

    $type = ''

    if ($country.Iso -eq 'FR') {
        $type = switch -Regex ($nsn) {
            '^1'    { 'Landline, Ile-de-France' }
            '^2'    { 'Landline, north-west' }
            '^3'    { 'Landline, north-east' }
            '^4'    { 'Landline, south-east' }
            '^5'    { 'Landline, south-west' }
            '^[67]' { 'Mobile' }
            '^8'    { 'Special rate or free number' }
            '^9'    { 'Non-geographic, often internet telephony' }
        }
    }

    return [pscustomobject] @{
        Valid          = $true
        Country        = $country.Name
        Iso            = $country.Iso
        CountryCode    = $country.Code
        NationalNumber = $nsn
        E164           = '+{0}{1}' -f $country.Code, $nsn
        International  = '+{0} {1}' -f $country.Code, $grouped
        National       = $national
        Rfc3966        = 'tel:+{0}-{1}' -f $country.Code, ($parts -join '-')
        Type           = [string] $type
        Extension      = $extension
        Note           = ''
    }
}
