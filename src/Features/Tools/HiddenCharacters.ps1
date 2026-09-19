<#
    Toolkit - Features / Hidden and deceptive characters

    Some characters do not show what they are. A zero-width space splits a word
    the eye reads as one; a right-to-left override reverses what follows, the
    trick behind a file named "gpj.exe" that runs as an executable; a Cyrillic
    "a" stands in a domain name for the Latin one, so a paypal.com written with
    it is not paypal.com. This reveals them in pasted text: where each one sits,
    what it is, and, for a look-alike, the ASCII letter it imitates.

    Legitimate accented text is left alone. An "e-acute" is a normal letter, not
    a look-alike, so a French sentence raises nothing; only characters that are
    invisible, that control direction, or that impersonate an ASCII character are
    reported.
#>

<#
.SYNOPSIS
    The characters that impersonate an ASCII letter or digit, by code point.

.DESCRIPTION
    A curated set of the common ones: Cyrillic and Greek letters that share a
    shape with a Latin letter, and the full-width Latin block. Not the whole
    Unicode confusables table, which runs to thousands, but the ones seen in
    phishing and in copied code. Each maps to the ASCII character it imitates and
    the script it comes from.

.OUTPUTS
    System.Collections.Hashtable keyed by code point (int).
#>
function Get-TkConfusableMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $map = @{}

    $add = {
        param($script, $pairs)
        foreach ($code in $pairs.Keys) {
            $map[$code] = [pscustomobject] @{ Latin = $pairs[$code]; Script = $script }
        }
    }

    & $add 'Cyrillic' @{
        0x0410 = 'A'; 0x0412 = 'B'; 0x0415 = 'E'; 0x0406 = 'I'; 0x0408 = 'J'
        0x041A = 'K'; 0x041C = 'M'; 0x041D = 'H'; 0x041E = 'O'; 0x0420 = 'P'
        0x0421 = 'C'; 0x0422 = 'T'; 0x0423 = 'Y'; 0x0425 = 'X'; 0x0405 = 'S'
        0x0430 = 'a'; 0x0435 = 'e'; 0x043E = 'o'; 0x0440 = 'p'; 0x0441 = 'c'
        0x0443 = 'y'; 0x0445 = 'x'; 0x0455 = 's'; 0x0456 = 'i'; 0x0458 = 'j'
    }

    & $add 'Greek' @{
        0x0391 = 'A'; 0x0392 = 'B'; 0x0395 = 'E'; 0x0396 = 'Z'; 0x0397 = 'H'
        0x0399 = 'I'; 0x039A = 'K'; 0x039C = 'M'; 0x039D = 'N'; 0x039F = 'O'
        0x03A1 = 'P'; 0x03A4 = 'T'; 0x03A5 = 'Y'; 0x03A7 = 'X'
        0x03BF = 'o'; 0x03B1 = 'a'; 0x03BD = 'v'; 0x03C1 = 'p'
    }

    # Full-width Latin: uppercase, lowercase and digits, one block each.
    for ($i = 0; $i -lt 26; $i++) {
        $map[0xFF21 + $i] = [pscustomobject] @{ Latin = [char] (65 + $i); Script = 'Full-width' }
        $map[0xFF41 + $i] = [pscustomobject] @{ Latin = [char] (97 + $i); Script = 'Full-width' }
    }
    for ($i = 0; $i -lt 10; $i++) {
        $map[0xFF10 + $i] = [pscustomobject] @{ Latin = [char] (48 + $i); Script = 'Full-width' }
    }

    return $map
}

<#
.SYNOPSIS
    Names a code point that is invisible, directional or a control character.

.OUTPUTS
    System.String, empty when the code point is not one of these.
#>
function Get-TkHiddenCharacterName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int] $CodePoint
    )

    $names = @{
        0x0009 = 'CHARACTER TABULATION'
        0x00AD = 'SOFT HYPHEN'
        0x034F = 'COMBINING GRAPHEME JOINER'
        0x061C = 'ARABIC LETTER MARK'
        0x115F = 'HANGUL CHOSEONG FILLER'
        0x1160 = 'HANGUL JUNGSEONG FILLER'
        0x17B4 = 'KHMER VOWEL INHERENT AQ'
        0x17B5 = 'KHMER VOWEL INHERENT AA'
        0x180E = 'MONGOLIAN VOWEL SEPARATOR'
        0x200B = 'ZERO WIDTH SPACE'
        0x200C = 'ZERO WIDTH NON-JOINER'
        0x200D = 'ZERO WIDTH JOINER'
        0x200E = 'LEFT-TO-RIGHT MARK'
        0x200F = 'RIGHT-TO-LEFT MARK'
        0x202A = 'LEFT-TO-RIGHT EMBEDDING'
        0x202B = 'RIGHT-TO-LEFT EMBEDDING'
        0x202C = 'POP DIRECTIONAL FORMATTING'
        0x202D = 'LEFT-TO-RIGHT OVERRIDE'
        0x202E = 'RIGHT-TO-LEFT OVERRIDE'
        0x2060 = 'WORD JOINER'
        0x2061 = 'FUNCTION APPLICATION'
        0x2062 = 'INVISIBLE TIMES'
        0x2063 = 'INVISIBLE SEPARATOR'
        0x2064 = 'INVISIBLE PLUS'
        0x2066 = 'LEFT-TO-RIGHT ISOLATE'
        0x2067 = 'RIGHT-TO-LEFT ISOLATE'
        0x2068 = 'FIRST STRONG ISOLATE'
        0x2069 = 'POP DIRECTIONAL ISOLATE'
        0xFEFF = 'ZERO WIDTH NO-BREAK SPACE (BOM)'
        0xFFF9 = 'INTERLINEAR ANNOTATION ANCHOR'
        0x00A0 = 'NO-BREAK SPACE'
        0x1680 = 'OGHAM SPACE MARK'
        0x2000 = 'EN QUAD'
        0x2001 = 'EM QUAD'
        0x2002 = 'EN SPACE'
        0x2003 = 'EM SPACE'
        0x2004 = 'THREE-PER-EM SPACE'
        0x2005 = 'FOUR-PER-EM SPACE'
        0x2006 = 'SIX-PER-EM SPACE'
        0x2007 = 'FIGURE SPACE'
        0x2008 = 'PUNCTUATION SPACE'
        0x2009 = 'THIN SPACE'
        0x200A = 'HAIR SPACE'
        0x202F = 'NARROW NO-BREAK SPACE'
        0x205F = 'MEDIUM MATHEMATICAL SPACE'
        0x3000 = 'IDEOGRAPHIC SPACE'
    }

    if ($names.ContainsKey($CodePoint)) {
        return $names[$CodePoint]
    }

    return ''
}

<#
.SYNOPSIS
    Finds every hidden or deceptive character in a text.

.DESCRIPTION
    Walks the text one code point at a time, surrogate pairs included, and reports
    each character that is invisible, a directional control, an unusual space, a
    C0 or C1 control, or a look-alike of an ASCII character. Ordinary letters,
    including accented ones, and the everyday whitespace of tab, newline and the
    plain space are left out.

.PARAMETER Text
    The text to inspect.

.OUTPUTS
    PSCustomObject[] with Line, Column, Index, CodePoint, Code, Category, Name and
    Confusable.
#>
function Get-TkHiddenCharacterFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $confusable = Get-TkConfusableMap

    # Invisible, directional and unusual-space code points, as lookup sets.
    $zeroWidth = @{}
    foreach ($code in @(0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E,
                        0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
                        0xFEFF, 0xFFF9)) { $zeroWidth[$code] = $true }

    $bidi = @{}
    foreach ($code in @(0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                        0x2066, 0x2067, 0x2068, 0x2069)) { $bidi[$code] = $true }

    $space = @{}
    foreach ($code in @(0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
                        0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000)) { $space[$code] = $true }

    $findings = New-Object System.Collections.Generic.List[pscustomobject]

    $line   = 1
    $column = 1
    $index  = 0

    while ($index -lt $Text.Length) {

        # A surrogate pair is one code point spread over two chars.
        if ([char]::IsHighSurrogate($Text[$index]) -and ($index + 1) -lt $Text.Length -and [char]::IsLowSurrogate($Text[$index + 1])) {
            $codePoint = [char]::ConvertToUtf32($Text[$index], $Text[$index + 1])
            $width     = 2
        }
        else {
            $codePoint = [int] $Text[$index]
            $width     = 1
        }

        $category = ''
        $latin    = ''

        if ($codePoint -eq 0x0A) {
            # A newline ends the line; nothing to report.
            $line++
            $column = 1
            $index += $width
            continue
        }

        if ($codePoint -eq 0x0D -or $codePoint -eq 0x09) {
            # Carriage return and tab are ordinary whitespace.
        }
        elseif ($bidi.ContainsKey($codePoint))      { $category = 'Bidirectional' }
        elseif ($zeroWidth.ContainsKey($codePoint)) { $category = 'Zero-width' }
        elseif ($space.ContainsKey($codePoint))     { $category = 'Unusual space' }
        elseif ($confusable.ContainsKey($codePoint)) {
            $category = 'Confusable'
            $latin    = $confusable[$codePoint].Latin
        }
        elseif ($codePoint -lt 0x20 -or ($codePoint -ge 0x7F -and $codePoint -le 0x9F)) {
            $category = 'Control'
        }

        if ($category) {

            $name = Get-TkHiddenCharacterName -CodePoint $codePoint

            if (-not $name) {
                $name = if ($category -eq 'Confusable') {
                            '{0} letter that looks like "{1}"' -f $confusable[$codePoint].Script, $latin
                        }
                        elseif ($category -eq 'Control') { 'CONTROL CHARACTER' }
                        else { $category.ToUpperInvariant() }
            }

            $findings.Add([pscustomobject] @{
                Line       = $line
                Column     = $column
                Index      = $index
                CodePoint  = $codePoint
                Code       = 'U+{0:X4}' -f $codePoint
                Category   = $category
                Name       = $name
                Confusable = $latin
            })
        }

        $column += $width
        $index  += $width
    }

    return @($findings)
}

<#
.SYNOPSIS
    Rewrites a text with its hidden and deceptive characters marked in place.

.DESCRIPTION
    Every reported character is replaced by a visible token, so the eye can see
    where it sits: a look-alike shows its code and the ASCII letter it imitates,
    an invisible character shows its code alone. Ordinary text is untouched.

.OUTPUTS
    System.String
#>
function Get-TkHiddenCharacterAnnotated {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding
    )

    $byIndex = @{}
    foreach ($item in $Finding) { $byIndex[$item.Index] = $item }

    $builder = New-Object System.Text.StringBuilder
    $index   = 0

    while ($index -lt $Text.Length) {

        if ($byIndex.ContainsKey($index)) {

            $item  = $byIndex[$index]
            $token = if ($item.Confusable) { '[{0}->{1}]' -f $item.Code, $item.Confusable } else { '[{0}]' -f $item.Code }

            [void] $builder.Append($token)

            # A surrogate pair is two chars for the one code point just written.
            $step   = if ($item.CodePoint -gt 0xFFFF) { 2 } else { 1 }
            $index += $step
        }
        else {
            [void] $builder.Append($Text[$index])
            $index += 1
        }
    }

    return $builder.ToString()
}

<#
.SYNOPSIS
    Writes a hidden character report as lines of text.

.OUTPUTS
    System.String[]
#>
function Format-TkHiddenCharacterReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return @('Paste some text to inspect it for hidden and deceptive characters.')
    }

    $findings = @(Get-TkHiddenCharacterFinding -Text $Text)
    $lines    = New-Object System.Collections.Generic.List[string]

    if ($findings.Count -eq 0) {
        $lines.Add('No hidden or deceptive characters found. Every character is ordinary text.')
        return $lines.ToArray()
    }

    $order   = @('Confusable', 'Bidirectional', 'Zero-width', 'Unusual space', 'Control')
    $summary = foreach ($category in $order) {
        $count = @($findings | Where-Object { $_.Category -eq $category }).Count
        if ($count -gt 0) { '{0} {1}' -f $count, $category.ToLowerInvariant() }
    }

    # The -f expression is parenthesised whole: without it the commas would be
    # read as further arguments to Add, not as the format's argument list.
    $lines.Add(('{0} suspicious character(s): {1}.' -f $findings.Count, (@($summary) -join ', ')))
    $lines.Add('')

    foreach ($item in $findings) {
        $suffix = if ($item.Confusable) { ' - looks like "{0}"' -f $item.Confusable } else { '' }
        $lines.Add(('  L{0}:C{1}  {2}  {3}  [{4}]{5}' -f $item.Line, $item.Column, $item.Code, $item.Name, $item.Category, $suffix))
    }

    $lines.Add('')
    $lines.Add('Text with the characters marked:')
    $lines.Add((Get-TkHiddenCharacterAnnotated -Text $Text -Finding $findings))

    return $lines.ToArray()
}
