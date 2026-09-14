<#
    Toolkit - Features / Credential tools

    Password generation, strength estimation and breach checking.

    The generator uses the cryptographic RNG, not Get-Random. Get-Random is
    seeded from a predictable source and is documented as unsuitable for
    security purposes; a password generator built on it produces credentials
    an attacker who learns the seed can reproduce.
#>

<#
.SYNOPSIS
    Generates a cryptographically random password.

.DESCRIPTION
    Draws from the requested character classes and guarantees at least one
    character from each selected class, then shuffles the result so the
    guaranteed characters are not always in the same positions.

    Ambiguous characters (0 O o 1 l I |) are excluded by default because
    these passwords get read aloud over the phone and typed from a sticker.

.PARAMETER Length
    Password length, 8 to 128.

.PARAMETER IncludeUppercase
    Include A to Z.

.PARAMETER IncludeLowercase
    Include a to z.

.PARAMETER IncludeDigits
    Include 0 to 9.

.PARAMETER IncludeSymbols
    Include punctuation.

.PARAMETER AllowAmbiguous
    Keep the visually ambiguous characters in the alphabet.

.OUTPUTS
    PSCustomObject with Password, Entropy and Alphabet size.

.EXAMPLE
    New-TkPassword -Length 24
#>
function New-TkPassword {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(8, 128)]
        [int] $Length = 20,

        [Parameter()]
        [bool] $IncludeUppercase = $true,

        [Parameter()]
        [bool] $IncludeLowercase = $true,

        [Parameter()]
        [bool] $IncludeDigits = $true,

        [Parameter()]
        [bool] $IncludeSymbols = $true,

        [Parameter()]
        [switch] $AllowAmbiguous
    )

    $classes = @()

    if ($IncludeUppercase) { $classes += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }
    if ($IncludeLowercase) { $classes += 'abcdefghijklmnopqrstuvwxyz' }
    if ($IncludeDigits)    { $classes += '0123456789' }
    if ($IncludeSymbols)   { $classes += '!#$%&()*+,-./:;<=>?@[]^_{|}~' }

    if ($classes.Count -eq 0) {
        throw 'At least one character class must be selected.'
    }

    if (-not $AllowAmbiguous) {

        $ambiguous = '0O1lI|'
        $classes   = @($classes | ForEach-Object {
            ($_.ToCharArray() | Where-Object { $ambiguous -notmatch [regex]::Escape($_) }) -join ''
        })
    }

    $alphabet = ($classes -join '').ToCharArray()

    if ($Length -lt $classes.Count) {
        throw ('A length of {0} cannot hold one character from each of the {1} selected classes.' -f $Length, $classes.Count)
    }

    $characters = New-Object 'System.Collections.Generic.List[char]'

    # One guaranteed character per class, so a policy requiring all four is
    # always satisfied.
    foreach ($class in $classes) {
        $characters.Add((Get-TkRandomCharacter -Alphabet $class.ToCharArray()))
    }

    while ($characters.Count -lt $Length) {
        $characters.Add((Get-TkRandomCharacter -Alphabet $alphabet))
    }

    # Fisher-Yates with cryptographic indices.
    for ($i = $characters.Count - 1; $i -gt 0; $i--) {

        $j    = Get-TkRandomInteger -MaxExclusive ($i + 1)
        $temp = $characters[$i]

        $characters[$i] = $characters[$j]
        $characters[$j] = $temp
    }

    $password = -join $characters
    $entropy  = [math]::Round($Length * [math]::Log($alphabet.Count, 2), 1)

    return [pscustomobject]@{
        Password     = $password
        Length       = $Length
        AlphabetSize = $alphabet.Count
        EntropyBits  = $entropy
        Strength     = Get-TkEntropyRating -Bits $entropy
    }
}

<#
.SYNOPSIS
    Generates a passphrase from random words.

.DESCRIPTION
    Diceware style. Easier to type on a phone or a server console than a
    random string of the same strength, which is what makes it the better
    choice for a password people have to type by hand.

.PARAMETER WordCount
    Number of words, 3 to 12.

.OUTPUTS
    PSCustomObject
#>
function New-TkPassphrase {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(3, 12)]
        [int] $WordCount = 5,

        [Parameter()]
        [string] $Separator = '-',

        [Parameter()]
        [switch] $AppendNumber
    )

    $words = Get-TkWordList

    $selected = @()

    for ($i = 0; $i -lt $WordCount; $i++) {
        $selected += $words[(Get-TkRandomInteger -MaxExclusive $words.Count)]
    }

    $passphrase = $selected -join $Separator

    if ($AppendNumber) {
        $passphrase = '{0}{1}{2}' -f $passphrase, $Separator, (Get-TkRandomInteger -MaxExclusive 1000)
    }

    # Strength comes from the word list size and the count, not from the
    # characters: a five word phrase from a 7776 word list is about 64 bits.
    $entropy = [math]::Round($WordCount * [math]::Log($words.Count, 2), 1)

    return [pscustomobject]@{
        Passphrase  = $passphrase
        WordCount   = $WordCount
        ListSize    = $words.Count
        EntropyBits = $entropy
        Strength    = Get-TkEntropyRating -Bits $entropy
    }
}

<#
.SYNOPSIS
    Draws a random character from an alphabet.

.OUTPUTS
    System.Char
#>
function Get-TkRandomCharacter {
    [CmdletBinding()]
    [OutputType([char])]
    param(
        [Parameter(Mandatory)]
        [char[]] $Alphabet
    )

    return $Alphabet[(Get-TkRandomInteger -MaxExclusive $Alphabet.Count)]
}

<#
.SYNOPSIS
    Returns a uniform random integer below a bound.

.DESCRIPTION
    Rejection sampling removes the modulo bias that makes the low indices of
    an alphabet more likely than the high ones. The bias is small, but a
    password generator is exactly the place not to accept a known bias.

.OUTPUTS
    System.Int32
#>
function Get-TkRandomInteger {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 2147483647)]
        [int] $MaxExclusive
    )

    if ($MaxExclusive -eq 1) {
        return 0
    }

    $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = New-Object 'byte[]' 4

    try {
        $limit = [uint32]::MaxValue - ([uint32]::MaxValue % [uint32] $MaxExclusive)

        do {
            $rng.GetBytes($buffer)
            $value = [BitConverter]::ToUInt32($buffer, 0)
        }
        while ($value -ge $limit)

        return [int] ($value % [uint32] $MaxExclusive)
    }
    finally {
        $rng.Dispose()
    }
}

<#
.SYNOPSIS
    Rates an entropy value in bits.

.OUTPUTS
    System.String
#>
function Get-TkEntropyRating {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [double] $Bits
    )

    if ($Bits -lt 40)  { return 'Very weak - crackable offline in minutes' }
    if ($Bits -lt 60)  { return 'Weak - not acceptable for an account that matters' }
    if ($Bits -lt 80)  { return 'Reasonable - acceptable with MFA' }
    if ($Bits -lt 128) { return 'Strong' }

    return 'Very strong'
}

<#
.SYNOPSIS
    Lists the passwords and words cracking tools try first, most used first.

.DESCRIPTION
    Short on purpose: it is the head of the real lists, where most human
    passwords fall, with the French ones a support desk in France meets.
    Written in lower case and compared once capitals, and symbols standing
    for letters, have been undone.

.OUTPUTS
    System.String[]
#>
function Get-TkCommonPasswordList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'password', 'azerty', 'qwerty', '123456', '12345678', '123456789', '1234567890', '111111', '123123',
        'abc123', 'password1', '000000', 'iloveyou', 'admin', 'welcome', 'motdepasse', 'soleil', 'bonjour',
        'doudou', 'loulou', 'chouchou', 'marseille', 'dragon', 'monkey', 'letmein', 'football', 'baseball',
        'master', 'sunshine', 'princess', 'qwertyuiop', 'azertyuiop', 'shadow', 'superman', 'michael',
        'jordan', 'hello', 'freedom', 'whatever', 'trustno1', 'starwars', 'computer', 'charlie', 'nicolas',
        'camille', 'julien', 'thomas', 'alexandre', 'pokemon', 'naruto', 'chocolat', 'coucou', 'jetaime',
        'licorne', 'toulouse', 'paris', 'france', 'orange', 'samsung', 'google', 'microsoft', 'windows',
        'summer', 'winter', 'spring', 'autumn', 'hiver', 'printemps', 'automne', 'changeme', 'secret',
        'root', 'toor', 'user', 'guest', 'test', 'demo', 'login', 'access', 'entreprise', 'societe',
        'company', 'office', 'support', 'service', 'bienvenue', 'abcdef', 'abcd1234', '1q2w3e4r',
        '1qaz2wsx', 'zaq12wsx', 'aaaaaa', '654321', '666666', '121212', '7777777', '987654321', '159753',
        '147258369', '112233', 'killer', 'hunter', 'ranger', 'buster', 'soccer', 'hockey', 'batman',
        'tigger', 'ginger', 'pepper', 'cookie', 'flower', 'lovely', 'angel', 'jessica', 'ashley', 'daniel',
        'andrew', 'matthew', 'joshua', 'robert', 'william', 'anthony', 'maxime', 'antoine', 'romain',
        'nathalie', 'isabelle', 'sophie', 'marie', 'pierre', 'lucas', 'emma', 'chloe', 'manon', 'louise',
        'bonheur', 'amour', 'maison', 'famille', 'vacances', 'rugby', 'olivier', 'celine'
    )
}

<#
.SYNOPSIS
    Writes a number of seconds, given as its power of ten, in words.

.PARAMETER Log10Seconds
    The base 10 logarithm of the duration, so durations far beyond what a
    double holds in seconds can still be written.

.OUTPUTS
    System.String
#>
function Format-TkCrackDuration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [double] $Log10Seconds
    )

    if ($Log10Seconds -lt 0) {
        return 'less than a second'
    }

    $count = {
        param($number, $unit)
        if ($number -eq 1) { '1 {0}' -f $unit } else { '{0} {1}s' -f $number, $unit }
    }

    if ($Log10Seconds -lt 7.5) {

        # Each unit gives way to the next half a unit before it, so a value
        # that rounds up reads "1 day" rather than "24 hours". The power of ten
        # is rounded too: 10 to the log of 86400 comes back as 86399.99999.
        $seconds = [math]::Round([math]::Pow(10, $Log10Seconds), 3)

        if ($seconds -lt 59.5)                { return (& $count ([long] [math]::Round($seconds)) 'second') }
        if ($seconds -lt 3570)                { return (& $count ([long] [math]::Round($seconds / 60)) 'minute') }
        if ($seconds -lt 84600)               { return (& $count ([long] [math]::Round($seconds / 3600)) 'hour') }
        if ($seconds -lt (2629800 - 43200))   { return (& $count ([long] [math]::Round($seconds / 86400)) 'day') }
        if ($seconds -lt (31557600 - 1314900)) { return (& $count ([long] [math]::Round($seconds / 2629800)) 'month') }
    }

    $yearsLog10 = $Log10Seconds - [math]::Log10(31557600)

    # The universe is about 13.8 billion years old.
    if ($yearsLog10 -ge 10.14) {
        return 'longer than the age of the universe'
    }

    $years = [math]::Pow(10, $yearsLog10)

    if ($years -lt 1000) { return (& $count ([long] [math]::Round($years)) 'year') }
    if ($years -lt 1e6)  { return ('{0} thousand years' -f [long] [math]::Round($years / 1e3)) }
    if ($years -lt 1e9)  { return ('{0} million years' -f [long] [math]::Round($years / 1e6)) }

    return ('{0} billion years' -f [long] [math]::Round($years / 1e9))
}

<#
.SYNOPSIS
    Estimates how long a password takes to crack.

.DESCRIPTION
    Two estimates, because they answer two questions:

      - brute force tries every combination of the same length and the same
        character types. It is the ceiling, and the only estimate that holds
        for a truly random password;
      - guessing is what cracking tools do first: common passwords, including
        with capitals and symbols standing for letters, keyboard runs,
        sequences, repeats, years and dates. The password is cut into the
        pieces that are cheapest to guess, the way zxcvbn does, and the
        pieces multiply.

    Each is turned into a duration for four attacks, from a login page that
    locks after a few tries to a stolen NTLM hash on a gaming graphics card.

.PARAMETER Text
    The password. Analysed in memory and never written anywhere.

.PARAMETER KnownEntropyBits
    For a generated secret, the entropy of the generator: an attacker who
    knows the method guesses in that many tries, and chance patterns in a
    random string do not help them.

.PARAMETER Now
    Today, for the distance of a year from the present.

.OUTPUTS
    PSCustomObject with Length, CharacterPool, BruteForceLog10, GuessesLog10,
    Bits, Score (0 to 4), Rating, EstimateLabel, Weaknesses, CrackTimes and
    Advice.
#>
function Measure-TkPasswordStrength {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter()] [double] $KnownEntropyBits = 0,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $length = $Text.Length

    # --- Brute force ---------------------------------------------------------
    $pool = 0

    if ($Text -cmatch '[a-z]')            { $pool += 26 }
    if ($Text -cmatch '[A-Z]')            { $pool += 26 }
    if ($Text -match '[0-9]')             { $pool += 10 }
    if ($Text -match '[ -/:-@\[-`{-~]')   { $pool += 33 }
    if ($Text -match '[^\x20-\x7E]')      { $pool += 100 }

    $charLog10  = [math]::Log10([math]::Max(10, $pool))
    $bruteLog10 = $length * $charLog10

    # --- Patterns ------------------------------------------------------------
    $found = New-Object System.Collections.Generic.List[object]

    $add = {
        param($start, $size, $kind, $log10, $note)
        $found.Add([pscustomobject] @{ Start = [int] $start; End = [int] ($start + $size); Kind = $kind; Log10 = [double] $log10; Note = $note })
    }

    $lower = $Text.ToLowerInvariant()

    # Common passwords and words, also written backwards or with symbols for
    # letters. A 1 stands for an i as often as for an l, so both are tried.
    $ranks = @{}
    $rank  = 0

    foreach ($word in (Get-TkCommonPasswordList)) {
        $rank++
        if (-not $ranks.ContainsKey($word)) { $ranks[$word] = $rank }
    }

    $leet = @{ '@' = 'a'; '4' = 'a'; '0' = 'o'; '3' = 'e'; '$' = 's'; '5' = 's'; '7' = 't'; '+' = 't'; '!' = 'i' }

    $variants = foreach ($one in @('i', 'l')) {

        $builder = New-Object System.Text.StringBuilder

        foreach ($character in $lower.ToCharArray()) {

            $key = [string] $character

            if ($key -eq '1')                { [void] $builder.Append($one) }
            elseif ($leet.ContainsKey($key)) { [void] $builder.Append($leet[$key]) }
            else                             { [void] $builder.Append($key) }
        }

        $builder.ToString()
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    for ($start = 0; $start -lt $length; $start++) {

        for ($size = 4; $size -le [math]::Min(20, $length - $start); $size++) {

            foreach ($variant in $variants) {

                $slice    = $variant.Substring($start, $size)
                $reversed = -join $slice.ToCharArray()[($size - 1)..0]
                $word     = $null

                if ($ranks.ContainsKey($slice))        { $word = $slice }
                elseif ($ranks.ContainsKey($reversed)) { $word = $reversed }

                if (-not $word -or -not $seen.Add(('{0}|{1}' -f $start, $size))) { continue }

                $original   = $Text.Substring($start, $size)
                $isReversed = $word -ne $slice
                $plain      = $original.ToLowerInvariant()

                if ($isReversed) { $plain = -join $plain.ToCharArray()[($size - 1)..0] }

                $log10 = [math]::Log10($ranks[$word])
                $how   = @()

                if ($original -cmatch '[A-Z]') {
                    $capitals = if ($original -cmatch '^[A-Z][^A-Z]*$' -or $original -cnotmatch '[a-z]') { 2 } else { 4 }
                    $log10   += [math]::Log10($capitals)
                    $how     += 'capitals'
                }

                if ($plain -ne $word) {
                    $log10 += [math]::Log10(2)
                    $how   += 'symbols for letters'
                }

                if ($isReversed) {
                    $log10 += [math]::Log10(2)
                    $how   += 'written backwards'
                }

                $note = 'a common password or word{0}' -f $(if ($how) { ' ({0})' -f ($how -join ', ') } else { '' })

                & $add $start $size 'Common password' $log10 $note
            }
        }
    }

    # Sequences of letters or digits, up or down: abcd, 4321.
    $classOf = {
        param($character)
        if ($character -cmatch '[a-z]') { 'lower' } elseif ($character -cmatch '[A-Z]') { 'upper' } elseif ($character -match '[0-9]') { 'digit' } else { '' }
    }

    $index = 0

    while ($index -lt $length - 2) {

        $class = & $classOf ([string] $Text[$index])
        $delta = [int] $Text[$index + 1] - [int] $Text[$index]

        if ($class -and [math]::Abs($delta) -eq 1 -and (& $classOf ([string] $Text[$index + 1])) -eq $class) {

            $last = $index + 1

            while ($last + 1 -lt $length -and ([int] $Text[$last + 1] - [int] $Text[$last]) -eq $delta -and
                   (& $classOf ([string] $Text[$last + 1])) -eq $class) {
                $last++
            }

            $size = $last - $index + 1

            if ($size -ge 3) {

                $base  = if ([string] $Text[$index] -in @('a', 'z', '0', '1', '9')) { 4 } elseif ($class -eq 'digit') { 10 } else { 26 }
                $log10 = [math]::Log10($base * $size * $(if ($delta -lt 0) { 2 } else { 1 }))

                & $add $index $size 'Sequence' $log10 ('a sequence of {0} characters' -f $size)

                $index = $last + 1
                continue
            }
        }

        $index++
    }

    # Repeats: aaaa, abcabc.
    foreach ($repeat in [regex]::Matches($Text, '(.+?)\1+')) {

        if ($repeat.Length -lt 3) { continue }

        $chunk = $repeat.Groups[1].Value
        $times = [int] ($repeat.Length / $chunk.Length)
        $what  = if ($chunk.Length -eq 1) { 'the same character' } else { 'the same {0} characters' -f $chunk.Length }

        & $add $repeat.Index $repeat.Length 'Repeat' ($chunk.Length * $charLog10 + [math]::Log10($times)) ('{0} repeated {1} times' -f $what, $times)
    }

    # Runs of neighbouring keys, on QWERTY, AZERTY and QWERTZ, either way.
    $rows = @('qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'azertyuiop', 'qsdfghjklm', 'wxcvbn', 'qwertzuiop', 'yxcvbnm', '1234567890')
    $rows = @($rows) + @($rows | ForEach-Object { -join $_.ToCharArray()[($_.Length - 1)..0] })

    $keyStart = 0

    while ($keyStart -lt $length - 3) {

        $run = 0

        for ($size = [math]::Min(12, $length - $keyStart); $size -ge 4 -and $run -eq 0; $size--) {

            $slice = $lower.Substring($keyStart, $size)

            foreach ($row in $rows) {
                if ($row.Contains($slice)) { $run = $size; break }
            }
        }

        if ($run -gt 0) {
            & $add $keyStart $run 'Keyboard' ([math]::Log10(10 * $run * 2)) ('a run of {0} neighbouring keys' -f $run)
            $keyStart += $run
        }
        else {
            $keyStart++
        }
    }

    # Years and dates.
    foreach ($year in [regex]::Matches($Text, '(?<!\d)(19\d\d|20\d\d)(?!\d)')) {
        $space = [math]::Max([math]::Abs([int] $year.Value - $Now.Year), 20)
        & $add $year.Index 4 'Year' ([math]::Log10($space)) 'a year'
    }

    foreach ($date in [regex]::Matches($Text, '(?<!\d)(0?[1-9]|[12]\d|3[01])([/.\-]?)(0?[1-9]|1[0-2])\2((19|20)?\d\d)(?!\d)')) {
        $log10 = [math]::Log10(365 * 20) + $(if ($date.Groups[2].Value) { [math]::Log10(4) } else { 0 })
        & $add $date.Index $date.Length 'Date' $log10 'a date'
    }

    # --- Cheapest way to guess the whole password ------------------------------
    $byEnd = @{}

    foreach ($piece in $found) {
        if (-not $byEnd.ContainsKey($piece.End)) { $byEnd[$piece.End] = New-Object System.Collections.Generic.List[object] }
        $byEnd[$piece.End].Add($piece)
    }

    $best = New-Object 'double[]' ($length + 1)
    $via  = New-Object 'object[]' ($length + 1)

    for ($position = 1; $position -le $length; $position++) {

        $best[$position] = $best[$position - 1] + $charLog10

        if ($byEnd.ContainsKey($position)) {

            foreach ($piece in $byEnd[$position]) {

                $cost = $best[$piece.Start] + $piece.Log10

                if ($cost -lt $best[$position]) {
                    $best[$position] = $cost
                    $via[$position]  = $piece
                }
            }
        }
    }

    $used     = New-Object System.Collections.Generic.List[object]
    $segments = 0
    $inRandom = $false
    $position = $length

    while ($position -gt 0) {

        $piece = $via[$position]

        if ($piece) {
            $used.Insert(0, $piece)
            $segments++
            $inRandom = $false
            $position = $piece.Start
        }
        else {
            if (-not $inRandom) { $segments++; $inRandom = $true }
            $position--
        }
    }

    # The attacker does not know in which order the pieces come.
    $orderLog10 = 0

    for ($piecesCount = 2; $piecesCount -le $segments; $piecesCount++) {
        $orderLog10 += [math]::Log10($piecesCount)
    }

    $guessLog10    = [math]::Min($best[$length] + $orderLog10, $bruteLog10)
    $estimateLabel = 'Guessing patterns first'

    if ($KnownEntropyBits -gt 0) {
        $guessLog10    = $KnownEntropyBits * [math]::Log10(2)
        $estimateLabel = 'Knowing how it was generated'
        $used.Clear()
    }

    $bits  = [math]::Round($guessLog10 / [math]::Log10(2), 1)
    $score = if ($bits -lt 40) { 0 } elseif ($bits -lt 60) { 1 } elseif ($bits -lt 80) { 2 } elseif ($bits -lt 128) { 3 } else { 4 }

    # --- Durations -----------------------------------------------------------
    $attacks = @(
        [pscustomobject] @{ Scenario = 'Online, throttled (100 guesses an hour)';                         Log10Rate = [math]::Log10(100 / 3600) }
        [pscustomobject] @{ Scenario = 'Online, not throttled (10 guesses a second)';                     Log10Rate = 1 }
        [pscustomobject] @{ Scenario = 'Offline, slow hash such as bcrypt (10 thousand a second)';        Log10Rate = 4 }
        [pscustomobject] @{ Scenario = 'Offline, fast hash such as NTLM, one GPU (100 billion a second)'; Log10Rate = 11 }
    )

    $times = foreach ($attack in $attacks) {
        [pscustomobject] @{
            Scenario   = $attack.Scenario
            BruteForce = Format-TkCrackDuration -Log10Seconds ($bruteLog10 - $attack.Log10Rate)
            Estimated  = Format-TkCrackDuration -Log10Seconds ($guessLog10 - $attack.Log10Rate)
        }
    }

    $advice = @()

    if ($KnownEntropyBits -le 0 -and $length -gt 0) {

        if ($used.Count -gt 0) {
            $advice += 'Leave out words, names, keyboard runs, sequences, years and dates: cracking tools try them before anything else, whatever the capitals and symbols around them.'
        }

        if ($length -lt 14) {
            $advice += 'Make it longer: every character multiplies the work. 14 random characters, or a passphrase of five random words, hold against a stolen fast hash.'
        }
    }

    return [pscustomobject] @{
        Length          = $length
        CharacterPool   = $pool
        BruteForceLog10 = [math]::Round($bruteLog10, 2)
        GuessesLog10    = [math]::Round($guessLog10, 2)
        Bits            = $bits
        Score           = $score
        Rating          = Get-TkEntropyRating -Bits $bits
        EstimateLabel   = $estimateLabel
        Weaknesses      = @($used | ForEach-Object { [pscustomobject] @{ Kind = $_.Kind; Note = $_.Note } })
        CrackTimes      = @($times)
        Advice          = @($advice)
    }
}

<#
.SYNOPSIS
    Checks a password against the Have I Been Pwned breach corpus.

.DESCRIPTION
    Uses the k-anonymity range API: the password is hashed with SHA1 locally,
    only the first five hex characters of the hash are sent, and the service
    returns every suffix sharing that prefix. The full hash, and therefore
    the password, never leaves the machine.

    This is the one place where SHA1 is correct rather than obsolete: it is
    the hash the corpus is indexed with, and it is being used as a lookup
    key, not as a security control.

.PARAMETER Password
    Password to check, as a SecureString.

.OUTPUTS
    PSCustomObject with Found and Count.
#>
function Test-TkPasswordBreached {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [securestring] $Password
    )

    $bstr  = [IntPtr]::Zero
    $plain = $null

    try {
        $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        $sha1  = [System.Security.Cryptography.SHA1]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
        $hash  = ([BitConverter]::ToString($sha1.ComputeHash($bytes)) -replace '-', '').ToUpperInvariant()

        $sha1.Dispose()

        $prefix = $hash.Substring(0, 5)
        $suffix = $hash.Substring(5)

        Write-TkLog -Level Information -Category 'Credentials' -Message (
            'Breach check using k-anonymity: only the prefix {0} is sent.' -f $prefix
        )

        $response = Invoke-RestMethod -Uri ('https://api.pwnedpasswords.com/range/{0}' -f $prefix) `
                                      -Headers @{ 'Add-Padding' = 'true' } `
                                      -TimeoutSec 20 -ErrorAction Stop

        foreach ($line in ($response -split "`r?`n")) {

            $parts = $line -split ':'

            if ($parts.Count -eq 2 -and $parts[0].Trim() -eq $suffix) {

                $count = [int64] $parts[1].Trim()

                if ($count -eq 0) {
                    continue
                }

                Write-TkLog -Level Warning -Category 'Credentials' -Message (
                    'This password appears in {0} known breaches. Do not use it.' -f $count
                )

                return [pscustomobject]@{
                    Found   = $true
                    Count   = $count
                    Message = 'Seen {0} times in breach corpora. Choose another password.' -f $count
                }
            }
        }

        return [pscustomobject]@{
            Found   = $false
            Count   = 0
            Message = 'Not present in the breach corpus. That does not make it strong, only unbreached.'
        }
    }
    catch {
        Write-TkLog -Level Error -Category 'Credentials' -Message (
            'Breach check failed: {0}' -f $_.Exception.Message
        )

        return [pscustomobject]@{
            Found   = $false
            Count   = -1
            Message = 'The check could not be performed.'
        }
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        $plain = $null
    }
}

<#
.SYNOPSIS
    Returns the word list used for passphrase generation.

.DESCRIPTION
    A compact list of short, unambiguous English words. Kept in code rather
    than in a catalog so passphrase generation keeps working in a build with
    no data files reachable.

.OUTPUTS
    System.String[]
#>
function Get-TkWordList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'anchor','amber','apple','arrow','atlas','aurora','autumn','badge','balance','banjo',
        'basket','beacon','bishop','bison','blanket','bonsai','border','bottle','boulder','branch',
        'bridge','bronze','bubble','buffalo','bureau','cabin','cactus','camera','candle','canvas',
        'canyon','captain','carbon','cargo','carpet','castle','cavern','cedar','cellar','cement',
        'chalk','chapel','charter','cherry','chimney','cinema','circus','citadel','cliff','clover',
        'cobalt','comet','compass','copper','coral','cottage','cotton','county','crater','crayon',
        'crimson','crystal','cypress','dagger','dahlia','daisy','dancer','dapple','dawn','decoy',
        'delta','denim','desert','diamond','dolphin','domino','donkey','dragon','drapes','drift',
        'dynamo','eagle','earth','echo','eclipse','elder','ember','emerald','engine','envoy',
        'escape','ethanol','everest','exile','fabric','falcon','fathom','feather','fennel','ferry',
        'fiddle','filter','fjord','flame','flint','floral','flute','forest','fossil','fountain',
        'fox','frost','galaxy','garden','garnet','gazelle','geyser','ginger','glacier','glider',
        'granite','grapes','gravel','guitar','gully','gypsum','hammer','harbor','harvest','hazel',
        'helmet','heron','hollow','honey','horizon','hunter','husky','indigo','island','ivory',
        'jacket','jaguar','jasmine','jetty','jigsaw','jungle','juniper','kayak','kernel','kettle',
        'keystone','kingdom','kitten','ladder','lagoon','lantern','lattice','lava','lemon','leopard',
        'lighthouse','lilac','linen','lobster','locket','lotus','lunar','lyric','magnet','mahogany',
        'mammoth','mango','manor','maple','marble','mariner','marsh','meadow','melody','meteor',
        'mimosa','mineral','mirror','mistral','monsoon','mosaic','mountain','mulberry','museum','mustard',
        'nebula','nectar','needle','nickel','nomad','notch','nutmeg','oasis','obsidian','ocean',
        'octave','olive','onyx','opal','orbit','orchard','origami','otter','outpost','oyster',
        'paddle','palace','panther','papaya','parade','parcel','parsley','pasture','pebble','pelican',
        'pepper','petal','pewter','phantom','pigeon','pillar','pilot','pioneer','pistachio','planet',
        'plateau','plaza','plume','pocket','pollen','poppy','portal','prairie','prism','pueblo',
        'pumpkin','puzzle','pyramid','quarry','quartz','quiver','radish','rafter','rainbow','rampart',
        'ranger','rapids','raven','reactor','reef','relay','ribbon','ridge','rifle','ripple',
        'river','roaster','rocket','roster','rubble','ruby','rudder','saffron','sailor','salmon',
        'sandal','sapphire','satchel','saturn','savanna','scarlet','scepter','scholar','scooter','sculptor',
        'seagull','seaside','sequoia','shadow','shelter','sherbet','shovel','shuttle','sierra','signal',
        'silver','siren','sketch','slalom','sliver','smoke','snapshot','solstice','sonnet','sparrow',
        'spindle','spiral','spruce','stadium','stallion','station','statue','stellar','stencil','stereo',
        'stitch','stone','stork','stratus','stream','stucco','studio','summit','sunset','surfer',
        'swallow','sycamore','symbol','syntax','tablet','tackle','talon','tandem','tangent','tapestry',
        'tavern','teapot','tempo','tender','terrace','thicket','thistle','thunder','timber','tinder',
        'topaz','torch','tornado','totem','tractor','trailer','transit','trapeze','treaty','trellis',
        'tribute','trident','trinket','triumph','trolley','trophy','tropic','trumpet','tulip','tundra',
        'tunnel','turban','turbine','turtle','tuxedo','ultra','umbrella','unicorn','uniform','upland',
        'uranium','urchin','valley','vanilla','vault','velvet','vendor','venture','verdict','vertex',
        'vessel','veteran','viaduct','victory','village','vintage','violet','viper','vision','vista',
        'volcano','voltage','voyage','walnut','walrus','wander','warden','warmth','waterfall','wavelet',
        'weaver','webbing','western','whale','wheat','whisker','willow','window','winter','wisdom',
        'wolfram','wombat','wonder','woodland','wrangler','xenon','yarrow','yellow','yodel','yonder',
        'zephyr','zenith','zinnia','zodiac','zombie'
    )
}
