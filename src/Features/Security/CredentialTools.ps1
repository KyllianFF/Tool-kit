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
