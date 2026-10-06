<#
    Toolkit - Core / Language of the interface and of the reports

    The interface is written in English, and English stays the key: a
    dictionary per language (data/strings-<language>.json, a list of pairs
    "en" and "text") maps an English text to its translation, and a text the
    dictionary does not hold is shown in English. That lets the translation grow page by page without a step
    where half the window has no text at all.

    What a person reads is translated; what a program reads is not. The JSON
    of a report, the journal, the logs and every identifier stay in English,
    which is the contract other tools and the tests rely on.

    Translations are data. They are only ever shown or formatted with -f,
    never run, and a test keeps the placeholders of every translation the
    same as its English.
#>

# The language the interface and the reports are shown in: en or fr. Read
# from the settings at start, and seeded into the background runspaces, which
# also write texts a person reads.
$script:TkLanguage = 'en'

# The dictionary of the current language, built on first use in each
# runspace: the exact texts, and the texts with placeholders as patterns.
$script:TkTextTable = $null

<#
.SYNOPSIS
    The languages the interface can be shown in.

.OUTPUTS
    PSCustomObject[] with Id and Name, the name written in its own language.
#>
function Get-TkLanguageChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $french = Import-TkCatalog -Name 'strings-fr'

    return @(
        [pscustomobject] @{ Id = 'en'; Name = 'English' }
        [pscustomobject] @{ Id = 'fr'; Name = $(if ($french -and $french.name) { [string] $french.name } else { 'French' }) }
    )
}

<#
.SYNOPSIS
    The language to show, from the setting and the language of Windows.

.DESCRIPTION
    Pure. The setting is en, fr or auto; auto follows the display language of
    Windows when the toolkit has it, and English otherwise. Anything else
    reads as English.

.OUTPUTS
    System.String: en or fr.
#>
function Resolve-TkLanguage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowEmptyString()] [AllowNull()] [string] $Setting = 'en',
        [Parameter()] [string] $Culture = ([System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName)
    )

    switch ([string] $Setting) {
        'fr'    { return 'fr' }
        'auto'  { return $(if ($Culture -eq 'fr') { 'fr' } else { 'en' }) }
        default { return 'en' }
    }
}

<#
.SYNOPSIS
    Reads the language from the settings, for this start.
#>
function Initialize-TkLanguage {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $settings = (Get-TkContext).Settings
    $setting  = if ($settings -and $settings.ContainsKey('Language')) { [string] $settings['Language'] } else { 'en' }

    $script:TkLanguage  = Resolve-TkLanguage -Setting $setting
    $script:TkTextTable = $null

    return $script:TkLanguage
}

<#
.SYNOPSIS
    The language the interface and the reports are shown in now.
#>
function Get-TkLanguage {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ([string]::IsNullOrEmpty($script:TkLanguage)) {
        return 'en'
    }

    return $script:TkLanguage
}

<#
.SYNOPSIS
    The dictionary of a language: exact texts, and patterns for the texts
    that carry placeholders.

.OUTPUTS
    PSCustomObject with Language, Exact (a case-sensitive dictionary) and
    Templates (Regex, Value), the longest English first.
#>
function Get-TkTextTable {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string] $Language = (Get-TkLanguage)
    )

    if ($script:TkTextTable -and $script:TkTextTable.Language -eq $Language) {
        return $script:TkTextTable
    }

    $exact     = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
    $templates = New-Object System.Collections.Generic.List[object]

    $catalog = if ($Language -ne 'en') { Import-TkCatalog -Name ('strings-{0}' -f $Language) } else { $null }

    # A list of pairs rather than an object: ConvertFrom-Json reads property
    # names without case, and WORKSTATION and Workstation are two texts. A
    # pair with a context ("Check" the noun of a report, not the button's
    # verb) is found only by the code that asks for that context.
    if ($catalog -and $catalog.strings) {
        foreach ($entry in @($catalog.strings)) {

            $key   = [string] $entry.en
            $value = [string] $entry.text

            if (-not $key -or -not $value) { continue }

            if ($entry.PSObject.Properties['context'] -and $entry.context) {
                $exact[('{0}|{1}' -f $entry.context, $key)] = $value
                continue
            }

            $exact[$key] = $value

            if ($key -match '\{\d+\}') {
                # Literal parts escaped, each placeholder a lazy group, the
                # whole text anchored. A placeholder can be narrowed by the
                # pair's "values" (a number, a drive letter): without that,
                # "Storage {0}" would read "Storage health" as one of its own.
                $narrow  = if ($entry.PSObject.Properties['values'] -and $entry.values) { $entry.values } else { $null }
                $pattern = '^' + ((@([regex]::Split($key, '(\{\d+\})') | ForEach-Object {
                    if ($_ -match '^\{(\d+)\}$') {
                        $index = $Matches[1]
                        $inner = if ($narrow -and $narrow.PSObject.Properties[$index]) { [string] $narrow.$index } else { '.+?' }
                        '(?<p{0}>{1})' -f $index, $inner
                    }
                    else { [regex]::Escape($_) }
                })) -join '') + '$'

                $highest = (@([regex]::Matches($key, '\{(\d+)\}') | ForEach-Object { [int] $_.Groups[1].Value }) | Measure-Object -Maximum).Maximum
                $templates.Add([pscustomobject] @{ Key = $key; Regex = New-Object System.Text.RegularExpressions.Regex($pattern); Value = $value; Highest = [int] $highest })
            }
        }
    }

    $script:TkTextTable = [pscustomobject] @{
        Language  = $Language
        Exact     = $exact
        Templates = @($templates | Sort-Object -Property { $_.Key.Length } -Descending)
    }

    return $script:TkTextTable
}

<#
.SYNOPSIS
    A text in the language of the interface.

.DESCRIPTION
    The English text is the key. With ArgumentList, the translation is
    formatted with -f, as the English would have been; without a
    translation, the English is.

.EXAMPLE
    Get-TkText -Text '{0} days ago' -ArgumentList 12
#>
function Get-TkText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowEmptyString()] [string] $Text,
        [Parameter(Position = 1)] [AllowEmptyCollection()] [object[]] $ArgumentList = @(),
        [Parameter()] [string] $Language = (Get-TkLanguage),

        # Where the text is used, when the same English means two things: the
        # pair of that context is tried first, then the plain one.
        [Parameter()] [AllowEmptyString()] [string] $Context = ''
    )

    $value = $Text

    if ($Language -ne 'en' -and $Text) {
        $table = Get-TkTextTable -Language $Language
        $found = $null
        if ($Context -and $table.Exact.TryGetValue(('{0}|{1}' -f $Context, $Text), [ref] $found)) { $value = $found }
        elseif ($table.Exact.TryGetValue($Text, [ref] $found)) { $value = $found }
    }

    if (@($ArgumentList).Count -gt 0) {
        return ($value -f $ArgumentList)
    }

    return $value
}

<#
.SYNOPSIS
    Translates a text that was written in English elsewhere, already formatted.

.DESCRIPTION
    For what is shown after it was built in English, in a background task or
    by code the reports share: "12 days ago" is matched against "{0} days
    ago", and its translation is given the same values. The exact text is
    tried first. With Exact, only the exact text is: the safe choice where
    the text may be a name or a value rather than a sentence of the toolkit.

.OUTPUTS
    System.String, the text unchanged when nothing matches.
#>
function ConvertTo-TkLocalText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowEmptyString()] [AllowNull()] [string] $Text,
        [Parameter()] [switch] $Exact,
        [Parameter()] [string] $Language = (Get-TkLanguage),

        # A value a template captured is translated too, once: "Up for 3d 4h"
        # holds a duration that is itself written in English.
        [Parameter(DontShow)] [int] $Depth = 0
    )

    if ($Language -eq 'en' -or [string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $table = Get-TkTextTable -Language $Language
    $found = $null

    if ($table.Exact.TryGetValue($Text, [ref] $found)) {
        return $found
    }

    if ($Exact) {
        return $Text
    }

    foreach ($template in $table.Templates) {

        $match = $template.Regex.Match($Text)

        if ($match.Success) {
            $values = @(0..$template.Highest | ForEach-Object {
                $captured = $match.Groups[('p{0}' -f $_)].Value
                if ($Depth -lt 1) { ConvertTo-TkLocalText -Text $captured -Language $Language -Depth ($Depth + 1) } else { $captured }
            })
            return ($template.Value -f $values)
        }
    }

    return $Text
}
