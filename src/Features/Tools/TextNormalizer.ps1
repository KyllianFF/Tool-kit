<#
    Toolkit - Features / Text normalizer

    The invisible differences that make a config file behave differently on two
    machines, or a diff show a change that is not one: the line endings a file
    was saved with, tabs where spaces were meant, trailing spaces, and a byte
    order mark at the front. This rewrites a pasted text to one set of choices
    and says what it changed. It is worked out on the machine; nothing is read
    from or written to disk.
#>

<#
.SYNOPSIS
    Rewrites a text to chosen line endings, tab handling and trimming.

.PARAMETER Text
    The text to normalise.

.PARAMETER LineEnding
    LF, CRLF or CR: the ending every line is given.

.PARAMETER Tabs
    Keep, ToSpaces (each tab becomes TabWidth spaces) or ToTabs (leading runs of
    TabWidth spaces become a tab).

.PARAMETER TabWidth
    The width a tab stands for.

.PARAMETER TrimTrailing
    Remove spaces and tabs at the end of every line.

.PARAMETER StripBom
    Remove a leading byte order mark.

.OUTPUTS
    PSCustomObject with Text and Summary.
#>
function Get-TkTextNormalization {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [ValidateSet('LF', 'CRLF', 'CR')]
        [string] $LineEnding = 'LF',

        [Parameter()]
        [ValidateSet('Keep', 'ToSpaces', 'ToTabs')]
        [string] $Tabs = 'Keep',

        [Parameter()]
        [int] $TabWidth = 4,

        [Parameter()]
        [bool] $TrimTrailing = $true,

        [Parameter()]
        [bool] $StripBom = $true
    )

    $summary = New-Object System.Collections.Generic.List[string]
    $value   = $Text

    # --- Byte order mark ---------------------------------------------------
    $bomRemoved = $false
    if ($StripBom -and $value.Length -gt 0 -and $value[0] -eq [char] 0xFEFF) {
        $value = $value.Substring(1)
        $bomRemoved = $true
    }

    # --- Count the line endings before touching them ----------------------
    $crlf   = ([regex]::Matches($value, "`r`n")).Count
    $noCrlf = $value -replace "`r`n", ''
    $lf     = ([regex]::Matches($noCrlf, "`n")).Count
    $cr     = ([regex]::Matches($noCrlf, "`r")).Count

    # --- Split into lines, whatever they ended with -----------------------
    $lines = $value -split "`r`n|`r|`n"

    $eol = switch ($LineEnding) { 'CRLF' { "`r`n" } 'CR' { "`r" } default { "`n" } }

    $trimmed  = 0
    $tabbed   = 0
    $spaces   = ' ' * $TabWidth

    for ($i = 0; $i -lt $lines.Count; $i++) {

        $line = $lines[$i]

        if ($Tabs -eq 'ToSpaces' -and $line.Contains("`t")) {
            $line = $line.Replace("`t", $spaces)
            $tabbed++
        }
        elseif ($Tabs -eq 'ToTabs' -and $line -match '^( +)') {

            $leading = $matches[1]
            $tabCount = [int] ($leading.Length / $TabWidth)

            if ($tabCount -gt 0) {
                $line = ("`t" * $tabCount) + (' ' * ($leading.Length % $TabWidth)) + $line.Substring($leading.Length)
                $tabbed++
            }
        }

        if ($TrimTrailing) {
            $stripped = $line -replace '[ \t]+$', ''
            if ($stripped -ne $line) { $trimmed++ }
            $line = $stripped
        }

        $lines[$i] = $line
    }

    $result = $lines -join $eol

    # --- Say what changed -------------------------------------------------
    $endingParts = @()
    if ($crlf) { $endingParts += ('{0} CRLF' -f $crlf) }
    if ($lf)   { $endingParts += ('{0} LF'   -f $lf) }
    if ($cr)   { $endingParts += ('{0} CR'   -f $cr) }
    if ($endingParts.Count -eq 0) { $endingParts = @('none') }

    $summary.Add(('Line endings: {0} -> {1}' -f ($endingParts -join ', '), $LineEnding))
    if ($bomRemoved)      { $summary.Add('Byte order mark removed.') }
    if ($trimmed -gt 0)   { $summary.Add(('Trimmed trailing whitespace on {0} line(s).' -f $trimmed)) }
    if ($tabbed  -gt 0)   { $summary.Add(('Tab conversion on {0} line(s).' -f $tabbed)) }
    if ($summary.Count -eq 1 -and -not $bomRemoved) { $summary.Add('Nothing else needed changing.') }

    return [pscustomobject] @{
        Text    = $result
        Summary = $summary.ToArray()
    }
}
