<#
    Toolkit - Features / CSV cleaner and viewer

    The CSV someone exported and pasted in, to read it as a table rather than a
    wall of commas. It works out the delimiter (comma, semicolon, tab or pipe),
    parses the quoting properly so a field can hold the delimiter, a quote or a
    newline of its own, and lays the rows out in aligned columns.

    It also cleans: trim the cells, drop the blank rows, drop the exact
    duplicates, and read the result back as a table, as JSON, or as CSV again.
    Everything happens on the machine; nothing is sent anywhere.
#>

<#
.SYNOPSIS
    The delimiters the parser recognises, by name.

.OUTPUTS
    PSCustomObject[] with Name and Char.
#>
function Get-TkCsvDelimiterChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'Comma';     Char = ',' }
        [pscustomobject] @{ Name = 'Semicolon'; Char = ';' }
        [pscustomobject] @{ Name = 'Tab';       Char = "`t" }
        [pscustomobject] @{ Name = 'Pipe';      Char = '|' }
    )
}

<#
.SYNOPSIS
    Parses a CSV text into rows of fields, following RFC 4180 quoting.

.DESCRIPTION
    A field wrapped in double quotes may contain the delimiter, a line break,
    or a doubled "" that stands for one quote. Outside quotes, a CR, LF or CRLF
    ends the record.

.PARAMETER Text
    The CSV text.

.PARAMETER Delimiter
    The field separator. Its first character is used.

.OUTPUTS
    System.Object[]: an array of string[] rows.
#>
function ConvertFrom-TkCsvText {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $Delimiter
    )

    $separator = $Delimiter[0]
    $rows      = New-Object System.Collections.Generic.List[object]
    $record    = New-Object System.Collections.Generic.List[string]
    $field     = New-Object System.Text.StringBuilder
    $inQuotes  = $false
    $length    = $Text.Length

    for ($i = 0; $i -lt $length; $i++) {

        $char = $Text[$i]

        if ($inQuotes) {

            if ($char -eq '"') {

                if ($i + 1 -lt $length -and $Text[$i + 1] -eq '"') {
                    [void] $field.Append('"')
                    $i++
                }
                else {
                    $inQuotes = $false
                }
            }
            else {
                [void] $field.Append($char)
            }

            continue
        }

        if ($char -eq '"') {
            $inQuotes = $true
        }
        elseif ($char -eq $separator) {
            $record.Add($field.ToString())
            [void] $field.Clear()
        }
        elseif ($char -eq "`r" -or $char -eq "`n") {

            $record.Add($field.ToString())
            [void] $field.Clear()
            $rows.Add($record.ToArray())
            $record.Clear()

            # Swallow the LF of a CRLF pair.
            if ($char -eq "`r" -and $i + 1 -lt $length -and $Text[$i + 1] -eq "`n") {
                $i++
            }
        }
        else {
            [void] $field.Append($char)
        }
    }

    # The field and record left open when the text does not end on a newline.
    $record.Add($field.ToString())

    if ($record.Count -gt 1 -or $record[0].Length -gt 0) {
        $rows.Add($record.ToArray())
    }

    return @($rows.ToArray())
}

<#
.SYNOPSIS
    Guesses the delimiter of a CSV text.

.DESCRIPTION
    Each candidate is tried in turn; the one that splits the rows into the most
    columns, most consistently, wins. A tie keeps the earlier candidate, so a
    plain comma is preferred.

.OUTPUTS
    System.String: the delimiter character.
#>
function Get-TkCsvDelimiter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $best      = ','
    $bestScore = 0.0

    foreach ($choice in @(Get-TkCsvDelimiterChoice)) {

        $rows = @(ConvertFrom-TkCsvText -Text $Text -Delimiter $choice.Char)
        $rows = @($rows | Select-Object -First 40)

        if ($rows.Count -eq 0) {
            continue
        }

        # The most common column count, and how many rows agree with it.
        $counts = @($rows | ForEach-Object { $_.Count })
        $mode   = ($counts | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)

        if ($null -eq $mode -or [int] $mode.Name -le 1) {
            continue
        }

        $agreement = $mode.Count / $rows.Count
        $score     = [int] $mode.Name * $agreement

        if ($score -gt $bestScore) {
            $bestScore = $score
            $best      = $choice.Char
        }
    }

    return $best
}

<#
.SYNOPSIS
    Parses and cleans a CSV text into a table model.

.PARAMETER Text
    The CSV text.

.PARAMETER Delimiter
    Auto (detect), or one of the names from Get-TkCsvDelimiterChoice.

.PARAMETER Header
    Treat the first row as the header.

.PARAMETER Trim
    Trim leading and trailing whitespace from every cell.

.PARAMETER DropBlank
    Drop rows whose cells are all empty.

.PARAMETER DropDuplicate
    Drop rows equal to one already kept.

.OUTPUTS
    PSCustomObject with Delimiter, DelimiterName, Header, Rows, ColumnCount,
    DroppedBlank and DroppedDuplicate.
#>
function Get-TkCsvTable {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [string] $Delimiter = 'Auto',

        [Parameter()]
        [switch] $Header,

        [Parameter()]
        [switch] $Trim,

        [Parameter()]
        [switch] $DropBlank,

        [Parameter()]
        [switch] $DropDuplicate
    )

    $named = @(Get-TkCsvDelimiterChoice) | Where-Object { $_.Name -eq $Delimiter } | Select-Object -First 1
    $char  = if ($named) { $named.Char } else { Get-TkCsvDelimiter -Text $Text }

    $rows = @(ConvertFrom-TkCsvText -Text $Text -Delimiter $char)

    if ($Trim) {
        $rows = @($rows | ForEach-Object { , @($_ | ForEach-Object { $_.Trim() }) })
    }

    $headerRow = $null

    if ($Header -and $rows.Count -gt 0) {
        $headerRow = $rows[0]
        $rows      = @($rows | Select-Object -Skip 1)
    }

    $droppedBlank     = 0
    $droppedDuplicate = 0
    $seen             = New-Object System.Collections.Generic.HashSet[string]
    $kept             = New-Object System.Collections.Generic.List[object]

    foreach ($row in $rows) {

        if ($DropBlank -and @($row | Where-Object { $_ -ne '' }).Count -eq 0) {
            $droppedBlank++
            continue
        }

        if ($DropDuplicate) {

            $key = ($row -join ([char] 0x241F))

            if (-not $seen.Add($key)) {
                $droppedDuplicate++
                continue
            }
        }

        $kept.Add($row)
    }

    $widths = @($headerRow) + @($kept.ToArray()) | Where-Object { $_ } | ForEach-Object { $_.Count }
    $columns = if ($widths) { ($widths | Measure-Object -Maximum).Maximum } else { 0 }

    return [pscustomobject] @{
        Delimiter        = $char
        DelimiterName    = if ($named) { $named.Name } else { (@(Get-TkCsvDelimiterChoice) | Where-Object { $_.Char -eq $char } | Select-Object -First 1).Name }
        Header           = $headerRow
        Rows             = @($kept.ToArray())
        ColumnCount      = $columns
        DroppedBlank     = $droppedBlank
        DroppedDuplicate = $droppedDuplicate
    }
}

<#
.SYNOPSIS
    Quotes a CSV field when it needs it.
#>
function Protect-TkCsvField {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter(Mandatory)]
        [string] $Delimiter
    )

    if ($Value -match ('["\r\n]|' + [regex]::Escape($Delimiter))) {
        return '"' + ($Value -replace '"', '""') + '"'
    }

    return $Value
}

<#
.SYNOPSIS
    Lays a parsed CSV out as an aligned table with a short summary.

.OUTPUTS
    System.String[]
#>
function Format-TkCsvTable {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [string] $Delimiter = 'Auto',

        [Parameter()]
        [switch] $Header,

        [Parameter()]
        [switch] $Trim,

        [Parameter()]
        [switch] $DropBlank,

        [Parameter()]
        [switch] $DropDuplicate
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste a CSV (comma, semicolon, tab or pipe) to read it as a table.')
    }

    $table = Get-TkCsvTable -Text $Text -Delimiter $Delimiter -Header:$Header -Trim:$Trim -DropBlank:$DropBlank -DropDuplicate:$DropDuplicate
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Delimiter: {0}   {1} column(s), {2} row(s)' -f $table.DelimiterName.ToLower(), $table.ColumnCount, $table.Rows.Count))

    if ($table.DroppedBlank -gt 0 -or $table.DroppedDuplicate -gt 0) {
        $lines.Add(('Dropped: {0} blank, {1} duplicate' -f $table.DroppedBlank, $table.DroppedDuplicate))
    }

    $lines.Add('')

    $columns = $table.ColumnCount

    if ($columns -eq 0) {
        $lines.Add('No rows to show.')
        return $lines.ToArray()
    }

    # A cell for every column of every shown row, padded to the same length.
    $shown   = @($table.Rows | Select-Object -First 200)
    $matrix  = New-Object System.Collections.Generic.List[object]

    if ($table.Header) {
        $matrix.Add($table.Header)
    }

    foreach ($row in $shown) {
        $matrix.Add($row)
    }

    # A newline inside a cell would break the row it sits on; show it as a
    # return glyph so the table stays one line per record.
    $flatten = { param($value) ([string] $value) -replace '\r\n|\r|\n', ([char] 0x21B5) }

    $widths = New-Object 'int[]' $columns

    foreach ($row in $matrix) {
        for ($c = 0; $c -lt $columns; $c++) {
            $cell = if ($c -lt $row.Count) { & $flatten $row[$c] } else { '' }
            if ($cell.Length -gt $widths[$c]) { $widths[$c] = [math]::Min($cell.Length, 40) }
        }
    }

    $renderRow = {
        param($row)
        $cells = for ($c = 0; $c -lt $columns; $c++) {
            $cell = if ($c -lt $row.Count) { & $flatten $row[$c] } else { '' }
            if ($cell.Length -gt 40) { $cell = $cell.Substring(0, 37) + '...' }
            $cell.PadRight($widths[$c])
        }
        ($cells -join '  ').TrimEnd()
    }

    if ($table.Header) {
        $lines.Add((& $renderRow $table.Header))
        $lines.Add((($widths | ForEach-Object { '-' * $_ }) -join '  '))
    }

    foreach ($row in $shown) {
        $lines.Add((& $renderRow $row))
    }

    if ($table.Rows.Count -gt $shown.Count) {
        $lines.Add('')
        $lines.Add(('... {0} more row(s) not shown.' -f ($table.Rows.Count - $shown.Count)))
    }

    return $lines.ToArray()
}

<#
.SYNOPSIS
    Reads a cleaned CSV back as JSON.

.DESCRIPTION
    With a header, each row becomes an object keyed by the header; a cell with
    no header, or a missing cell, is keyed or filled plainly. With no header,
    the rows come back as arrays.

.OUTPUTS
    System.String
#>
function ConvertTo-TkCsvJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [string] $Delimiter = 'Auto',

        [Parameter()]
        [switch] $Header,

        [Parameter()]
        [switch] $Trim,

        [Parameter()]
        [switch] $DropBlank,

        [Parameter()]
        [switch] $DropDuplicate
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return '[]'
    }

    $table = Get-TkCsvTable -Text $Text -Delimiter $Delimiter -Header:$Header -Trim:$Trim -DropBlank:$DropBlank -DropDuplicate:$DropDuplicate

    if ($table.Rows.Count -eq 0) {
        return '[]'
    }

    $records = New-Object System.Collections.Generic.List[object]

    foreach ($row in $table.Rows) {

        if ($table.Header) {

            $object = [ordered] @{}

            for ($c = 0; $c -lt $table.ColumnCount; $c++) {
                $key = if ($c -lt $table.Header.Count -and $table.Header[$c] -ne '') { [string] $table.Header[$c] } else { 'column{0}' -f ($c + 1) }
                $object[$key] = if ($c -lt $row.Count) { $row[$c] } else { '' }
            }

            $records.Add([pscustomobject] $object)
        }
        else {
            $records.Add(@($row))
        }
    }

    # A single record still has to come out as a JSON array.
    return ('[' + (@($records | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress }) -join ',') + ']')
}

<#
.SYNOPSIS
    Writes a cleaned CSV back out, quoted where needed.

.OUTPUTS
    System.String
#>
function ConvertTo-TkCsvText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [string] $Delimiter = 'Auto',

        [Parameter()]
        [switch] $Header,

        [Parameter()]
        [switch] $Trim,

        [Parameter()]
        [switch] $DropBlank,

        [Parameter()]
        [switch] $DropDuplicate
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $table  = Get-TkCsvTable -Text $Text -Delimiter $Delimiter -Header:$Header -Trim:$Trim -DropBlank:$DropBlank -DropDuplicate:$DropDuplicate
    $lines  = New-Object System.Collections.Generic.List[string]

    $emit = {
        param($row)
        (@($row | ForEach-Object { Protect-TkCsvField -Value ([string] $_) -Delimiter $table.Delimiter }) -join $table.Delimiter)
    }

    if ($table.Header) {
        $lines.Add((& $emit $table.Header))
    }

    foreach ($row in $table.Rows) {
        $lines.Add((& $emit $row))
    }

    return ($lines -join [Environment]::NewLine)
}
