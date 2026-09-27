<#
    Toolkit - Features / .reg and PowerShell converter

    A .reg file is how a registry change is handed around; a script, a GPO
    or an Intune remediation wants it as commands. This turns a .reg file
    into PowerShell and into reg.exe commands, and PowerShell registry
    commands back into a .reg file.

    Pure text work: nothing is written to the registry. PowerShell is read
    with the parser, never run: a value is taken only when it is a literal,
    and anything computed (a variable, a sub-expression, a call) is reported
    rather than guessed.
#>

<#
.SYNOPSIS
    The registry roots, in their long, short and PowerShell forms.

.OUTPUTS
    PSCustomObject[] with Long, Short and Drive.
#>
function Get-TkRegistryRoot {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Long = 'HKEY_LOCAL_MACHINE';  Short = 'HKLM'; Drive = 'HKLM:' }
        [pscustomobject] @{ Long = 'HKEY_CURRENT_USER';   Short = 'HKCU'; Drive = 'HKCU:' }
        [pscustomobject] @{ Long = 'HKEY_CLASSES_ROOT';   Short = 'HKCR'; Drive = 'Registry::HKEY_CLASSES_ROOT' }
        [pscustomobject] @{ Long = 'HKEY_USERS';          Short = 'HKU';  Drive = 'Registry::HKEY_USERS' }
        [pscustomobject] @{ Long = 'HKEY_CURRENT_CONFIG'; Short = 'HKCC'; Drive = 'Registry::HKEY_CURRENT_CONFIG' }
    )
}

<#
.SYNOPSIS
    Normalises a key path written any of the usual ways to its long form.

.DESCRIPTION
    Pure. Accepts HKEY_LOCAL_MACHINE\..., HKLM\..., HKLM:\..., and
    Registry::HKEY_LOCAL_MACHINE\...

.OUTPUTS
    System.String, or '' when the root is not a registry root.
#>
function ConvertTo-TkRegistryLongPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Path
    )

    $text = $Path.Trim() -replace '^(Microsoft\.PowerShell\.Core\\)?Registry::', '' -replace '/', '\'

    foreach ($root in (Get-TkRegistryRoot)) {
        foreach ($form in @($root.Long, $root.Short)) {
            if ($text -match ('^{0}:?(\\(?<rest>.*))?$' -f [regex]::Escape($form))) {
                $rest = $Matches['rest']
                if ($rest) { return ('{0}\{1}' -f $root.Long, $rest.TrimEnd('\')) } else { return $root.Long }
            }
        }
    }

    return ''
}

<#
.SYNOPSIS
    Turns hexadecimal byte text ("01,ff,00") into bytes.

.OUTPUTS
    System.Byte[], or $null when the text is not a byte list.
#>
function ConvertFrom-TkRegHexList {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Text = ''
    )

    $parts = @(($Text -replace '\s', '') -split ',' | Where-Object { $_ -ne '' })

    if (@($parts | Where-Object { $_ -notmatch '^[0-9A-Fa-f]{1,2}$' }).Count -gt 0) {
        return $null
    }

    return , [byte[]] @($parts | ForEach-Object { [Convert]::ToByte($_, 16) })
}

<#
.SYNOPSIS
    Reads a .reg file into keys, values and deletions.

.DESCRIPTION
    Pure. Understands the Windows Registry Editor 5.00 and REGEDIT4 formats:
    [key] and [-key], "name"=... and @=..., string values with their \\ and
    \" escapes, dword:, hex: (binary), hex(2): (expandable string), hex(7):
    (multi-string), hex(b): (qword), hex(4): (dword), and "name"=- to delete
    a value; hex lists continued over several lines with a trailing \.

.OUTPUTS
    PSCustomObject with Entries (Action, Key, Name, Type, Value), Errors and
    HasHeader.
#>
function ConvertFrom-TkRegFile {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $errors  = New-Object System.Collections.Generic.List[string]

    # Joined first, so a hex list continued with \ reads as one line.
    $lines   = New-Object System.Collections.Generic.List[string]
    $numbers = New-Object System.Collections.Generic.List[int]
    $pending = ''
    $number  = 0
    $start   = 0

    foreach ($raw in ($Text -split '\r?\n')) {
        $number++
        $line = $raw.TrimEnd()
        if (-not $pending) { $start = $number }

        if ($line.EndsWith('\') -and $line -match '^\s*("|@|[0-9A-Fa-f]{2},)' -and $line -notmatch '^\s*\[') {
            $pending += $line.Substring(0, $line.Length - 1).Trim()
            continue
        }

        $lines.Add($pending + $(if ($pending) { $line.Trim() } else { $line }))
        $numbers.Add($start)
        $pending = ''
    }

    if ($pending) { $lines.Add($pending); $numbers.Add($start) }

    $hasHeader = $false
    $key       = ''

    for ($i = 0; $i -lt $lines.Count; $i++) {

        $line = $lines[$i].Trim()
        $at   = $numbers[$i]

        if (-not $line -or $line.StartsWith(';')) { continue }

        if ($line -eq 'Windows Registry Editor Version 5.00' -or $line -eq 'REGEDIT4') {
            $hasHeader = $true
            continue
        }

        if ($line -match '^\[(?<delete>-)?(?<path>[^\]]+)\]$') {
            $long = ConvertTo-TkRegistryLongPath -Path $Matches['path']
            if (-not $long) {
                $errors.Add(('Line {0}: "{1}" does not start with a registry root.' -f $at, $Matches['path']))
                $key = ''
                continue
            }

            if ($Matches['delete']) {
                $entries.Add([pscustomobject] @{ Action = 'DeleteKey'; Key = $long; Name = ''; Type = ''; Value = $null })
                $key = ''
            }
            else {
                $entries.Add([pscustomobject] @{ Action = 'Key'; Key = $long; Name = ''; Type = ''; Value = $null })
                $key = $long
            }
            continue
        }

        if ($line -notmatch '^(?:"(?<name>(?:[^"\\]|\\.)*)"|(?<default>@))\s*=\s*(?<data>.*)$') {
            $errors.Add(('Line {0}: not a key or a value: {1}' -f $at, $line))
            continue
        }

        if (-not $key) {
            $errors.Add(('Line {0}: a value outside any key.' -f $at))
            continue
        }

        $name = if ($Matches['default']) { '' } else { $Matches['name'] -replace '\\(.)', '$1' }
        $data = $Matches['data'].Trim()

        $value = $null
        $type  = ''

        if ($data -eq '-') {
            $entries.Add([pscustomobject] @{ Action = 'DeleteValue'; Key = $key; Name = $name; Type = ''; Value = $null })
            continue
        }
        elseif ($data -match '^"(?<s>(?:[^"\\]|\\.)*)"$') {
            $type  = 'REG_SZ'
            $value = $Matches['s'] -replace '\\(.)', '$1'
        }
        elseif ($data -match '^dword:(?<d>[0-9A-Fa-f]{1,8})$') {
            $type  = 'REG_DWORD'
            $value = [Convert]::ToUInt32($Matches['d'], 16)
        }
        elseif ($data -match '^hex(?:\((?<kind>[0-9A-Fa-f]+)\))?:(?<bytes>.*)$') {
            $kind  = if ($Matches['kind']) { $Matches['kind'].ToLowerInvariant() } else { '3' }
            $bytes = ConvertFrom-TkRegHexList -Text $Matches['bytes']

            if ($null -eq $bytes) {
                $errors.Add(('Line {0}: "{1}" has a byte list that is not hexadecimal.' -f $at, $name))
                continue
            }

            # A flag rather than continue: inside a switch, continue only
            # leaves the switch, and the bad value would still be added.
            $problem = ''

            switch ($kind) {
                '3' { $type = 'REG_BINARY'; $value = $bytes }
                '2' { $type = 'REG_EXPAND_SZ'; $value = [System.Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char] 0) }
                '7' {
                    $type  = 'REG_MULTI_SZ'
                    $value = @([System.Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char] 0) -split [char] 0)
                    if ($value.Count -eq 1 -and $value[0] -eq '') { $value = @() }
                }
                'b' {
                    if ($bytes.Length -ne 8) { $problem = 'is a qword without 8 bytes'; break }
                    $type  = 'REG_QWORD'
                    $value = [BitConverter]::ToUInt64($bytes, 0)
                }
                '4' {
                    if ($bytes.Length -ne 4) { $problem = 'is a dword without 4 bytes'; break }
                    $type  = 'REG_DWORD'
                    $value = [BitConverter]::ToUInt32($bytes, 0)
                }
                '1' { $type = 'REG_SZ'; $value = [System.Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char] 0) }
                default { $problem = ('has a value type hex({0}) that PowerShell cannot write' -f $kind) }
            }

            if ($problem) {
                $errors.Add(('Line {0}: "{1}" {2}.' -f $at, $name, $problem))
                continue
            }
        }
        else {
            $errors.Add(('Line {0}: the value of "{1}" is not in a form a .reg file uses.' -f $at, $name))
            continue
        }

        $entries.Add([pscustomobject] @{ Action = 'Value'; Key = $key; Name = $name; Type = $type; Value = $value })
    }

    return [pscustomobject] @{ Entries = @($entries.ToArray()); Errors = @($errors.ToArray()); HasHeader = $hasHeader }
}

<#
.SYNOPSIS
    Writes registry entries as PowerShell.

.DESCRIPTION
    Pure. A key is created only when it is missing: New-Item -Force on a
    registry key that exists would empty it. Values are written with
    New-ItemProperty -Force, which replaces a value of any type.

.OUTPUTS
    System.String[]
#>
function ConvertTo-TkRegPowerShell {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Entry = @()
    )

    $quote = { param($text) "'" + ([string] $text -replace "'", "''") + "'" }
    $drive = {
        param($long)
        foreach ($root in (Get-TkRegistryRoot)) {
            if ($long -eq $root.Long) { return $root.Drive }
            if ($long.StartsWith($root.Long + '\')) { return ('{0}\{1}' -f $root.Drive, $long.Substring($root.Long.Length + 1)) }
        }
        return $long
    }

    $lines = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Entry) {

        $path = & $quote (& $drive $item.Key)

        switch ($item.Action) {

            'Key'       { $lines.Add(('if (-not (Test-Path -LiteralPath {0})) {{ New-Item -Path {0} -Force | Out-Null }}' -f $path)) }
            'DeleteKey' { $lines.Add(('Remove-Item -LiteralPath {0} -Recurse -Force -ErrorAction SilentlyContinue' -f $path)) }

            'DeleteValue' {
                $name = if ($item.Name) { & $quote $item.Name } else { "'(default)'" }
                $lines.Add(('Remove-ItemProperty -LiteralPath {0} -Name {1} -ErrorAction SilentlyContinue' -f $path, $name))
            }

            'Value' {
                $name = if ($item.Name) { & $quote $item.Name } else { "'(default)'" }

                $pair = switch ($item.Type) {
                    'REG_SZ'        { 'String',       (& $quote $item.Value) }
                    'REG_EXPAND_SZ' { 'ExpandString', (& $quote $item.Value) }
                    'REG_DWORD'     { 'DWord',        ('0x{0:X8}' -f [uint32] $item.Value) }
                    'REG_QWORD'     { 'QWord',        ('0x{0:X16}' -f [uint64] $item.Value) }
                    'REG_BINARY'    { 'Binary',       ('([byte[]] ({0}))' -f ((@($item.Value) | ForEach-Object { '0x{0:X2}' -f $_ }) -join ',')) }
                    'REG_MULTI_SZ'  { 'MultiString',  ('@({0})' -f ((@($item.Value) | ForEach-Object { & $quote $_ }) -join ', ')) }
                }

                $lines.Add(('New-ItemProperty -LiteralPath {0} -Name {1} -PropertyType {2} -Value {3} -Force | Out-Null' -f $path, $name, $pair[0], $pair[1]))
            }
        }
    }

    return @($lines.ToArray())
}

<#
.SYNOPSIS
    Writes registry entries as reg.exe commands, for a batch file, a GPO or an Intune script.

.OUTPUTS
    System.String[]
#>
function ConvertTo-TkRegCommand {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Entry = @()
    )

    $short = {
        param($long)
        foreach ($root in (Get-TkRegistryRoot)) {
            if ($long -eq $root.Long) { return $root.Short }
            if ($long.StartsWith($root.Long + '\')) { return ('{0}\{1}' -f $root.Short, $long.Substring($root.Long.Length + 1)) }
        }
        return $long
    }

    # reg.exe reads \" as a quote, and a backslash just before the closing
    # quote would escape it, so a trailing backslash is doubled.
    $quote = {
        param($text)
        $inner = ([string] $text) -replace '"', '\"'
        if ($inner.EndsWith('\')) { $inner += '\' }
        '"' + $inner + '"'
    }

    $lines = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Entry) {

        $key = & $quote (& $short $item.Key)
        $who = if ($item.Name) { '/v {0}' -f (& $quote $item.Name) } else { '/ve' }

        switch ($item.Action) {
            'Key'         { $lines.Add(('reg add {0} /f' -f $key)) }
            'DeleteKey'   { $lines.Add(('reg delete {0} /f' -f $key)) }
            'DeleteValue' { $lines.Add(('reg delete {0} {1} /f' -f $key, $who)) }
            'Value' {
                $data = switch ($item.Type) {
                    'REG_SZ'        { & $quote $item.Value }
                    'REG_EXPAND_SZ' { & $quote $item.Value }
                    'REG_DWORD'     { '0x{0:X}' -f [uint32] $item.Value }
                    'REG_QWORD'     { '0x{0:X}' -f [uint64] $item.Value }
                    'REG_BINARY'    { (@($item.Value) | ForEach-Object { '{0:X2}' -f $_ }) -join '' }
                    'REG_MULTI_SZ'  { & $quote ((@($item.Value)) -join '\0') }
                }

                $dataPart = if ('' -eq $data) { '' } else { ' /d {0}' -f $data }
                $lines.Add(('reg add {0} {1} /t {2}{3} /f' -f $key, $who, $item.Type, $dataPart))
            }
        }
    }

    return @($lines.ToArray())
}

<#
.SYNOPSIS
    Reads the registry commands of a PowerShell script, without running it.

.DESCRIPTION
    Pure. The script is parsed, never run. New-Item, New-ItemProperty,
    Set-ItemProperty, Remove-Item and Remove-ItemProperty on registry paths
    are read; a value is taken only when it is a literal (a number, a
    string, an array of them, or a [byte[]] cast of numbers). Anything else
    is reported. Without -PropertyType, the type is the one Set-ItemProperty
    would give: DWord for a number, QWord for a large one, MultiString for
    an array of strings, Binary for bytes.

.OUTPUTS
    PSCustomObject with Entries and Errors.
#>
function ConvertFrom-TkRegPowerShell {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Script
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $errors  = New-Object System.Collections.Generic.List[string]

    $tokens      = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Script, [ref] $tokens, [ref] $parseErrors)

    if (@($parseErrors).Count -gt 0) {
        return [pscustomobject] @{ Entries = @(); Errors = @(('The script does not parse: {0}' -f $parseErrors[0].Message)); }
    }

    # A literal only: no variable but $true, $false and $null, nothing run.
    $literal = {
        param($node)

        $variables = @($node.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
                       Where-Object { @('true', 'false', 'null') -notcontains $_.VariablePath.UserPath })

        if ($variables.Count -gt 0) { throw 'computed' }

        $inner = $node
        while ($inner -is [System.Management.Automation.Language.ParenExpressionAst]) { $inner = $inner.Pipeline.PipelineElements[0].Expression }

        if ($inner -is [System.Management.Automation.Language.ConvertExpressionAst] -and $inner.Type.TypeName.FullName -match '^(System\.)?Byte\[\]$') {
            return , [byte[]] @($inner.Child.SafeGetValue())
        }

        return $inner.SafeGetValue()
    }

    foreach ($command in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {

        $verb = [string] $command.GetCommandName()

        if (@('New-Item', 'New-ItemProperty', 'Set-ItemProperty', 'Remove-Item', 'Remove-ItemProperty') -notcontains $verb) {
            continue
        }

        # Named parameters, and the first positional one as the path.
        $named      = @{}
        $positional = New-Object System.Collections.Generic.List[object]
        $elements   = $command.CommandElements

        for ($i = 1; $i -lt $elements.Count; $i++) {
            $element = $elements[$i]
            if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
                $argument = $element.Argument
                if (-not $argument -and $i + 1 -lt $elements.Count -and $elements[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) {
                    $argument = $elements[$i + 1]
                    $i++
                }
                $named[$element.ParameterName.ToLowerInvariant()] = $argument
            }
            else {
                $positional.Add($element)
            }
        }

        $read = {
            param($keys)
            foreach ($k in $keys) { if ($named.ContainsKey($k) -and $named[$k]) { return (& $literal $named[$k]) } }
            return $null
        }

        $where = $command.Extent.StartLineNumber

        try {
            $pathValue = & $read @('literalpath', 'path')
            if ($null -eq $pathValue -and $positional.Count -gt 0) { $pathValue = & $literal $positional[0] }

            $long = ConvertTo-TkRegistryLongPath -Path ([string] $pathValue)
            if (-not $long) {
                $errors.Add(('Line {0}: {1} is not on a registry path.' -f $where, $verb))
                continue
            }

            $name = [string] (& $read @('name'))
            if ($name -eq '(default)') { $name = '' }

            switch ($verb) {
                'New-Item'            { $entries.Add([pscustomobject] @{ Action = 'Key'; Key = $long; Name = ''; Type = ''; Value = $null }) }
                'Remove-Item'         { $entries.Add([pscustomobject] @{ Action = 'DeleteKey'; Key = $long; Name = ''; Type = ''; Value = $null }) }
                'Remove-ItemProperty' { $entries.Add([pscustomobject] @{ Action = 'DeleteValue'; Key = $long; Name = $name; Type = ''; Value = $null }) }

                default {
                    $value = & $read @('value')
                    $kind  = [string] (& $read @('propertytype', 'type'))

                    $type = switch -Regex ($kind) {
                        '^String$'       { 'REG_SZ' }
                        '^ExpandString$' { 'REG_EXPAND_SZ' }
                        '^DWord$'        { 'REG_DWORD' }
                        '^QWord$'        { 'REG_QWORD' }
                        '^Binary$'       { 'REG_BINARY' }
                        '^MultiString$'  { 'REG_MULTI_SZ' }
                        '^$' {
                            if ($value -is [byte[]]) { 'REG_BINARY' }
                            elseif ($value -is [array]) { 'REG_MULTI_SZ' }
                            elseif ($value -is [long] -or $value -is [uint64]) { 'REG_QWORD' }
                            elseif ($value -is [int] -or $value -is [uint32]) { 'REG_DWORD' }
                            else { 'REG_SZ' }
                        }
                        default { '' }
                    }

                    if (-not $type) {
                        $errors.Add(('Line {0}: the type {1} has no .reg form.' -f $where, $kind))
                        break
                    }

                    $typed = switch ($type) {
                        # 0xFFFFFFFF reads as -1 in PowerShell: keep the low 32 bits.
                        'REG_DWORD'    { [uint32] ([int64] $value -band [int64] 4294967295) }
                        'REG_QWORD'    { [uint64] [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64] $value), 0) }
                        'REG_BINARY'   { , [byte[]] @($value) }
                        'REG_MULTI_SZ' { , [string[]] @($value) }
                        default        { [string] $value }
                    }

                    $entries.Add([pscustomobject] @{ Action = 'Value'; Key = $long; Name = $name; Type = $type; Value = $typed })
                }
            }
        }
        catch {
            $errors.Add(('Line {0}: {1} uses a value that is computed or does not fit its type; only literal values can be converted.' -f $where, $verb))
        }
    }

    return [pscustomobject] @{ Entries = @($entries.ToArray()); Errors = @($errors.ToArray()) }
}

<#
.SYNOPSIS
    Writes registry entries as a .reg file.

.OUTPUTS
    System.String
#>
function ConvertTo-TkRegFileText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Entry = @()
    )

    $escape = { param($text) ([string] $text) -replace '\\', '\\' -replace '"', '\"' }
    $hex    = { param([byte[]] $bytes) (@($bytes) | ForEach-Object { '{0:x2}' -f $_ }) -join ',' }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Windows Registry Editor Version 5.00')

    $current = $null

    foreach ($item in $Entry) {

        if ($item.Action -eq 'DeleteKey') {
            $lines.Add('')
            $lines.Add(('[-{0}]' -f $item.Key))
            $current = $null
            continue
        }

        if ($item.Key -ne $current) {
            $lines.Add('')
            $lines.Add(('[{0}]' -f $item.Key))
            $current = $item.Key
        }

        if ($item.Action -eq 'Key') { continue }

        $name = if ($item.Name) { '"{0}"' -f (& $escape $item.Name) } else { '@' }

        if ($item.Action -eq 'DeleteValue') {
            $lines.Add(('{0}=-' -f $name))
            continue
        }

        $data = switch ($item.Type) {
            'REG_SZ'        { '"{0}"' -f (& $escape $item.Value) }
            'REG_DWORD'     { 'dword:{0:x8}' -f [uint32] $item.Value }
            'REG_QWORD'     { 'hex(b):{0}' -f (& $hex ([BitConverter]::GetBytes([uint64] $item.Value))) }
            'REG_BINARY'    { 'hex:{0}' -f (& $hex ([byte[]] @($item.Value))) }
            'REG_EXPAND_SZ' { 'hex(2):{0}' -f (& $hex ([System.Text.Encoding]::Unicode.GetBytes([string] $item.Value + [char] 0))) }
            'REG_MULTI_SZ'  { 'hex(7):{0}' -f (& $hex ([System.Text.Encoding]::Unicode.GetBytes(((@($item.Value) | ForEach-Object { [string] $_ + [char] 0 }) -join '') + [char] 0))) }
        }

        $lines.Add(('{0}={1}' -f $name, $data))
    }

    return (($lines -join "`r`n") + "`r`n")
}

<#
.SYNOPSIS
    Converts in one direction and lays out the result for the panel.

.PARAMETER Text
    The .reg file or the PowerShell script.

.PARAMETER Direction
    RegToPowerShell or PowerShellToReg.

.OUTPUTS
    System.String
#>
function Format-TkRegConversion {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [ValidateSet('RegToPowerShell', 'PowerShellToReg')] [string] $Direction
    )

    if (-not $Text.Trim()) {
        return $(if ($Direction -eq 'RegToPowerShell') { 'Paste the content of a .reg file.' } else { 'Paste PowerShell registry commands (New-ItemProperty, Set-ItemProperty, Remove-Item...).' })
    }

    $lines = New-Object System.Collections.Generic.List[string]

    if ($Direction -eq 'RegToPowerShell') {
        $parsed = ConvertFrom-TkRegFile -Text $Text

        if (-not $parsed.HasHeader) {
            $lines.Add('Note: the "Windows Registry Editor Version 5.00" line is missing; regedit would refuse to import this file.')
        }
        foreach ($problem in $parsed.Errors) { $lines.Add(('Skipped: {0}' -f $problem)) }
        if ($lines.Count -gt 0) { $lines.Add('') }

        if (@($parsed.Entries).Count -eq 0) {
            $lines.Add('Nothing to convert.')
            return ($lines -join [Environment]::NewLine)
        }

        $lines.Add('# PowerShell (elevated for HKLM)')
        foreach ($line in (ConvertTo-TkRegPowerShell -Entry $parsed.Entries)) { $lines.Add($line) }
        $lines.Add('')
        $lines.Add(':: reg.exe (a .cmd file, a GPO or an Intune script; in a .cmd file write each % as %%)')
        foreach ($line in (ConvertTo-TkRegCommand -Entry $parsed.Entries)) { $lines.Add($line) }
    }
    else {
        $parsed = ConvertFrom-TkRegPowerShell -Script $Text

        foreach ($problem in $parsed.Errors) { $lines.Add(('Skipped: {0}' -f $problem)) }
        if ($lines.Count -gt 0) { $lines.Add('') }

        if (@($parsed.Entries).Count -eq 0) {
            $lines.Add('No registry command with literal values was found.')
            return ($lines -join [Environment]::NewLine)
        }

        $lines.Add((ConvertTo-TkRegFileText -Entry $parsed.Entries).TrimEnd())
    }

    return ($lines -join [Environment]::NewLine)
}
