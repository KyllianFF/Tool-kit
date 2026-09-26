<#
    Toolkit - Features / WMI and CIM query builder

    The WMI query, written for you. Pick a class, choose the properties, add the
    conditions one per line as "property operator value", and the tool composes
    the WQL and the three ways an administrator runs it: Get-CimInstance with a
    filter, Get-CimInstance with a query, and the old wmic command line.

    It quotes the string values and leaves the numbers alone, maps != to the <>
    that WQL wants, and keeps a namespace other than root\cimv2 in every form.
    Nothing is queried here; it only writes the commands.
#>

<#
.SYNOPSIS
    Common CIM classes, to fill the class box from a list.

.OUTPUTS
    PSCustomObject[] with Name and Note.
#>
function Get-TkWmiClass {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'Win32_OperatingSystem';          Note = 'The operating system: version, boot time, memory.' }
        [pscustomobject] @{ Name = 'Win32_ComputerSystem';           Note = 'The machine: model, manufacturer, domain, memory.' }
        [pscustomobject] @{ Name = 'Win32_BIOS';                     Note = 'Firmware: vendor, version, serial number.' }
        [pscustomobject] @{ Name = 'Win32_Processor';                Note = 'The CPUs: name, cores, speed.' }
        [pscustomobject] @{ Name = 'Win32_PhysicalMemory';           Note = 'The memory modules: size, speed, slot.' }
        [pscustomobject] @{ Name = 'Win32_DiskDrive';                Note = 'The physical disks: model, size, interface.' }
        [pscustomobject] @{ Name = 'Win32_LogicalDisk';              Note = 'The volumes: drive letter, size, free space.' }
        [pscustomobject] @{ Name = 'Win32_NetworkAdapter';           Note = 'The network adapters, physical and virtual.' }
        [pscustomobject] @{ Name = 'Win32_NetworkAdapterConfiguration'; Note = 'IP configuration per adapter.' }
        [pscustomobject] @{ Name = 'Win32_Service';                  Note = 'The services: state, start mode, account.' }
        [pscustomobject] @{ Name = 'Win32_Process';                  Note = 'The running processes.' }
        [pscustomobject] @{ Name = 'Win32_StartupCommand';           Note = 'What runs at sign-in.' }
        [pscustomobject] @{ Name = 'Win32_Product';                  Note = 'Installed MSI products (slow to enumerate).' }
        [pscustomobject] @{ Name = 'Win32_QuickFixEngineering';      Note = 'Installed hotfixes and updates.' }
        [pscustomobject] @{ Name = 'Win32_UserAccount';              Note = 'Local and domain user accounts.' }
        [pscustomobject] @{ Name = 'Win32_Group';                    Note = 'Local and domain groups.' }
        [pscustomobject] @{ Name = 'Win32_PnPEntity';                Note = 'Plug and Play devices.' }
        [pscustomobject] @{ Name = 'Win32_LogonSession';             Note = 'Active logon sessions.' }
    )
}

<#
.SYNOPSIS
    Turns one "property operator value" line into a WQL predicate.

.DESCRIPTION
    Operators: = , != or <> (not equal), < > <= >= , and LIKE (with % as the
    wildcard). A number is left bare; anything else is quoted, its quotes and
    backslashes escaped. Surrounding quotes the user typed are taken off first.
    A line starting with # is a comment.

.OUTPUTS
    System.String, or $null when the line is blank, a comment or unparseable.
#>
function ConvertTo-TkWqlCondition {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Line
    )

    $text = $Line.Trim()

    if ($text.Length -eq 0 -or $text.StartsWith('#')) {
        return $null
    }

    if ($text -notmatch '^(?<prop>\w+)\s*(?<op><=|>=|<>|!=|=|<|>|[Ll][Ii][Kk][Ee])\s*(?<val>.*)$') {
        return $null
    }

    $prop = $Matches['prop']
    $op   = $Matches['op']
    $val  = $Matches['val'].Trim()

    if ($val.Length -eq 0) {
        return $null
    }

    # A not-equal is spelled <> in WQL; LIKE is upper-cased.
    $operator = switch -Regex ($op) {
        '^(!=|<>)$'          { '<>'; break }
        '^[Ll][Ii][Kk][Ee]$' { 'LIKE'; break }
        default              { $op }
    }

    # Strip a pair of quotes the user may have typed around the value.
    if ($val.Length -ge 2 -and
        (($val[0] -eq '"' -and $val[$val.Length - 1] -eq '"') -or
         ($val[0] -eq "'" -and $val[$val.Length - 1] -eq "'"))) {
        $val = $val.Substring(1, $val.Length - 2)
    }

    $isNumber = ($operator -ne 'LIKE') -and ($val -match '^-?\d+(\.\d+)?$')

    if ($isNumber) {
        $literal = $val
    }
    else {
        $escaped = $val -replace '\\', '\\' -replace "'", "\'"
        $literal = "'" + $escaped + "'"
    }

    return ('{0} {1} {2}' -f $prop, $operator, $literal)
}

<#
.SYNOPSIS
    Joins the parsed predicates into a WQL WHERE body.

.OUTPUTS
    System.String, empty when there are no conditions.
#>
function Build-TkWqlWhere {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Conditions = @(),

        [Parameter()]
        [ValidateSet('All', 'Any')]
        [string] $Match = 'All'
    )

    $predicates = @($Conditions | Where-Object { $_ })

    if ($predicates.Count -eq 0) {
        return ''
    }

    $joiner = if ($Match -eq 'Any') { ' OR ' } else { ' AND ' }

    return ($predicates -join $joiner)
}

<#
.SYNOPSIS
    Builds the CIM and WMI commands for a class, its properties and conditions.

.PARAMETER ClassName
    The CIM class, for example Win32_Service.

.PARAMETER Namespace
    The WMI namespace. root\cimv2 is the default and is left implicit.

.PARAMETER Properties
    A comma separated list, or * for all.

.PARAMETER Conditions
    The conditions text, one per line.

.PARAMETER Match
    All (AND) or Any (OR).

.OUTPUTS
    System.String[]
#>
function Format-TkWmiReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $ClassName,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Namespace = 'root\cimv2',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Properties = '*',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Conditions = '',

        [Parameter()]
        [ValidateSet('All', 'Any')]
        [string] $Match = 'All'
    )

    $class = $ClassName.Trim()

    if ($class.Length -eq 0) {
        return @('Pick or type a CIM class (for example Win32_Service) to build the query.')
    }

    $namespaceValue = $Namespace.Trim()
    $isDefaultNs    = ($namespaceValue.Length -eq 0) -or ($namespaceValue -ieq 'root\cimv2')

    # The property list, or nothing when it is * or empty.
    $propertyList = @($Properties -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '*' })
    $propText     = if ($propertyList.Count -gt 0) { $propertyList -join ',' } else { '*' }

    # The conditions, parsed, with the unparseable ones set aside.
    $predicates = New-Object System.Collections.Generic.List[string]
    $invalid    = New-Object System.Collections.Generic.List[string]
    $number     = 0

    foreach ($line in ($Conditions -split '\r?\n')) {

        $number++
        $trimmed = $line.Trim()

        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
            continue
        }

        $predicate = ConvertTo-TkWqlCondition -Line $line

        if ($predicate) {
            $predicates.Add($predicate)
        }
        else {
            $invalid.Add(('L{0,-3} not "property operator value": {1}' -f $number, $trimmed))
        }
    }

    $where = Build-TkWqlWhere -Conditions $predicates.ToArray() -Match $Match

    $lines = New-Object System.Collections.Generic.List[string]

    # --- Get-CimInstance with a filter ---
    $cim = New-Object System.Text.StringBuilder
    [void] $cim.Append(('Get-CimInstance -ClassName {0}' -f $class))
    if (-not $isDefaultNs) { [void] $cim.Append((' -Namespace {0}' -f $namespaceValue)) }
    if ($where) { [void] $cim.Append((' -Filter "{0}"' -f $where)) }
    if ($propertyList.Count -gt 0) { [void] $cim.Append((' -Property {0}' -f $propText)) }
    if ($propertyList.Count -gt 0) { [void] $cim.Append((' | Select-Object {0}' -f $propText)) }

    $lines.Add('PowerShell (Get-CimInstance):')
    $lines.Add(('  {0}' -f $cim.ToString()))
    $lines.Add('')

    # --- WQL ---
    $wql = 'SELECT {0} FROM {1}' -f $propText, $class
    if ($where) { $wql = '{0} WHERE {1}' -f $wql, $where }

    $lines.Add('WQL:')
    $lines.Add(('  {0}' -f $wql))
    $lines.Add('')

    $lines.Add('PowerShell (Get-CimInstance -Query):')
    if ($isDefaultNs) {
        $lines.Add(('  Get-CimInstance -Query "{0}"' -f ($wql -replace '"', '""')))
    }
    else {
        $lines.Add(('  Get-CimInstance -Namespace {0} -Query "{1}"' -f $namespaceValue, ($wql -replace '"', '""')))
    }
    $lines.Add('')

    # --- wmic ---
    $wmic = New-Object System.Text.StringBuilder
    [void] $wmic.Append('wmic')
    if (-not $isDefaultNs) { [void] $wmic.Append((' /namespace:\\{0}' -f $namespaceValue)) }
    [void] $wmic.Append((' path {0}' -f $class))
    if ($where) { [void] $wmic.Append((' where "{0}"' -f $where)) }
    [void] $wmic.Append((' get {0}' -f $(if ($propertyList.Count -gt 0) { $propText -replace ',', ', ' } else { '*' })))

    $lines.Add('Command line (wmic, deprecated):')
    $lines.Add(('  {0}' -f $wmic.ToString()))

    if ($invalid.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Ignored lines:')
        foreach ($bad in $invalid) { $lines.Add(('  {0}' -f $bad)) }
    }

    return $lines.ToArray()
}
