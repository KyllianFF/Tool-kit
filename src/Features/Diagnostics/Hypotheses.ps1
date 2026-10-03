<#
    Toolkit - Features / Diagnosis by explainable rules

    Each report judges its own field. Putting them together - three blue
    screens, and a driver installed two days before the first - is what an
    experienced technician does in their head. This file does it from rules
    written as data (data/diagnosis-rules.json, docs/DIAGNOSIS-RULES.md):
    each rule names the reports it reads, the conditions on their data, the
    hypothesis it supports and how confident it is, the evidence to show and
    the next step.

    The evaluator is deliberately small: a closed list of operators, field
    paths, counts, and times relative to the document or to another match.
    A rule is never code, nothing is run by a rule, and every conclusion
    comes with the evidence it rests on. A rule whose reports are missing is
    said "not evaluated", never "no problem".
#>

<#
.SYNOPSIS
    The operators a rule may use, and nothing else.
#>
function Get-TkRuleOperator {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @('eq', 'ne', 'gt', 'ge', 'lt', 'le', 'like', 'notlike', 'in', 'contains', 'exists', 'within', 'olderthan', 'before', 'after')
}

<#
.SYNOPSIS
    The diagnosis rules, from their catalog.
#>
function Get-TkHypothesisRule {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $catalog = Import-TkCatalog -Name 'diagnosis-rules'

    if (-not $catalog) {
        return @()
    }

    return @($catalog.rules | Where-Object { $_ })
}

<#
.SYNOPSIS
    Reads a value along a dotted path, through dictionaries and objects.

.DESCRIPTION
    Pure. A report document read from a file is made of dictionaries; one
    built in memory, or a test's, may hold objects. Both are read the same
    way. A missing step gives null.
#>
function Get-TkRulePath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Data,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Path
    )

    $node = $Data

    foreach ($part in @($Path -split '\.' | Where-Object { $_ })) {

        if ($null -eq $node) {
            return $null
        }

        if ($node -is [System.Collections.IDictionary]) {
            $node = if ($node.Contains($part)) { $node[$part] } else { $null }
        }
        elseif ($node.PSObject -and $node.PSObject.Properties[$part]) {
            $node = $node.PSObject.Properties[$part].Value
        }
        else {
            return $null
        }
    }

    return $node
}

<#
.SYNOPSIS
    A value as a moment in time, or null when it is not one.

.DESCRIPTION
    Pure. A date, or a text written as an ISO 8601 date, as the report
    documents write them. Any other text is not taken for a date, so a
    number or a label never compares as one.
#>
function ConvertTo-TkRuleDate {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($Value -is [datetime]) {
        return $Value
    }

    if ($Value -is [datetimeoffset]) {
        return $Value.LocalDateTime
    }

    $text = [string] $Value

    if ($text -notmatch '^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}.*)?$') {
        return $null
    }

    $parsed = [datetime]::MinValue

    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $parsed)) {
        if ($parsed.Kind -eq [System.DateTimeKind]::Utc) { return $parsed.ToLocalTime() }
        return $parsed
    }

    return $null
}

<#
.SYNOPSIS
    A value as a number, or null when it is not one.
#>
function ConvertTo-TkRuleNumber {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or $Value -is [bool]) {
        return $null
    }

    $number = 0.0

    if ([double]::TryParse([string] $Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref] $number)) {
        return $number
    }

    return $null
}

<#
.SYNOPSIS
    Says whether two values are equal the way a rule means it.

.DESCRIPTION
    Pure. A boolean is compared as a boolean, a number as a number, and
    anything else as text, ignoring case.
#>
function Test-TkRuleEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowNull()] $Actual,
        [Parameter()] [AllowNull()] $Expected
    )

    if ($null -eq $Actual -or $null -eq $Expected) {
        return ($null -eq $Actual -and $null -eq $Expected)
    }

    if ($Expected -is [bool]) {
        $flag = $false
        if ($Actual -is [bool]) { return ($Actual -eq $Expected) }
        if ([bool]::TryParse([string] $Actual, [ref] $flag)) { return ($flag -eq $Expected) }
        return $false
    }

    $left  = ConvertTo-TkRuleNumber -Value $Actual
    $right = ConvertTo-TkRuleNumber -Value $Expected

    if ($null -ne $left -and $null -ne $right) {
        return ($left -eq $right)
    }

    return ([string]::Equals([string] $Actual, [string] $Expected, [System.StringComparison]::OrdinalIgnoreCase))
}

<#
.SYNOPSIS
    Evaluates one condition of a rule on one value.

.DESCRIPTION
    Pure. Dates are judged against Now, the moment the document was
    collected, so an old snapshot is read as it was. "before" and "after"
    compare with the earliest moment of an earlier match ("of", read in its
    field "at"): within that many days before it, or after it.

.PARAMETER Binding
    The earlier matches of the rule, by name.

.OUTPUTS
    System.Boolean
#>
function Test-TkRuleCondition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory)]
        $Condition,

        [Parameter()]
        [hashtable] $Binding = @{},

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $op       = ([string] (Get-TkRulePath -Data $Condition -Path 'op')).ToLowerInvariant()
    $expected = Get-TkRulePath -Data $Condition -Path 'value'
    $days     = ConvertTo-TkRuleNumber -Value (Get-TkRulePath -Data $Condition -Path 'days')

    switch ($op) {

        'exists'   { return ($null -ne $Value -and [string] $Value -ne '') }
        'eq'       { return (Test-TkRuleEqual -Actual $Value -Expected $expected) }
        'ne'       { return -not (Test-TkRuleEqual -Actual $Value -Expected $expected) }
        'like'     { return ($null -ne $Value -and ([string] $Value) -like ([string] $expected)) }
        'notlike'  { return -not ($null -ne $Value -and ([string] $Value) -like ([string] $expected)) }
        'in'       { return (@(@($expected) | Where-Object { Test-TkRuleEqual -Actual $Value -Expected $_ }).Count -gt 0) }

        'contains' {
            if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and $Value -isnot [System.Collections.IDictionary]) {
                return (@(@($Value) | Where-Object { Test-TkRuleEqual -Actual $_ -Expected $expected }).Count -gt 0)
            }
            return ($null -ne $Value -and ([string] $Value).IndexOf([string] $expected, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        }

        { $_ -in @('gt', 'ge', 'lt', 'le') } {
            $left  = ConvertTo-TkRuleNumber -Value $Value
            $right = ConvertTo-TkRuleNumber -Value $expected
            if ($null -eq $left -or $null -eq $right) { return $false }
            switch ($op) {
                'gt' { return ($left -gt $right) }
                'ge' { return ($left -ge $right) }
                'lt' { return ($left -lt $right) }
                'le' { return ($left -le $right) }
            }
        }

        { $_ -in @('within', 'olderthan') } {
            $when = ConvertTo-TkRuleDate -Value $Value
            if ($null -eq $when -or $null -eq $days) { return $false }
            $limit = $Now.AddDays(-$days)
            if ($op -eq 'within') { return ($when -ge $limit -and $when -le $Now.AddMinutes(5)) }
            return ($when -lt $limit)
        }

        { $_ -in @('before', 'after') } {
            $when  = ConvertTo-TkRuleDate -Value $Value
            $of    = [string] (Get-TkRulePath -Data $Condition -Path 'of')
            $at    = [string] (Get-TkRulePath -Data $Condition -Path 'at')
            if ($null -eq $when -or $null -eq $days -or -not $of -or -not $Binding.ContainsKey($of)) { return $false }

            $marks = @(@($Binding[$of]) | ForEach-Object { ConvertTo-TkRuleDate -Value $(if ($at) { Get-TkRulePath -Data $_ -Path $at } else { $_ }) } | Where-Object { $_ } | Sort-Object)
            if ($marks.Count -eq 0) { return $false }

            $first = [datetime] $marks[0]
            if ($op -eq 'before') { return ($when -le $first -and $when -ge $first.AddDays(-$days)) }
            return ($when -ge $first -and $when -le $first.AddDays($days))
        }
    }

    throw ('"{0}" is not an operator a rule may use.' -f $op)
}

<#
.SYNOPSIS
    The data a rule path points at in a report document.

.DESCRIPTION
    The first part of the path is the report, the rest a path in its Data:
    "Crashes.Crashes" is the Crashes array of the Crashes report, "Storage"
    the whole Data of the Storage report.
#>
function Get-TkRuleData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Document,
        [Parameter(Mandatory)] [string] $Path
    )

    $parts = $Path -split '\.', 2
    $data  = Get-TkRulePath -Data $Document -Path ('Reports.{0}.Data' -f $parts[0])

    if ($parts.Count -gt 1) {
        return (Get-TkRulePath -Data $data -Path $parts[1])
    }

    return $data
}

<#
.SYNOPSIS
    Writes a value for the evidence: a date as a date, a list as a list.
#>
function Format-TkRuleValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $when = ConvertTo-TkRuleDate -Value $Value
    if ($when) {
        return $when.ToString('yyyy-MM-dd HH:mm')
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and $Value -isnot [System.Collections.IDictionary]) {
        return ((@($Value) | ForEach-Object { Format-TkRuleValue -Value $_ }) -join '; ')
    }

    return [string] $Value
}

<#
.SYNOPSIS
    Evaluates one rule on a report document.

.DESCRIPTION
    Pure. Not evaluated when a report it reads was not collected, was skipped
    or failed: the reason is given, and nothing is concluded either way.
    Otherwise each match is taken in order; a match on a list counts the
    items that meet all its conditions (at least one, unless the rule says
    otherwise) and keeps them for the evidence and for the matches after it.

.OUTPUTS
    PSCustomObject with Id, Title, Explanation, Confidence, Status
    (Matched, NotMatched, NotEvaluated), Reason, Evidence and Action.
#>
function Invoke-TkHypothesisRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] $Document,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $field = { param($name) Get-TkRulePath -Data $Rule -Path $name }
    $make  = {
        param($status, $reason, $evidence)
        [pscustomobject] @{
            Id          = [string] (& $field 'id')
            Title       = [string] (& $field 'title')
            Explanation = [string] (& $field 'explanation')
            Confidence  = [string] (& $field 'confidence')
            Status      = $status
            Reason      = $reason
            Evidence    = @($evidence)
            Action      = [pscustomobject] @{
                Advice = [string] (& $field 'action.advice')
                Report = [string] (& $field 'action.report')
                Fix    = [string] (& $field 'action.fix')
                Topic  = [string] (& $field 'action.topic')
            }
        }
    }

    foreach ($name in @(& $field 'reports')) {
        $report = Get-TkRulePath -Data $Document -Path ('Reports.{0}' -f $name)
        $status = [string] (Get-TkRulePath -Data $report -Path 'Status')

        if (-not $report) {
            return (& $make 'NotEvaluated' ('{0} was not collected.' -f $name) @())
        }

        if ($status -ne 'Ok') {
            return (& $make 'NotEvaluated' ('{0} {1}: {2}' -f $name, $(if ($status -eq 'Skipped') { 'was skipped' } else { 'failed' }), (Get-TkRulePath -Data $report -Path 'Reason')) @())
        }
    }

    $binding = @{}

    foreach ($match in @(& $field 'match')) {

        $from = [string] (Get-TkRulePath -Data $match -Path 'from')
        $as   = [string] (Get-TkRulePath -Data $match -Path 'as')

        if ($from) {

            $hits = New-Object System.Collections.Generic.List[object]

            foreach ($item in @(Get-TkRuleData -Document $Document -Path $from)) {
                $meets = $true
                foreach ($condition in @(Get-TkRulePath -Data $match -Path 'where')) {
                    if (-not $condition) { continue }
                    if (-not (Test-TkRuleCondition -Value (Get-TkRulePath -Data $item -Path ([string] (Get-TkRulePath -Data $condition -Path 'field'))) -Condition $condition -Binding $binding -Now $Now)) {
                        $meets = $false
                        break
                    }
                }
                if ($meets) { $hits.Add($item) }
            }

            # Not named $rule: variables ignore case, and it would replace the
            # rule being evaluated.
            $count     = Get-TkRulePath -Data $match -Path 'count'
            $countTest = if ($count) { $count } else { [pscustomobject] @{ op = 'ge'; value = 1 } }

            if (-not (Test-TkRuleCondition -Value $hits.Count -Condition $countTest -Binding $binding -Now $Now)) {
                return (& $make 'NotMatched' '' @())
            }

            if ($as) { $binding[$as] = $hits.ToArray() }
        }
        else {

            $value = Get-TkRuleData -Document $Document -Path ([string] (Get-TkRulePath -Data $match -Path 'path'))

            if (-not (Test-TkRuleCondition -Value $value -Condition $match -Binding $binding -Now $Now)) {
                return (& $make 'NotMatched' '' @())
            }

            if ($as) { $binding[$as] = @($value) }
        }
    }

    $evidence = foreach ($item in @(& $field 'evidence')) {

        $label = [string] (Get-TkRulePath -Data $item -Path 'label')
        $of    = [string] (Get-TkRulePath -Data $item -Path 'of')
        $show  = @(Get-TkRulePath -Data $item -Path 'show' | Where-Object { $_ })

        $lines = if ($of) {
            $found = @($binding[$of])
            $shown = @($found | Select-Object -First 8 | ForEach-Object {
                $entry = $_
                ((@($show | ForEach-Object { Format-TkRuleValue -Value (Get-TkRulePath -Data $entry -Path ([string] $_)) }) | Where-Object { $_ }) -join ' - ')
            })
            if ($found.Count -gt 8) { $shown += ('and {0} more' -f ($found.Count - 8)) }
            $shown
        }
        else {
            @(Format-TkRuleValue -Value (Get-TkRuleData -Document $Document -Path ([string] (Get-TkRulePath -Data $item -Path 'path'))))
        }

        [pscustomobject] @{ Label = $label; Lines = @($lines | Where-Object { $_ }) }
    }

    return (& $make 'Matched' '' $evidence)
}

<#
.SYNOPSIS
    Evaluates every rule on a report document.

.DESCRIPTION
    Pure. The document's own moment is "now", so a snapshot of last month
    reads as it was then. What matched comes first, the most confident
    first; then what could not be evaluated, with why.

.OUTPUTS
    PSCustomObject with Rules, Matched, NotEvaluated and NotMatched.
#>
function Resolve-TkHypothesis {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Document,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Rule,
        [Parameter()] [AllowNull()] $Now
    )

    if (-not $PSBoundParameters.ContainsKey('Rule')) {
        $Rule = @(Get-TkHypothesisRule)
    }

    $moment = if ($Now) { [datetime] $Now } else { ConvertTo-TkRuleDate -Value (Get-TkRulePath -Data $Document -Path 'GeneratedAt') }
    if (-not $moment) { $moment = Get-Date }

    $results = @(foreach ($item in @($Rule | Where-Object { $_ })) { Invoke-TkHypothesisRule -Rule $item -Document $Document -Now $moment })
    $rank    = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }

    $matched = @(foreach ($level in @('High', 'Medium', 'Low')) { $results | Where-Object { $_.Status -eq 'Matched' -and $_.Confidence -eq $level } })
    $matched += @($results | Where-Object { $_.Status -eq 'Matched' -and -not $rank.ContainsKey([string] $_.Confidence) })

    $severity = if (@($matched | Where-Object { $_.Confidence -ne 'Low' }).Count) { 'Warning' } elseif ($matched.Count) { 'Info' } else { 'Pass' }

    return [pscustomobject] @{
        At           = $moment.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        Severity     = $severity
        Rules        = $results.Count
        Matched      = @($matched | ForEach-Object {
            Add-Member -InputObject $_ -NotePropertyName 'Severity' -NotePropertyValue $(if ($_.Confidence -eq 'Low') { 'Info' } else { 'Warning' }) -Force -PassThru
        })
        NotEvaluated = @($results | Where-Object { $_.Status -eq 'NotEvaluated' })
        NotMatched   = @($results | Where-Object { $_.Status -eq 'NotMatched' }).Count
    }
}

<#
.SYNOPSIS
    The reports the rules read, in the order they are first named.
#>
function Get-TkHypothesisReportName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Rule
    )

    if (-not $PSBoundParameters.ContainsKey('Rule')) {
        $Rule = @(Get-TkHypothesisRule)
    }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Rule | ForEach-Object { @(Get-TkRulePath -Data $_ -Path 'reports') })) {
        if ($name -and -not $names.Contains([string] $name)) { $names.Add([string] $name) }
    }

    return , [string[]] $names.ToArray()
}

<#
.SYNOPSIS
    Collects what the rules read, and evaluates them.

.DESCRIPTION
    The reports already collected into the same document are taken as they
    are (Options.Collected); the others are collected here, with the rights
    this session has. A report that needs more is skipped, and the rules on
    it say so.

.OUTPUTS
    PSCustomObject, as Resolve-TkHypothesis returns it.
#>
function Get-TkHypothesisReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [hashtable] $Options = @{}
    )

    $rules     = @(Get-TkHypothesisRule)
    $collected = $Options['Collected']
    $table     = @(Get-TkHeadlessReport)
    $elevated  = [bool] (Test-TkIsElevated)
    $reports   = [ordered] @{}

    foreach ($name in (Get-TkHypothesisReportName -Rule $rules)) {

        if ($collected -is [System.Collections.IDictionary] -and $collected.Contains($name)) {
            $reports[$name] = $collected[$name]
            continue
        }

        $entry = $table | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($entry) {
            $reports[$name] = Invoke-TkHeadlessCollector -Entry $entry -Elevated $elevated -Options @{ AuditLevel = 'Essential' }
        }
    }

    $document = [ordered] @{ GeneratedAt = (Get-Date).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture); Reports = $reports }

    return (Resolve-TkHypothesis -Document $document -Rule $rules)
}
