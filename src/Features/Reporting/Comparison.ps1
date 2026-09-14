<#
    Toolkit - Features / Report comparison

    What changed on a machine between two report documents: the one saved
    before an intervention and the one collected after it, or last month's and
    today's.

    A difference of the raw JSON would be useless: every run has another time,
    other durations, another free space and another processor load. What is
    compared is what a technician reads:

      - the judgement of each row, followed by what identifies the row rather
        than by its position: a disk by its kind and name, a device by its
        identifier, an audit control by its Id, a finding by its heading with
        the measurements taken out;
      - the rows that appeared or went, and the events that are new since:
        crashes, stability events, updates;
      - a few facts: the Windows build, the BIOS version, the memory, the
        antivirus, the audit score.

    The rules are a table, like the reports, so what is compared can be read
    and argued with in one place.
#>

<#
.SYNOPSIS
    Lists how the rows of each report are compared.

.DESCRIPTION
    Path is where the rows are inside the data of the report. Key names the
    fields that identify a row. Mode State compares rows present in both and
    reports the ones that appeared or went; Mode Event only reports rows that
    are new. Judge is the field holding the judgement, Watch the fields whose
    change is worth naming. Normalize takes the numbers out of the key, for
    headings that carry a measurement.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkComparisonRule {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $rule = {
        param($report, $section, $path, $key, $label, $mode, $judge, $watch, $normalize)

        [pscustomobject] @{
            Report    = $report
            Section   = $section
            Path      = [string] $path
            Key       = @($key)
            Label     = @($label)
            Mode      = $mode
            Judge     = [string] $judge
            Watch     = @($watch)
            Normalize = [bool] $normalize
        }
    }

    return @(
        (& $rule 'Storage'     'Storage'           ''          @('Kind', 'Name')           @('Kind', 'Name')       'State' 'Severity' @('Health')                                   $false)
        (& $rule 'Devices'     'Devices'           ''          @('DeviceId')               @('Name')               'State' 'Severity' @('Code')                                     $false)
        (& $rule 'Crashes'     'Crashes'           'Crashes'   @('When', 'Code')           @('Kind', 'Info.Name')  'Event' 'Severity' @()                                           $false)
        (& $rule 'Crashes'     'Stability'         'Stability' @('When', 'Kind', 'Source') @('Kind', 'Source')     'Event' 'Severity' @()                                           $false)
        (& $rule 'Performance' 'Performance'       'Findings'  @('Heading')                @('Heading')            'State' 'Severity' @()                                           $true)
        (& $rule 'Performance' 'Startup programs'  'Startup'   @('Name', 'Scope')          @('Name')               'State' ''         @('Enabled')                                  $false)
        (& $rule 'Wifi'        'Wi-Fi'             'Findings'  @('Heading')                @('Heading')            'State' 'Severity' @()                                           $true)
        (& $rule 'Proxy'       'Proxy'             'Findings'  @('Heading')                @('Heading')            'State' 'Severity' @()                                           $true)
        (& $rule 'Identity'    'Sign-in'           ''          @('Kind')                   @('Kind')               'State' 'Severity' @('Value')                                    $false)
        (& $rule 'Printing'    'Printing'          ''          @('Kind', 'Name')           @('Kind', 'Name')       'State' 'Severity' @('Status')                                   $false)
        (& $rule 'Profiles'    'Profiles'          ''          @('Kind', 'Name')           @('Kind', 'Name')       'State' 'Severity' @()                                           $false)
        (& $rule 'Updates'     'Updates'           ''          @('When', 'Title')          @('Title')              'Event' 'Severity' @()                                           $false)
        (& $rule 'Audit'       'Audit'             'Findings'  @('Id')                     @('Id', 'Name')         'State' 'Status'   @('Measured')                                 $false)
        (& $rule 'Network'     'Network adapters'  ''          @('Name')                   @('Name')               'State' ''         @('Status', 'IPv4Address', 'Gateway', 'DnsServers') $false)
        (& $rule 'Lifecycle'   'Software support'  'Programs'  @('ProductId', 'Cycle')     @('Title')              'State' 'Severity' @('Version')                                  $false)
    )
}

<#
.SYNOPSIS
    Lists the facts compared between two documents.

.DESCRIPTION
    Each path starts with the report name, then the fields inside its data.
    The first path found in a document is used, so the facts come from the
    inventory when it was collected and from the dashboard otherwise.

.OUTPUTS
    PSCustomObject[] with Label and Path.
#>
function Get-TkComparisonFact {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Windows version'; Path = @('Inventory.System.DisplayVersion', 'Dashboard.OS.DisplayVersion') }
        [pscustomobject] @{ Label = 'Windows build';   Path = @('Inventory.System.Build', 'Dashboard.OS.Build') }
        [pscustomobject] @{ Label = 'Windows support'; Path = @('Lifecycle.Windows.Ends') }
        [pscustomobject] @{ Label = 'Activation';      Path = @('Inventory.System.Activation', 'Dashboard.OS.Activation') }
        [pscustomobject] @{ Label = 'BIOS version';    Path = @('Inventory.Identity.BiosVersion', 'Dashboard.Identity.BiosVersion') }
        [pscustomobject] @{ Label = 'Domain';          Path = @('Inventory.Identity.Domain', 'Dashboard.Identity.Domain') }
        [pscustomobject] @{ Label = 'Memory';          Path = @('Inventory.Hardware.TotalMemory') }
        [pscustomobject] @{ Label = 'Antivirus';       Path = @('Inventory.Security.Antivirus') }
        [pscustomobject] @{ Label = 'Firewall';        Path = @('Inventory.Security.Firewall') }
        [pscustomobject] @{ Label = 'Secure Boot';     Path = @('Inventory.Security.SecureBoot') }
        [pscustomobject] @{ Label = 'TPM';             Path = @('Inventory.Security.Tpm') }
        [pscustomobject] @{ Label = 'BitLocker';       Path = @('Inventory.Security.BitLocker') }
        [pscustomobject] @{ Label = 'Restart pending'; Path = @('Reboot.Pending') }
        [pscustomobject] @{ Label = 'Audit score';     Path = @('Audit.Score.Score') }
    )
}

<#
.SYNOPSIS
    Lists the reports a snapshot of the Intervention page collects.

.DESCRIPTION
    Every report worth comparing. The Dashboard repeats the others, and the
    profile sizes take half a minute on their own for a judgement that rarely
    changes during a visit.
#>
function Get-TkSnapshotReportName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @('Inventory', 'Network', 'Reboot', 'Storage', 'Performance', 'Devices', 'Crashes',
             'Wifi', 'Proxy', 'Identity', 'Updates', 'Printing', 'Lifecycle', 'Audit')
}

<#
.SYNOPSIS
    Returns the folder snapshots are saved in, beside the journal.
#>
function Get-TkSnapshotFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $folder = Join-Path -Path (Get-TkContext).DataRoot -ChildPath 'snapshots'

    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    return $folder
}

<#
.SYNOPSIS
    Reads a value in plain data by a dotted path.

.PARAMETER Data
    Ordered dictionaries and arrays, as ConvertTo-TkPlainData writes them.

.PARAMETER Path
    Field names separated by dots. An empty path returns the data itself.
#>
function Get-TkDocumentValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Data,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Path
    )

    $node = $Data

    foreach ($part in @($Path -split '\.' | Where-Object { $_ })) {

        if ($node -is [System.Collections.IDictionary] -and $node.Contains($part)) {
            $node = $node[$part]
        }
        else {
            return $null
        }
    }

    return $node
}

<#
.SYNOPSIS
    Ranks a judgement, higher being worse.
#>
function Get-TkSeverityRank {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    switch ([string] $Value) {
        'Fail'        { return 3 }
        'Warning'     { return 2 }
        'NotAssessed' { return 1 }
        default       { return 0 }
    }
}

<#
.SYNOPSIS
    Builds the key that identifies a row between two documents.

.PARAMETER Row
    One row of plain data.

.PARAMETER Field
    The fields the key is made of.

.PARAMETER Normalize
    Takes the numbers out, so "Signal -55 dBm" and "Signal -83 dBm" are the
    same finding.
#>
function Get-TkComparisonKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Row,
        [Parameter(Mandatory)] [string[]] $Field,
        [Parameter()] [bool] $Normalize = $false
    )

    $parts = foreach ($name in $Field) {

        $text = [string] (Get-TkDocumentValue -Data $Row -Path $name)

        if ($Normalize) {
            $text = $text -replace '-?\d+([.,]\d+)?', '#'
        }

        $text.Trim().ToLowerInvariant()
    }

    return ($parts -join ' | ')
}

<#
.SYNOPSIS
    Compares the rows of one rule between two documents.

.PARAMETER Rule
    A row of Get-TkComparisonRule.

.PARAMETER Before
    The rows in the earlier document.

.PARAMETER After
    The rows in the later document.

.OUTPUTS
    PSCustomObject[] with Report, Section, Item, Change (Judgement, Value,
    Appeared, Gone or New), Before, After and Direction (Worse, Better or
    Neutral).
#>
function Compare-TkReportRow {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Rule,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Before = @(),
        [Parameter()] [AllowEmptyCollection()] [object[]] $After = @()
    )

    $index = {
        param($rows)

        $map = [ordered] @{}

        foreach ($row in @($rows | Where-Object { $_ -is [System.Collections.IDictionary] })) {

            $key = Get-TkComparisonKey -Row $row -Field $Rule.Key -Normalize $Rule.Normalize

            if (-not $map.Contains($key)) {
                $map[$key] = $row
            }
        }

        $map
    }

    $label = {
        param($row)
        (@($Rule.Label | ForEach-Object { [string] (Get-TkDocumentValue -Data $row -Path $_) } | Where-Object { $_ })) -join ' - '
    }

    $judgement = {
        param($row)
        if ($Rule.Judge) { [string] (Get-TkDocumentValue -Data $row -Path $Rule.Judge) } else { '' }
    }

    $change = {
        param($item, $kind, $was, $now, $direction)
        [pscustomobject] @{ Report = $Rule.Report; Section = $Rule.Section; Item = $item; Change = $kind; Before = $was; After = $now; Direction = $direction }
    }

    $old     = & $index $Before
    $new     = & $index $After
    $changes = @()

    foreach ($key in @($new.Keys)) {

        $row = $new[$key]
        $now = & $judgement $row

        if (-not $old.Contains($key)) {

            $changes += & $change (& $label $row) $(if ($Rule.Mode -eq 'Event') { 'New' } else { 'Appeared' }) '' $now `
                $(if ((Get-TkSeverityRank -Value $now) -ge 2) { 'Worse' } else { 'Neutral' })
            continue
        }

        # An event seen in both documents is the same event, nothing more.
        if ($Rule.Mode -eq 'Event') {
            continue
        }

        $previous = $old[$key]
        $was      = & $judgement $previous

        $rankBefore = Get-TkSeverityRank -Value $was
        $rankAfter  = Get-TkSeverityRank -Value $now

        if ($rankAfter -ne $rankBefore) {

            $changes += & $change (& $label $row) 'Judgement' $was $now $(if ($rankAfter -gt $rankBefore) { 'Worse' } else { 'Better' })
            continue
        }

        foreach ($field in $Rule.Watch) {

            # Not $before and $after: variable names ignore case, and those
            # would be the typed array parameters of this function.
            $valueThen = [string] (Get-TkDocumentValue -Data $previous -Path $field)
            $valueNow  = [string] (Get-TkDocumentValue -Data $row -Path $field)

            if ($valueThen -ne $valueNow) {
                $changes += & $change (& $label $row) 'Value' ('{0}: {1}' -f $field, $valueThen) ('{0}: {1}' -f $field, $valueNow) 'Neutral'
            }
        }
    }

    # An event that is no longer in the document only aged out of the period
    # it covers; a state row that went is news.
    if ($Rule.Mode -ne 'Event') {

        foreach ($key in @($old.Keys)) {

            if ($new.Contains($key)) {
                continue
            }

            $row = $old[$key]
            $was = & $judgement $row

            $changes += & $change (& $label $row) 'Gone' $was '' $(if ((Get-TkSeverityRank -Value $was) -ge 2) { 'Better' } else { 'Neutral' })
        }
    }

    return $changes
}

<#
.SYNOPSIS
    Compares two report documents.

.PARAMETER Reference
    The earlier document, as plain data.

.PARAMETER Difference
    The later document, as plain data.

.OUTPUTS
    PSCustomObject with SameComputer, Reference, Difference, Reports, Facts,
    Changes and Counts.
#>
function Compare-TkReportDocument {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Reference,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Difference
    )

    $thenReports = Get-TkDocumentValue -Data $Reference -Path 'Reports'
    $nowReports  = Get-TkDocumentValue -Data $Difference -Path 'Reports'

    if ($thenReports -isnot [System.Collections.IDictionary]) { $thenReports = [ordered] @{} }
    if ($nowReports -isnot [System.Collections.IDictionary])  { $nowReports = [ordered] @{} }

    $describe = {
        param($entry)
        if (-not $entry) { 'Not collected' }
        elseif ([string] $entry.Status -ne 'Ok') { [string] $entry.Status }
        elseif ($entry.Worst) { [string] $entry.Worst }
        else { 'Collected' }
    }

    # --- Reports ----------------------------------------------------------
    $reports = foreach ($name in @(@($thenReports.Keys) + @($nowReports.Keys) | Select-Object -Unique)) {

        $then = if ($thenReports.Contains($name)) { $thenReports[$name] } else { $null }
        $now  = if ($nowReports.Contains($name)) { $nowReports[$name] } else { $null }

        # Only what was collected on both sides is compared: a report skipped
        # for want of rights is not a report that improved.
        $compared  = [bool] ($then -and $now -and [string] $then.Status -eq 'Ok' -and [string] $now.Status -eq 'Ok')
        $direction = 'Neutral'

        if ($compared) {

            $rankThen = Get-TkSeverityRank -Value $then.Worst
            $rankNow  = Get-TkSeverityRank -Value $now.Worst

            $direction = if ($rankNow -gt $rankThen) { 'Worse' } elseif ($rankNow -lt $rankThen) { 'Better' } else { 'Neutral' }
        }

        [pscustomobject] @{
            Report    = [string] $name
            Before    = & $describe $then
            After     = & $describe $now
            Compared  = $compared
            Direction = $direction
        }
    }

    $reports = @($reports)

    # --- Rows -------------------------------------------------------------
    $changes = @()

    foreach ($rule in @(Get-TkComparisonRule)) {

        $summary = $reports | Where-Object { $_.Report -eq $rule.Report } | Select-Object -First 1

        if (-not $summary -or -not $summary.Compared) {
            continue
        }

        $path = ('Data.' + $rule.Path).TrimEnd('.')

        $beforeRows = @(Get-TkDocumentValue -Data $thenReports[$rule.Report] -Path $path)
        $afterRows  = @(Get-TkDocumentValue -Data $nowReports[$rule.Report] -Path $path)

        $changes += @(Compare-TkReportRow -Rule $rule -Before $beforeRows -After $afterRows)
    }

    # --- Facts ------------------------------------------------------------
    $valueOf = {
        param($document, $paths)

        foreach ($candidate in $paths) {

            $parts = $candidate -split '\.', 2
            $entry = Get-TkDocumentValue -Data $document -Path ('Reports.' + $parts[0])

            if ($entry -is [System.Collections.IDictionary] -and [string] $entry.Status -eq 'Ok') {

                $value = Get-TkDocumentValue -Data $entry -Path ('Data.' + $parts[1])

                if ($null -ne $value) {
                    return $value
                }
            }
        }

        return $null
    }

    $facts = foreach ($fact in @(Get-TkComparisonFact)) {

        $then = & $valueOf $Reference $fact.Path
        $now  = & $valueOf $Difference $fact.Path

        # A fact read on one side only says what was collected, not what changed.
        if ($null -eq $then -or $null -eq $now -or [string] $then -eq [string] $now) {
            continue
        }

        [pscustomobject] @{ Fact = $fact.Label; Before = [string] $then; After = [string] $now }
    }

    return [pscustomobject] @{
        SameComputer = ([string] $Reference.Computer -eq [string] $Difference.Computer)
        Reference    = [pscustomobject] @{ Computer = [string] $Reference.Computer; GeneratedAt = [string] $Reference.GeneratedAt }
        Difference   = [pscustomobject] @{ Computer = [string] $Difference.Computer; GeneratedAt = [string] $Difference.GeneratedAt }
        Reports      = $reports
        Facts        = @($facts)
        Changes      = @($changes)
        Counts       = [pscustomobject] @{
            Worse   = @($changes | Where-Object { $_.Direction -eq 'Worse' }).Count
            Better  = @($changes | Where-Object { $_.Direction -eq 'Better' }).Count
            Neutral = @($changes | Where-Object { $_.Direction -eq 'Neutral' }).Count
        }
    }
}

<#
.SYNOPSIS
    Reads a report document written by a headless run.

.PARAMETER Path
    The JSON file.

.PARAMETER Json
    The JSON text.

.OUTPUTS
    The document as plain data: ordered dictionaries and arrays.
#>
function Read-TkReportDocument {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Json')]
        [string] $Json
    )

    $text = $Json

    if ($PSCmdlet.ParameterSetName -eq 'Path') {

        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw ('The report document {0} does not exist.' -f $resolved)
        }

        # ReadAllText reads UTF-8 whether or not the file starts with a byte
        # order mark, which Get-Content in Windows PowerShell 5.1 does not.
        $text = [System.IO.File]::ReadAllText($resolved)
    }

    try {
        $parsed = $text | ConvertFrom-Json
    }
    catch {
        throw ('This file is not a toolkit report: it is not valid JSON ({0}).' -f $_.Exception.Message)
    }

    $data = ConvertTo-TkPlainData -InputObject $parsed -Depth 32

    if ($data -isnot [System.Collections.IDictionary] -or -not $data.Contains('Reports')) {
        throw 'This file is not a toolkit report: it has no Reports section.'
    }

    return $data
}
