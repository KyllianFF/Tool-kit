<#
    Toolkit - Features / Fixes: verified plan

    A fix is run and it is assumed to have worked. A verified plan closes the
    loop: it reads the reports that show the problem, runs the fixes one by
    one, reads the same reports again and says what changed, better or worse,
    report by report. The proof goes into the journal, and so into the
    intervention report.

    What checks a fix is data: each fix of data/fixes.json names in verifyWith
    the headless reports its effect shows in. A fix that names none is run and
    said to be unverified, never claimed as proven. A fix has no revert of its
    own, so the way back is a restore point taken first, and the result says
    where it is when the machine is worse.
#>

<#
.SYNOPSIS
    The reports a set of fixes is checked with, each named once.

.DESCRIPTION
    Only names of the headless report table are kept, so an edited catalog
    cannot make the plan run anything else.

.OUTPUTS
    System.String[]
#>
function Get-TkPlanReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Fix
    )

    $known = @(Get-TkHeadlessReport | ForEach-Object { $_.Name })

    return @(@($Fix | ForEach-Object { @($_.verifyWith) } | Where-Object { $known -contains [string] $_ } | ForEach-Object { [string] $_ }) | Select-Object -Unique)
}

<#
.SYNOPSIS
    The steps of a verified plan, for New-TkActionQueue.

.DESCRIPTION
    A restore point first when asked; the reports read before; each fix, in
    the order given; the reports read again. The fixes are critical steps:
    with Stop at the first failure, one that fails stops the rest.

.OUTPUTS
    PSCustomObject[]
#>
function New-TkVerifiedPlanStep {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string[]] $FixId,
        [Parameter()] [switch] $RestorePoint
    )

    $catalog = @(Get-TkFix)
    $fixes   = foreach ($id in $FixId) {
        $fix = $catalog | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if (-not $fix) { throw ('Unknown fix: {0}' -f $id) }
        $fix
    }

    $reports = @(Get-TkPlanReport -Fix @($fixes))
    $steps   = New-Object System.Collections.Generic.List[object]

    if ($RestorePoint) {
        $steps.Add([pscustomobject] @{
            Key = 'restore'; Label = 'Create a restore point'; Critical = $false; Parameters = @{}
            Work = {
                if (@(New-TkRestorePoint -Description 'Toolkit - before a verified plan' -Confirm:$false) -contains $true) { [pscustomobject] @{ Ok = $true; Text = 'Created.' } }
                else { [pscustomobject] @{ Ok = $false; Text = 'Not created: Windows makes one a day at most, or System Protection is off.' } }
            }
        })
    }

    $read = {
        param($names)
        [pscustomobject] @{ Ok = $true; Text = ''; Document = (New-TkReportDocument -Name $names) }
    }

    if ($reports.Count -gt 0) {
        $steps.Add([pscustomobject] @{ Key = 'before'; Label = ('Read before: {0}' -f ($reports -join ', ')); Critical = $true; Parameters = @{ names = $reports }; Work = $read })
    }

    foreach ($fix in $fixes) {
        $steps.Add([pscustomobject] @{
            Key = ('fix:{0}' -f $fix.id); Label = [string] $fix.name; Critical = $true; Parameters = @{ id = [string] $fix.id }
            Work = {
                param($id)
                $definition = Get-TkFix | Where-Object { $_.id -eq $id } | Select-Object -First 1
                $out        = @(Invoke-TkFix -Fix $definition -Confirm:$false)
                [pscustomobject] @{ Ok = ($out.Count -gt 0 -and $out[-1] -eq $true); Text = '' }
            }
        })
    }

    if ($reports.Count -gt 0) {
        $steps.Add([pscustomobject] @{ Key = 'after'; Label = ('Read after: {0}' -f ($reports -join ', ')); Critical = $false; Parameters = @{ names = $reports }; Work = $read })
    }

    return @($steps.ToArray())
}

<#
.SYNOPSIS
    Says, report by report, whether the machine is better or worse after the plan.

.DESCRIPTION
    Pure. A report is worse when its worst judgement got worse, or stayed and
    more of its rows got worse than better; better the other way round. The
    plan is worse when any report is, better when one is and none is worse.
    Fixes that name no report are listed as unverified, and those that need
    a restart as not verifiable before it.

.OUTPUTS
    PSCustomObject with Verdict (Better, Same, Worse or NotVerified),
    Reports, Unverified and AwaitRestart.
#>
function Get-TkPlanVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowNull()] [System.Collections.IDictionary] $Before,
        [Parameter()] [AllowNull()] [System.Collections.IDictionary] $After,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Fix = @()
    )

    $reports = @()

    if ($Before -and $After) {

        $comparison = Compare-TkReportDocument -Reference $Before -Difference $After

        $reports = @(foreach ($report in @($comparison.Reports)) {
            $changes = @($comparison.Changes | Where-Object { $_.Report -eq $report.Report })
            $worse   = @($changes | Where-Object { $_.Direction -eq 'Worse' }).Count
            $better  = @($changes | Where-Object { $_.Direction -eq 'Better' }).Count

            $direction = if (-not $report.Compared) { 'NotCompared' }
                         elseif ($report.Direction -eq 'Worse' -or ($report.Direction -ne 'Better' -and $worse -gt $better)) { 'Worse' }
                         elseif ($report.Direction -eq 'Better' -or $better -gt $worse) { 'Better' }
                         else { 'Same' }

            [pscustomobject] @{ Report = $report.Report; Before = $report.Before; After = $report.After; Direction = $direction; Better = $better; Worse = $worse; Changes = $changes }
        })
    }

    $compared = @($reports | Where-Object { $_.Direction -ne 'NotCompared' })
    $verdict  = if ($compared.Count -eq 0) { 'NotVerified' }
                elseif (@($compared | Where-Object { $_.Direction -eq 'Worse' }).Count -gt 0) { 'Worse' }
                elseif (@($compared | Where-Object { $_.Direction -eq 'Better' }).Count -gt 0) { 'Better' }
                else { 'Same' }

    return [pscustomobject] @{
        Verdict      = $verdict
        Reports      = $reports
        Unverified   = @($Fix | Where-Object { @($_.verifyWith).Count -eq 0 } | ForEach-Object { [string] $_.name })
        AwaitRestart = @($Fix | Where-Object { $_.requiresRestart } | ForEach-Object { [string] $_.name })
    }
}
