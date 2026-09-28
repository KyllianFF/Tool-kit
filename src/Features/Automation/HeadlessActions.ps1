<#
    Toolkit - Features / Headless actions

    The fixes, tweaks and audit corrections of the interface, taken without a
    window, for an RMM agent, a remote session or a deployment script:

        $toolkit = [scriptblock]::Create((irm <published url>))
        & $toolkit -Fix flush-dns, reset-print-spooler              # the plan: nothing changes
        & $toolkit -Fix flush-dns, reset-print-spooler -Execute     # runs them
        exit $LASTEXITCODE

    Five rules shape this file.

    The allow lists are the interface's: a fix is an id of the fixes catalog
    run through Get-TkFixDispatchTable, a tweak an id of the tweaks catalog, a
    correction an id of Get-TkRemediationTable. What is typed on the command
    line only ever selects an entry; it never reaches a command.

    Nothing changes without -Execute. Until then the run is a plan that says
    what would run and what would be refused, and its exit code says the same.

    The whole request is checked before anything runs. An unknown id, an
    action that needs administrator rights in a standard session, one that
    works on the signed-in account's own profile when the run is SYSTEM (as an
    RMM agent's is), or a correction that needs a person at the machine,
    refuses the run: a typo never leaves a machine half changed.

    It never elevates. An RMM agent already runs as SYSTEM or elevated, and a
    standard session is told to run elevated, as the reports are.

    The result is a JSON document versioned like the reports
    (docs/HEADLESS-ACTIONS.md), an exit code (0 done or would run, 3010 done
    and a restart is needed, 1 an action failed, 2 refused), and each action
    is journaled by the engine that runs it, as in the interface.
#>

<#
.SYNOPSIS
    The name and version of the action result format.

.OUTPUTS
    PSCustomObject with Name and Version.
#>
function Get-TkActionSchema {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject] @{ Name = 'toolkit-actions'; Version = '1.0' }
}

<#
.SYNOPSIS
    Says whether this process runs as the SYSTEM account, as RMM agents do.

.OUTPUTS
    System.Boolean
#>
function Test-TkIsSystemAccount {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        return ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    The fixes that work on the signed-in account's own profile or session.

.DESCRIPTION
    Run as SYSTEM, each of them would reach SYSTEM's profile instead and
    report a success that changed nothing for the user: the Teams, icon and
    Store caches, OneDrive, the Office accounts, the application proxy, the
    Windows Hello container, the Windows Security app, Explorer and the Start
    menu. Named by their dispatch key in Get-TkFixDispatchTable.

.OUTPUTS
    System.String[]
#>
function Get-TkUserScopedFixAction {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'ClearTeamsCache', 'RebuildIconCache', 'ResetOfficeActivation', 'ResetOneDrive', 'ResetProxySettings',
        'ResetWindowsHelloPin', 'ResetWindowsSecurityApp', 'ResetWindowsStore', 'RestartExplorer', 'RestartStartMenu'
    )
}

<#
.SYNOPSIS
    The corrections never taken without a person at the machine, and why.

.OUTPUTS
    System.Collections.Hashtable, keyed by correction id.
#>
function Get-TkHeadlessRefusedRemediation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'restart-to-firmware' = 'It restarts into the firmware setup, which then waits for someone at the keyboard.'
    }
}

<#
.SYNOPSIS
    Says whether a tweak writes the signed-in account's registry.

.OUTPUTS
    System.Boolean
#>
function Test-TkUserScopedTweak {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Tweak
    )

    # Every entry, not only the first: a tweak may set a machine policy and
    # the account's own value together. ConvertTo-TkArray hands back its array
    # whole, so each list is walked as it comes.
    foreach ($list in @($Tweak.registry, $Tweak.registryKeys)) {
        foreach ($entry in (ConvertTo-TkArray $list)) {
            if ([string] $entry.path -match '^(HKCU:|(Registry::)?HKEY_CURRENT_USER\\)') {
                return $true
            }
        }
    }

    return $false
}

<#
.SYNOPSIS
    Lists what a headless run can take: the fixes, the tweaks or the corrections.

.DESCRIPTION
    Refused holds why an entry is never taken without a window; UserScoped
    marks the ones refused when the run is SYSTEM. Source is the catalog
    entry the engine receives, and is left out of what is printed.

.OUTPUTS
    PSCustomObject[] with Kind, Id, Name, Elevated, RequiresRestart, Risk,
    UserScoped, Refused, Description and Source.
#>
function Get-TkHeadlessActionCatalog {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Fix', 'Tweak', 'Remediation')]
        [string] $Kind
    )

    $item = {
        param($id, $name, $elevated, $restart, $risk, $userScoped, $refused, $description, $source)
        [pscustomobject] @{
            Kind = $Kind; Id = [string] $id; Name = [string] $name; Elevated = [bool] $elevated; RequiresRestart = [bool] $restart
            Risk = [string] $risk; UserScoped = [bool] $userScoped; Refused = [string] $refused; Description = [string] $description; Source = $source
        }
    }

    switch ($Kind) {

        'Fix' {
            $dispatch   = Get-TkFixDispatchTable
            $userScoped = @(Get-TkUserScopedFixAction)

            return @(foreach ($fix in @(Get-TkFix)) {
                $refused = if ($dispatch.ContainsKey([string] $fix.action)) { '' } else { 'Its action is not a registered fix.' }
                & $item $fix.id $fix.name $fix.requiresElevation $fix.requiresRestart $fix.risk ($userScoped -contains [string] $fix.action) $refused $fix.description $fix
            })
        }

        'Tweak' {
            return @(foreach ($tweak in @(Get-TkTweak)) {
                & $item $tweak.id $tweak.name $tweak.requiresElevation $tweak.requiresRestart $tweak.impact (Test-TkUserScopedTweak -Tweak $tweak) '' $tweak.description $tweak
            })
        }

        'Remediation' {
            $table   = Get-TkRemediationTable
            $refused = Get-TkHeadlessRefusedRemediation

            return @(foreach ($id in @($table.Keys | Sort-Object)) {
                $entry  = $table[$id]
                $reason = if ([string] $entry.Kind -eq 'Open') { 'It opens a page for a person to act on, and changes nothing.' }
                          elseif ($refused.ContainsKey($id)) { $refused[$id] }
                          else { '' }
                & $item $id $entry.Name $entry.Elevated $entry.Restart '' $false $reason $entry.Explanation $entry
            })
        }
    }
}

<#
.SYNOPSIS
    Turns the ids of a headless run into its plan, every action checked.

.PARAMETER Elevated
    Whether the run has administrator rights.

.PARAMETER System
    Whether the run is the SYSTEM account.

.OUTPUTS
    PSCustomObject[], one per action, with Status Planned or Refused and the
    reason of a refusal.
#>
function Resolve-TkHeadlessAction {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $Fix = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Tweak = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Remediate = @(),
        [Parameter()] [switch] $Revert,
        [Parameter()] [bool] $Elevated = $false,
        [Parameter()] [bool] $System = $false
    )

    $split    = { param($values) @(@($values) | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ } | Select-Object -Unique) }
    $requests = @(
        @{ Kind = 'Fix';         Parameter = 'Fix';       Ids = @(& $split $Fix);       Operation = 'Run' }
        @{ Kind = 'Tweak';       Parameter = 'Tweak';     Ids = @(& $split $Tweak);     Operation = $(if ($Revert) { 'Revert' } else { 'Apply' }) }
        @{ Kind = 'Remediation'; Parameter = 'Remediate'; Ids = @(& $split $Remediate); Operation = 'Run' }
    )

    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($request in $requests) {

        if ($request.Ids.Count -eq 0) {
            continue
        }

        $catalog = @(Get-TkHeadlessActionCatalog -Kind $request.Kind)

        foreach ($id in $request.Ids) {

            $entry  = $catalog | Where-Object { $_.Id -eq $id } | Select-Object -First 1
            $reason = if (-not $entry) { 'Unknown id: -{0} List shows the ones there are.' -f $request.Parameter }
                      elseif ($entry.Refused) { $entry.Refused }
                      elseif ($entry.Elevated -and -not $Elevated) { 'Needs administrator rights: run the command from an elevated PowerShell.' }
                      elseif ($entry.UserScoped -and $System) { 'Works on the signed-in account''s own profile; run as SYSTEM, it would reach SYSTEM''s. Run it in that account''s session.' }
                      else { '' }

            $plan.Add([pscustomobject] @{
                Kind            = $request.Kind
                Id              = $(if ($entry) { $entry.Id } else { $id })
                Name            = $(if ($entry) { $entry.Name } else { '' })
                Operation       = $request.Operation
                Elevated        = $(if ($entry) { $entry.Elevated } else { $false })
                RequiresRestart = $(if ($entry) { $entry.RequiresRestart } else { $false })
                Status          = $(if ($reason) { 'Refused' } else { 'Planned' })
                Reason          = $reason
                DurationMs      = 0
                Messages        = @()
                Source          = $(if ($entry) { $entry.Source } else { $null })
            })
        }
    }

    return @($plan.ToArray())
}

<#
.SYNOPSIS
    Takes the actions of a checked plan, in order, through the interface's engines.

.DESCRIPTION
    A restore point is taken first when the plan holds tweaks, as the Tweaks
    page does. Each action runs even when one before it failed: they are
    independent, and the result says which failed.
#>
function Invoke-TkHeadlessActionPlan {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Plan
    )

    $tweaks = @($Plan | Where-Object { $_.Kind -eq 'Tweak' })

    if ($tweaks.Count -gt 0 -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Create a restore point')) {
        [void] (New-TkRestorePoint -Description ('Toolkit - before {0} headless tweak(s)' -f $tweaks.Count) -Confirm:$false)
    }

    $log = [string] (Get-TkContext).LogFile

    foreach ($action in $Plan) {

        if (-not $PSCmdlet.ShouldProcess($action.Name, $action.Operation)) {
            continue
        }

        $timer    = [System.Diagnostics.Stopwatch]::StartNew()
        $success  = $false
        $messages = @()

        try {
            switch ($action.Kind) {

                'Fix' {
                    $out     = @(Invoke-TkFix -Fix $action.Source -Confirm:$false)
                    $success = ($out.Count -gt 0 -and $out[-1] -eq $true)
                }

                'Tweak' {
                    $out      = Invoke-TkTweak -Tweak $action.Source -Action $action.Operation -Confirm:$false
                    $success  = [bool] $out.Success
                    $messages = @($out.Messages | ForEach-Object { [string] $_ })
                }

                'Remediation' {
                    $out     = @(Invoke-TkRemediation -Id $action.Id -Confirm:$false)
                    $success = ($out.Count -gt 0 -and $out[-1] -eq $true)
                }
            }
        }
        catch {
            $messages += $_.Exception.Message
        }

        $action.Status     = if ($success) { 'Succeeded' } else { 'Failed' }
        $action.Reason     = if ($success) { '' } else { 'It did not complete; the toolkit log says why: {0}' -f $log }
        $action.DurationMs = $timer.ElapsedMilliseconds
        $action.Messages   = $messages
    }
}

<#
.SYNOPSIS
    Plans or takes fixes, tweaks and audit corrections without a window, and returns the result as JSON.

.PARAMETER Fix
    Fix ids from the fixes catalog, or List.

.PARAMETER Tweak
    Tweak ids from the tweaks catalog, or List. Applied, or reverted with Revert.

.PARAMETER Remediate
    Correction ids from the audit corrections, or List.

.PARAMETER Revert
    Reverts the tweaks instead of applying them.

.PARAMETER Execute
    Takes the actions. Without it the run is a plan and nothing changes.

.PARAMETER OutFile
    Where to write the JSON. Without it the JSON is returned.

.PARAMETER Redact
    Pseudonymises the result, as for the reports.

.OUTPUTS
    System.String: the JSON, or the full path of the file written. The exit
    code is left in $LASTEXITCODE.
#>
function Invoke-TkHeadlessAction {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $Fix = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Tweak = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Remediate = @(),
        [Parameter()] [switch] $Revert,
        [Parameter()] [switch] $Execute,
        [Parameter()] [AllowEmptyString()] [string] $OutFile = '',

        [Parameter()]
        [ValidateSet('None', 'Personal', 'Strict')]
        [string] $Redact = 'None'
    )

    $asked = { param($values) @(@($values) | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ }) }
    $lists = @(
        @{ Kind = 'Fix';         Ids = @(& $asked $Fix) }
        @{ Kind = 'Tweak';       Ids = @(& $asked $Tweak) }
        @{ Kind = 'Remediation'; Ids = @(& $asked $Remediate) }
    )

    if (@($lists | Where-Object { $_.Ids -contains 'List' }).Count -gt 0) {

        # What can be asked for, with why an entry would be refused.
        $rows = foreach ($list in @($lists | Where-Object { $_.Ids -contains 'List' })) {
            @(Get-TkHeadlessActionCatalog -Kind $list.Kind) | Select-Object -Property Kind, Id, Name, Elevated, RequiresRestart, Risk, UserScoped, Refused, Description
        }

        $json     = ConvertTo-Json -InputObject (ConvertTo-TkPlainData -InputObject @($rows)) -Depth 8
        $exitCode = 0
    }
    else {

        if ($Revert -and $lists[1].Ids.Count -eq 0) {
            throw '-Revert undoes tweaks: name them with -Tweak.'
        }

        $elevated = [bool] (Test-TkIsElevated)
        $system   = [bool] (Test-TkIsSystemAccount)
        $plan     = @(Resolve-TkHeadlessAction -Fix $Fix -Tweak $Tweak -Remediate $Remediate -Revert:$Revert -Elevated $elevated -System $system)

        if ($plan.Count -eq 0) {
            throw 'Name the actions with -Fix, -Tweak or -Remediate, or List to see the ones there are.'
        }

        $refused = @($plan | Where-Object { $_.Status -eq 'Refused' }).Count

        if ($Execute -and $refused -eq 0) {
            Write-TkLog -Level Information -Category 'Headless' -Message ('Headless actions: {0}' -f ((@($plan | ForEach-Object { '{0} {1}' -f $_.Kind, $_.Id })) -join ', '))
            Invoke-TkHeadlessActionPlan -Plan $plan -Confirm:$false
        }
        elseif ($Execute) {
            foreach ($action in @($plan | Where-Object { $_.Status -eq 'Planned' })) {
                $action.Status = 'NotRun'
                $action.Reason = 'Another action of the request was refused, so nothing was run.'
            }
        }

        $failed   = @($plan | Where-Object { $_.Status -eq 'Failed' }).Count
        $restart  = @($plan | Where-Object { $_.Status -eq 'Succeeded' -and $_.RequiresRestart }).Count -gt 0
        $exitCode = if ($refused -gt 0) { 2 } elseif ($failed -gt 0) { 1 } elseif ($restart) { 3010 } else { 0 }
        $outcome  = if ($refused -gt 0) { 'Refused' } elseif (-not $Execute) { 'Planned' } elseif ($failed -gt 0) { 'Failed' } else { 'Done' }
        $schema   = Get-TkActionSchema
        $context  = Get-TkContext

        $counts = [ordered] @{}
        foreach ($status in @('Planned', 'Refused', 'NotRun', 'Succeeded', 'Failed')) {
            $counts[$status] = @($plan | Where-Object { $_.Status -eq $status }).Count
        }

        $document = [ordered] @{
            Schema        = $schema.Name
            SchemaVersion = $schema.Version
            Computer      = $env:COMPUTERNAME
            MachineId     = Get-TkMachineId
            User          = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
            GeneratedAt   = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            Toolkit       = [ordered] @{ Version = [string] $context.Version; Commit = [string] $context.Commit }
            Elevated      = $elevated
            System        = $system
            Privacy       = $Redact
            Mode          = $(if ($Execute) { 'Execute' } else { 'Plan' })
            Summary       = [ordered] @{ Outcome = $outcome; ExitCode = $exitCode; RestartRequired = $restart; Counts = $counts }
            Actions       = @($plan | ForEach-Object {
                [ordered] @{
                    Kind = $_.Kind; Id = $_.Id; Name = $_.Name; Operation = $_.Operation; Elevated = $_.Elevated; RequiresRestart = $_.RequiresRestart
                    Status = $_.Status; Reason = $_.Reason; DurationMs = $_.DurationMs; Messages = @($_.Messages)
                }
            })
        }

        Write-TkLog -Level Information -Category 'Headless' -Message ('Headless actions {0}: {1}, exit code {2}.' -f $document.Mode.ToLowerInvariant(), $outcome, $exitCode)

        $json = ConvertTo-Json -InputObject (ConvertTo-TkPlainData -InputObject $document) -Depth 12
    }

    if ($Redact -ne 'None') {
        $json = (Protect-TkExportText -Text $json -Level $Redact -Label 'headless-actions').Text
    }

    # Left for the caller: an RMM script ends with exit $LASTEXITCODE. An exit
    # here would close the console of someone who ran it by hand.
    Set-Variable -Name 'LASTEXITCODE' -Value $exitCode -Scope Global

    if (-not $OutFile) {
        return $json
    }

    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))

    return $path
}
