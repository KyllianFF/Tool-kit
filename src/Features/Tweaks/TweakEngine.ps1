<#
    Toolkit - Features / Tweak engine

    A tweak is a declarative object, never a script. It describes registry
    values, service start-up types and scheduled tasks, plus the original
    state to restore. The engine below is the only code that applies them.

    Why declarative:

      - Every tweak is reversible, because the revert path is described in
        the same object as the apply path. Tools that ship one-way scripts
        are how machines end up in states nobody can undo.
      - The current state can be read back, so the interface shows what is
        actually applied rather than what the user last clicked.
      - Adding a tweak is a data change that needs no new code and no new
        tests of the engine.
#>

<#
.SYNOPSIS
    Returns every tweak from the catalog.

.PARAMETER Category
    Optional category filter.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkTweak {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [string] $Category
    )

    $catalog = Import-TkCatalog -Name 'tweaks'

    if (-not $catalog) {
        return @()
    }

    $tweaks = @($catalog.tweaks)

    if ($Category) {
        $tweaks = @($tweaks | Where-Object { $_.category -eq $Category })
    }

    return $tweaks
}

<#
.SYNOPSIS
    Reads whether a tweak is currently applied.

.DESCRIPTION
    A tweak counts as applied when every registry value it declares already
    holds the target data. Services and scheduled tasks are not used for the
    decision: they are frequently changed by other tooling and would make the
    state flap.

.PARAMETER Tweak
    Tweak object from the catalog.

.OUTPUTS
    System.Boolean
#>
function Test-TkTweakApplied {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Tweak
    )

    $values = ConvertTo-TkArray $Tweak.registry
    $keys   = ConvertTo-TkArray $Tweak.registryKeys

    if ($values.Count -eq 0 -and $keys.Count -eq 0) {
        return $false
    }

    foreach ($entry in $values) {

        $current = Get-TkRegistryValue -Path $entry.path -Name $entry.name

        if ($null -eq $current) {
            return $false
        }

        # Compare as text: JSON numbers arrive as Int64 while the registry
        # returns Int32, and a strict comparison would never match.
        if ([string] $current -ne [string] $entry.value) {
            return $false
        }
    }

    foreach ($key in $keys) {

        # A key the tweak creates must exist; one it deletes must not.
        $shouldExist = ($key.applyAction -eq 'create')

        if ((Test-Path -LiteralPath $key.path) -ne $shouldExist) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Applies or reverts a tweak.

.DESCRIPTION
    Walks the three sections of a tweak object in a fixed order: registry,
    then services, then scheduled tasks. Failures are collected rather than
    thrown so one unavailable service cannot abandon a tweak half applied.

.PARAMETER Tweak
    Tweak object from the catalog.

.PARAMETER Action
    Apply or Revert.

.OUTPUTS
    PSCustomObject with Success, RequiresRestart and Messages.
#>
function Invoke-TkTweak {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Tweak,

        [Parameter(Mandatory)]
        [ValidateSet('Apply', 'Revert')]
        [string] $Action
    )

    $messages = @()
    $failures = 0

    if ($Tweak.requiresElevation -and -not (Assert-TkElevated -Operation ('Tweak: {0}' -f $Tweak.name))) {

        return [pscustomobject]@{
            Success         = $false
            RequiresRestart = $false
            Messages        = @('Administrator rights are required for this tweak.')
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Tweak.name, $Action)) {

        return [pscustomobject]@{
            Success         = $false
            RequiresRestart = $false
            Messages        = @('Cancelled.')
        }
    }

    $stopwatch = Start-TkOperation -Name ('{0}: {1}' -f $Action, $Tweak.name) -Category 'Tweaks'

    # --- Registry ---------------------------------------------------------
    foreach ($entry in (ConvertTo-TkArray $Tweak.registry)) {

        if ($Action -eq 'Apply') {
            $ok = Set-TkRegistryValue -Path $entry.path -Name $entry.name `
                                      -Value $entry.value -Type $entry.type -Confirm:$false
        }
        else {
            # "delete" means the value did not exist before the tweak, so the
            # faithful revert is removal, not writing a guessed default.
            if ($entry.PSObject.Properties.Name -contains 'defaultAction' -and $entry.defaultAction -eq 'delete') {
                $ok = Remove-TkRegistryValue -Path $entry.path -Name $entry.name -Confirm:$false
            }
            else {
                $ok = Set-TkRegistryValue -Path $entry.path -Name $entry.name `
                                          -Value $entry.default -Type $entry.type -Confirm:$false
            }
        }

        if (-not $ok) {
            $failures++
            $messages += ('Registry step failed: {0}\{1}' -f $entry.path, $entry.name)
        }
    }

    # --- Whole registry keys ----------------------------------------------
    # Some shell behaviours are driven by the presence of a key rather than
    # by a value, the Windows 11 classic context menu being the usual case.
    # Removing only the value would leave the key in place and the tweak
    # would appear to revert without actually reverting.
    foreach ($key in (ConvertTo-TkArray $Tweak.registryKeys)) {

        $wanted = if ($Action -eq 'Apply') { $key.applyAction } else { $key.revertAction }

        if (-not (Set-TkRegistryKeyPresence -Path $key.path -Presence $wanted -DefaultValue $key.defaultValue)) {
            $failures++
            $messages += ('Registry key step failed: {0}' -f $key.path)
        }
    }

    # --- Services ---------------------------------------------------------
    foreach ($service in (ConvertTo-TkArray $Tweak.services)) {

        $target = if ($Action -eq 'Apply') { $service.startup } else { $service.default }

        if (-not (Set-TkServiceStartup -Name $service.name -StartupType $target)) {
            $failures++
            $messages += ('Service step failed: {0}' -f $service.name)
        }
    }

    # --- Scheduled tasks --------------------------------------------------
    foreach ($taskPath in (ConvertTo-TkArray $Tweak.scheduledTasks)) {

        $enable = ($Action -eq 'Revert')

        if (-not (Set-TkScheduledTaskState -FullName $taskPath -Enabled $enable)) {
            $failures++
            $messages += ('Scheduled task step failed: {0}' -f $taskPath)
        }
    }

    $success = ($failures -eq 0)

    Stop-TkOperation -Name ('{0}: {1}' -f $Action, $Tweak.name) -Stopwatch $stopwatch `
                     -Category 'Tweaks' -Success $success

    if ($success) {
        $messages += ('{0} {1}.' -f $Tweak.name, $(if ($Action -eq 'Apply') { 'applied' } else { 'reverted' }))
    }

    return [pscustomobject]@{
        Success         = $success
        RequiresRestart = [bool] $Tweak.requiresRestart
        Messages        = $messages
    }
}

<#
.SYNOPSIS
    Creates or removes a whole registry key.

.DESCRIPTION
    Used by tweaks whose effect depends on a key existing rather than on a
    value. When creating, an optional default value can be written at the
    same time, which is what the shell CLSID overrides need.

.PARAMETER Presence
    'create' or 'delete'. Any other value is a no-op, so a tweak can declare
    an action for only one direction.

.OUTPUTS
    System.Boolean
#>
function Set-TkRegistryKeyPresence {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [AllowNull()]
        [string] $Presence,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $DefaultValue
    )

    if ([string]::IsNullOrWhiteSpace($Presence)) {
        return $true
    }

    if ($Path -match '^HK(LM|CR|EY_LOCAL_MACHINE|EY_CLASSES_ROOT)') {

        if (-not (Assert-TkElevated -Operation ('Registry key change at {0}' -f $Path))) {
            return $false
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Path, ('Registry key {0}' -f $Presence))) {
        return $false
    }

    try {
        switch ($Presence) {

            'create' {
                if (-not (Test-Path -LiteralPath $Path)) {
                    New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
                }

                if ($PSBoundParameters.ContainsKey('DefaultValue')) {
                    Set-ItemProperty -LiteralPath $Path -Name '(Default)' -Value $DefaultValue -ErrorAction Stop
                }

                break
            }

            'delete' {
                if (Test-Path -LiteralPath $Path) {
                    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
                }

                break
            }

            default {
                Write-TkLog -Level Warning -Category 'Tweaks' -Message (
                    'Unknown registry key action "{0}"; step skipped.' -f $Presence
                )
            }
        }

        Write-TkLog -Level Information -Category 'Tweaks' -Message (
            'Registry key {0}: {1}' -f $Presence, $Path
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Tweaks' -Message (
            'Registry key {0} failed for {1}: {2}' -f $Presence, $Path, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Sets the start-up type of a service.

.DESCRIPTION
    Missing services are reported as success: on a given Windows edition or
    build a service in the catalog may simply not exist, and that is not a
    failure of the tweak.

.PARAMETER StartupType
    Automatic, AutomaticDelayed, Manual or Disabled.

.OUTPUTS
    System.Boolean
#>
function Set-TkServiceStartup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Automatic', 'AutomaticDelayed', 'Manual', 'Disabled')]
        [string] $StartupType
    )

    if (-not (Assert-TkElevated -Operation ('Change service {0}' -f $Name))) {
        return $false
    }

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if (-not $service) {

        Write-TkLog -Level Debug -Category 'Tweaks' -Message (
            'Service "{0}" does not exist on this build; step skipped.' -f $Name
        )

        return $true
    }

    if (-not $PSCmdlet.ShouldProcess($Name, ('Set start-up to {0}' -f $StartupType))) {
        return $false
    }

    try {
        if ($StartupType -eq 'Disabled' -and $service.Status -eq 'Running') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        }

        # AutomaticDelayed is not a Set-Service value; the delayed flag lives
        # in the service registry key.
        if ($StartupType -eq 'AutomaticDelayed') {

            Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop

            Set-TkRegistryValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $Name) `
                                -Name 'DelayedAutostart' -Value 1 -Type DWord -Confirm:$false | Out-Null
        }
        else {
            Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        }

        Write-TkLog -Level Information -Category 'Tweaks' -Message (
            'Service {0} start-up set to {1}.' -f $Name, $StartupType
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Tweaks' -Message (
            'Could not change service {0}: {1}' -f $Name, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Enables or disables a scheduled task by full path.

.PARAMETER FullName
    Full task path, for example \Microsoft\Windows\Feeds\FeedTask.

.OUTPUTS
    System.Boolean
#>
function Set-TkScheduledTaskState {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $FullName,

        [Parameter(Mandatory)]
        [bool] $Enabled
    )

    if (-not (Assert-TkElevated -Operation ('Change scheduled task {0}' -f $FullName))) {
        return $false
    }

    $taskName = Split-Path -Path $FullName -Leaf
    $taskPath = Split-Path -Path $FullName -Parent

    if (-not $taskPath.EndsWith('\')) {
        $taskPath = $taskPath + '\'
    }

    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue

    if (-not $task) {

        Write-TkLog -Level Debug -Category 'Tweaks' -Message (
            'Scheduled task "{0}" not present; step skipped.' -f $FullName
        )

        return $true
    }

    $verb = if ($Enabled) { 'Enable' } else { 'Disable' }

    if (-not $PSCmdlet.ShouldProcess($FullName, $verb)) {
        return $false
    }

    try {
        if ($Enabled) {
            Enable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
        }
        else {
            Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
        }

        Write-TkLog -Level Information -Category 'Tweaks' -Message (
            'Scheduled task {0} {1}d.' -f $FullName, $verb.ToLower()
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Tweaks' -Message (
            'Could not change scheduled task {0}: {1}' -f $FullName, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Applies or reverts several tweaks, creating one restore point first.

.PARAMETER TweakId
    Identifiers from the catalog.

.PARAMETER Action
    Apply or Revert.

.OUTPUTS
    PSCustomObject with Applied, Failed and RequiresRestart.
#>
function Invoke-TkTweakBatch {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]] $TweakId,

        [Parameter(Mandatory)]
        [ValidateSet('Apply', 'Revert')]
        [string] $Action,

        [Parameter()]
        [switch] $SkipRestorePoint
    )

    $all      = Get-TkTweak
    $selected = @($all | Where-Object { $TweakId -contains $_.id })

    if ($selected.Count -eq 0) {

        Write-TkLog -Level Warning -Category 'Tweaks' -Message 'No matching tweak was selected.'

        return [pscustomobject]@{ Applied = 0; Failed = 0; RequiresRestart = $false }
    }

    if (-not $SkipRestorePoint) {
        New-TkRestorePoint -Description ('Toolkit - before {0} of {1} tweaks' -f $Action.ToLower(), $selected.Count) -Confirm:$false | Out-Null
    }

    $applied         = 0
    $failed          = 0
    $requiresRestart = $false

    foreach ($tweak in $selected) {

        $result = Invoke-TkTweak -Tweak $tweak -Action $Action -Confirm:$false

        if ($result.Success) {
            $applied++
        }
        else {
            $failed++
        }

        if ($result.RequiresRestart) {
            $requiresRestart = $true
        }

        foreach ($message in $result.Messages) {
            Write-TkLog -Level Information -Category 'Tweaks' -Message $message
        }
    }

    return [pscustomobject]@{
        Applied         = $applied
        Failed          = $failed
        RequiresRestart = $requiresRestart
    }
}
