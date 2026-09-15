<#
    Toolkit - Features / Tweak engine

    A tweak is a declarative object, never a script. It describes registry
    values and keys, optional Windows features, capabilities, service start-up
    types, scheduled tasks and audit subcategories, plus the original state to
    restore. The engine below is the only code that applies them.

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
    A tweak counts as applied when every registry value, key, optional
    feature, capability and audit subcategory it declares is already in its
    target state. Services and scheduled tasks are not used for the decision:
    they are frequently changed by other tooling and would make the state
    flap.

    The audit policy is only readable elevated. Without rights it is left out
    of the decision, and a tweak with nothing else to check reads as not
    applied rather than guessed.

.PARAMETER Tweak
    Tweak object from the catalog.

.PARAMETER FeatureStates
    Install states from Get-TkOptionalFeatureStateTable, for a caller testing
    many tweaks with one query. Read here when omitted; null when they could
    not be read, which makes a feature tweak read as not applied.

.PARAMETER AuditSettings
    Settings from Read-TkAuditPolicyBackup, or null when the policy is not
    readable. Read here when omitted.

.OUTPUTS
    System.Boolean
#>
function Test-TkTweakApplied {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Tweak,

        [Parameter()]
        [AllowNull()]
        [hashtable] $FeatureStates,

        [Parameter()]
        [AllowNull()]
        [hashtable] $AuditSettings
    )

    $values       = ConvertTo-TkArray $Tweak.registry
    $keys         = ConvertTo-TkArray $Tweak.registryKeys
    $features     = ConvertTo-TkArray $Tweak.optionalFeatures
    $capabilities = ConvertTo-TkArray $Tweak.capabilities
    $audits       = ConvertTo-TkArray $Tweak.auditPolicy

    # What could actually be compared. The audit part only counts once read.
    $checked = $values.Count + $keys.Count + $features.Count + $capabilities.Count

    if (($checked + $audits.Count) -eq 0) {
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

    if ($features.Count -gt 0) {

        if (-not $PSBoundParameters.ContainsKey('FeatureStates')) {
            $FeatureStates = Get-TkOptionalFeatureStateTable
        }

        if ($null -eq $FeatureStates) {
            return $false
        }

        foreach ($feature in $features) {

            $state = if ($FeatureStates.ContainsKey([string] $feature.name)) { $FeatureStates[[string] $feature.name] } else { $null }

            if (-not (Test-TkOptionalFeatureState -InstallState $state -Target $feature.state)) {
                return $false
            }
        }
    }

    foreach ($capability in $capabilities) {

        # A file the capability installs is read back without rights, where
        # Get-WindowsCapability needs an administrator.
        $installed = Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables([string] $capability.installedPath))

        if ($installed -ne ($capability.state -eq 'Installed')) {
            return $false
        }
    }

    if ($audits.Count -gt 0) {

        if (-not $PSBoundParameters.ContainsKey('AuditSettings')) {
            $AuditSettings = Read-TkAuditPolicyBackup
        }

        if ($null -ne $AuditSettings) {

            foreach ($audit in $audits) {

                $guid    = ([string] $audit.subcategory).ToUpperInvariant()
                $setting = if ($AuditSettings.ContainsKey($guid)) { [int] $AuditSettings[$guid] } else { 0 }

                if (-not (Test-TkAuditSettingState -Setting $setting -Success $audit.success -Failure $audit.failure)) {
                    return $false
                }

                $checked++
            }
        }
    }

    return ($checked -gt 0)
}

<#
.SYNOPSIS
    Applies or reverts a tweak.

.DESCRIPTION
    Walks the sections of a tweak object in a fixed order: registry values and
    keys, optional features and capabilities, services, scheduled tasks, then
    the audit policy. Failures are collected rather than thrown so one
    unavailable service cannot abandon a tweak half applied.

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

    # --- Optional features and capabilities -------------------------------
    # Before services: a capability can install the very service the next
    # section sets the start-up type of, as the OpenSSH server does.
    foreach ($feature in (ConvertTo-TkArray $Tweak.optionalFeatures)) {

        $target = if ($Action -eq 'Apply') { $feature.state } else { $feature.default }

        if (-not (Set-TkOptionalFeatureState -Name $feature.name -State $target -Confirm:$false)) {
            $failures++
            $messages += ('Optional feature step failed: {0}' -f $feature.name)
        }
    }

    foreach ($capability in (ConvertTo-TkArray $Tweak.capabilities)) {

        $target = if ($Action -eq 'Apply') { $capability.state } else { $capability.default }

        if (-not (Set-TkCapabilityState -Name $capability.name -State $target -Confirm:$false)) {
            $failures++
            $messages += ('Capability step failed: {0}' -f $capability.name)
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

    # --- Audit policy -----------------------------------------------------
    foreach ($audit in (ConvertTo-TkArray $Tweak.auditPolicy)) {

        $recordSuccess = if ($Action -eq 'Apply') { $audit.success } else { $audit.defaultSuccess }
        $recordFailure = if ($Action -eq 'Apply') { $audit.failure } else { $audit.defaultFailure }

        if (-not (Set-TkAuditSubcategory -Subcategory $audit.subcategory -Success $recordSuccess -Failure $recordFailure -Confirm:$false)) {
            $failures++
            $messages += ('Audit policy step failed: {0}' -f $audit.name)
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

# ---------------------------------------------------------------------------
# Optional features, capabilities and audit policy
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Tells whether a name is safe to hand to the servicing commands.

.DESCRIPTION
    Feature and capability names come from the catalog, and the catalog is
    data: letters, digits, dots, dashes, underscores and the tildes of a
    capability name, nothing a command line could read as an option or a
    second command.

.OUTPUTS
    System.Boolean
#>
function Test-TkServicingName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Name
    )

    return ($Name -match '^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$')
}

<#
.SYNOPSIS
    Reads the install state of every optional Windows feature at once.

.DESCRIPTION
    One Win32_OptionalFeature query, which a standard user may run, where
    Get-WindowsOptionalFeature needs an administrator and takes one call per
    feature.

.OUTPUTS
    Hashtable of feature name to InstallState (1 enabled, 2 disabled, 3
    absent), or null when the query fails.
#>
function Get-TkOptionalFeatureStateTable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $table = @{}

        foreach ($feature in @(Get-CimInstance -ClassName Win32_OptionalFeature -ErrorAction Stop)) {
            $table[[string] $feature.Name] = [int] $feature.InstallState
        }

        return $table
    }
    catch {
        Write-TkLog -Level Warning -Category 'Tweaks' -Message (
            'The optional features could not be read: {0}' -f $_.Exception.Message
        )

        return $null
    }
}

<#
.SYNOPSIS
    Compares an optional feature install state with the one a tweak wants.

.PARAMETER InstallState
    From Win32_OptionalFeature, or null for a feature this build does not
    list. A feature that is not there is as disabled as one can be: nothing is
    left to remove.

.OUTPUTS
    System.Boolean
#>
function Test-TkOptionalFeatureState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $InstallState,

        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        [string] $Target
    )

    $enabled = ($null -ne $InstallState -and [int] $InstallState -eq 1)

    return $(if ($Target -eq 'Enabled') { $enabled } else { -not $enabled })
}

<#
.SYNOPSIS
    Compares an audit subcategory setting with what a tweak asks for.

.DESCRIPTION
    Only what the tweak turns on is required. Recording more, failures as well
    as successes for instance, still counts as applied: a stricter policy set
    by a domain is not a tweak half applied.

.PARAMETER Setting
    From an auditpol backup: 1 successes, 2 failures, 3 both, 0 nothing.

.OUTPUTS
    System.Boolean
#>
function Test-TkAuditSettingState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [int] $Setting,

        [Parameter(Mandatory)]
        [ValidateSet('enable', 'disable')]
        [string] $Success,

        [Parameter(Mandatory)]
        [ValidateSet('enable', 'disable')]
        [string] $Failure
    )

    if ($Success -eq 'enable' -and ($Setting -band 1) -eq 0) {
        return $false
    }

    if ($Failure -eq 'enable' -and ($Setting -band 2) -eq 0) {
        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Enables or disables an optional Windows feature without restarting.

.DESCRIPTION
    Disabling a feature this build does not have succeeds: it is already
    gone, as PowerShell 2.0 is from recent Windows 11. Enabling one it does
    not have fails, and says the edition or build is the reason.

.OUTPUTS
    System.Boolean
#>
function Set-TkOptionalFeatureState {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        [string] $State
    )

    if (-not (Test-TkServicingName -Name $Name)) {
        Write-TkLog -Level Error -Category 'Tweaks' -Message ('Refused: "{0}" is not a valid feature name.' -f $Name)
        return $false
    }

    if (-not (Assert-TkElevated -Operation ('Change the optional feature {0}' -f $Name))) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($Name, ('Set the optional feature to {0}' -f $State))) {
        return $false
    }

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
    }
    catch {
        $feature = $null
    }

    if ($null -eq $feature) {

        if ($State -eq 'Disabled') {
            Write-TkLog -Level Information -Category 'Tweaks' -Message ('{0} is not part of this build: nothing to remove.' -f $Name)
            return $true
        }

        Write-TkLog -Level Warning -Category 'Tweaks' -Message (
            '{0} is not available on this edition or build of Windows.' -f $Name
        )

        return $false
    }

    $enabled = ([string] $feature.State) -in @('Enabled', 'EnablePending')

    if ($enabled -eq ($State -eq 'Enabled')) {
        Write-TkLog -Level Information -Category 'Tweaks' -Message ('{0} is already {1}.' -f $Name, $State.ToLowerInvariant())
        return $true
    }

    try {
        if ($State -eq 'Enabled') {
            Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart -ErrorAction Stop | Out-Null
        }
        else {
            Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop | Out-Null
        }

        Write-TkLog -Level Information -Category 'Tweaks' -Message (
            '{0} {1}. A restart completes it.' -f $Name, $State.ToLowerInvariant()
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Tweaks' -Message (
            '{0} could not be {1}: {2}' -f $Name, $State.ToLowerInvariant(), $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Installs or removes a Windows capability, a feature on demand.

.DESCRIPTION
    Installing downloads the capability from Windows Update, or from the
    source a WSUS policy names, which can take a few minutes.

.OUTPUTS
    System.Boolean
#>
function Set-TkCapabilityState {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Installed', 'NotPresent')]
        [string] $State
    )

    if (-not (Test-TkServicingName -Name $Name)) {
        Write-TkLog -Level Error -Category 'Tweaks' -Message ('Refused: "{0}" is not a valid capability name.' -f $Name)
        return $false
    }

    if (-not (Assert-TkElevated -Operation ('Change the capability {0}' -f $Name))) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($Name, ('Set the capability to {0}' -f $State))) {
        return $false
    }

    try {
        $capability = Get-WindowsCapability -Online -Name $Name -ErrorAction Stop | Select-Object -First 1

        if ($null -eq $capability) {

            if ($State -eq 'NotPresent') {
                return $true
            }

            Write-TkLog -Level Warning -Category 'Tweaks' -Message ('{0} is not offered for this build of Windows.' -f $Name)
            return $false
        }

        $installed = ([string] $capability.State -eq 'Installed')

        if ($installed -eq ($State -eq 'Installed')) {
            Write-TkLog -Level Information -Category 'Tweaks' -Message ('{0} is already {1}.' -f $Name, $State)
            return $true
        }

        if ($State -eq 'Installed') {
            Add-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
        }
        else {
            Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
        }

        Write-TkLog -Level Information -Category 'Tweaks' -Message ('{0} set to {1}.' -f $Name, $State)

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'Tweaks' -Message (
            '{0} could not be set to {1}: {2}' -f $Name, $State, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Sets what one audit subcategory records.

.DESCRIPTION
    By GUID, never by name: auditpol only accepts subcategory names in the
    language of the machine.

.PARAMETER Subcategory
    The subcategory GUID, in braces.

.OUTPUTS
    System.Boolean
#>
function Set-TkAuditSubcategory {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Subcategory,

        [Parameter(Mandatory)]
        [ValidateSet('enable', 'disable')]
        [string] $Success,

        [Parameter(Mandatory)]
        [ValidateSet('enable', 'disable')]
        [string] $Failure
    )

    if ($Subcategory -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') {
        Write-TkLog -Level Error -Category 'Tweaks' -Message ('Refused: "{0}" is not an audit subcategory GUID.' -f $Subcategory)
        return $false
    }

    if (-not (Assert-TkElevated -Operation ('Change the audit subcategory {0}' -f $Subcategory))) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($Subcategory, ('Audit successes: {0}, failures: {1}' -f $Success, $Failure))) {
        return $false
    }

    $result = Invoke-TkProcess -FilePath 'auditpol.exe' `
                               -ArgumentList @('/set', ('/subcategory:{0}' -f $Subcategory), ('/success:{0}' -f $Success), ('/failure:{0}' -f $Failure)) `
                               -TimeoutSeconds 30

    if ($result.ExitCode -ne 0) {
        Write-TkLog -Level Error -Category 'Tweaks' -Message (
            'auditpol could not set {0} (exit code {1}).' -f $Subcategory, $result.ExitCode
        )
    }

    return ($result.ExitCode -eq 0)
}
