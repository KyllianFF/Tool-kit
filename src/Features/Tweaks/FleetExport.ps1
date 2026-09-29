<#
    Toolkit - Features / Tweaks: export for the fleet

    A tweak validated on one machine has to reach a hundred. This writes the
    ticked tweaks as what fleet tools take, without anyone retyping a key:

      - an Intune remediation pair: a detection script that exits 1 when the
        machine is not in the applied state, and the remediation that applies;
      - a standalone PowerShell script with -Check and -Revert, for a GPO
        startup script, an RMM or a technician;
      - a .reg file to apply, and one to revert, for the registry part.

    Every tweak declares its applied value and its value to restore, so the
    detection, the remediation and the revert agree by construction. The
    machine part (HKLM, services, tasks, features, capabilities, audit policy)
    and the account part (HKCU) are written apart: Intune runs a machine
    script as SYSTEM, and an account script with the user's credentials.

    The catalog is data: every value is checked against a strict form before
    it is written into a script, and written as a quoted literal, so an edited
    catalog cannot turn an export into a command. The scripts are plain text
    with a header naming the toolkit, the date, the tweaks and the SHA-256 of
    the body, and they download and start nothing else.
#>

<#
.SYNOPSIS
    Turns one tweak into the steps a fleet script runs, each checked.

.DESCRIPTION
    Pure. A step has a Scope (Machine or User), a Label, and the PowerShell of
    its Test (true in the applied state), Apply and Revert, plus its .reg
    lines when it is a registry step. A value that does not have the strict
    form it should refuses the whole tweak, with the reason.

.OUTPUTS
    PSCustomObject with Id, Name, Steps and Refused.
#>
function Get-TkFleetStep {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Tweak
    )

    $q      = { param($value) ConvertTo-TkPsLiteral -Value ([string] $value) }
    $steps  = New-Object System.Collections.Generic.List[object]
    $refuse = { param($why) [pscustomobject] @{ Id = [string] $Tweak.id; Name = [string] $Tweak.name; Steps = @(); Refused = $why } }
    $add    = {
        param($scope, $label, $test, $apply, $revert, $regApply, $regRevert)
        $steps.Add([pscustomobject] @{ Scope = $scope; Label = $label; Test = $test; Apply = $apply; Revert = $revert; RegApply = @($regApply); RegRevert = @($regRevert) })
    }

    $registryPath = '^(HKLM:|HKCU:|Registry::HKEY_USERS\\\.DEFAULT)\\[^\r\n\x00]+$'

    # --- Registry values -------------------------------------------------------
    foreach ($entry in (ConvertTo-TkArray $Tweak.registry)) {

        $path = [string] $entry.path
        $name = [string] $entry.name
        $type = [string] $entry.type

        if ($path -notmatch $registryPath -or $name -notmatch '^[^\r\n\x00\\]{1,255}$' -or $type -notin @('DWord', 'String')) {
            return (& $refuse ('A registry step does not have the form a script can carry: {0}\{1}.' -f $path, $name))
        }

        foreach ($value in @($entry.value, $entry.default)) {
            if ($type -eq 'DWord' -and ([string] $value -notmatch '^\d{1,10}$' -or [double] $value -gt 4294967295)) { return (& $refuse ('{0} is not a DWORD value.' -f $value)) }
            if ($type -eq 'String' -and [string] $value -match '[\r\n\x00]') { return (& $refuse 'A string value holds a line break.') }
        }

        $scope   = if ($path -like 'HKCU:*') { 'User' } else { 'Machine' }
        $literal = { param($value) if ($type -eq 'DWord') { [string] ([uint32] $value) } else { & $q $value } }
        $delete  = ($entry.PSObject.Properties.Name -contains 'defaultAction' -and $entry.defaultAction -eq 'delete')
        $label   = '{0}\{1} = {2}' -f $path, $name, $entry.value

        $revert = if ($delete) { 'Remove-FleetValue -Path {0} -Name {1}' -f (& $q $path), (& $q $name) }
                  else { 'Set-FleetValue -Path {0} -Name {1} -Type {2} -Value {3}' -f (& $q $path), (& $q $name), $type, (& $literal $entry.default) }

        $regKey   = ConvertTo-TkRegKeyName -Path $path
        $regValue = { param($value) if ($type -eq 'DWord') { 'dword:{0:x8}' -f ([uint32] $value) } else { '"{0}"' -f (([string] $value) -replace '\\', '\\' -replace '"', '\"') } }
        $regName  = '"{0}"' -f ($name -replace '\\', '\\' -replace '"', '\"')

        & $add $scope $label `
            ('Test-FleetValue -Path {0} -Name {1} -Value {2}' -f (& $q $path), (& $q $name), (& $literal $entry.value)) `
            ('Set-FleetValue -Path {0} -Name {1} -Type {2} -Value {3}' -f (& $q $path), (& $q $name), $type, (& $literal $entry.value)) `
            $revert `
            @(('[{0}]' -f $regKey), ('{0}={1}' -f $regName, (& $regValue $entry.value))) `
            @(('[{0}]' -f $regKey), $(if ($delete) { '{0}=-' -f $regName } else { '{0}={1}' -f $regName, (& $regValue $entry.default) }))
    }

    # --- Whole registry keys ------------------------------------------------------
    foreach ($key in (ConvertTo-TkArray $Tweak.registryKeys)) {

        $path = [string] $key.path

        if ($path -notmatch $registryPath -or [string] $key.applyAction -notin @('create', 'delete') -or [string] $key.revertAction -notin @('create', 'delete') -or [string] $key.defaultValue -match '[\r\n\x00]') {
            return (& $refuse ('A registry key step does not have the form a script can carry: {0}.' -f $path))
        }

        $scope   = if ($path -like 'HKCU:*') { 'User' } else { 'Machine' }
        $present = { param($action) if ($action -eq 'create') { '$true' } else { '$false' } }
        $regKey  = ConvertTo-TkRegKeyName -Path $path
        $reg     = { param($action) if ($action -eq 'create') { @(('[{0}]' -f $regKey), ('@="{0}"' -f (([string] $key.defaultValue) -replace '\\', '\\' -replace '"', '\"'))) } else { @('[-{0}]' -f $regKey) } }

        & $add $scope ('Key {0} {1}' -f $path, $(if ($key.applyAction -eq 'create') { 'present' } else { 'absent' })) `
            ('Test-FleetKey -Path {0} -Present {1}' -f (& $q $path), (& $present $key.applyAction)) `
            ('Set-FleetKey -Path {0} -Present {1} -Default {2}' -f (& $q $path), (& $present $key.applyAction), (& $q $key.defaultValue)) `
            ('Set-FleetKey -Path {0} -Present {1} -Default {2}' -f (& $q $path), (& $present $key.revertAction), (& $q $key.defaultValue)) `
            (& $reg $key.applyAction) (& $reg $key.revertAction)
    }

    # --- Optional features and capabilities, before services ------------------------
    foreach ($feature in (ConvertTo-TkArray $Tweak.optionalFeatures)) {
        if ([string] $feature.name -notmatch '^[A-Za-z0-9._~-]+$' -or [string] $feature.state -notin @('Enabled', 'Disabled') -or [string] $feature.default -notin @('Enabled', 'Disabled')) {
            return (& $refuse ('An optional feature step does not have the form a script can carry: {0}.' -f $feature.name))
        }
        & $add 'Machine' ('Optional feature {0} {1}' -f $feature.name, $feature.state.ToLowerInvariant()) `
            ('Test-FleetFeature -Name {0} -State {1}' -f (& $q $feature.name), $feature.state) `
            ('Set-FleetFeature -Name {0} -State {1}' -f (& $q $feature.name), $feature.state) `
            ('Set-FleetFeature -Name {0} -State {1}' -f (& $q $feature.name), $feature.default) @() @()
    }

    foreach ($capability in (ConvertTo-TkArray $Tweak.capabilities)) {
        if ([string] $capability.name -notmatch '^[A-Za-z0-9._~-]+$' -or [string] $capability.state -notin @('Installed', 'NotPresent') -or [string] $capability.default -notin @('Installed', 'NotPresent')) {
            return (& $refuse ('A capability step does not have the form a script can carry: {0}.' -f $capability.name))
        }
        & $add 'Machine' ('Capability {0} {1}' -f $capability.name, $capability.state.ToLowerInvariant()) `
            ('Test-FleetCapability -Name {0} -State {1}' -f (& $q $capability.name), $capability.state) `
            ('Set-FleetCapability -Name {0} -State {1}' -f (& $q $capability.name), $capability.state) `
            ('Set-FleetCapability -Name {0} -State {1}' -f (& $q $capability.name), $capability.default) @() @()
    }

    # --- Services -------------------------------------------------------------------------
    foreach ($service in (ConvertTo-TkArray $Tweak.services)) {
        $allowed = @('Automatic', 'AutomaticDelayed', 'Manual', 'Disabled')
        if ([string] $service.name -notmatch '^[A-Za-z0-9_.-]+$' -or [string] $service.startup -notin $allowed -or [string] $service.default -notin $allowed) {
            return (& $refuse ('A service step does not have the form a script can carry: {0}.' -f $service.name))
        }
        & $add 'Machine' ('Service {0} {1}' -f $service.name, $service.startup) `
            ('Test-FleetService -Name {0} -StartupType {1}' -f (& $q $service.name), $service.startup) `
            ('Set-FleetService -Name {0} -StartupType {1}' -f (& $q $service.name), $service.startup) `
            ('Set-FleetService -Name {0} -StartupType {1}' -f (& $q $service.name), $service.default) @() @()
    }

    # --- Scheduled tasks: disabled by the tweak, enabled again by its revert -------------
    foreach ($task in (ConvertTo-TkArray $Tweak.scheduledTasks)) {
        $full = [string] $task
        if ($full -notmatch '^\\([^\\\r\n"\x00]+\\)*[^\\\r\n"\x00]+$') {
            return (& $refuse ('A scheduled task step does not have the form a script can carry: {0}.' -f $full))
        }
        $cut  = $full.LastIndexOf('\')
        $path = $full.Substring(0, $cut + 1)
        $name = $full.Substring($cut + 1)
        & $add 'Machine' ('Task {0} disabled' -f $full) `
            ('Test-FleetTask -Path {0} -Name {1} -Enabled $false' -f (& $q $path), (& $q $name)) `
            ('Set-FleetTask -Path {0} -Name {1} -Enabled $false' -f (& $q $path), (& $q $name)) `
            ('Set-FleetTask -Path {0} -Name {1} -Enabled $true' -f (& $q $path), (& $q $name)) @() @()
    }

    # --- Audit policy, by subcategory GUID ---------------------------------------------------
    foreach ($audit in (ConvertTo-TkArray $Tweak.auditPolicy)) {
        $values = @($audit.success, $audit.failure, $audit.defaultSuccess, $audit.defaultFailure)
        if ([string] $audit.subcategory -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$' -or @($values | Where-Object { [string] $_ -notin @('enable', 'disable') }).Count -gt 0) {
            return (& $refuse ('An audit policy step does not have the form a script can carry: {0}.' -f $audit.name))
        }
        & $add 'Machine' ('Audit {0}: successes {1}, failures {2}' -f $audit.name, $audit.success, $audit.failure) `
            ('Test-FleetAudit -Guid {0} -Success {1} -Failure {2}' -f (& $q $audit.subcategory), $audit.success, $audit.failure) `
            ('Set-FleetAudit -Guid {0} -Success {1} -Failure {2}' -f (& $q $audit.subcategory), $audit.success, $audit.failure) `
            ('Set-FleetAudit -Guid {0} -Success {1} -Failure {2}' -f (& $q $audit.subcategory), $audit.defaultSuccess, $audit.defaultFailure) @() @()
    }

    return [pscustomobject] @{ Id = [string] $Tweak.id; Name = [string] $Tweak.name; Steps = @($steps.ToArray()); Refused = '' }
}

<#
.SYNOPSIS
    The key name a .reg file writes for a PowerShell registry path.

.OUTPUTS
    System.String
#>
function ConvertTo-TkRegKeyName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    switch -Regex ($Path) {
        '^HKLM:\\(.+)$'     { return 'HKEY_LOCAL_MACHINE\' + $Matches[1] }
        '^HKCU:\\(.+)$'     { return 'HKEY_CURRENT_USER\' + $Matches[1] }
        '^Registry::(.+)$'  { return $Matches[1] }
        default             { return $Path }
    }
}

<#
.SYNOPSIS
    The functions every fleet script carries, so it depends on nothing but Windows.

.OUTPUTS
    System.String
#>
function Get-TkFleetRuntime {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
function Set-FleetValue {
    param([string] $Path, [string] $Name, [string] $Type, $Value)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Remove-FleetValue {
    param([string] $Path, [string] $Name)
    if (Test-Path -LiteralPath $Path) { Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue }
}

function Test-FleetValue {
    param([string] $Path, [string] $Name, $Value)
    try { $actual = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $false }
    # A DWORD over 2147483647 reads back as a negative Int32.
    if ($actual -is [int] -and $actual -lt 0) { $actual = [int64] $actual + 4294967296 }
    return ([string] $actual -eq [string] $Value)
}

function Set-FleetKey {
    param([string] $Path, [bool] $Present, [string] $Default)
    if ($Present) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -LiteralPath $Path -Name '(Default)' -Value $Default
    }
    elseif (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Test-FleetKey {
    param([string] $Path, [bool] $Present)
    return ((Test-Path -LiteralPath $Path) -eq $Present)
}

function Set-FleetService {
    param([string] $Name, [string] $StartupType)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { return }
    if ($StartupType -eq 'Disabled' -and $service.Status -eq 'Running') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
    if ($StartupType -eq 'AutomaticDelayed') {
        Set-Service -Name $Name -StartupType Automatic
        Set-FleetValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $Name) -Name 'DelayedAutostart' -Type DWord -Value 1
    }
    else {
        Set-Service -Name $Name -StartupType $StartupType
    }
}

function Test-FleetService {
    param([string] $Name, [string] $StartupType)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { return $true }
    $wanted = if ($StartupType -eq 'AutomaticDelayed') { 'Automatic' } else { $StartupType }
    return ([string] $service.StartType -eq $wanted)
}

function Set-FleetTask {
    param([string] $Path, [string] $Name, [bool] $Enabled)
    $task = Get-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) { return }
    if ($Enabled) { Enable-ScheduledTask -InputObject $task | Out-Null } else { Disable-ScheduledTask -InputObject $task | Out-Null }
}

function Test-FleetTask {
    param([string] $Path, [string] $Name, [bool] $Enabled)
    $task = Get-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) { return $true }
    return (([string] $task.State -ne 'Disabled') -eq $Enabled)
}

function Set-FleetFeature {
    param([string] $Name, [string] $State)
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue
    if (-not $feature) { if ($State -eq 'Enabled') { throw ('{0} is not available on this edition of Windows.' -f $Name) }; return }
    if ($State -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart | Out-Null }
    else { Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart | Out-Null }
}

function Test-FleetFeature {
    param([string] $Name, [string] $State)
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue
    $enabled = $feature -and ([string] $feature.State -in @('Enabled', 'EnablePending'))
    return ($enabled -eq ($State -eq 'Enabled'))
}

function Set-FleetCapability {
    param([string] $Name, [string] $State)
    if ($State -eq 'Installed') { Add-WindowsCapability -Online -Name $Name | Out-Null }
    elseif (Get-WindowsCapability -Online -Name $Name | Where-Object { [string] $_.State -eq 'Installed' }) { Remove-WindowsCapability -Online -Name $Name | Out-Null }
}

function Test-FleetCapability {
    param([string] $Name, [string] $State)
    $installed = [bool] (Get-WindowsCapability -Online -Name $Name -ErrorAction SilentlyContinue | Where-Object { [string] $_.State -eq 'Installed' })
    return ($installed -eq ($State -eq 'Installed'))
}

function Set-FleetAudit {
    param([string] $Guid, [string] $Success, [string] $Failure)
    & auditpol.exe /set ('/subcategory:{0}' -f $Guid) ('/success:{0}' -f $Success) ('/failure:{0}' -f $Failure) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('auditpol could not set {0} (exit code {1}).' -f $Guid, $LASTEXITCODE) }
}

function Test-FleetAudit {
    param([string] $Guid, [string] $Success, [string] $Failure)
    # A backup names the subcategory by GUID and ends each row in a number
    # (1 successes, 2 failures, 3 both), whatever the language of Windows.
    $file = Join-Path $env:SystemRoot ('Temp\fleet-auditpol-{0}.csv' -f [guid]::NewGuid())
    try {
        & auditpol.exe /backup ('/file:{0}' -f $file) | Out-Null
        $row = @(Get-Content -LiteralPath $file -ErrorAction Stop | Where-Object { $_ -match [regex]::Escape($Guid) }) | Select-Object -First 1
        $have = if ($row) { [int] (($row.TrimEnd() -split ',')[-1]) } else { 0 }
    }
    catch { return $false }
    finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    $want = $(if ($Success -eq 'enable') { 1 } else { 0 }) + $(if ($Failure -eq 'enable') { 2 } else { 0 })
    return ($have -eq $want)
}
'@
}

<#
.SYNOPSIS
    Writes one fleet script: detection, remediation or standalone.

.DESCRIPTION
    Pure. The header names the toolkit, the date, the tweaks, the scope and
    the SHA-256 of what follows the header, so a reviewer can tell the body
    was not changed after it was generated.

.OUTPUTS
    System.String
#>
function New-TkFleetScript {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Step,
        [Parameter(Mandatory)] [ValidateSet('Detect', 'Remediate', 'Standalone')] [string] $Kind,
        [Parameter(Mandatory)] [ValidateSet('Machine', 'User')] [string] $Scope,
        [Parameter(Mandatory)] [string[]] $TweakName,
        [Parameter()] [string] $Toolkit = ('{0} {1} ({2})' -f (Get-TkContext).AppName, (Get-TkContext).Version, (Get-TkContext).Commit),
        [Parameter()] [datetime] $When = (Get-Date)
    )

    $nl   = "`r`n"
    $body = New-Object System.Text.StringBuilder

    if ($Kind -eq 'Standalone') {
        [void] $body.Append('[CmdletBinding()]' + $nl + 'param(' + $nl + '    # Says whether each step is in the applied state, and changes nothing.' + $nl + '    [switch] $Check,' + $nl + $nl + '    # Puts back the state before the tweaks.' + $nl + '    [switch] $Revert' + $nl + ')' + $nl + $nl)
    }

    [void] $body.Append('$ErrorActionPreference = ''Stop''' + $nl + $nl + (Get-TkFleetRuntime) + $nl + $nl)
    [void] $body.Append('$steps = @(' + $nl)

    foreach ($item in $Step) {
        [void] $body.Append(('    @{{ Label = {0}; Test = {{ {1} }}; Apply = {{ {2} }}; Revert = {{ {3} }} }}' -f (ConvertTo-TkPsLiteral -Value $item.Label), $item.Test, $item.Apply, $item.Revert) + $nl)
    }

    [void] $body.Append(')' + $nl + $nl)

    switch ($Kind) {
        'Detect' {
            [void] $body.Append(@'
$missing = @($steps | Where-Object { -not (& $_.Test) } | ForEach-Object { $_.Label })

if ($missing.Count -gt 0) {
    Write-Output ('Not in the applied state: {0}' -f ($missing -join '; '))
    exit 1
}

Write-Output 'In the applied state.'
exit 0
'@)
        }

        'Remediate' {
            [void] $body.Append(@'
$failed = 0

foreach ($step in $steps) {
    try {
        & $step.Apply
        Write-Output ('Done: {0}' -f $step.Label)
    }
    catch {
        $failed++
        Write-Output ('Failed: {0}: {1}' -f $step.Label, $_.Exception.Message)
    }
}

exit $(if ($failed -gt 0) { 1 } else { 0 })

# To roll back, run the standalone script of this export with -Revert.
'@)
        }

        'Standalone' {
            [void] $body.Append(@'
if ($Check) {
    $missing = 0
    foreach ($step in $steps) {
        $applied = [bool] (& $step.Test)
        if (-not $applied) { $missing++ }
        Write-Output ('{0}: {1}' -f $(if ($applied) { 'Applied' } else { 'Not applied' }), $step.Label)
    }
    exit $(if ($missing -gt 0) { 1 } else { 0 })
}

$failed = 0

foreach ($step in $steps) {
    try {
        if ($Revert) { & $step.Revert } else { & $step.Apply }
        Write-Output ('{0}: {1}' -f $(if ($Revert) { 'Reverted' } else { 'Applied' }), $step.Label)
    }
    catch {
        $failed++
        Write-Output ('Failed: {0}: {1}' -f $step.Label, $_.Exception.Message)
    }
}

exit $(if ($failed -gt 0) { 1 } else { 0 })
'@)
        }
    }

    $text    = $body.ToString().Replace("`r`n", "`n").Replace("`n", "`r`n")
    $runsAs  = if ($Scope -eq 'Machine') { 'SYSTEM or an administrator (Intune: run this script using the logged-on credentials = No)' } else { 'the signed-in user (Intune: run this script using the logged-on credentials = Yes)' }
    $purpose = switch ($Kind) { 'Detect' { 'Intune detection: exit 1 when a step is not in the applied state.' } 'Remediate' { 'Intune remediation: applies every step.' } default { 'Standalone: applies every step; -Check says which are applied; -Revert puts them back.' } }

    $header = @(
        '<#'
        ('    {0}' -f $purpose)
        ('    Tweaks: {0}' -f ($TweakName -join ', '))
        ('    Scope: {0}; runs as {1}.' -f $Scope.ToLowerInvariant(), $runsAs)
        ('    Generated by {0} on {1}.' -f $Toolkit, $When.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture))
        ('    Body SHA-256: {0}' -f (Get-TkTextSha256 -Text $text))
        '    Plain text: it downloads and starts nothing else. Read it before deploying it.'
        '#>'
    ) -join "`r`n"

    if ($Scope -eq 'Machine' -and $Kind -eq 'Standalone') {
        $header += "`r`n#Requires -RunAsAdministrator"
    }

    return $header + "`r`n" + $text
}

<#
.SYNOPSIS
    The SHA-256 of a text, as a fleet script's header records it.

.OUTPUTS
    System.String, upper case hexadecimal.
#>
function Get-TkTextSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        return ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '')
    }
    finally {
        $sha.Dispose()
    }
}

<#
.SYNOPSIS
    Writes the registry part of the steps as a .reg file, to apply or to revert.

.OUTPUTS
    System.String, or empty when no step touches the registry.
#>
function ConvertTo-TkFleetReg {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Step,
        [Parameter()] [switch] $Revert,
        [Parameter(Mandatory)] [string[]] $TweakName,
        [Parameter()] [datetime] $When = (Get-Date)
    )

    $lines = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Step) {
        $block = if ($Revert) { @($item.RegRevert) } else { @($item.RegApply) }
        foreach ($line in @($block | Where-Object { $_ })) { $lines.Add($line) }
    }

    if ($lines.Count -eq 0) {
        return ''
    }

    $other = @($Step | Where-Object { @($_.RegApply).Count -eq 0 }).Count

    $text = New-Object System.Collections.Generic.List[string]
    $text.Add('Windows Registry Editor Version 5.00')
    $text.Add('')
    $text.Add(('; {0} the tweaks: {1}' -f $(if ($Revert) { 'Reverts' } else { 'Applies' }), ($TweakName -join ', ')))
    $text.Add(('; Generated by the toolkit on {0}. Only the registry part.' -f $When.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)))
    if ($other -gt 0) {
        $text.Add(('; {0} other step(s) (services, tasks, features, capabilities, audit policy) are in the PowerShell scripts only.' -f $other))
    }

    $current = ''
    foreach ($line in $lines) {
        if ($line.StartsWith('[')) {
            if ($line -eq $current -and -not $line.StartsWith('[-')) { continue }
            $text.Add('')
            $current = $line
        }
        $text.Add($line)
    }

    return (($text.ToArray()) -join "`r`n") + "`r`n"
}

<#
.SYNOPSIS
    Writes the export of the ticked tweaks for the fleet into a new folder.

.DESCRIPTION
    One set per scope that has steps: machine and user. Each set is an
    Intune detection script, its remediation, a standalone script and, for
    the registry part, a .reg file to apply and one to revert. A README says
    what each file is and how to deploy it. A tweak whose catalog entry does
    not have the form a script can carry is left out and named.

.OUTPUTS
    PSCustomObject with Folder, Files, Exported and Refused.
#>
function Export-TkFleetPackage {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Tweak,
        [Parameter(Mandatory)] [string] $Folder
    )

    $converted = @($Tweak | ForEach-Object { Get-TkFleetStep -Tweak $_ })
    $exported  = @($converted | Where-Object { -not $_.Refused })
    $refused   = @($converted | Where-Object { $_.Refused })
    $when      = Get-Date
    $target    = [System.IO.Path]::Combine($Folder, ('toolkit-fleet-{0}' -f $when.ToString('yyyyMMdd-HHmmss')))
    $files     = New-Object System.Collections.Generic.List[string]

    if ($exported.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($target, 'Write the fleet scripts')) {
        return [pscustomobject] @{ Folder = ''; Files = @(); Exported = @(); Refused = @($refused) }
    }

    New-Item -ItemType Directory -Path $target -Force | Out-Null

    $utf8    = New-Object System.Text.UTF8Encoding($true)
    $unicode = New-Object System.Text.UnicodeEncoding($false, $true)
    $write   = { param($name, $content, $encoding) $path = [System.IO.Path]::Combine($target, $name); [System.IO.File]::WriteAllText($path, $content, $encoding); $files.Add($path) }
    $readme  = New-Object System.Collections.Generic.List[string]

    $readme.Add(('Fleet export of {0} tweak(s), written by the toolkit on {1}.' -f $exported.Count, $when.ToString('yyyy-MM-dd HH:mm')))
    $readme.Add('')

    foreach ($scope in @('Machine', 'User')) {

        $steps = @($exported | ForEach-Object { $_.Steps } | Where-Object { $_.Scope -eq $scope })
        if ($steps.Count -eq 0) { continue }

        $names = @($exported | Where-Object { @($_.Steps | Where-Object { $_.Scope -eq $scope }).Count -gt 0 } | ForEach-Object { $_.Name })
        $stem  = 'toolkit-{0}' -f $scope.ToLowerInvariant()

        & $write ('{0}-detect.ps1' -f $stem)    (New-TkFleetScript -Step $steps -Kind Detect -Scope $scope -TweakName $names -When $when) $utf8
        & $write ('{0}-remediate.ps1' -f $stem) (New-TkFleetScript -Step $steps -Kind Remediate -Scope $scope -TweakName $names -When $when) $utf8
        & $write ('{0}.ps1' -f $stem)           (New-TkFleetScript -Step $steps -Kind Standalone -Scope $scope -TweakName $names -When $when) $utf8

        $apply = ConvertTo-TkFleetReg -Step $steps -TweakName $names -When $when
        if ($apply) {
            & $write ('{0}.reg' -f $stem)        $apply $unicode
            & $write ('{0}-revert.reg' -f $stem) (ConvertTo-TkFleetReg -Step $steps -Revert -TweakName $names -When $when) $unicode
        }

        $readme.Add(('{0} part ({1} step(s)): {2}' -f $scope, $steps.Count, ($names -join ', ')))
        $readme.Add(('  {0}-detect.ps1 and {0}-remediate.ps1: an Intune remediation (Devices, Scripts and remediations). Run with the logged-on credentials: {1}. Run in 64-bit PowerShell: Yes.' -f $stem, $(if ($scope -eq 'User') { 'Yes' } else { 'No' })))
        $readme.Add(('  {0}.ps1: the same steps for a GPO {1} script, an RMM or by hand; -Check says which are applied, -Revert puts them back.' -f $stem, $(if ($scope -eq 'User') { 'logon' } else { 'startup' })))
        if ($apply) { $readme.Add(('  {0}.reg and {0}-revert.reg: the registry part only.' -f $stem)) }
        $readme.Add('')
    }

    if ($refused.Count -gt 0) {
        $readme.Add('Left out:')
        foreach ($item in $refused) { $readme.Add(('  {0}: {1}' -f $item.Name, $item.Refused)) }
        $readme.Add('')
    }

    $readme.Add('Each script names the SHA-256 of its body in its header. Sign them with your code signing certificate before deploying where scripts must be signed.')
    & $write 'README.txt' (($readme.ToArray()) -join "`r`n") $utf8

    return [pscustomobject] @{ Folder = $target; Files = @($files.ToArray()); Exported = @($exported); Refused = @($refused) }
}
