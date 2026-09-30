<#
    Toolkit - Features / Impact before hardening

    The hardenings that help most - restricting NTLM, removing SMBv1,
    protecting LSA, removing PowerShell 2.0 - now and then break an
    application, and without proof they are not applied. Windows has an audit
    mode for most of them: it records what the hardening would have refused,
    and changes nothing else. This file turns those modes on and off, and
    reads what they recorded.

    Turning one on writes only the documented audit values. A value already
    as strict or stricter is kept as it is, and what was replaced is
    recorded, so turning it off puts back exactly what was there. The record
    is kept under HKLM, where only an administrator writes. A log too small
    to hold a few days is enlarged, and put back afterwards.

    A report never says "no use seen" for a mode that is not on, nor for days
    the log no longer holds.
#>

# The least size of a log that has to hold several days of audit events.
$script:TkImpactLogBytes = 33554432

# Where the record of what was turned on, and what it replaced, is kept.
$script:TkImpactStateKey = 'HKLM:\SOFTWARE\Toolkit'

<#
.SYNOPSIS
    The audit modes the toolkit can measure with, one per hardening.

.DESCRIPTION
    Settings are the audit values written to turn the mode on. Keep lists the
    values already as strict or stricter, which are left alone; Restore lists
    the only values turning it off may write back. Hardened names the values
    that mean the hardening itself is already in place, so there is nothing
    left to measure.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkImpactProbe {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

    return @(
        [pscustomobject] @{
            Id           = 'ntlm'
            Name         = 'NTLM'
            Hardening    = 'Restricting NTLM'
            Action       = 'restricting NTLM'
            Control      = 'NET-002'
            Description  = 'Records each NTLM authentication this machine sends or accepts that a restriction would refuse, with the server or the process behind it.'
            Settings     = @(
                [pscustomobject] @{ Path = $msv; Name = 'AuditReceivingNTLMTraffic';  Value = 2; Keep = @(2);    Restore = @(0, 1) }
                [pscustomobject] @{ Path = $msv; Name = 'RestrictSendingNTLMTraffic'; Value = 1; Keep = @(1, 2); Restore = @(0) }
            )
            Hardened     = @(
                [pscustomobject] @{ Path = $msv; Name = 'RestrictSendingNTLMTraffic';   Values = @(2) }
                [pscustomobject] @{ Path = $msv; Name = 'RestrictReceivingNTLMTraffic'; Values = @(2) }
            )
            LogName      = 'Microsoft-Windows-NTLM/Operational'
            EventIds     = @(8001, 8002)
            NeedsRestart = $false
        }
        [pscustomobject] @{
            Id           = 'smb1'
            Name         = 'SMBv1'
            Hardening    = 'Removing SMBv1'
            Action       = 'removing SMBv1'
            Control      = 'SMB-001'
            Description  = 'Records each client that still connects to this machine with SMBv1, by its address.'
            Settings     = @(
                [pscustomobject] @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AuditSmb1Access'; Value = 1; Keep = @(1); Restore = @(0) }
            )
            Hardened     = @(
                [pscustomobject] @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Values = @(0) }
            )
            LogName      = 'Microsoft-Windows-SMBServer/Audit'
            EventIds     = @(3000)
            NeedsRestart = $false
        }
        [pscustomobject] @{
            Id           = 'lsa'
            Name         = 'LSA protection'
            Hardening    = 'Protecting LSA (RunAsPPL)'
            Action       = 'protecting LSA'
            Control      = 'CRED-002'
            Description  = 'Records each module loaded into LSASS that protection would refuse: an unsigned plug-in, a smart card or password filter driver. It takes effect after the next restart.'
            Settings     = @(
                [pscustomobject] @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe'; Name = 'AuditLevel'; Value = 8; Keep = @(8); Restore = @(0) }
            )
            Hardened     = @(
                [pscustomobject] @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL'; Values = @(1, 2) }
            )
            LogName      = 'Microsoft-Windows-CodeIntegrity/Operational'
            EventIds     = @(3065, 3066)
            NeedsRestart = $true
        }
        [pscustomobject] @{
            Id           = 'ps2'
            Name         = 'PowerShell 2.0'
            Hardening    = 'Removing PowerShell 2.0'
            Action       = 'removing PowerShell 2.0'
            Control      = 'PS-001'
            Description  = 'Windows PowerShell records every engine start with its version: the starts of the 2.0 engine are what its removal would stop. There is nothing to turn on.'
            Settings     = @()
            Hardened     = @()
            LogName      = 'Windows PowerShell'
            EventIds     = @(400)
            NeedsRestart = $false
        }
    )
}

<#
.SYNOPSIS
    Reads one DWORD value; null when it or its key is missing.
#>
function Get-TkImpactValue {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return [long] $item.$Name
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Writes one DWORD value, or removes it when the value is null.
#>
function Set-TkImpactValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [AllowNull()] $Value
    )

    if (-not $PSCmdlet.ShouldProcess(('{0}\{1}' -f $Path, $Name), $(if ($null -eq $Value) { 'Remove' } else { 'Set to {0}' -f $Value }))) {
        return
    }

    if ($null -eq $Value) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $Path -Name $Name -Value ([int] $Value) -PropertyType DWord -Force | Out-Null
}

<#
.SYNOPSIS
    Reads whether a log is enabled and how large it may grow.

.OUTPUTS
    PSCustomObject with Readable, Enabled, MaxBytes, Records and Reason.
#>
function Get-TkImpactLog {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $LogName
    )

    try {
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return [pscustomobject] @{ Readable = $true; Enabled = [bool] $log.IsEnabled; MaxBytes = [long] $log.MaximumSizeInBytes; Records = [long] $log.RecordCount; Reason = '' }
    }
    catch {
        $denied = $_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)unauthori|denied|refus|non autoris'
        return [pscustomobject] @{
            Readable = $false; Enabled = $false; MaxBytes = 0; Records = 0
            Reason   = $(if ($denied) { 'The log needs administrator rights to be read.' } else { $_.Exception.Message })
        }
    }
}

<#
.SYNOPSIS
    Enables a log and sets its largest size.
#>
function Set-TkImpactLog {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $LogName,
        [Parameter(Mandatory)] [bool] $Enabled,
        [Parameter()] [long] $MaxBytes = 0
    )

    if (-not $PSCmdlet.ShouldProcess($LogName, 'Configure the log')) {
        return
    }

    $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)

    try {
        $config.IsEnabled = $Enabled
        if ($MaxBytes -gt 0) { $config.MaximumSizeInBytes = $MaxBytes }
        $config.SaveChanges()
    }
    finally {
        $config.Dispose()
    }
}

<#
.SYNOPSIS
    The record of the measurements, from its JSON text.

.DESCRIPTION
    Pure. A missing or broken record is an empty one. Started stays the text
    it was written as: PowerShell 7 would turn it into a date on its own, and
    Windows PowerShell 5.1 would not.

.OUTPUTS
    System.Collections.Hashtable, probe id to its record.
#>
function ConvertFrom-TkImpactStateText {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $state = @{}

    if (-not $Text.Trim()) {
        return $state
    }

    try {
        $data = ConvertFrom-Json -InputObject $Text -ErrorAction Stop
    }
    catch {
        return $state
    }

    foreach ($property in @($data.PSObject.Properties)) {
        $record = $property.Value
        if ($record -and $record.PSObject.Properties['Started'] -and $record.Started -is [datetime]) {
            $record.Started = ([datetime] $record.Started).ToString('o')
        }
        $state[[string] $property.Name] = $record
    }

    return $state
}

<#
.SYNOPSIS
    The record of the measurements, as the JSON text it is kept as.
#>
function ConvertTo-TkImpactStateText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable] $State
    )

    if ($State.Count -eq 0) {
        return ''
    }

    return (ConvertTo-Json -InputObject $State -Depth 6 -Compress)
}

<#
.SYNOPSIS
    Reads the record of the measurements the toolkit turned on.

.OUTPUTS
    System.Collections.Hashtable, probe id to its record; empty when none.
#>
function Read-TkImpactState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $text = [string] (Get-ItemProperty -LiteralPath $script:TkImpactStateKey -Name 'ImpactMeasurements' -ErrorAction Stop).ImpactMeasurements
    }
    catch {
        return @{}
    }

    return (ConvertFrom-TkImpactStateText -Text $text)
}

<#
.SYNOPSIS
    Saves the record of the measurements the toolkit turned on.
#>
function Write-TkImpactState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable] $State
    )

    if (-not $PSCmdlet.ShouldProcess($script:TkImpactStateKey, 'Record the measurements')) {
        return
    }

    if ($State.Count -eq 0) {
        Remove-ItemProperty -LiteralPath $script:TkImpactStateKey -Name 'ImpactMeasurements' -ErrorAction SilentlyContinue
        return
    }

    if (-not (Test-Path -LiteralPath $script:TkImpactStateKey)) {
        New-Item -Path $script:TkImpactStateKey -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $script:TkImpactStateKey -Name 'ImpactMeasurements' -PropertyType String -Force `
        -Value (ConvertTo-TkImpactStateText -State $State) | Out-Null
}

<#
.SYNOPSIS
    Says what turning a mode on would write, and what it would keep.

.DESCRIPTION
    Pure. A value already as strict as the audit value or stricter is kept:
    a machine that already refuses NTLM must not be put back to auditing it.

.PARAMETER Current
    The current values, by name; null for a value that is not set.

.OUTPUTS
    PSCustomObject[] with Path, Name, Value, Set, Existed and Previous.
#>
function Get-TkImpactPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Probe,
        [Parameter(Mandatory)] [hashtable] $Current
    )

    return @(foreach ($setting in @($Probe.Settings)) {
        $now  = $Current[$setting.Name]
        $keep = ($null -ne $now) -and (@($setting.Keep) -contains [long] $now)

        [pscustomobject] @{
            Path     = $setting.Path
            Name     = $setting.Name
            Value    = $setting.Value
            Set      = -not $keep
            Existed  = ($null -ne $now)
            Previous = $now
        }
    })
}

<#
.SYNOPSIS
    Says what turning a mode off does with one value it had recorded.

.DESCRIPTION
    Pure. A value the toolkit did not set is left alone, and so is one that
    changed since. Otherwise the recorded value is written back, or the value
    removed when there was none; a recorded value that the toolkit could not
    have replaced, which only a changed record would hold, is removed rather
    than written.

.OUTPUTS
    PSCustomObject with Action (Leave, Restore, Remove), Value and Reason.
#>
function Get-TkImpactRestore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Setting,
        [Parameter(Mandatory)] $Record,
        [Parameter()] [AllowNull()] $Current
    )

    $result = { param($action, $value, $reason) [pscustomobject] @{ Action = $action; Value = $value; Reason = $reason } }

    if (-not $Record.Set) {
        return (& $result 'Leave' $null ('{0} was already {1} and was left as it was.' -f $Setting.Name, $Record.Previous))
    }

    if ($null -eq $Current -or [long] $Current -ne [long] $Setting.Value) {
        return (& $result 'Leave' $null ('{0} changed since it was turned on, and was left as it is now.' -f $Setting.Name))
    }

    if (-not $Record.Existed -or $null -eq $Record.Previous) {
        return (& $result 'Remove' $null ('{0} was not set before, and was removed.' -f $Setting.Name))
    }

    if (@($Setting.Restore) -contains [long] $Record.Previous) {
        return (& $result 'Restore' ([long] $Record.Previous) ('{0} was put back to {1}.' -f $Setting.Name, $Record.Previous))
    }

    return (& $result 'Remove' $null ('{0}: the recorded value {1} is not one the toolkit could have replaced, so the value was removed rather than written.' -f $Setting.Name, $Record.Previous))
}

<#
.SYNOPSIS
    Says whether the hardening a probe prepares is already in place.
#>
function Test-TkImpactHardened {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Probe
    )

    $checks = @($Probe.Hardened)

    if ($checks.Count -eq 0) {
        return $false
    }

    foreach ($check in $checks) {
        $value = Get-TkImpactValue -Path $check.Path -Name $check.Name
        if ($null -eq $value -or @($check.Values) -notcontains [long] $value) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Turns an audit mode on, recording what it replaces.

.DESCRIPTION
    Needs administrator rights. Refused for a hardening already in place and
    for PowerShell 2.0, which needs no mode. The log is enabled, and enlarged
    to 32 MB when it is smaller. Journaled with what was changed.

.OUTPUTS
    PSCustomObject with Ok and Message.
#>
function Start-TkImpactMeasurement {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $done  = { param($ok, $message) [pscustomobject] @{ Ok = $ok; Message = $message } }
    $probe = @(Get-TkImpactProbe | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1

    if (-not $probe) {
        return (& $done $false ('There is no measurement named {0}.' -f $Id))
    }

    if (@($probe.Settings).Count -eq 0) {
        return (& $done $false ('{0} needs nothing turned on: {1}' -f $probe.Name, $probe.Description))
    }

    if (-not (Test-TkIsElevated)) {
        return (& $done $false 'Turning an audit mode on needs administrator rights.')
    }

    if (Test-TkImpactHardened -Probe $probe) {
        return (& $done $false ('{0} is already in place here: there is nothing left to measure.' -f $probe.Hardening))
    }

    $state = Read-TkImpactState

    if ($state.ContainsKey($probe.Id)) {
        return (& $done $true ('{0} is already being measured, since {1}.' -f $probe.Name, ([datetime] $state[$probe.Id].Started).ToString('yyyy-MM-dd HH:mm')))
    }

    if (-not $PSCmdlet.ShouldProcess($probe.Name, 'Turn the audit mode on')) {
        return (& $done $false 'Nothing was changed.')
    }

    $current = @{}
    foreach ($setting in @($probe.Settings)) {
        $current[$setting.Name] = Get-TkImpactValue -Path $setting.Path -Name $setting.Name
    }

    $plan    = @(Get-TkImpactPlan -Probe $probe -Current $current)
    $changes = New-Object System.Collections.Generic.List[string]

    foreach ($step in $plan) {
        if ($step.Set) {
            Set-TkImpactValue -Path $step.Path -Name $step.Name -Value $step.Value -Confirm:$false
            $changes.Add(('{0} {1} -> {2}' -f $step.Name, $(if ($step.Existed) { $step.Previous } else { '(not set)' }), $step.Value))
        }
        else {
            $changes.Add(('{0} kept at {1}' -f $step.Name, $step.Previous))
        }
    }

    $log       = Get-TkImpactLog -LogName $probe.LogName
    $logRecord = [ordered] @{ Name = $probe.LogName; Enabled = $false; EnabledBefore = [bool] $log.Enabled; Resized = $false; MaxBytesBefore = [long] $log.MaxBytes }

    if ($log.Readable -and (-not $log.Enabled -or $log.MaxBytes -lt $script:TkImpactLogBytes)) {
        $resize = $log.MaxBytes -lt $script:TkImpactLogBytes
        Set-TkImpactLog -LogName $probe.LogName -Enabled $true -MaxBytes $(if ($resize) { $script:TkImpactLogBytes } else { 0 }) -Confirm:$false
        $logRecord.Enabled = -not $log.Enabled
        $logRecord.Resized = $resize
        if ($resize) { $changes.Add(('log {0} enlarged from {1} KB to {2} KB' -f $probe.LogName, [int] ($log.MaxBytes / 1KB), [int] ($script:TkImpactLogBytes / 1KB))) }
        if ($logRecord.Enabled) { $changes.Add(('log {0} enabled' -f $probe.LogName)) }
    }

    $state[$probe.Id] = [ordered] @{
        Started   = $Now.ToString('o')
        StartedBy = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
        Settings  = @($plan | ForEach-Object { [ordered] @{ Name = $_.Name; Set = [bool] $_.Set; Existed = [bool] $_.Existed; Previous = $_.Previous } })
        Log       = $logRecord
    }

    Write-TkImpactState -State $state -Confirm:$false

    $detail = $changes -join '; '
    Write-TkLog -Level Information -Category 'Hardening' -Message ('Impact measurement started for {0}: {1}' -f $probe.Name, $detail)
    Add-TkJournalEntry -Name ('Impact measurement started: {0}' -f $probe.Name) -Category 'Hardening' -Detail $detail

    return (& $done $true ('Measuring {0}: the audit mode records what {1} would refuse, and changes nothing else. {2}Come back after a few days of normal work, including the monthly tasks if there are any.' -f
        $probe.Name, $probe.Action, $(if ($probe.NeedsRestart) { 'It takes effect after the next restart. ' } else { '' })))
}

<#
.SYNOPSIS
    Turns an audit mode off, putting back what it replaced.

.DESCRIPTION
    Needs administrator rights. Only a mode the toolkit turned on is turned
    off, and only the values it set and that have not changed since are put
    back. Journaled with what was done.

.OUTPUTS
    PSCustomObject with Ok and Message.
#>
function Stop-TkImpactMeasurement {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id
    )

    $done  = { param($ok, $message) [pscustomobject] @{ Ok = $ok; Message = $message } }
    $probe = @(Get-TkImpactProbe | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1

    if (-not $probe) {
        return (& $done $false ('There is no measurement named {0}.' -f $Id))
    }

    if (-not (Test-TkIsElevated)) {
        return (& $done $false 'Turning an audit mode off needs administrator rights.')
    }

    $state = Read-TkImpactState

    if (-not $state.ContainsKey($probe.Id)) {
        return (& $done $false ('{0} was not turned on by the toolkit: nothing was changed.' -f $probe.Name))
    }

    if (-not $PSCmdlet.ShouldProcess($probe.Name, 'Turn the audit mode off')) {
        return (& $done $false 'Nothing was changed.')
    }

    $record = $state[$probe.Id]
    $notes  = New-Object System.Collections.Generic.List[string]

    foreach ($setting in @($probe.Settings)) {

        $saved = @($record.Settings | Where-Object { $_ -and [string] $_.Name -eq $setting.Name }) | Select-Object -First 1

        if (-not $saved) {
            $notes.Add(('{0} had no record, and was left as it is.' -f $setting.Name))
            continue
        }

        $restore = Get-TkImpactRestore -Setting $setting -Record $saved -Current (Get-TkImpactValue -Path $setting.Path -Name $setting.Name)

        switch ($restore.Action) {
            'Restore' { Set-TkImpactValue -Path $setting.Path -Name $setting.Name -Value $restore.Value -Confirm:$false }
            'Remove'  { Set-TkImpactValue -Path $setting.Path -Name $setting.Name -Value $null -Confirm:$false }
        }

        $notes.Add($restore.Reason)
    }

    $logRecord = $record.Log
    if ($logRecord -and ($logRecord.Resized -or $logRecord.Enabled)) {

        $log     = Get-TkImpactLog -LogName $probe.LogName
        $before  = [long] $logRecord.MaxBytesBefore
        $shrink  = $logRecord.Resized -and $log.MaxBytes -eq $script:TkImpactLogBytes -and $before -ge 65536 -and $before -lt $script:TkImpactLogBytes
        $disable = [bool] $logRecord.Enabled -and $log.Enabled

        if ($log.Readable -and ($shrink -or $disable)) {
            Set-TkImpactLog -LogName $probe.LogName -Enabled (-not $disable) -MaxBytes $(if ($shrink) { $before } else { 0 }) -Confirm:$false
            if ($shrink)  { $notes.Add(('The log was put back to {0} KB.' -f [int] ($before / 1KB))) }
            if ($disable) { $notes.Add('The log was disabled again, as it was.') }
        }
    }

    $state.Remove($probe.Id)
    Write-TkImpactState -State $state -Confirm:$false

    $detail = $notes -join ' '
    Write-TkLog -Level Information -Category 'Hardening' -Message ('Impact measurement stopped for {0}: {1}' -f $probe.Name, $detail)
    Add-TkJournalEntry -Name ('Impact measurement stopped: {0}' -f $probe.Name) -Category 'Hardening' -Detail $detail

    return (& $done $true ('{0} is no longer measured. {1}' -f $probe.Name, $detail))
}

<#
.SYNOPSIS
    The values of an event read by ConvertFrom-TkTimelineEvent, in one table.

.DESCRIPTION
    Pure. Each named value by its name, from the event data or the user
    data, and every value by its position as #0, #1...

.OUTPUTS
    System.Collections.Hashtable
#>
function ConvertTo-TkImpactData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Fact
    )

    $table = @{}

    if ($Fact.Field -is [System.Collections.IDictionary]) {
        foreach ($key in @($Fact.Field.Keys)) {
            $table[[string] $key] = [string] $Fact.Field[$key]
        }
    }

    $values = @($Fact.Value)
    for ($index = 0; $index -lt $values.Count; $index++) {
        $table[('#{0}' -f $index)] = [string] $values[$index]
    }

    return $table
}

<#
.SYNOPSIS
    Turns one audit event into who or what would have been refused.

.DESCRIPTION
    Pure. Key is what a hardening would break: the server NTLM was sent to,
    the process or client that received it, the SMBv1 client, the module
    LSASS loaded, the program that started PowerShell 2.0. A PowerShell start
    of another version gives nothing.

.OUTPUTS
    PSCustomObject with Key, Detail and EventId, or nothing.
#>
function ConvertTo-TkImpactRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $ProbeId,
        [Parameter(Mandatory)] [int] $EventId,
        [Parameter(Mandatory)] [hashtable] $Data
    )

    $first = { param($names) foreach ($name in $names) { if ([string] $Data[$name]) { return ([string] $Data[$name]).Trim() } } return '' }
    $who   = {
        $user   = & $first @('ClientUserName', 'UserName')
        $domain = & $first @('ClientDomainName', 'DomainName')
        if ($user) { if ($domain) { '{0}\{1}' -f $domain, $user } else { $user } } else { '' }
    }
    $row   = { param($key, $detail) [pscustomobject] @{ Key = $key; Detail = $detail; EventId = $EventId } }

    switch ($ProbeId) {

        'ntlm' {
            $process = & $first @('ProcessName', 'CallerProcessName', 'ClientProcessName')
            $account = & $who
            $by      = @($process, $account) | Where-Object { $_ }

            if ($EventId -eq 8001) {
                $target = & $first @('TargetName', 'ServerName')
                return (& $row ('Sent to {0}' -f $(if ($target) { $target } else { 'an unnamed server' })) ($by -join ', as '))
            }

            $client = & $first @('WorkstationName', 'ClientName', 'ClientAddress', 'RemoteAddress')
            return (& $row $(if ($client) { 'Received from {0}' -f $client } else { 'Received by {0}' -f $(if ($process) { $process } else { 'a local service' }) }) ($by -join ', as '))
        }

        'smb1' {
            $client = & $first @('ClientName', 'ClientAddress', 'Client', '#0')
            return (& $row ('SMBv1 client {0}' -f $(if ($client) { $client } else { '(unnamed)' })) '')
        }

        'lsa' {
            $file = (& $first @('FileNameBuffer', 'FileName', '#1')) -replace '^\\Device\\HarddiskVolume\d+', ''
            return (& $row ('Module {0}' -f $(if ($file) { $file } else { '(unnamed)' })) 'Loaded into LSASS; LSA protection would refuse it.')
        }

        'ps2' {
            $text = [string] $Data['#2']
            if ($text -notmatch '(?m)EngineVersion=2\.') {
                return
            }
            $starter = if ($text -match '(?m)HostApplication=([^\r\n]*)') { $Matches[1].Trim() } else { '' }
            $script  = if ($text -match '(?m)ScriptName=([^\r\n]*)') { $Matches[1].Trim() } else { '' }
            return (& $row ('PowerShell 2.0 started by {0}' -f $(if ($starter) { $starter } else { 'an unnamed host' })) $script)
        }
    }
}

<#
.SYNOPSIS
    Reads what an audit mode recorded since a moment.

.OUTPUTS
    PSCustomObject with Readable, Reason, Log, Oldest (the oldest event the
    log still holds) and Rows (Key, Detail, EventId, Time).
#>
function Read-TkImpactEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Probe,
        [Parameter()] [AllowNull()] $Since,
        [Parameter()] [int] $MaxEvents = 5000
    )

    $log    = Get-TkImpactLog -LogName $Probe.LogName
    $result = [pscustomobject] @{ Readable = $log.Readable; Reason = $log.Reason; Log = $log; Oldest = $null; Rows = @() }

    if (-not $log.Readable) {
        return $result
    }

    try {
        $result.Oldest = (Get-WinEvent -LogName $Probe.LogName -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated
    }
    catch {
        $result.Oldest = $null
    }

    $filter = @{ LogName = $Probe.LogName; Id = @($Probe.EventIds) }
    if ($Since) { $filter['StartTime'] = [datetime] $Since }

    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $result.Readable = $false
            $result.Reason   = $_.Exception.Message
        }
        return $result
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($item in $events) {

        # The PowerShell log is large and its values carry no names: the
        # third one is enough, and far quicker than the XML.
        $data = if ($Probe.Id -eq 'ps2') { @{ '#2' = [string] @($item.Properties)[2].Value } } else { ConvertTo-TkImpactData -Fact (ConvertFrom-TkTimelineEvent -Record $item) }

        $row = ConvertTo-TkImpactRow -ProbeId $Probe.Id -EventId $item.Id -Data $data
        if ($row) {
            Add-Member -InputObject $row -NotePropertyName 'Time' -NotePropertyValue $item.TimeCreated
            $rows.Add($row)
        }
    }

    $result.Rows = $rows.ToArray()
    return $result
}

<#
.SYNOPSIS
    Groups what was recorded by who or what would be refused.

.OUTPUTS
    PSCustomObject[] with Key, Count, First, Last and Detail, most used first.
#>
function Group-TkImpactRow {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row
    )

    return @($Row | Where-Object { $_ } | Group-Object -Property Key | ForEach-Object {
        $times = @($_.Group | ForEach-Object { [datetime] $_.Time } | Sort-Object)
        [pscustomobject] @{
            Key    = $_.Name
            Count  = $_.Count
            First  = $times[0]
            Last   = $times[-1]
            Detail = (@($_.Group | ForEach-Object { $_.Detail } | Where-Object { $_ } | Select-Object -Unique -First 3)) -join '; '
        }
    } | Sort-Object -Property @{ Expression = { $_.Count }; Descending = $true }, Key)
}

<#
.SYNOPSIS
    Says what a measurement shows, honestly about what it could see.

.DESCRIPTION
    Pure. "No use seen" is said only for a mode that is on, for as many days
    as the log still holds, and never for less than a day. A mode that needs
    a restart and has not had one says so.

.PARAMETER Measuring
    Whether the audit mode is on (always true for PowerShell 2.0).

.PARAMETER Started
    When the toolkit turned it on; null when it was on already, or for
    PowerShell 2.0.

.OUTPUTS
    PSCustomObject with Verdict, Severity, Headline, Note and Days.
#>
function Resolve-TkImpactVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Probe,
        [Parameter(Mandatory)] [bool] $Measuring,
        [Parameter()] [AllowNull()] $Started,
        [Parameter()] [bool] $Hardened = $false,
        [Parameter(Mandatory)] [pscustomobject] $Evidence,
        [Parameter()] [AllowNull()] $LastBoot,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $make = { param($verdict, $severity, $headline, $note, $days) [pscustomobject] @{ Verdict = $verdict; Severity = $severity; Headline = $headline; Note = $note; Days = $days } }

    if ($Hardened) {
        return (& $make 'Hardened' 'Pass' ('{0} is already in place: there is nothing left to measure.' -f $Probe.Hardening) '' 0)
    }

    if (-not $Evidence.Readable) {
        return (& $make 'NotReadable' 'NotAssessed' 'What was recorded could not be read.' $Evidence.Reason 0)
    }

    $sources = @(Group-TkImpactRow -Row @($Evidence.Rows))
    $uses    = @($Evidence.Rows).Count

    if (-not $Measuring) {
        $note = if ($uses -gt 0) { 'The log still holds {0} use(s) from an earlier measurement.' -f $uses } else { '' }
        return (& $make 'NotMeasured' 'Info' 'Not measured: turn the audit mode on to find out.' $note 0)
    }

    if ($Probe.NeedsRestart -and $Started -and $LastBoot -and ([datetime] $LastBoot) -lt ([datetime] $Started)) {
        return (& $make 'Waiting' 'Info' 'Turned on: it takes effect after the next restart.' '' 0)
    }

    # What the log can vouch for: from the start, or from its oldest event
    # when it has been overwritten since.
    $from     = if ($Started) { [datetime] $Started } elseif ($Evidence.Oldest) { [datetime] $Evidence.Oldest } else { $Now }
    $coverage = ''
    if ($Evidence.Oldest -and ([datetime] $Evidence.Oldest) -gt $from) {
        $from     = [datetime] $Evidence.Oldest
        $coverage = ' The log only reaches back to {0}: anything earlier was overwritten.' -f $from.ToString('yyyy-MM-dd HH:mm')
    }

    $days  = [math]::Round(($Now - $from).TotalDays, 1)
    $whole = [int] [math]::Floor($days)

    if ($uses -gt 0) {
        return (& $make 'InUse' 'Warning' ('{0} use(s) by {1} source(s) in {2}: {3} would break them.' -f $uses, $sources.Count, $(if ($whole -ge 1) { '{0} day(s)' -f $whole } else { 'less than a day' }), $Probe.Action) ('Deal with them first, or keep an exception for them.' + $coverage) $days)
    }

    if ($days -lt 1) {
        return (& $make 'TooEarly' 'Info' ('Measuring for {0} hour(s): too early to say.' -f [int] [math]::Floor(($Now - $from).TotalHours)) $coverage.Trim() $days)
    }

    return (& $make 'NoUseSeen' 'Pass' ('No use seen in {0} day(s): {1} should break nothing that ran here in that time.' -f $whole, $Probe.Action) ('A task that runs monthly or quarterly may not have run yet.' + $coverage) $days)
}

<#
.SYNOPSIS
    What every audit mode shows now: on or off, since when, and what it saw.

.OUTPUTS
    PSCustomObject[], one per probe.
#>
function Get-TkImpactReport {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $state    = Read-TkImpactState
    $lastBoot = try { [datetime] (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $null }

    return @(foreach ($probe in @(Get-TkImpactProbe)) {

        $record    = if ($state.ContainsKey($probe.Id)) { $state[$probe.Id] } else { $null }
        $started   = if ($record) { [datetime] $record.Started } else { $null }
        $settings  = @($probe.Settings)
        $measuring = ($settings.Count -eq 0) -or (@($settings | Where-Object {
            $value = Get-TkImpactValue -Path $_.Path -Name $_.Name
            $null -eq $value -or @($_.Keep) -notcontains [long] $value
        }).Count -eq 0)
        $hardened  = Test-TkImpactHardened -Probe $probe
        $evidence  = Read-TkImpactEvidence -Probe $probe -Since $started
        $verdict   = Resolve-TkImpactVerdict -Probe $probe -Measuring $measuring -Started $started -Hardened $hardened -Evidence $evidence -LastBoot $lastBoot -Now $Now

        [pscustomobject] @{
            Id        = $probe.Id
            Name      = $probe.Name
            Hardening = $probe.Hardening
            Control   = $probe.Control
            Measuring = $measuring
            ByToolkit = [bool] $record
            Started   = $(if ($started) { $started.ToString('o') } else { '' })
            StartedBy = $(if ($record) { [string] $record.StartedBy } else { '' })
            Verdict   = $verdict.Verdict
            Severity  = $verdict.Severity
            Headline  = $verdict.Headline
            Note      = $verdict.Note
            Days      = $verdict.Days
            Uses      = @($evidence.Rows).Count
            Sources   = @(Group-TkImpactRow -Row @($evidence.Rows) | Select-Object -First 50 | ForEach-Object {
                [pscustomobject] @{ Key = $_.Key; Count = $_.Count; First = $_.First.ToString('o'); Last = $_.Last.ToString('o'); Detail = $_.Detail }
            })
        }
    })
}

<#
.SYNOPSIS
    The hint an audit finding gets when its hardening can be measured first.
#>
function Format-TkImpactHint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Finding
    )

    if ([string] $Finding.Status -notin @('Fail', 'Warning')) {
        return ''
    }

    $probe = @(Get-TkImpactProbe | Where-Object { $_.Control -eq [string] $Finding.Id }) | Select-Object -First 1

    if (-not $probe) {
        return ''
    }

    return ('Before changing it, measure what it would break: Audit, Before hardening, {0}.' -f $probe.Name)
}
