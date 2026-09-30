<#
    Toolkit - Features / Assistance mode ("My PC")

    For the person in front of the PC, not the technician: the same
    judgements as the Dashboard, said in plain words, each with what they can
    do themselves; then a request for support, prepared with what they agree
    to send.

    Nothing here changes the PC or needs an administrator. The request is a
    report document (docs/REPORT-FORMAT.md) with the description and the
    verdicts added, pseudonymised by default: support opens it like any other
    report. Nothing is sent anywhere; the file goes through the usual support
    channel.
#>

<#
.SYNOPSIS
    The reports a request may attach, in the order they are offered.

.DESCRIPTION
    Only reports a standard user can collect, and only what a support call
    about a workstation starts with.
#>
function Get-TkAssistReportName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @('Reboot', 'Storage', 'Network', 'Wifi', 'Proxy', 'Updates')
}

<#
.SYNOPSIS
    What each report a request may attach holds, in plain words.
#>
function Get-TkAssistReportLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    switch ($Name) {
        'Reboot'  { return 'Whether a restart is waiting, and why' }
        'Storage' { return 'The disks: their health and their free space' }
        'Network' { return 'The network connection: addresses, gateway, name servers' }
        'Wifi'    { return 'The Wi-Fi connection and its signal (never its password)' }
        'Proxy'   { return 'The proxy settings of this account' }
        'Updates' { return 'The history of Windows updates' }
    }

    return $Name
}

<#
.SYNOPSIS
    One plain verdict: what it is, what to do about it.
#>
function New-TkAssistVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warning', 'Fail', 'Info', 'NotAssessed')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Headline,
        [Parameter()] [AllowEmptyString()] [string] $Advice = '',
        [Parameter()] [AllowEmptyString()] [string] $Detail = ''
    )

    return [pscustomobject] @{ Id = $Id; Severity = $Severity; Headline = $Headline; Advice = $Advice; Detail = $Detail }
}

<#
.SYNOPSIS
    The Dashboard's judgements, in plain words, with what the user can do.

.DESCRIPTION
    Pure. One verdict per question, problems first. A judgement that could
    not be made says so ("could not be checked") rather than disappearing:
    silence would read as "all is well". The battery is only mentioned on a
    machine that has one.

.PARAMETER Tile
    The health tiles, from ConvertTo-TkDashboardHealth.

.PARAMETER Adapter
    The adapter that carries traffic, from Select-TkPrimaryAdapter; null
    when none does.

.OUTPUTS
    PSCustomObject[] as built by New-TkAssistVerdict.
#>
function ConvertTo-TkAssistVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Tile,

        [Parameter()]
        [AllowNull()]
        $Adapter
    )

    $byTitle   = @{}
    foreach ($item in @($Tile | Where-Object { $_ })) { $byTitle[[string] $item.Title] = $item }
    $unchecked = 'This could not be checked. It is not a sign of a problem, and support will see it in the request.'
    $out       = New-Object System.Collections.Generic.List[object]

    # --- Network ----------------------------------------------------------
    $address = if ($Adapter) { [string] $Adapter.IPv4Address } else { '' }
    # The adapter that carries the traffic may be a VPN's, when one is on.
    $names   = if ($Adapter) { [string] $Adapter.Description + ' ' + [string] $Adapter.Name } else { '' }
    $through = if ($names -match '(?i)vpn|wireguard|openvpn|tap-windows|anyconnect|globalprotect|forti|tailscale|zerotier|tunnel') { 'a VPN' }
               elseif ($names -match '(?i)wi-?fi|wireless|wlan|802\.11') { 'Wi-Fi' }
               else { 'a cable' }

    if (-not $Adapter -or -not $address -or $address -eq 'None') {
        $out.Add((New-TkAssistVerdict -Id 'network' -Severity 'Fail' -Headline 'Your PC is not connected to a network' `
            -Advice 'Turn Wi-Fi on and choose your network, or check that the network cable is plugged in at both ends. If nothing connects, restart the box or ask a colleague whether theirs works.'))
    }
    elseif ($address -like '169.254.*') {
        $out.Add((New-TkAssistVerdict -Id 'network' -Severity 'Fail' -Headline 'Your PC is connected, but the network gave it no address' `
            -Advice 'Disconnect and reconnect the Wi-Fi, or unplug the cable and plug it back in. If it stays like this, restart the box, then the PC.'))
    }
    elseif ([string] $Adapter.Gateway -eq 'None' -or -not [string] $Adapter.Gateway) {
        $out.Add((New-TkAssistVerdict -Id 'network' -Severity 'Warning' -Headline 'Your PC is connected, but with no way out to the internet' `
            -Advice 'Reconnect to the network. If only this PC is affected, send the request.'))
    }
    else {
        $out.Add((New-TkAssistVerdict -Id 'network' -Severity 'Pass' -Headline ('Your PC is connected through {0}' -f $through) -Detail ([string] $Adapter.Name)))
    }

    # --- Restart ----------------------------------------------------------
    $restart = $byTitle['Restart']
    if (-not $restart -or $restart.Severity -eq 'NotAssessed') {
        $out.Add((New-TkAssistVerdict -Id 'restart' -Severity 'NotAssessed' -Headline 'Whether a restart is waiting could not be checked' -Advice $unchecked))
    }
    elseif ($restart.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'restart' -Severity 'Warning' -Headline 'Your PC is waiting to restart' `
            -Advice 'Save your work, then restart the PC (Start, Power, Restart) rather than shutting it down: updates finish installing during the restart.' -Detail ([string] $restart.Detail)))
    }
    else {
        $out.Add((New-TkAssistVerdict -Id 'restart' -Severity 'Pass' -Headline 'No restart is waiting' -Detail ([string] $restart.Detail)))
    }

    # --- Updates ----------------------------------------------------------
    $updates = $byTitle['Updates']
    if (-not $updates -or $updates.Severity -eq 'NotAssessed') {
        $out.Add((New-TkAssistVerdict -Id 'updates' -Severity 'NotAssessed' -Headline 'The Windows updates could not be checked' -Advice $unchecked))
    }
    elseif ($updates.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'updates' -Severity $updates.Severity -Headline ('Windows has not installed an update for a while: the last one was {0}' -f ([string] $updates.Value).ToLowerInvariant()) `
            -Advice 'Open Settings, Windows Update, and select Check for updates. Leave the PC on and plugged in until it has finished, then restart it.'))
    }
    else {
        $out.Add((New-TkAssistVerdict -Id 'updates' -Severity 'Pass' -Headline ('Windows is up to date: the last update was installed {0}' -f ([string] $updates.Value).ToLowerInvariant())))
    }

    # --- Storage ----------------------------------------------------------
    # Titled with its drive, "Storage C:", when a volume was read.
    $storage = @($Tile | Where-Object { $_ -and [string] $_.Title -match '^Storage\b' }) | Select-Object -First 1
    $drive   = if ($storage -and [string] $storage.Title -match '^Storage\s+(\S+)') { ' {0}' -f $Matches[1] } else { '' }
    if (-not $storage -or $storage.Severity -eq 'NotAssessed') {
        $out.Add((New-TkAssistVerdict -Id 'storage' -Severity 'NotAssessed' -Headline 'The free space on the disk could not be checked' -Advice $unchecked))
    }
    elseif ($storage.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'storage' -Severity $storage.Severity -Headline ('Your disk{0} is almost full ({1})' -f $drive, $storage.Detail) `
            -Advice 'Empty the Recycle Bin, then open Settings, System, Storage, and use the cleanup recommendations. Move large personal files, such as videos, to your network or cloud folder.'))
    }
    else {
        $out.Add((New-TkAssistVerdict -Id 'storage' -Severity 'Pass' -Headline ('There is room on the disk{0} ({1})' -f $drive, $storage.Detail)))
    }

    # --- Disks ------------------------------------------------------------
    $disks = $byTitle['Disks']
    if ($disks -and $disks.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'disks' -Severity $disks.Severity -Headline 'A disk reports a problem' `
            -Advice 'Copy your important files somewhere else now, such as your network or cloud folder, and send the request: the disk may need replacing.' -Detail ([string] $disks.Detail)))
    }
    elseif ($disks -and $disks.Severity -eq 'Pass') {
        $out.Add((New-TkAssistVerdict -Id 'disks' -Severity 'Pass' -Headline 'The disks report no problem'))
    }

    # --- Blue screens -----------------------------------------------------
    $crashes = $byTitle['Blue screens']
    if ($crashes -and $crashes.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'crashes' -Severity $crashes.Severity -Headline ('Windows stopped unexpectedly: {0}' -f ([string] $crashes.Value).ToLowerInvariant()) `
            -Advice 'Note what you were doing each time it happened, and put it in your request.'))
    }

    # --- Devices ----------------------------------------------------------
    $devices = $byTitle['Devices']
    if ($devices -and $devices.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'devices' -Severity $devices.Severity -Headline 'A device is not working properly' `
            -Advice 'Unplug it and plug it back in, then restart the PC. If it is still not working, send the request.' -Detail ([string] $devices.Detail)))
    }

    # --- Sign-in ----------------------------------------------------------
    $signIn = $byTitle['Sign-in']
    if ($signIn -and $signIn.Severity -in @('Warning', 'Fail')) {
        $out.Add((New-TkAssistVerdict -Id 'sign-in' -Severity $signIn.Severity -Headline 'Your PC has trouble with your organisation account' `
            -Advice 'Restart the PC and sign in again while connected to the office network or the VPN.' -Detail ([string] $signIn.Detail)))
    }

    # --- Battery ----------------------------------------------------------
    $battery = $byTitle['Battery']
    if ($battery -and [string] $battery.Value -ne 'No battery') {
        $out.Add((New-TkAssistVerdict -Id 'battery' -Severity 'Info' -Headline ('Battery: {0}' -f $battery.Value) -Detail ([string] $battery.Detail)))
    }

    # Problems first, each group in the order above. Sort-Object has no
    # -Stable in Windows PowerShell 5.1, so the groups are taken in turn.
    return @(foreach ($severity in @('Fail', 'Warning', 'NotAssessed', 'Info', 'Pass')) {
        $out | Where-Object { $_.Severity -eq $severity }
    })
}

<#
.SYNOPSIS
    Reads the PC and returns the plain verdicts.
#>
function Get-TkAssistVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $health  = Get-TkDashboardHealthData
    $network = Get-TkDashboardNetwork

    return @(ConvertTo-TkAssistVerdict -Tile @(ConvertTo-TkDashboardHealth -Snapshot $health) -Adapter $network.Adapter)
}

<#
.SYNOPSIS
    The text to paste into the ticket, from a request as it was written.

.DESCRIPTION
    Pure. Built from the document once pseudonymised, so it names the PC and
    the user the way the file does.
#>
function Format-TkAssistSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Document,
        [Parameter(Mandatory)] [string] $FileName
    )

    $request = $Document.Request
    $lines   = New-Object System.Collections.Generic.List[string]

    $lines.Add(('Support request from {0}, {1}.' -f $Document.Computer, ([datetime] $request.Created).ToString('yyyy-MM-dd HH:mm')))
    $lines.Add('')
    $lines.Add('What happens:')
    $lines.Add($(if ([string] $request.Description) { [string] $request.Description } else { '(not described)' }))
    $lines.Add('')
    $lines.Add('What the PC shows:')

    $problems = @($request.Verdicts | Where-Object { $_.Severity -in @('Fail', 'Warning', 'NotAssessed') })
    if ($problems.Count -eq 0) {
        $lines.Add('- Nothing wrong was found on the usual points.')
    }
    foreach ($verdict in $problems) {
        $lines.Add(('- {0}' -f $verdict.Headline))
    }

    $lines.Add('')
    $lines.Add(('Attached: {0} ({1}).' -f $FileName, $(if (@($request.Attached).Count) { (@($request.Attached) -join ', ') } else { 'the verdicts only' })))

    if ([string] $Document.Privacy -ne 'None') {
        $lines.Add('The names of this PC and of its user are replaced by aliases in the file.')
    }

    return ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    Writes a request for support: the chosen reports, the verdicts and the
    description, pseudonymised unless the user agreed to show their names.

.PARAMETER Report
    The reports the user left ticked; any other name is refused.

.PARAMETER ShowNames
    The user agreed to show the name of the PC and their own.

.OUTPUTS
    PSCustomObject with Path, Summary, Privacy and Attached.
#>
function New-TkAssistRequest {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Description = '',

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Report = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Verdict = @(),

        [Parameter()]
        [switch] $ShowNames,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $offered  = @(Get-TkAssistReportName)
    $unknown  = @($Report | Where-Object { $offered -notcontains $_ })

    if ($unknown.Count -gt 0) {
        throw ('{0} is not a report a request can attach.' -f $unknown[0])
    }

    $attached = @($offered | Where-Object { $Report -contains $_ })
    $level    = if ($ShowNames) { 'None' } else { 'Personal' }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write the support request')) {
        return $null
    }

    $document = New-TkReportDocument -Name $attached -Table @(Get-TkHeadlessReport) -Options @{ AuditLevel = 'Essential' } -Privacy $level

    $document['Request'] = [ordered] @{
        Kind        = 'assistance'
        Created     = $Now.ToString('o')
        Description = $Description.Trim()
        Verdicts    = @($Verdict | Where-Object { $_ } | ForEach-Object { [ordered] @{ Id = [string] $_.Id; Severity = [string] $_.Severity; Headline = [string] $_.Headline } })
        Attached    = $attached
        Declined    = @($offered | Where-Object { $attached -notcontains $_ })
    }

    $json = ConvertTo-Json -InputObject $document -Depth 40

    if ($level -ne 'None') {
        $json = (Protect-TkExportText -Text $json -Level $level -Label 'support-request').Text
    }

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))

    Write-TkLog -Level Information -Category 'Report' -Message ('Support request written to {0} ({1}; {2}).' -f $full, $level, $(if ($attached.Count) { $attached -join ', ' } else { 'no report' }))

    return [pscustomobject] @{
        Path     = $full
        Summary  = Format-TkAssistSummary -Document (ConvertFrom-Json -InputObject $json) -FileName ([System.IO.Path]::GetFileName($full))
        Privacy  = $level
        Attached = $attached
    }
}
