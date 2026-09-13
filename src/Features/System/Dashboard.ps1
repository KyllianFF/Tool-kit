<#
    Toolkit - Features / Dashboard

    What the Dashboard shows, read in three parts, and the judgement behind
    each health tile.

    The parts are read at the same time and each fills its own card: the
    identity of the machine in a moment, the network a little later, the
    health of the disks and the update history last. One combined read left
    the whole page empty for as long as the slowest reader took.

    No threshold lives here. Free space is judged by Get-TkFreeSpaceAssessment,
    patch age by Get-TkPatchAgeSeverity and disk health by Get-TkStorageHealth:
    the same functions the System page, the audit and the diagnostics use, so a
    tile can never disagree with the page it opens.
#>

<#
.SYNOPSIS
    Reads which machine this is: identity and operating system.

.OUTPUTS
    PSCustomObject with Identity and OS.
#>
function Get-TkDashboardWorkstation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject] @{
        Identity = Read-TkDashboardPart -Part 'Identity'         -Reader { Get-TkMachineIdentity }
        OS       = Read-TkDashboardPart -Part 'Operating system' -Reader { Get-TkOperatingSystemInfo }
    }
}

<#
.SYNOPSIS
    Reads the network adapters and picks the one that carries traffic.

.OUTPUTS
    PSCustomObject with Adapter, the primary one, and Adapters, all of them.
#>
function Get-TkDashboardNetwork {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $adapters = @(Read-TkDashboardPart -Part 'Network adapters' -Reader { Get-TkNetworkAdapterInfo })

    return [pscustomobject] @{
        Adapter  = Select-TkPrimaryAdapter -Adapter $adapters
        Adapters = $adapters
    }
}

<#
.SYNOPSIS
    Reads what the health tiles judge: restart, updates, volumes, disks and
    battery.

.OUTPUTS
    PSCustomObject with Reboot, LastHotFix, Volumes, Disks and Battery.
#>
function Get-TkDashboardHealthData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $disks = @(Read-TkDashboardPart -Part 'Storage health' -Reader { Get-TkStorageHealth } |
               Where-Object { $_.Kind -eq 'Disk' })

    return [pscustomobject] @{
        Reboot     = Read-TkDashboardPart -Part 'Pending restart' -Reader { Get-TkPendingRebootStatus }
        LastHotFix = Read-TkDashboardPart -Part 'Update history'  -Reader { Select-TkLastHotFix -HotFix @(Get-HotFix -ErrorAction Stop) }
        Volumes    = @(Read-TkDashboardPart -Part 'Volumes' -Reader { Get-TkVolumeUsage })
        Disks      = $disks
        Battery    = @(Read-TkDashboardPart -Part 'Battery' -Reader { Get-TkBatteryState })
        Devices    = @(Read-TkDashboardPart -Part 'Devices' -Reader { Get-TkDeviceProblem })
        Crashes    = @(Read-TkDashboardPart -Part 'Crash history' -Reader { Get-TkCrashHistory -Days 30 })
    }
}

<#
.SYNOPSIS
    Reads everything the Dashboard shows, in one call.

.DESCRIPTION
    The interface reads the three parts in parallel and never calls this. It
    exists for a console session, the support bundle and the off screen
    render, which want the whole picture in one object.

.OUTPUTS
    PSCustomObject
#>
function Get-TkDashboardSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $workstation = Get-TkDashboardWorkstation
    $network     = Get-TkDashboardNetwork
    $health      = Get-TkDashboardHealthData

    return [pscustomobject] @{
        Identity   = $workstation.Identity
        OS         = $workstation.OS
        Adapter    = $network.Adapter
        Adapters   = $network.Adapters
        Reboot     = $health.Reboot
        LastHotFix = $health.LastHotFix
        Volumes    = $health.Volumes
        Disks      = $health.Disks
        Battery    = $health.Battery
        Devices    = $health.Devices
        Crashes    = $health.Crashes
    }
}

<#
.SYNOPSIS
    Runs one reader for the Dashboard and turns a failure into nothing.

.DESCRIPTION
    Nulls are dropped as well as failures. An array built from a reader that
    returned nothing would otherwise hold one null element, and every tile
    would have to guard against a record with no fields.

    Whatever the reader returns is unrolled first. Several readers in this
    project return their array with the comma operator, which hands the
    pipeline one object that is an array. Get-TkBatteryState does, and on a
    desktop its empty array arrived as a single item: the Dashboard reported a
    battery on a machine that has none.

.PARAMETER Part
    What is being read, for the log.

.PARAMETER Reader
    Script block that reads it.
#>
function Read-TkDashboardPart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Part,

        [Parameter(Mandatory)]
        [scriptblock] $Reader
    )

    try {
        & $Reader | ForEach-Object { $_ } | Where-Object { $null -ne $_ }
    }
    catch {
        Write-TkLog -Level Warning -Category 'Dashboard' -Message (
            '{0} could not be read: {1}' -f $Part, $_.Exception.Message
        )
    }
}

<#
.SYNOPSIS
    Builds the data behind one health tile.

.PARAMETER Percent
    When given, the tile draws a fill bar of that percentage.

.PARAMETER Page
    The page the tile opens when it is clicked.

.PARAMETER TabControl
    Name of the tab control on that page holding the entry, when it is in a tab.

.PARAMETER Tab
    Header of that tab.

.PARAMETER List
    Name of the chooser on that page holding the entry the tile is about.

.PARAMETER Choice
    Title of that entry. Matched on the title rather than the position, so a
    reordered list cannot send the battery tile to the sound test.

.OUTPUTS
    PSCustomObject
#>
function New-TkHealthTileData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Detail = '',

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warning', 'Fail', 'Info', 'NotAssessed')]
        [string] $Severity,

        [Parameter()]
        [Nullable[double]] $Percent = $null,

        [Parameter(Mandatory)]
        [string] $Page,

        [Parameter()]
        [AllowEmptyString()]
        [string] $TabControl = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Tab = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $List = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Choice = ''
    )

    return [pscustomobject] @{
        Title    = $Title
        Value    = $Value
        Detail     = $Detail
        Severity   = $Severity
        Percent    = $Percent
        Page       = $Page
        TabControl = $TabControl
        Tab        = $Tab
        List       = $List
        Choice     = $Choice
    }
}

<#
.SYNOPSIS
    Turns the health readings into the health tiles.

.DESCRIPTION
    One tile per question a support call starts with: does it need a restart,
    is it patched, is the system drive full, are the disks healthy, how is the
    battery. Each tile names the page, and the entry on that page, that deals
    with it.

    Kept apart from the drawing, so the judgement can be tested without a
    window.

.PARAMETER Snapshot
    Anything with Reboot, LastHotFix, Volumes, Disks and Battery: the health
    part, or a whole snapshot.

.PARAMETER Now
    The moment patch age is measured from. A parameter, so a test is not at
    the mercy of the calendar.

.PARAMETER SystemDrive
    The drive the storage tile reports on.

.OUTPUTS
    PSCustomObject[], as built by New-TkHealthTileData.
#>
function ConvertTo-TkDashboardHealth {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        $Snapshot,

        [Parameter()]
        [datetime] $Now = (Get-Date),

        [Parameter()]
        [string] $SystemDrive = $env:SystemDrive
    )

    $tiles = @()

    # --- Restart ----------------------------------------------------------
    $reboot      = $Snapshot.Reboot
    $restartOpen = @{ Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Reports'; List = 'DiagnosticChoices'; Choice = 'Pending reboot' }

    if ($null -eq $reboot) {
        $tiles += New-TkHealthTileData @restartOpen -Title 'Restart' -Value 'Unknown' -Severity 'NotAssessed' `
                                       -Detail 'The pending restart state could not be read.'
    }
    elseif ($reboot.Pending) {
        $tiles += New-TkHealthTileData @restartOpen -Title 'Restart' -Value 'Restart pending' -Severity 'Warning' `
                                       -Detail ([string] @($reboot.Reasons)[0])
    }
    else {
        $tiles += New-TkHealthTileData @restartOpen -Title 'Restart' -Value 'Not needed' -Severity 'Pass' `
                                       -Detail ('Up for {0}' -f $reboot.Uptime)
    }

    # --- Updates ----------------------------------------------------------
    $hotFix      = $Snapshot.LastHotFix
    $updatesOpen = @{ Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Reports'; List = 'DiagnosticChoices'; Choice = 'Update history' }

    if ($null -eq $hotFix -or $null -eq $hotFix.InstalledOn) {
        $tiles += New-TkHealthTileData @updatesOpen -Title 'Updates' -Value 'Unknown' -Severity 'NotAssessed' `
                                       -Detail 'No dated update was found.'
    }
    else {
        $days = [math]::Max(0, [int] ($Now - [datetime] $hotFix.InstalledOn).TotalDays)

        $age = if ($days -eq 0) { 'Today' }
               elseif ($days -eq 1) { '1 day ago' }
               else { '{0} days ago' -f $days }

        $tiles += New-TkHealthTileData @updatesOpen -Title 'Updates' -Value $age `
                                       -Severity (Get-TkPatchAgeSeverity -Days $days) `
                                       -Detail ('Last installed: {0}' -f $hotFix.HotFixID)
    }

    # --- Storage ----------------------------------------------------------
    # The system drive, because it is the one that stops Windows when it fills.
    $volumes = @($Snapshot.Volumes | Where-Object { $null -ne $_ })
    $system  = $volumes | Where-Object { [string] $_.Drive -eq $SystemDrive } | Select-Object -First 1

    if ($null -eq $system) {
        $system = $volumes | Select-Object -First 1
    }

    if ($null -eq $system) {
        $tiles += New-TkHealthTileData -Title 'Storage' -Value 'Unknown' -Severity 'NotAssessed' -Page 'System' `
                                       -Detail 'No fixed volume was read.'
    }
    else {
        # A whole percentage: formatted in the local culture, a decimal reads
        # 46,6 on a French Windows beside sizes printed as 1.99 TB.
        $tiles += New-TkHealthTileData -Title ('Storage {0}' -f $system.Drive) -Page 'System' `
                                       -Value ('{0}% used' -f [math]::Round($system.UsedPercent)) `
                                       -Detail ('{0} free of {1}' -f $system.Free, $system.Size) `
                                       -Severity $system.Severity -Percent $system.UsedPercent
    }

    # --- Physical disks ---------------------------------------------------
    $disks     = @($Snapshot.Disks | Where-Object { $null -ne $_ })
    $disksOpen = @{ Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Reports'; List = 'DiagnosticChoices'; Choice = 'Storage health' }

    if ($disks.Count -eq 0) {
        $tiles += New-TkHealthTileData @disksOpen -Title 'Disks' -Value 'Unknown' -Severity 'NotAssessed' `
                                       -Detail 'No physical disk was read.'
    }
    else {
        $failing = @($disks | Where-Object { $_.Severity -eq 'Fail' })
        $warning = @($disks | Where-Object { $_.Severity -eq 'Warning' })

        if ($failing.Count -gt 0) {
            $tiles += New-TkHealthTileData @disksOpen -Title 'Disks' -Value ('{0} failing' -f $failing.Count) -Severity 'Fail' `
                                           -Detail ((@($failing | ForEach-Object { $_.Name })) -join ', ')
        }
        elseif ($warning.Count -gt 0) {
            $tiles += New-TkHealthTileData @disksOpen -Title 'Disks' -Value ('{0} worth a look' -f $warning.Count) -Severity 'Warning' `
                                           -Detail ((@($warning | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Notes })) -join '; ')
        }
        else {
            $tiles += New-TkHealthTileData @disksOpen -Title 'Disks' -Value 'All healthy' -Severity 'Pass' `
                                           -Detail ('{0} physical disk(s)' -f $disks.Count)
        }
    }

    # --- Devices ----------------------------------------------------------
    # A device disabled on purpose is information, not a problem to count.
    $devicesOpen = @{ Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Reports'; List = 'DiagnosticChoices'; Choice = 'Devices' }

    if ($null -eq $Snapshot.PSObject.Properties['Devices']) {
        $tiles += New-TkHealthTileData @devicesOpen -Title 'Devices' -Value 'Unknown' -Severity 'NotAssessed' `
                                       -Detail 'The devices were not read.'
    }
    else {
        $problems = @($Snapshot.Devices | Where-Object { $null -ne $_ -and $_.Severity -ne 'Info' })
        $failing  = @($problems | Where-Object { $_.Severity -eq 'Fail' })

        if ($problems.Count -eq 0) {
            $tiles += New-TkHealthTileData @devicesOpen -Title 'Devices' -Value 'No problem' -Severity 'Pass' `
                                           -Detail 'No device flagged in Device Manager.'
        }
        else {
            $tiles += New-TkHealthTileData @devicesOpen -Title 'Devices' `
                                           -Value $(if ($failing.Count -gt 0) { '{0} failing' -f $failing.Count } else { '{0} worth a look' -f $problems.Count }) `
                                           -Severity $(if ($failing.Count -gt 0) { 'Fail' } else { 'Warning' }) `
                                           -Detail ((@($problems | ForEach-Object { 'Code {0}: {1}' -f $_.Code, $_.Name })) -join '; ')
        }
    }

    # --- Blue screens -----------------------------------------------------
    $crashesOpen = @{ Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Reports'; List = 'DiagnosticChoices'; Choice = 'Crashes' }

    if ($null -eq $Snapshot.PSObject.Properties['Crashes']) {
        $tiles += New-TkHealthTileData @crashesOpen -Title 'Blue screens' -Value 'Unknown' -Severity 'NotAssessed' `
                                       -Detail 'The crash history was not read.'
    }
    else {
        $blue = @($Snapshot.Crashes | Where-Object { $null -ne $_ -and $_.Code -ne 0 } |
                  Sort-Object -Property When -Descending)

        if ($blue.Count -eq 0) {
            $tiles += New-TkHealthTileData @crashesOpen -Title 'Blue screens' -Value 'None in 30 days' -Severity 'Pass' `
                                           -Detail 'No stop code recorded.'
        }
        else {
            $last = $blue[0]

            $tiles += New-TkHealthTileData @crashesOpen -Title 'Blue screens' -Value ('{0} in 30 days' -f $blue.Count) `
                                           -Severity 'Fail' `
                                           -Detail ('Last: {0} {1}, {2}' -f $last.Info.CodeHex, $last.Info.Name, ([datetime] $last.When).ToString('yyyy-MM-dd'))
        }
    }

    # --- Battery ----------------------------------------------------------
    # Reported, never judged: wear is expected, and a desktop has none at all.
    $battery     = @($Snapshot.Battery | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $batteryOpen = @{ Page = 'Diagnostics'; TabControl = 'DiagnosticsTabs'; Tab = 'Hardware tests'; List = 'HardwareChoices'; Choice = 'Battery' }

    if ($null -eq $battery) {
        $tiles += New-TkHealthTileData @batteryOpen -Title 'Battery' -Value 'No battery' -Severity 'Info' `
                                       -Detail 'Mains powered.'
    }
    else {
        $tiles += New-TkHealthTileData @batteryOpen -Title 'Battery' -Severity 'Info' `
                                       -Value $(if ($battery.Charge) { [string] $battery.Charge } else { 'Present' }) `
                                       -Detail ([string] $battery.Health)
    }

    return $tiles
}
