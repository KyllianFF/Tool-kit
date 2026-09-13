<#
    Toolkit - Features / Dashboard

    What the Dashboard shows, read in one pass, and the judgement behind each
    health tile.

    No threshold lives here. Free space is judged by Get-TkFreeSpaceAssessment,
    patch age by Get-TkPatchAgeSeverity and disk health by Get-TkStorageHealth:
    the same functions the System page, the audit and the diagnostics use, so a
    tile can never disagree with the page it opens.
#>

<#
.SYNOPSIS
    Reads everything the Dashboard shows.

.DESCRIPTION
    Runs in a background runspace, so it returns plain data only. Each part is
    read on its own and a failure is logged and left empty: a desktop with no
    battery, or a machine whose update history cannot be read, still gets the
    rest of its Dashboard.

.OUTPUTS
    PSCustomObject
#>
function Get-TkDashboardSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $identity = Read-TkDashboardPart -Part 'Identity'         -Reader { Get-TkMachineIdentity }
    $os       = Read-TkDashboardPart -Part 'Operating system' -Reader { Get-TkOperatingSystemInfo }
    $reboot   = Read-TkDashboardPart -Part 'Pending restart'  -Reader { Get-TkPendingRebootStatus }
    $hotFix   = Read-TkDashboardPart -Part 'Update history'   -Reader { Select-TkLastHotFix -HotFix @(Get-HotFix -ErrorAction Stop) }

    $adapters = @(Read-TkDashboardPart -Part 'Network adapters' -Reader { Get-TkNetworkAdapterInfo })
    $volumes  = @(Read-TkDashboardPart -Part 'Volumes'          -Reader { Get-TkVolumeUsage })
    $battery  = @(Read-TkDashboardPart -Part 'Battery'          -Reader { Get-TkBatteryState })

    $disks = @(Read-TkDashboardPart -Part 'Storage health' -Reader { Get-TkStorageHealth } |
               Where-Object { $_.Kind -eq 'Disk' })

    return [pscustomobject] @{
        Identity   = $identity
        OS         = $os
        Adapter    = Select-TkPrimaryAdapter -Adapter $adapters
        Reboot     = $reboot
        LastHotFix = $hotFix
        Volumes    = $volumes
        Disks      = $disks
        Battery    = $battery
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
        [string] $Page
    )

    return [pscustomobject] @{
        Title    = $Title
        Value    = $Value
        Detail   = $Detail
        Severity = $Severity
        Percent  = $Percent
        Page     = $Page
    }
}

<#
.SYNOPSIS
    Turns a Dashboard snapshot into the health tiles.

.DESCRIPTION
    One tile per question a support call starts with: does it need a restart,
    is it patched, is the system drive full, are the disks healthy, how is the
    battery. Each tile names the page that deals with it.

    Kept apart from the drawing, so the judgement can be tested without a
    window.

.PARAMETER Snapshot
    Output of Get-TkDashboardSnapshot.

.PARAMETER Now
    The moment patch age is measured from. A parameter, so a test is not at
    the mercy of the calendar.

.PARAMETER SystemDrive
    The drive the storage tile reports on.

.OUTPUTS
    PSCustomObject[] with Title, Value, Detail, Severity, Percent and Page.
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
    $reboot = $Snapshot.Reboot

    if ($null -eq $reboot) {
        $tiles += New-TkHealthTileData -Title 'Restart' -Value 'Unknown' -Severity 'NotAssessed' -Page 'Diagnostics' `
                                       -Detail 'The pending restart state could not be read.'
    }
    elseif ($reboot.Pending) {
        $tiles += New-TkHealthTileData -Title 'Restart' -Value 'Restart pending' -Severity 'Warning' -Page 'Diagnostics' `
                                       -Detail ([string] @($reboot.Reasons)[0])
    }
    else {
        $tiles += New-TkHealthTileData -Title 'Restart' -Value 'Not needed' -Severity 'Pass' -Page 'Diagnostics' `
                                       -Detail ('Up for {0}' -f $reboot.Uptime)
    }

    # --- Updates ----------------------------------------------------------
    $hotFix = $Snapshot.LastHotFix

    if ($null -eq $hotFix -or $null -eq $hotFix.InstalledOn) {
        $tiles += New-TkHealthTileData -Title 'Updates' -Value 'Unknown' -Severity 'NotAssessed' -Page 'Diagnostics' `
                                       -Detail 'No dated update was found.'
    }
    else {
        $days = [math]::Max(0, [int] ($Now - [datetime] $hotFix.InstalledOn).TotalDays)

        $age = if ($days -eq 0) { 'Today' }
               elseif ($days -eq 1) { '1 day ago' }
               else { '{0} days ago' -f $days }

        $tiles += New-TkHealthTileData -Title 'Updates' -Value $age -Page 'Diagnostics' `
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
        $tiles += New-TkHealthTileData -Title ('Storage {0}' -f $system.Drive) -Page 'System' `
                                       -Value ('{0}% used' -f [math]::Round($system.UsedPercent)) `
                                       -Detail ('{0} free of {1}' -f $system.Free, $system.Size) `
                                       -Severity $system.Severity -Percent $system.UsedPercent
    }

    # --- Physical disks ---------------------------------------------------
    $disks = @($Snapshot.Disks | Where-Object { $null -ne $_ })

    if ($disks.Count -eq 0) {
        $tiles += New-TkHealthTileData -Title 'Disks' -Value 'Unknown' -Severity 'NotAssessed' -Page 'Diagnostics' `
                                       -Detail 'No physical disk was read.'
    }
    else {
        $failing = @($disks | Where-Object { $_.Severity -eq 'Fail' })
        $warning = @($disks | Where-Object { $_.Severity -eq 'Warning' })

        if ($failing.Count -gt 0) {
            $tiles += New-TkHealthTileData -Title 'Disks' -Value ('{0} failing' -f $failing.Count) -Severity 'Fail' `
                                           -Page 'Diagnostics' -Detail ((@($failing | ForEach-Object { $_.Name })) -join ', ')
        }
        elseif ($warning.Count -gt 0) {
            $tiles += New-TkHealthTileData -Title 'Disks' -Value ('{0} worth a look' -f $warning.Count) -Severity 'Warning' `
                                           -Page 'Diagnostics' `
                                           -Detail ((@($warning | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Notes })) -join '; ')
        }
        else {
            $tiles += New-TkHealthTileData -Title 'Disks' -Value 'All healthy' -Severity 'Pass' -Page 'Diagnostics' `
                                           -Detail ('{0} physical disk(s)' -f $disks.Count)
        }
    }

    # --- Battery ----------------------------------------------------------
    # Reported, never judged: wear is expected, and a desktop has none at all.
    $battery = @($Snapshot.Battery | Where-Object { $null -ne $_ }) | Select-Object -First 1

    if ($null -eq $battery) {
        $tiles += New-TkHealthTileData -Title 'Battery' -Value 'No battery' -Severity 'Info' -Page 'Hardware' `
                                       -Detail 'Mains powered.'
    }
    else {
        $tiles += New-TkHealthTileData -Title 'Battery' -Severity 'Info' -Page 'Hardware' `
                                       -Value $(if ($battery.Charge) { [string] $battery.Charge } else { 'Present' }) `
                                       -Detail ([string] $battery.Health)
    }

    return $tiles
}
