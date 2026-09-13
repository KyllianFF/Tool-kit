<#
    Toolkit - UI / System page

    Displays the machine inventory and drives the vendor actions. The CIM
    queries run in the background because TPM and BitLocker lookups take a
    noticeable moment on some machines and would otherwise freeze the window.
#>

# Last inventory snapshot, kept so the vendor buttons and the export do not
# have to query CIM again.
$script:TkSystemSnapshot = $null

<#
.SYNOPSIS
    Wires the System page.
#>
function Initialize-TkSystemPage {
    [CmdletBinding()]
    param()

    Register-TkClick -Name 'BtnRefreshSystem' -Action { Update-TkSystemPage }

    Register-TkClick -Name 'BtnCopySerial' -Action {

        if (-not $script:TkSystemSnapshot) {
            Set-TkStatus -Text 'Refresh the page first.'
            return
        }

        $serial = $script:TkSystemSnapshot.Identity.SerialNumber

        if (Set-TkClipboard -Text $serial) {
            Set-TkStatus -Text ('Serial number copied: {0}' -f $serial)
        }
    }

    Register-TkClick -Name 'BtnVendorDrivers' -Action {
        Open-TkVendorSupport -Kind 'Drivers' -Identity $script:TkSystemSnapshot.Identity | Out-Null
    }

    Register-TkClick -Name 'BtnVendorWarranty' -Action {
        Open-TkVendorSupport -Kind 'Warranty' -Identity $script:TkSystemSnapshot.Identity | Out-Null
    }

    Register-TkClick -Name 'BtnVendorTool' -Action {

        if (-not (Test-TkIsElevated)) {
            Set-TkStatus -Text 'Installing the firmware utility requires an elevated instance.'
            return
        }

        $identity = $script:TkSystemSnapshot.Identity
        $vendor   = Get-TkVendorProfile -Manufacturer $identity.Manufacturer

        if (-not $vendor -or [string]::IsNullOrWhiteSpace($vendor.updateToolPackage)) {
            Set-TkStatus -Text 'No firmware utility is known for this manufacturer.'
            return
        }

        $confirmed = Confirm-TkAction -Title 'Install firmware utility' -Message (
            "Install {0} through winget?`n`nThe toolkit does not flash firmware itself: the vendor utility takes over from there." -f $vendor.updateToolName
        )

        if (-not $confirmed) {
            return
        }

        $packageId = $vendor.updateToolPackage

        Invoke-TkBackgroundAction -StatusText ('Installing {0}...' -f $vendor.updateToolName) `
            -ArgumentList @($packageId) `
            -ScriptBlock {
                param($id)
                Install-TkWingetPackage -PackageId $id -Confirm:$false
            } `
            -OnComplete {
                param($result)

                if ($result.Output -contains $true) {
                    Write-TkLog -Level Information -Category 'Vendor' -Message 'Firmware utility installed.'
                }
                else {
                    Write-TkLog -Level Warning -Category 'Vendor' -Message 'The firmware utility could not be installed.'
                }
            }
    }

    Register-TkClick -Name 'BtnExportReport' -Action { Export-TkSystemReportFromUi }

    $volumeBox = Get-TkControl -Name 'SystemVolumeChoice'

    if ($volumeBox) {

        $volumeBox.Add_SelectionChanged({

            $box = Get-TkControl -Name 'SystemVolumeChoice'

            if ($box -and $box.SelectedItem) {
                Show-TkSystemVolume -Drive ([string] $box.SelectedItem.Tag)
            }
        })
    }

    Add-TkQuickActionPanel -PanelName 'SystemQuickActions'

    # The inventory costs a few seconds of CIM queries, and the toolkit opens
    # on the Dashboard now, so it waits for the page to be opened.
    Register-TkFirstShow -PageName 'System' -Action { Update-TkSystemPage }
}

<#
.SYNOPSIS
    Collects the inventory and refreshes every field on the page.
#>
function Update-TkSystemPage {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading the system inventory...' `
        -ScriptBlock {

            # Runs in a background runspace: return plain data only.
            [pscustomobject]@{
                Identity = Get-TkMachineIdentity
                OS       = Get-TkOperatingSystemInfo
                Hardware = Get-TkHardwareInfo
                Security = Get-TkPlatformSecurityInfo
                Bios     = Get-TkBiosStatus
                Volumes  = @(Get-TkVolumeUsage)
            }
        } `
        -OnComplete {
            param($result)

            $snapshot = @($result.Output) | Select-Object -First 1

            if (-not $snapshot) {
                Set-TkStatus -Text 'The inventory could not be read.'
                return
            }

            $script:TkSystemSnapshot = $snapshot
            Write-TkSystemPageFields -Snapshot $snapshot

            Set-TkStatus -Text ('Inventory refreshed at {0}.' -f (Get-Date -Format 'HH:mm:ss'))
        }
}

<#
.SYNOPSIS
    Writes an inventory snapshot into the page controls.

.PARAMETER Snapshot
    Object returned by the inventory background task.
#>
function Write-TkSystemPageFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot
    )

    $identity = $Snapshot.Identity
    $os       = $Snapshot.OS
    $hardware = $Snapshot.Hardware
    $security = $Snapshot.Security
    $bios     = $Snapshot.Bios

    # Field name to value. Keeping the mapping as data makes adding a field a
    # one line change here plus one in the XAML.
    $fields = @{
        'ValManufacturer' = $identity.Manufacturer
        'ValModel'        = $identity.Model
        'ValSerial'       = $identity.SerialNumber
        'ValAssetTag'     = $identity.AssetTag
        'ValChassis'      = if ($identity.IsVirtual) { '{0} (virtual machine)' -f $identity.ChassisType }
                            else { $identity.ChassisType }
        'ValBoard'        = $identity.BaseBoard
        'ValDomain'       = if ($identity.PartOfDomain) { '{0} (joined)' -f $identity.Domain }
                            else { '{0} (workgroup)' -f $identity.Domain }
        'ValUser'         = $identity.LoggedOnUser

        'ValBiosVendor'   = $bios.Vendor
        'ValBiosVersion'  = $bios.Version
        'ValBiosDate'     = $bios.ReleaseDate
        'ValBiosAge'      = if ($null -ne $bios.AgeDays) { '{0} days' -f $bios.AgeDays } else { 'Unknown' }
        'ValBiosAdvice'   = $bios.Recommendation

        'ValOsCaption'    = $os.Caption
        'ValOsVersion'    = $os.DisplayVersion
        'ValOsBuild'      = $os.Build
        'ValActivation'   = $os.Activation
        'ValInstalled'    = if ($os.InstallDate) { ([datetime] $os.InstallDate).ToString('yyyy-MM-dd') } else { 'Unknown' }
        'ValUptime'       = $os.UptimeText
        'ValTimeZone'     = $os.TimeZone
        'ValPowerShell'   = $os.PowerShell

        'ValCpu'          = $hardware.CpuName
        'ValCores'        = '{0} cores / {1} threads' -f $hardware.CpuCores, $hardware.CpuThreads
        'ValMemory'       = '{0} in {1} module(s)' -f $hardware.TotalMemory, @($hardware.MemoryModules).Count
        'ValGpu'          = (@($hardware.Graphics | ForEach-Object { $_.Name }) -join ', ')

        'ValSecureBoot'   = $security.SecureBoot
        'ValTpm'          = $security.Tpm
        'ValBitLocker'    = $security.BitLocker
        'ValFirewall'     = $security.Firewall
        'ValAntivirus'    = $security.Antivirus
        'ValDefender'     = $security.Defender
    }

    foreach ($name in $fields.Keys) {

        $control = Get-TkControl -Name $name

        if ($control) {
            $control.Text = [string] $fields[$name]
        }
    }

    # A board that never recorded a serial number reports the placeholder.
    # Copying it would put the words "Not available" on the clipboard, and a
    # warranty lookup would search for them, so both buttons stand down.
    $hasSerial = -not [string]::IsNullOrWhiteSpace($identity.SerialNumber) -and
                 $identity.SerialNumber -ne (Format-TkValue $null)

    foreach ($name in @('BtnCopySerial', 'BtnVendorWarranty')) {

        $button = Get-TkControl -Name $name

        if ($button) {
            $button.IsEnabled = $hasSerial
        }
    }

    Update-TkSystemVolumeChoice -Volume @($Snapshot.Volumes)
    Update-TkVendorToolButton -Identity $identity

    Set-TkObjectTable -ControlName 'DocDisks' -InputObject $hardware.Disks `
        -Property @('Name', 'Size', 'MediaType', 'BusType', 'Health') `
        -Column   @('Model', 'Size', 'Type', 'Bus', 'Health') `
        -Weight   @(3.0, 1.0, 0.9, 0.9, 0.9) `
        -EmptyText 'No physical disk was returned.'
}

<#
.SYNOPSIS
    Lists the volumes in the disk selector, with the system drive selected.

.PARAMETER Volume
    Output of Get-TkVolumeUsage.
#>
function Update-TkSystemVolumeChoice {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Volume = @()
    )

    $box = Get-TkControl -Name 'SystemVolumeChoice'

    if ($null -eq $box) {
        return
    }

    $box.Items.Clear()

    $volumes = @($Volume | Where-Object { $null -ne $_ })

    if ($volumes.Count -eq 0) {

        Set-TkUsageBar -BarName 'SystemVolumeBar' -FillName 'SystemVolumeFill' -Percent 0

        $detail = Get-TkControl -Name 'SystemVolumeDetail'

        if ($detail) {
            $detail.Text = 'No fixed volume was returned.'
        }

        return
    }

    $selected = $null

    foreach ($item in $volumes) {

        $entry = New-Object System.Windows.Controls.ComboBoxItem
        $entry.Content = '{0}  {1}' -f $item.Drive, $item.Label
        $entry.Tag     = [string] $item.Drive

        [void] $box.Items.Add($entry)

        # The system drive, because it is the one that stops Windows when it
        # fills.
        if ([string] $item.Drive -eq $env:SystemDrive) {
            $selected = $entry
        }
    }

    if ($null -eq $selected) {
        $selected = $box.Items[0]
    }

    # Selecting raises SelectionChanged, which draws the bar.
    $box.SelectedItem = $selected
}

<#
.SYNOPSIS
    Draws the fill bar and the figures for one volume.

.PARAMETER Drive
    Drive letter with its colon, such as C:.
#>
function Show-TkSystemVolume {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Drive
    )

    $volume = @($script:TkSystemSnapshot.Volumes) |
              Where-Object { $null -ne $_ -and [string] $_.Drive -eq $Drive } |
              Select-Object -First 1

    $detail = Get-TkControl -Name 'SystemVolumeDetail'

    if ($null -eq $volume) {

        Set-TkUsageBar -BarName 'SystemVolumeBar' -FillName 'SystemVolumeFill' -Percent 0

        if ($detail) {
            $detail.Text = 'This volume is no longer in the inventory. Refresh the page.'
        }

        return
    }

    Set-TkUsageBar -BarName 'SystemVolumeBar' -FillName 'SystemVolumeFill' `
                   -Percent $volume.UsedPercent -Severity $volume.Severity

    if ($detail) {

        # A whole percentage: formatted in the local culture, a decimal would
        # read 46,6 on a French Windows next to sizes printed as 1.99 TB.
        $text = '{0}% used: {1} free of {2}, {3}.' -f [math]::Round($volume.UsedPercent), $volume.Free, $volume.Size, $volume.FileSystem

        if ($volume.Note) {
            $text += ' ' + $volume.Note
        }

        $detail.Text = $text
    }
}

<#
.SYNOPSIS
    Shows the firmware utility button only when the catalog knows one.

.DESCRIPTION
    A button that answers "no utility is known for this manufacturer" after
    being pressed is a button that should not have been there. The hint beside
    it says what happens either way.

.PARAMETER Identity
    The machine identity from the inventory.
#>
function Update-TkVendorToolButton {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Identity
    )

    $vendor = if ($Identity) { Get-TkVendorProfile -Manufacturer $Identity.Manufacturer } else { $null }
    $known  = ($null -ne $vendor -and -not [string]::IsNullOrWhiteSpace($vendor.updateToolPackage))

    $button = Get-TkControl -Name 'BtnVendorTool'

    if ($button) {

        $button.Visibility = if ($known) { [System.Windows.Visibility]::Visible }
                             else { [System.Windows.Visibility]::Collapsed }

        if ($known) {
            $button.Content = 'Install {0}' -f $vendor.updateToolName
        }
    }

    $hint = Get-TkControl -Name 'ValVendorToolHint'

    if ($hint) {
        $hint.Text = if ($known) {
                         'The toolkit never flashes firmware itself: it installs {0}, which takes over from there.' -f $vendor.updateToolName
                     }
                     else {
                         'No firmware utility is known for this manufacturer. The support site, beside the manufacturer above, has the downloads.'
                     }
    }
}

<#
.SYNOPSIS
    Asks for a destination and writes the inventory report.
#>
function Export-TkSystemReportFromUi {
    [CmdletBinding()]
    param()

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title      = 'Export the system report'
    $dialog.Filter     = 'JSON report (*.json)|*.json|Text report (*.txt)|*.txt'
    $dialog.FileName   = '{0}-inventory-{1}.json' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd')

    if (-not $dialog.ShowDialog()) {
        return
    }

    $path   = $dialog.FileName
    $format = if ($path -like '*.txt') { 'Text' } else { 'Json' }

    $written = Export-TkSystemReport -Path $path -Format $format -Confirm:$false

    if ($written) {
        Set-TkStatus -Text ('Report written to {0}' -f $written)
    }
    else {
        Set-TkStatus -Text 'The report could not be written.'
    }
}
