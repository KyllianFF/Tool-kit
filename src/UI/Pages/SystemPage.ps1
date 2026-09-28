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

    # --- Windows Update ---------------------------------------------------
    Register-TkClick -Name 'BtnCheckUpdates'   -Action { Invoke-TkCheckUpdatesFromUi }
    Register-TkClick -Name 'BtnInstallUpdates' -Action { Invoke-TkInstallUpdatesFromUi }

    Register-TkClick -Name 'BtnCopySerial' -Action {

        if (-not $script:TkSystemSnapshot -or -not $script:TkSystemSnapshot.Identity) {
            Set-TkStatus -Text 'The identity is still being read.'
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

    # The inventory costs a few seconds of CIM queries, and the toolkit opens
    # on the Dashboard now, so it waits for the page to be opened.
    Register-TkFirstShow -PageName 'System' -Action { Update-TkSystemPage }
}

<#
.SYNOPSIS
    Reads the inventory in four parallel parts, each filling its own cards.

.DESCRIPTION
    One combined read left every card empty for as long as the slowest reader
    took, with nothing on screen to say anything was happening. The identity
    answers in a moment, the operating system soon after, the hardware and the
    platform security last; each card now shows that it is reading and fills
    as soon as its own part lands.

    The snapshot is filled part by part as well, so the vendor buttons and the
    volume selector have what they need as soon as their part is read.
#>
function Update-TkSystemPage {
    [CmdletBinding()]
    param()

    if ($null -eq $script:TkSystemSnapshot) {
        $script:TkSystemSnapshot = [pscustomobject] @{
            Identity = $null
            Bios     = $null
            OS       = $null
            Hardware = $null
            Volumes  = @()
            Security = $null
        }
    }

    foreach ($card in @('SystemIdentity', 'SystemFirmware', 'SystemOs', 'SystemHardware', 'SystemSecurity')) {
        Set-TkCardLoading -Name $card -Loading $true
    }

    # Runs in a background runspace: every script block returns plain data only.
    Invoke-TkBackgroundAction -StatusText 'Reading the machine identity and firmware...' `
        -ScriptBlock {
            [pscustomobject] @{
                Identity = Get-TkMachineIdentity
                Bios     = Get-TkBiosStatus
            }
        } `
        -OnComplete {
            param($result)

            $part = @($result.Output) | Select-Object -First 1

            if ($part) {
                $script:TkSystemSnapshot.Identity = $part.Identity
                $script:TkSystemSnapshot.Bios     = $part.Bios
            }

            Write-TkSystemIdentity -Identity $script:TkSystemSnapshot.Identity -Bios $script:TkSystemSnapshot.Bios

            Set-TkCardLoading -Name 'SystemIdentity' -Loading $false
            Set-TkCardLoading -Name 'SystemFirmware' -Loading $false
        }

    Invoke-TkBackgroundAction -StatusText 'Reading the operating system...' `
        -ScriptBlock { Get-TkOperatingSystemInfo } `
        -OnComplete {
            param($result)

            $part = @($result.Output) | Select-Object -First 1

            if ($part) {
                $script:TkSystemSnapshot.OS = $part
            }

            Write-TkSystemOs -OS $script:TkSystemSnapshot.OS
            Set-TkCardLoading -Name 'SystemOs' -Loading $false
        }

    Invoke-TkBackgroundAction -StatusText 'Reading processors, memory, disks and volumes...' `
        -ScriptBlock {
            [pscustomobject] @{
                Hardware = Get-TkHardwareInfo
                Volumes  = @(Get-TkVolumeUsage)
            }
        } `
        -OnComplete {
            param($result)

            $part = @($result.Output) | Select-Object -First 1

            if ($part) {
                $script:TkSystemSnapshot.Hardware = $part.Hardware
                $script:TkSystemSnapshot.Volumes  = @($part.Volumes)
            }

            Write-TkSystemHardware -Hardware $script:TkSystemSnapshot.Hardware -Volume @($script:TkSystemSnapshot.Volumes)
            Set-TkCardLoading -Name 'SystemHardware' -Loading $false
        }

    Invoke-TkBackgroundAction -StatusText 'Reading the platform security...' `
        -ScriptBlock { Get-TkPlatformSecurityInfo } `
        -OnComplete {
            param($result)

            $part = @($result.Output) | Select-Object -First 1

            if ($part) {
                $script:TkSystemSnapshot.Security = $part
            }

            Write-TkSystemSecurity -Security $script:TkSystemSnapshot.Security
            Set-TkCardLoading -Name 'SystemSecurity' -Loading $false
        }
}

<#
.SYNOPSIS
    Writes a whole inventory snapshot at once, for a console session or a
    render.

.PARAMETER Snapshot
    Anything with Identity, Bios, OS, Hardware, Volumes and Security.
#>
function Write-TkSystemPageFields {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot
    )

    Write-TkSystemIdentity -Identity $Snapshot.Identity -Bios $Snapshot.Bios
    Write-TkSystemOs       -OS $Snapshot.OS
    Write-TkSystemHardware -Hardware $Snapshot.Hardware -Volume @($Snapshot.Volumes)
    Write-TkSystemSecurity -Security $Snapshot.Security

    foreach ($card in @('SystemIdentity', 'SystemFirmware', 'SystemOs', 'SystemHardware', 'SystemSecurity')) {
        Set-TkCardLoading -Name $card -Loading $false
    }
}

<#
.SYNOPSIS
    Writes a placeholder into fields whose part could not be read.

.PARAMETER Name
    Control names.
#>
function Set-TkSystemFieldsUnavailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Name
    )

    $field = @{}

    foreach ($item in $Name) {
        $field[$item] = 'Not available'
    }

    Set-TkFieldText -Field $field
}

<#
.SYNOPSIS
    Fills the Identity and Firmware cards, and the buttons that depend on them.

.PARAMETER Identity
    Output of Get-TkMachineIdentity, or null.

.PARAMETER Bios
    Output of Get-TkBiosStatus, or null.
#>
function Write-TkSystemIdentity {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Identity,

        [Parameter()]
        $Bios
    )

    if ($Identity) {

        Set-TkFieldText -Field @{
            'ValManufacturer' = $Identity.Manufacturer
            'ValModel'        = $Identity.Model
            'ValSerial'       = $Identity.SerialNumber
            'ValAssetTag'     = $Identity.AssetTag
            'ValChassis'      = if ($Identity.IsVirtual) { '{0} (virtual machine)' -f $Identity.ChassisType }
                                else { $Identity.ChassisType }
            'ValBoard'        = $Identity.BaseBoard
            'ValDomain'       = if ($Identity.PartOfDomain) { '{0} (joined)' -f $Identity.Domain }
                                else { '{0} (workgroup)' -f $Identity.Domain }
            'ValUser'         = $Identity.LoggedOnUser
        }
    }
    else {
        Set-TkSystemFieldsUnavailable -Name @('ValManufacturer', 'ValModel', 'ValSerial', 'ValAssetTag',
                                              'ValChassis', 'ValBoard', 'ValDomain', 'ValUser')
    }

    if ($Bios) {

        Set-TkFieldText -Field @{
            'ValBiosVendor'  = $Bios.Vendor
            'ValBiosVersion' = $Bios.Version
            'ValBiosDate'    = $Bios.ReleaseDate
            'ValBiosAge'     = if ($null -ne $Bios.AgeDays) { '{0} days' -f $Bios.AgeDays } else { 'Unknown' }
            'ValBiosAdvice'  = $Bios.Recommendation
        }
    }
    else {
        Set-TkSystemFieldsUnavailable -Name @('ValBiosVendor', 'ValBiosVersion', 'ValBiosDate', 'ValBiosAge')
    }

    # A board that never recorded a serial number reports the placeholder.
    # Copying it would put the words "Not available" on the clipboard, and a
    # warranty lookup would search for them, so both buttons stand down. They
    # start disabled in the markup for the same reason, until this has run.
    $hasSerial = ($null -ne $Identity) -and
                 -not [string]::IsNullOrWhiteSpace($Identity.SerialNumber) -and
                 $Identity.SerialNumber -ne (Format-TkValue $null)

    foreach ($name in @('BtnCopySerial', 'BtnVendorWarranty')) {

        $button = Get-TkControl -Name $name

        if ($button) {
            $button.IsEnabled = $hasSerial
        }
    }

    Update-TkVendorToolButton -Identity $Identity
}

<#
.SYNOPSIS
    Fills the Operating system card.

.PARAMETER OS
    Output of Get-TkOperatingSystemInfo, or null.
#>
function Write-TkSystemOs {
    [CmdletBinding()]
    param(
        [Parameter()]
        $OS
    )

    if ($null -eq $OS) {
        Set-TkSystemFieldsUnavailable -Name @('ValOsCaption', 'ValOsVersion', 'ValOsBuild', 'ValActivation',
                                              'ValInstalled', 'ValUptime', 'ValTimeZone', 'ValPowerShell')
        return
    }

    Set-TkFieldText -Field @{
        'ValOsCaption'  = $OS.Caption
        'ValOsVersion'  = $OS.DisplayVersion
        'ValOsBuild'    = $OS.Build
        'ValActivation' = $OS.Activation
        'ValInstalled'  = if ($OS.InstallDate) { ([datetime] $OS.InstallDate).ToString('yyyy-MM-dd') } else { 'Unknown' }
        'ValUptime'     = $OS.UptimeText
        'ValTimeZone'   = $OS.TimeZone
        'ValPowerShell' = $OS.PowerShell
    }
}

<#
.SYNOPSIS
    Fills the Hardware card: processors, memory, graphics, volumes and disks.

.PARAMETER Hardware
    Output of Get-TkHardwareInfo, or null.

.PARAMETER Volume
    Output of Get-TkVolumeUsage.
#>
function Write-TkSystemHardware {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Hardware,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]] $Volume = @()
    )

    if ($Hardware) {

        Set-TkFieldText -Field @{
            'ValCpu'    = $Hardware.CpuName
            'ValCores'  = '{0} cores / {1} threads' -f $Hardware.CpuCores, $Hardware.CpuThreads
            'ValMemory' = '{0} in {1} module(s)' -f $Hardware.TotalMemory, @($Hardware.MemoryModules).Count
            'ValGpu'    = (@($Hardware.Graphics | ForEach-Object { $_.Name }) -join ', ')
        }
    }
    else {
        Set-TkSystemFieldsUnavailable -Name @('ValCpu', 'ValCores', 'ValMemory', 'ValGpu')
    }

    Write-TkSystemVolumeList -Volume $Volume

    Set-TkObjectTable -ControlName 'DocDisks' -InputObject @(if ($Hardware) { $Hardware.Disks }) `
        -Property @('Name', 'Size', 'MediaType', 'BusType', 'Health') `
        -Column   @('Model', 'Size', 'Type', 'Bus', 'Health') `
        -Weight   @(3.0, 1.0, 0.9, 0.9, 0.9) `
        -EmptyText 'No physical disk was returned.'
}

<#
.SYNOPSIS
    Fills the Platform security card.

.PARAMETER Security
    Output of Get-TkPlatformSecurityInfo, or null.
#>
function Write-TkSystemSecurity {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Security
    )

    if ($null -eq $Security) {
        Set-TkSystemFieldsUnavailable -Name @('ValSecureBoot', 'ValTpm', 'ValBitLocker', 'ValFirewall',
                                              'ValAntivirus', 'ValDefender')
        return
    }

    Set-TkFieldText -Field @{
        'ValSecureBoot' = $Security.SecureBoot
        'ValTpm'        = $Security.Tpm
        'ValBitLocker'  = $Security.BitLocker
        'ValFirewall'   = $Security.Firewall
        'ValAntivirus'  = $Security.Antivirus
        'ValDefender'   = $Security.Defender
    }
}

<#
.SYNOPSIS
    Draws one row per fixed volume: its name, its figures and a fill bar.

.DESCRIPTION
    Every volume at once, the system drive first. The earlier selector showed
    one drive at a time, and the one filling up was rarely the one selected.

.PARAMETER Volume
    Output of Get-TkVolumeUsage.
#>
function Write-TkSystemVolumeList {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]] $Volume = @()
    )

    $list = Get-TkControl -Name 'SystemVolumeList'

    if ($null -eq $list) {
        return
    }

    $list.Children.Clear()

    $volumes = @(Get-TkVolumeDisplayOrder -Volume @($Volume))

    if ($volumes.Count -eq 0) {

        $empty = New-Object System.Windows.Controls.TextBlock
        $empty.Text = 'No fixed volume was returned.'
        $empty.SetResourceReference([System.Windows.Controls.TextBlock]::StyleProperty, 'Muted')

        [void] $list.Children.Add($empty)
        return
    }

    foreach ($item in $volumes) {
        [void] $list.Children.Add((New-TkVolumeRow -Volume $item))
    }
}

<#
.SYNOPSIS
    Builds the row for one volume.

.PARAMETER Volume
    One record from Get-TkVolumeUsage.
#>
function New-TkVolumeRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Volume
    )

    $row = New-Object System.Windows.Controls.StackPanel
    $row.Margin = New-Object System.Windows.Thickness(0, 0, 0, 12)

    # --- Name on the left, figures on the right ----------------------------
    $header = New-Object System.Windows.Controls.DockPanel
    $header.LastChildFill = $true

    # A whole percentage: formatted in the local culture, a decimal reads
    # 46,6 on a French Windows beside sizes printed as 1.99 TB.
    $figures = New-Object System.Windows.Controls.TextBlock
    $figures.Text              = '{0}% used, {1} free of {2}' -f [math]::Round($Volume.UsedPercent), $Volume.Free, $Volume.Size
    $figures.FontSize          = 12
    $figures.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $figures.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextMuted')

    [System.Windows.Controls.DockPanel]::SetDock($figures, [System.Windows.Controls.Dock]::Right)

    $role = if ([string] $Volume.Drive -eq $env:SystemDrive) { ', system drive' } else { '' }

    $name = New-Object System.Windows.Controls.TextBlock
    $name.Text              = '{0}  {1}, {2}{3}' -f $Volume.Drive, $Volume.Label, $Volume.FileSystem, $role
    $name.FontSize          = 13
    $name.FontWeight        = [System.Windows.FontWeights]::SemiBold
    $name.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $name.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'TextPrimary')

    [void] $header.Children.Add($figures)
    [void] $header.Children.Add($name)
    [void] $row.Children.Add($header)

    # --- The bar -----------------------------------------------------------
    $bar = New-TkUsageBar -Percent ([double] $Volume.UsedPercent) -Severity $Volume.Severity -Height 8
    $bar.Margin = New-Object System.Windows.Thickness(0, 6, 0, 0)

    [void] $row.Children.Add($bar)

    # --- What a warning means, in the colour of the warning ------------------
    if ($Volume.Note) {

        $note = New-Object System.Windows.Controls.TextBlock
        $note.Text         = $Volume.Note
        $note.FontSize     = 11
        $note.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $note.Margin       = New-Object System.Windows.Thickness(0, 4, 0, 0)
        $note.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty,
            (Get-TkSeverityBrushKey -Severity $Volume.Severity))

        [void] $row.Children.Add($note)
    }

    return $row
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

    $level  = Get-TkExportPrivacyLevel
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title      = 'Export the system report'
    $dialog.Filter     = 'JSON report (*.json)|*.json|Text report (*.txt)|*.txt'
    $dialog.FileName   = '{0}-inventory-{1}.json' -f (Get-TkExportComputerName -Level $level), (Get-Date -Format 'yyyyMMdd')

    if (-not $dialog.ShowDialog()) {
        return
    }

    $path   = $dialog.FileName
    $format = if ($path -like '*.txt') { 'Text' } else { 'Json' }

    $written = Export-TkSystemReport -Path $path -Format $format -Privacy $level -Confirm:$false

    if ($written) {
        Set-TkStatus -Text ('Report written to {0}.{1}' -f $written, (Format-TkPrivacyNote -Result ([pscustomobject] @{ Level = $level; Replaced = $null })))
    }
    else {
        Set-TkStatus -Text 'The report could not be written.'
    }
}


# ---------------------------------------------------------------------------
# Windows Update
# ---------------------------------------------------------------------------

# The updates from the last check, so the install can find them again.
$script:TkAvailableUpdates = @()

<#
.SYNOPSIS
    Asks Windows Update what is available and lists it with a checkbox each.

.DESCRIPTION
    The search reads only. Each update becomes a checkbox carrying its record,
    so the install can read back exactly what was ticked.
#>
function Invoke-TkCheckUpdatesFromUi {
    [CmdletBinding()]
    param()

    Set-TkStatus -Text 'Asking Windows Update what is available...'

    $panel = Get-TkControl -Name 'UpdateList'
    if ($panel) {
        $panel.Children.Clear()
        $waiting = New-Object System.Windows.Controls.TextBlock
        $waiting.Text = 'Checking with Windows Update, this can take a minute...'
        $waiting.TextWrapping = 'Wrap'
        [void] $panel.Children.Add($waiting)
    }

    Invoke-TkBackgroundAction -StatusText 'Checking Windows Update...' `
        -ScriptBlock { Get-TkAvailableUpdate } `
        -OnComplete {
            param($result)

            $updates = @($result.Output)
            $script:TkAvailableUpdates = $updates

            $panel = Get-TkControl -Name 'UpdateList'
            if (-not $panel) { return }

            $panel.Children.Clear()

            if ($updates.Count -eq 0) {
                $none = New-Object System.Windows.Controls.TextBlock
                $none.Text = 'Windows Update has nothing for this machine right now.'
                $none.TextWrapping = 'Wrap'
                [void] $panel.Children.Add($none)
                Set-TkStatus -Text 'Windows Update: nothing available.'
                return
            }

            foreach ($update in $updates) {

                $reboot = if ($update.RequiresReboot) { ', needs a restart' } elseif ($update.MayReboot) { ', may need a restart' } else { '' }
                $check  = New-Object System.Windows.Controls.CheckBox
                $check.Content = '{0}  [{1}]  {2}{3}' -f $update.Title, $update.SeverityLabel, $update.SizeText, $reboot
                $check.Tag     = $update
                $check.Margin  = '0,4,0,4'
                Set-TkResourceBrush -Element $check -Property Foreground -Key 'TextPrimary'
                [void] $panel.Children.Add($check)
            }

            Set-TkStatus -Text ('Windows Update: {0} available.' -f $updates.Count)
        }
}

<#
.SYNOPSIS
    Installs the ticked updates, after confirming and checking for elevation.
#>
function Invoke-TkInstallUpdatesFromUi {
    [CmdletBinding()]
    param()

    $panel = Get-TkControl -Name 'UpdateList'
    if (-not $panel) { return }

    $chosen = @(foreach ($child in $panel.Children) {
        if ($child -is [System.Windows.Controls.CheckBox] -and $child.IsChecked -and $child.Tag) { $child.Tag }
    })

    if ($chosen.Count -eq 0) {
        Set-TkStatus -Text 'Tick the updates to install first.'
        return
    }

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Installing updates needs administrator rights. Restart as administrator from the header.'
        return
    }

    $ids     = @($chosen | ForEach-Object { $_.UpdateId })
    $titles  = @($chosen | ForEach-Object { $_.Title })

    $message = @(
        'This will download and install through Windows Update:'
        ''
        ($titles | ForEach-Object { '    ' + $_ })
        ''
        'Some updates restart the machine. Save your work first. Install now?'
    ) -join [Environment]::NewLine

    if (-not (Confirm-TkAction -Title 'Install updates' -Message $message)) {
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Downloading and installing updates, this can take a while...' `
        -ArgumentList @(, $ids) `
        -ScriptBlock {
            param($updateIds)
            Install-TkWindowsUpdate -UpdateId $updateIds -Confirm:$false
        } `
        -OnComplete {
            param($result)

            $outcome = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Installed'] } | Select-Object -First 1

            if (-not $outcome) {
                Set-TkStatus -Text 'The install did not complete. See the output panel.'
                return
            }

            $reboot = if ($outcome.RebootRequired) { ' A restart is needed to finish.' } else { '' }
            Set-TkStatus -Text ('Updates: {0} installed, {1} failed.{2}' -f $outcome.Installed, $outcome.Failed, $reboot)
            Invoke-TkCheckUpdatesFromUi
        }
}
