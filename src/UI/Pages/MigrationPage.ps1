<#
    Toolkit - UI / Migration page

    Wires the page: what to carry over, what a reinstall depends on, the
    installed applications saved as a profile, the driver export and the copy
    of the user folders. The readers draw a document in the output, like the
    reports; the copy asks first, with the sizes and the free space.
#>

<#
.SYNOPSIS
    Wires the Migration page and lists the personal folders to copy.
#>
function Initialize-TkMigrationPage {
    [CmdletBinding()]
    param()

    $list = Get-TkControl -Name 'MigrationFolderList'

    if ($list) {
        foreach ($known in @(Get-TkKnownFolder | Where-Object Exists)) {
            $box = New-Object System.Windows.Controls.CheckBox
            $box.Content   = $known.Key
            $box.Tag       = $known.Path
            $box.IsChecked = $true
            $box.Margin    = New-Object System.Windows.Thickness(0, 0, 0, 6)
            $box.ToolTip   = $known.Path
            [void] $list.Children.Add($box)
        }
    }

    $cloud = Get-TkControl -Name 'MigrationCloudTarget'
    if ($cloud) {
        [void] $cloud.Items.Add('Windows folders of this account')
        foreach ($root in @(Get-TkCloudRoot)) { [void] $cloud.Items.Add(('{0}   {1}' -f $root.Name, $root.Path)) }
        $cloud.SelectedIndex = 0
        $cloud.Add_SelectionChanged({ Set-TkImportTargetFromCloud })
    }

    Register-TkClick -Name 'BtnMigrationPackageBrowse' -Action {
        $picked = Select-TkFolderPath -Description 'The package folder the export created (Migration-<PC>-<user>-<date>).'
        if ($picked) { (Get-TkControl -Name 'MigrationPackage').Text = $picked; Invoke-TkReadMigrationPackageFromUi }
    }
    Register-TkClick -Name 'BtnMigrationReadPackage' -Action { Invoke-TkReadMigrationPackageFromUi }
    Register-TkClick -Name 'BtnMigrationImport'      -Action { Invoke-TkMigrationImportFromUi }

    Register-TkClick -Name 'BtnMigrationInventory' -Action { Invoke-TkMigrationInventoryFromUi }
    Register-TkClick -Name 'BtnMigrationReinstall' -Action { Invoke-TkReinstallCheckFromUi }
    Register-TkClick -Name 'BtnMigrationProfile'   -Action { Save-TkInstalledProfileFromUi }
    Register-TkClick -Name 'BtnMigrationDrivers'   -Action { Invoke-TkDriverExportFromUi }
    Register-TkClick -Name 'BtnMigrationBrowse'    -Action { Select-TkMigrationDestination }
    Register-TkClick -Name 'BtnMigrationCopy'      -Action { Invoke-TkMigrationCopyFromUi }
}

<#
.SYNOPSIS
    Lets the user pick the destination folder.
#>
function Select-TkMigrationDestination {
    [CmdletBinding()]
    param()

    $picked = Select-TkFolderPath -Description 'Where to copy to: an external drive is best.'

    if ($picked) {
        (Get-TkControl -Name 'MigrationDestination').Text = $picked
    }
}

<#
.SYNOPSIS
    Asks for a folder.

.OUTPUTS
    System.String, or empty when cancelled.
#>
function Select-TkFolderPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [string] $Description = 'Choose a folder.',
        [Parameter()] [AllowEmptyString()] [string] $Start = ''
    )

    Add-Type -AssemblyName System.Windows.Forms

    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description         = $Description
    $dialog.ShowNewFolderButton = $true
    if ($Start -and (Test-Path -LiteralPath $Start -PathType Container)) { $dialog.SelectedPath = $Start }

    try {
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.SelectedPath }
        return ''
    }
    finally {
        $dialog.Dispose()
    }
}

<#
.SYNOPSIS
    Lists what to carry over to the new machine.
#>
function Invoke-TkMigrationInventoryFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Listing what to carry over, the folder sizes take a moment...' `
        -ScriptBlock { Get-TkMigrationInventory } `
        -OnComplete {
            param($result)

            $inventory = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Drives'] } | Select-Object -Last 1

            if (-not $inventory) {
                return
            }

            $document = New-TkFlowDocument
            Add-TkHeading   -Document $document -Text 'What to carry over' -Level 1
            Add-TkParagraph -Document $document -Muted -Text 'What this account uses that a new machine does not bring back by itself. Read only.'

            # --- Folders -------------------------------------------------------
            Add-TkHeading -Document $document -Text 'Personal folders' -Level 2
            Add-TkTable -Document $document -Column @('Folder', 'Size', 'Files', 'Where it comes back from') -Weight @(1.2, 0.8, 0.7, 2.6) `
                -Row @($inventory.Folders | ForEach-Object {
                    , @($_.Name, (Format-TkBytes -Bytes $_.Bytes), [string] $_.Files,
                        $(if ($_.InOneDrive) { 'OneDrive: sign in on the new machine' } else { 'This disk only: copy it' }))
                })

            # --- Applications -----------------------------------------------------
            $applications = @($inventory.Applications)
            $count        = Measure-TkApplicationInventory -Application $applications
            Add-TkHeading -Document $document -Text 'Applications' -Level 2
            Add-TkParagraph -Document $document -Muted -Text (
                '{0} application(s): {1} come back with winget, {2} from the Microsoft Store, {3} with Windows itself, {4} by hand. The export writes the whole list and a winget file for the new machine.' -f
                    $count.Total, $count.Winget, $count.Store, $count.Inbox, $count.Manual)
            $manual = @($applications | Where-Object Reinstall -eq 'By hand')
            if ($manual.Count -gt 0) {
                Add-TkSeverityLine -Document $document -Severity 'Warning' -Heading ('{0} application(s) to reinstall by hand' -f $manual.Count) `
                    -Note 'winget does not know them: keep their installer, and their licence key or account, before the old machine goes.'
                Add-TkTable -Document $document -Column @('Application', 'Version', 'Publisher') -Weight @(2.4, 1, 1.6) `
                    -Row @($manual | ForEach-Object { , @($_.Name, $_.Version, $_.Publisher) })
            }

            # --- Drives and printers --------------------------------------------
            $drives = @($inventory.Drives)
            Add-TkHeading -Document $document -Text 'Network drives' -Level 2
            if ($drives.Count -eq 0) {
                Add-TkParagraph -Document $document -Muted -Text 'No network drive is mapped for this account.'
            }
            else {
                Add-TkTable -Document $document -Column @('Drive', 'Share', 'To map it again') -Weight @(0.5, 2, 2.6) `
                    -Row @($drives | ForEach-Object { , @($_.Letter, $_.Path, $_.Command) })
            }

            $printers = @($inventory.Printers)
            Add-TkHeading -Document $document -Text 'Printers' -Level 2
            if ($printers.Count -eq 0) {
                Add-TkParagraph -Document $document -Muted -Text 'No real printer is installed: the PDF, XPS, OneNote and fax printers are left out.'
            }
            else {
                Add-TkTable -Document $document -Column @('Printer', 'Kind', 'Where', 'To add it again') -Weight @(1.8, 1.1, 1.2, 2.4) `
                    -Row @($printers | ForEach-Object {
                        , @($_.Name, $_.Kind, $_.Where, $(if ($_.Command) { $_.Command } elseif ($_.Kind -like 'Discovered*') { 'appears again on the same network' } else { 'reinstall its driver' }))
                    })
            }

            # --- Mail and browsers ----------------------------------------------
            $data = $inventory.UserData
            Add-TkHeading -Document $document -Text 'Mail and browsers' -Level 2

            foreach ($file in @($data.Pst)) {
                Add-TkSeverityLine -Document $document -Severity 'Warning' -Heading ('Outlook data file: {0}' -f (Split-Path -Path $file.Path -Leaf)) `
                    -Detail (Format-TkBytes -Bytes $file.Length) -Note ('{0}. Mail archived in a PST exists nowhere else: copy it, close Outlook first.' -f $file.Path)
            }

            if ($data.Signatures -gt 0) {
                Add-TkSeverityLine -Document $document -Severity 'Info' -Heading ('{0} Outlook signature(s)' -f $data.Signatures) `
                    -Note 'Kept in %APPDATA%\Microsoft\Signatures, not in the mailbox for the classic Outlook: copy the folder.'
            }

            foreach ($browser in @($data.Browsers)) {
                Add-TkSeverityLine -Document $document -Severity 'Info' -Heading ('{0}: {1} profile(s) with bookmarks' -f $browser.Name, $browser.Profiles) `
                    -Note 'Signed in to the browser, the bookmarks and passwords come back with the account; otherwise export the bookmarks first.'
            }

            if (@($data.Pst).Count -eq 0 -and $data.Signatures -eq 0 -and @($data.Browsers).Count -eq 0) {
                Add-TkParagraph -Document $document -Muted -Text 'No PST file, Outlook signature or browser profile was found.'
            }

            Set-TkDocument -ControlName 'MigrationOutput' -Document $document
            Set-TkStatus -Text 'Carry-over list ready.'
        }
}

<#
.SYNOPSIS
    Checks what a reinstall depends on.
#>
function Invoke-TkReinstallCheckFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Checking the activation and BitLocker...' `
        -ScriptBlock { Get-TkReinstallState } `
        -OnComplete {
            param($result)

            $state = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Activation'] } | Select-Object -Last 1

            if (-not $state) {
                return
            }

            $document = New-TkFlowDocument
            Add-TkHeading   -Document $document -Text 'Before a reinstall' -Level 1
            Add-TkParagraph -Document $document -Muted -Text 'What a reinstall depends on. The product key and the recovery keys are never read out here.'

            foreach ($finding in @(ConvertTo-TkReinstallFinding -State $state)) {
                Add-TkSeverityLine -Document $document -Severity $finding.Severity -Heading $finding.Heading -Detail $finding.Detail -Note $finding.Note
            }

            Add-TkSeverityLine -Document $document -Severity 'Info' -Heading 'Drivers' `
                -Note 'Windows Update finds most drivers again. For a machine it does not cover, Export drivers copies them to the destination below, to add back with pnputil.'

            Set-TkDocument -ControlName 'MigrationOutput' -Document $document
            Set-TkStatus -Text 'Reinstall checks done.'
        }
}

<#
.SYNOPSIS
    Saves the catalogue applications installed here as a configuration profile.
#>
function Save-TkInstalledProfileFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Asking winget what is installed...' `
        -ScriptBlock { @(Get-TkInstalledPackageId) } `
        -OnComplete {
            param($result)

            $applications = @(Get-TkInstalledCatalogApplication -InstalledId @($result.Output | ForEach-Object { [string] $_ }))

            if ($applications.Count -eq 0) {
                Set-TkStatus -Text 'None of the catalogue applications is installed, or winget did not answer.'
                return
            }

            $dialog = New-Object Microsoft.Win32.SaveFileDialog
            $dialog.Title            = 'Save the installed applications as a profile'
            $dialog.Filter           = 'Toolkit profile (*.json)|*.json'
            $dialog.FileName         = ('{0}-applications.json' -f $env:COMPUTERNAME)
            $dialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')

            if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
                return
            }

            $profileData = New-TkConfigProfile -Name ([System.IO.Path]::GetFileNameWithoutExtension($dialog.FileName)) -ApplicationId $applications

            try {
                [System.IO.File]::WriteAllText($dialog.FileName, ($profileData | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
                Set-TkStatus -Text ('{0} application(s) saved. On the new machine: Software, Load profile, then Install selected.' -f $applications.Count)
            }
            catch {
                Set-TkStatus -Text ('The profile could not be written: {0}' -f $_.Exception.Message)
            }
        }
}

<#
.SYNOPSIS
    Reads the destination box, and says what is wrong with it.

.OUTPUTS
    System.String, the destination, or empty when it was refused.
#>
function Get-TkMigrationDestinationFromUi {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Source = @()
    )

    $destination = ([string] (Get-TkControl -Name 'MigrationDestination').Text).Trim()
    $problem     = Test-TkMigrationDestination -Destination $destination -Source $Source

    if ($problem) {
        Set-TkStatus -Text $problem
        return ''
    }

    return $destination
}

<#
.SYNOPSIS
    Exports the drivers to the destination, through a single UAC prompt.
#>
function Invoke-TkDriverExportFromUi {
    [CmdletBinding()]
    param()

    $destination = Get-TkMigrationDestinationFromUi

    if (-not $destination) {
        return
    }

    if (-not (Confirm-TkAction -Title 'Export drivers' -Message ("Copy the third-party drivers of this machine to a folder in:`n`n{0}`n`nThis needs administrator rights; nothing on this machine changes." -f $destination))) {
        return
    }

    $status = if (Test-TkIsElevated) { 'Exporting the drivers...' } else { 'Waiting for administrator consent...' }

    Start-TkPrivilegedAction -Name 'ExportDrivers' -StatusText $status -Parameters @{ Destination = $destination } -OnResult {
        param($outcome)

        if ($outcome) {
            $document = New-TkFlowDocument
            Add-TkHeading -Document $document -Text 'Driver export' -Level 1
            Add-TkSeverityLine -Document $document -Severity $(if ($outcome.Ok) { 'Pass' } else { 'Warning' }) -Heading ([string] $outcome.Message)
            Set-TkDocument -ControlName 'MigrationOutput' -Document $document
        }
    }
}

<#
.SYNOPSIS
    Copies the ticked personal folders, after a confirmation with the sizes.
#>
function Invoke-TkMigrationCopyFromUi {
    [CmdletBinding()]
    param()

    $ticked = @((Get-TkControl -Name 'MigrationFolderList').Children | Where-Object { $_.IsChecked } | ForEach-Object { [string] $_.Tag })
    $apps   = [bool] (Get-TkControl -Name 'MigrationIncludeApps').IsChecked

    if ($ticked.Count -eq 0 -and -not $apps) {
        Set-TkStatus -Text 'Tick the folders to copy, or the applications, first.'
        return
    }

    $destination = Get-TkMigrationDestinationFromUi -Source $ticked

    if (-not $destination) {
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Measuring the folders to copy...' `
        -ParameterList @{ folders = $ticked; destination = $destination } `
        -ScriptBlock {
            param($folders, $destination)

            $sizes = @(Get-TkUserFolderSize | Where-Object { $folders -contains $_.Path })
            $root  = if ($destination -match '^[A-Za-z]:') { $destination.Substring(0, 2) + '\' } else { $destination }
            $free  = try { [long] (New-Object System.IO.DriveInfo($root)).AvailableFreeSpace } catch { [long] -1 }

            [pscustomobject] @{ Sizes = $sizes; Free = $free }
        } `
        -OnComplete {
            param($result)

            $measure = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Sizes'] } | Select-Object -Last 1
            if (-not $measure) { return }

            $label = 'Migration-{0}-{1}-{2:yyyyMMdd}' -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date)
            $plan  = @(New-TkMigrationCopyPlan -Folder @($measure.Sizes) -Destination $destination -Label $label)
            $copy  = @($plan | Where-Object { -not $_.Skip })
            $total = [long] ($copy | Measure-Object -Property Bytes -Sum).Sum

            if ($copy.Count -eq 0 -and -not $apps) {
                Set-TkStatus -Text 'Nothing to copy: every folder ticked is kept by OneDrive.'
                return
            }

            if ($measure.Free -ge 0 -and $total -gt $measure.Free) {
                Set-TkStatus -Text ('The destination has {0} free; the folders need {1}.' -f (Format-TkBytes -Bytes $measure.Free), (Format-TkBytes -Bytes $total))
                return
            }

            $lines = @($plan | ForEach-Object { if ($_.Skip) { '- {0}: skipped, {1}' -f $_.Name, $_.Skip } else { '- {0}: {1}' -f $_.Name, (Format-TkBytes -Bytes $_.Bytes) } })
            if ($apps) { $lines += '- Applications: the full list, and a winget file to reinstall them' }
            $message = "Copy to {0}\{1}:`n`n{2}`n`nTotal {3}{4}. Nothing is deleted from this machine; files kept online only by OneDrive are not downloaded." -f `
                $destination.TrimEnd('\'), $label, ($lines -join "`n"), (Format-TkBytes -Bytes $total),
                $(if ($measure.Free -ge 0) { ', {0} free at the destination' -f (Format-TkBytes -Bytes $measure.Free) } else { '' })

            if (-not (Confirm-TkAction -Title 'Copy the user folders' -Message $message)) {
                return
            }

            Invoke-TkBackgroundAction -StatusText 'Copying the user folders, this can take a while...' `
                -ParameterList @{ plan = $plan; root = [System.IO.Path]::Combine($destination.TrimEnd('\') + '\', $label); apps = $apps } `
                -ScriptBlock {
                    param($plan, $root, $apps)
                    $copied  = @(Copy-TkMigrationFolder -Plan @($plan | Where-Object { $_ }) -Confirm:$false)
                    $section = @{}
                    if ($apps) {
                        $section['applications'] = Export-TkMigrationApplication -Root $root -Confirm:$false
                        $copied += [pscustomobject] @{ Name = 'Applications'; Ok = [bool] $section['applications'].list
                                                       Text = ('{0} listed, {1} in the winget file' -f $section['applications'].total, $section['applications'].winget); Log = '' }
                    }
                    [void] (Save-TkMigrationManifest -Root $root -Plan @($plan | Where-Object { $_ }) -Result $copied -Section $section -Confirm:$false)
                    $copied
                } `
                -OnComplete {
                    param($copied)

                    $rows = @($copied.Output | Where-Object { $_ -and $_.PSObject.Properties['Ok'] })

                    $document = New-TkFlowDocument
                    Add-TkHeading -Document $document -Text 'User folders copied' -Level 1

                    foreach ($row in $rows) {
                        Add-TkSeverityLine -Document $document -Severity $(if ($row.Ok) { 'Pass' } else { 'Warning' }) -Heading $row.Name -Detail $row.Text -Note $row.Log
                    }

                    Set-TkDocument -ControlName 'MigrationOutput' -Document $document
                    Set-TkStatus -Text ('{0} of {1} folder(s) copied without error.' -f @($rows | Where-Object Ok).Count, $rows.Count)
                }
        }.GetNewClosure()
}


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

# The package read last and the destination box of each of its folders.
$script:TkImportPackage = $null
$script:TkImportRows    = @()

<#
.SYNOPSIS
    Keeps the package read and its rows, for the import.

.DESCRIPTION
    A function rather than an assignment in a completion block, where
    $script: is not this file's scope.
#>
function Set-TkImportState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [AllowNull()] [object] $Package,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Row = @()
    )

    if ($PSCmdlet.ShouldProcess('import', 'Remember the package')) {
        $script:TkImportPackage = $Package
        $script:TkImportRows    = @($Row)
    }
}

<#
.SYNOPSIS
    Where a folder of the package goes by default: the same Windows folder of this account.

.OUTPUTS
    System.String
#>
function Get-TkDefaultImportTarget {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Key = ''
    )

    if (-not $Key) { return '' }

    return [string] (@(Get-TkKnownFolder | Where-Object Key -eq $Key) | Select-Object -First 1).Path
}

<#
.SYNOPSIS
    Reads the package and draws a destination row for each of its folders.
#>
function Invoke-TkReadMigrationPackageFromUi {
    [CmdletBinding()]
    param()

    $package = Read-TkMigrationPackage -Path ([string] (Get-TkControl -Name 'MigrationPackage').Text)
    $list    = Get-TkControl -Name 'MigrationImportList'
    $list.Children.Clear()

    if ($package.Error) {
        Set-TkImportState -Package $null -Confirm:$false
        Set-TkStatus -Text $package.Error
        return
    }

    $rows = foreach ($folder in @($package.Folders)) {

        $label = New-Object System.Windows.Controls.TextBlock
        $label.Text   = if ($folder.Bytes -ge 0) { '{0}   {1}' -f $folder.Name, (Format-TkBytes -Bytes $folder.Bytes) } else { $folder.Name }
        $label.Margin = New-Object System.Windows.Thickness(0, 0, 0, 4)

        $box = New-Object System.Windows.Controls.TextBox
        $box.Text    = Get-TkDefaultImportTarget -Key $folder.Key
        $box.Tag     = 'Where it goes; empty leaves it out'
        $box.ToolTip = $folder.Source

        $browse = New-Object System.Windows.Controls.Button
        $browse.Content = 'Browse'
        $browse.Margin  = New-Object System.Windows.Thickness(8, 0, 0, 0)
        $browse.Tag     = $box
        $browse.Add_Click({
            param($source, $clickArgs)
            $null = $clickArgs
            $picked = Select-TkFolderPath -Description 'Where this folder goes on this machine.' -Start ([string] $source.Tag.Text)
            if ($picked) { $source.Tag.Text = $picked }
        })

        $line = New-Object System.Windows.Controls.DockPanel
        [System.Windows.Controls.DockPanel]::SetDock($browse, [System.Windows.Controls.Dock]::Right)
        [void] $line.Children.Add($browse)
        [void] $line.Children.Add($box)

        $row = New-Object System.Windows.Controls.StackPanel
        $row.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
        [void] $row.Children.Add($label)
        [void] $row.Children.Add($line)
        [void] $list.Children.Add($row)

        [pscustomobject] @{ Name = $folder.Name; Key = $folder.Key; Box = $box }
    }

    Set-TkImportState -Package $package -Row @($rows) -Confirm:$false
    (Get-TkControl -Name 'MigrationCloudTarget').SelectedIndex = 0

    $appsBox  = Get-TkControl -Name 'MigrationImportApps'
    $appsNote = Get-TkControl -Name 'MigrationImportAppsNote'
    $packageApps = $package.Applications

    if ($packageApps) {
        $manual = @($packageApps.Applications | Where-Object { $_.Reinstall -eq 'By hand' }).Count
        $appsBox.Content    = 'Reinstall the {0} application(s) winget knows' -f $packageApps.WingetCount
        $appsBox.IsChecked  = [bool] $packageApps.Winget
        $appsBox.IsEnabled  = [bool] $packageApps.Winget
        $appsBox.Visibility = [System.Windows.Visibility]::Visible
        $appsNote.Text       = '{0} other application(s) come back by hand; the import report lists them.' -f $manual
        $appsNote.Visibility = [System.Windows.Visibility]::Visible
    }
    else {
        $appsBox.IsChecked   = $false
        $appsBox.Visibility  = [System.Windows.Visibility]::Collapsed
        $appsNote.Visibility = [System.Windows.Visibility]::Collapsed
    }

    $from = if ($package.FromManifest) { 'from {0} ({1}), {2}' -f $package.Computer, $package.User, $package.Created } else { 'without a manifest: folders matched by name' }
    Set-TkStatus -Text ('{0} folder(s) in the package, {1}.' -f @($package.Folders).Count, $from)
}

<#
.SYNOPSIS
    Points every destination at the Windows folders, or at the same folders inside a cloud folder.
#>
function Set-TkImportTargetFromCloud {
    [CmdletBinding()]
    param()

    $combo = Get-TkControl -Name 'MigrationCloudTarget'
    if (-not $combo -or @($script:TkImportRows).Count -eq 0) { return }

    $roots = @(Get-TkCloudRoot)

    foreach ($row in @($script:TkImportRows)) {
        $row.Box.Text = if ($combo.SelectedIndex -le 0) { Get-TkDefaultImportTarget -Key $row.Key }
                        else { [System.IO.Path]::Combine($roots[$combo.SelectedIndex - 1].Path, $row.Name) }
    }
}

<#
.SYNOPSIS
    Imports the package: finds the conflicts, asks, then copies what is not there yet.
#>
function Invoke-TkMigrationImportFromUi {
    [CmdletBinding()]
    param()

    $package = $script:TkImportPackage

    if (-not $package) {
        Set-TkStatus -Text 'Read a package first.'
        return
    }

    $targets = @{}
    foreach ($row in @($script:TkImportRows)) { $targets[$row.Name] = [string] $row.Box.Text }

    $plan = New-TkMigrationImportPlan -Package $package -Target $targets

    if (@($plan.Errors).Count -gt 0) {
        Set-TkStatus -Text (@($plan.Errors)[0])
        return
    }

    $reinstall = [bool] ((Get-TkControl -Name 'MigrationImportApps').IsChecked) -and $package.Applications -and $package.Applications.Winget
    $wingetFile = if ($reinstall) { [string] $package.Applications.Winget } else { '' }
    $manualApps = if ($package.Applications) { @($package.Applications.Applications | Where-Object { $_.Reinstall -eq 'By hand' }) } else { @() }

    if (@($plan.Steps).Count -eq 0 -and -not $reinstall) {
        Set-TkStatus -Text 'Every destination is empty and no application is to be reinstalled: there is nothing to import.'
        return
    }

    Invoke-TkBackgroundAction -StatusText 'Comparing the package with this machine...' `
        -ParameterList @{ steps = @($plan.Steps) } `
        -ScriptBlock {
            param($steps)
            foreach ($step in $steps) {
                $check = Find-TkMigrationConflict -Source $step.Source -Target $step.Target
                [pscustomobject] @{ Name = $step.Name; New = $check.New; Same = $check.Same; Conflicts = @($check.Conflicts) }
            }
        } `
        -OnComplete {
            param($result)

            $checks = @($result.Output | Where-Object { $_ -and $_.PSObject.Properties['Conflicts'] })
            $lines  = @(foreach ($step in @($plan.Steps)) {
                $check = @($checks | Where-Object Name -eq $step.Name) | Select-Object -First 1
                '- {0} -> {1}: {2} new file(s), {3} already there, {4} conflict(s)' -f $step.Name, $step.Target, $check.New, $check.Same, @($check.Conflicts).Count
            })
            $conflicts = @($checks | ForEach-Object { $_.Conflicts })

            if ($wingetFile) { $lines += ('- Applications: winget import of {0} package(s), as you, which can take a while' -f $package.Applications.WingetCount) }
            $message = "Import into this machine:`n`n{0}`n`nOnly the new files are copied. {1}" -f ($lines -join "`n"),
                $(if ($conflicts.Count -gt 0) { '{0} file(s) exist here with other content: they are kept as they are, and listed.' -f $conflicts.Count } else { 'No file here is touched.' })

            if (-not (Confirm-TkAction -Title 'Import the package' -Message $message)) {
                return
            }

            Invoke-TkBackgroundAction -StatusText 'Importing, this can take a while...' `
                -ParameterList @{ steps = @($plan.Steps); wingetFile = $wingetFile } `
                -ScriptBlock {
                    param($steps, $wingetFile)
                    if (@($steps).Count -gt 0) { Import-TkMigrationFolder -Step $steps -Confirm:$false }
                    if ($wingetFile) {
                        $reinstalled = Invoke-TkWingetImport -Path $wingetFile -Confirm:$false
                        [pscustomobject] @{ Name = 'Applications (winget)'; Ok = $reinstalled.Ok; Text = $reinstalled.Text; Log = '' }
                    }
                } `
                -OnComplete {
                    param($imported)

                    $rows = @($imported.Output | Where-Object { $_ -and $_.PSObject.Properties['Ok'] })

                    $document = New-TkFlowDocument
                    Add-TkHeading -Document $document -Text 'Package imported' -Level 1
                    Add-TkParagraph -Document $document -Muted -Text 'Only files that were not on this machine were copied; nothing here was overwritten.'

                    foreach ($row in $rows) {
                        Add-TkSeverityLine -Document $document -Severity $(if ($row.Ok) { 'Pass' } else { 'Warning' }) -Heading $row.Name -Detail $row.Text -Note $row.Log
                    }

                    if ($conflicts.Count -gt 0) {
                        Add-TkHeading -Document $document -Text ('Kept as they were: {0} conflict(s)' -f $conflicts.Count) -Level 2
                        Add-TkParagraph -Document $document -Muted -Text 'The version on this machine was kept; the one in the package is still in the package. Compare them and keep the one you want.'
                        Add-TkTable -Document $document -Column @('File here', 'Size here', 'Changed here', 'In the package') -Weight @(3, 0.8, 1.1, 1.1) `
                            -Row @($conflicts | Select-Object -First 100 | ForEach-Object {
                                , @($_.Target, (Format-TkBytes -Bytes $_.TargetBytes), ([datetime] $_.TargetTime).ToString('yyyy-MM-dd HH:mm'), ([datetime] $_.SourceTime).ToString('yyyy-MM-dd HH:mm'))
                            })
                    }

                    if ($manualApps.Count -gt 0) {
                        Add-TkHeading -Document $document -Text ('To reinstall by hand: {0} application(s)' -f $manualApps.Count) -Level 2
                        Add-TkParagraph -Document $document -Muted -Text 'winget does not know these; install them from their publisher, with their licence.'
                        Add-TkTable -Document $document -Column @('Application', 'Version', 'Publisher') -Weight @(2.4, 1, 1.6) `
                            -Row @($manualApps | ForEach-Object { , @([string] $_.Name, [string] $_.Version, [string] $_.Publisher) })
                    }

                    Set-TkDocument -ControlName 'MigrationOutput' -Document $document
                    Set-TkStatus -Text ('{0} of {1} step(s) done without error.' -f @($rows | Where-Object Ok).Count, $rows.Count)
                }.GetNewClosure()
        }.GetNewClosure()
}
