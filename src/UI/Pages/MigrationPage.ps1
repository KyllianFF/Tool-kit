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
        foreach ($folder in @(Get-TkPersonalFolder)) {
            $box = New-Object System.Windows.Controls.CheckBox
            $box.Content   = Split-Path -Path $folder -Leaf
            $box.Tag       = $folder
            $box.IsChecked = $true
            $box.Margin    = New-Object System.Windows.Thickness(0, 0, 0, 6)
            $box.ToolTip   = $folder
            [void] $list.Children.Add($box)
        }
    }

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

    Add-Type -AssemblyName System.Windows.Forms

    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description         = 'Where to copy to: an external drive is best.'
    $dialog.ShowNewFolderButton = $true

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        (Get-TkControl -Name 'MigrationDestination').Text = $dialog.SelectedPath
    }

    $dialog.Dispose()
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

    if ($ticked.Count -eq 0) {
        Set-TkStatus -Text 'Tick the folders to copy first.'
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

            if ($copy.Count -eq 0) {
                Set-TkStatus -Text 'Nothing to copy: every folder ticked is kept by OneDrive.'
                return
            }

            if ($measure.Free -ge 0 -and $total -gt $measure.Free) {
                Set-TkStatus -Text ('The destination has {0} free; the folders need {1}.' -f (Format-TkBytes -Bytes $measure.Free), (Format-TkBytes -Bytes $total))
                return
            }

            $lines = @($plan | ForEach-Object { if ($_.Skip) { '- {0}: skipped, {1}' -f $_.Name, $_.Skip } else { '- {0}: {1}' -f $_.Name, (Format-TkBytes -Bytes $_.Bytes) } })
            $message = "Copy to {0}\{1}:`n`n{2}`n`nTotal {3}{4}. Nothing is deleted from this machine; files kept online only by OneDrive are not downloaded." -f `
                $destination.TrimEnd('\'), $label, ($lines -join "`n"), (Format-TkBytes -Bytes $total),
                $(if ($measure.Free -ge 0) { ', {0} free at the destination' -f (Format-TkBytes -Bytes $measure.Free) } else { '' })

            if (-not (Confirm-TkAction -Title 'Copy the user folders' -Message $message)) {
                return
            }

            Invoke-TkBackgroundAction -StatusText 'Copying the user folders, this can take a while...' `
                -ParameterList @{ plan = $plan } `
                -ScriptBlock {
                    param($plan)
                    Copy-TkMigrationFolder -Plan $plan -Confirm:$false
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
