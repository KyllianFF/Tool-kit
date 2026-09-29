<#
    Toolkit - UI / Fixes page

    Each fix is a card, and the card is the button: the row you are reading is
    the row you press. The cards live inside a data template, so instead of
    naming every one they are handled by a single class handler on the list,
    reading the fix identifier from the tag of whichever card was pressed.
#>

<#
.SYNOPSIS
    Returns the icon character for a risk level.

.DESCRIPTION
    The tile colour already ranks the three levels. The glyph repeats it in a
    second channel, which is what makes the ranking survive a colour blind
    reader and a bad screen. See Get-TkCategoryGlyph for the icon rules.

.OUTPUTS
    System.String
#>
function Get-TkFixGlyph {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Key
    )

    $glyphs = @{
        'low'    = 0xE73E  # tick
        'medium' = 0xE946  # information
        'high'   = 0xE7BA  # warning triangle
    }

    $lookup = if ($Key) { $Key.ToLowerInvariant() } else { '' }
    $point  = if ($lookup -and $glyphs.ContainsKey($lookup)) { $glyphs[$lookup] } else { 0xE90F }

    return [string] [char] $point
}

<#
.SYNOPSIS
    Wires the Fixes page and loads the catalog.
#>
function Initialize-TkFixesPage {
    [CmdletBinding()]
    param()

    $fixes = Get-TkFix

    # Read once. Elevation cannot change without restarting the process, so
    # asking per row would give the same answer every time.
    $elevated = Test-TkIsElevated

    $items = @()

    foreach ($fix in $fixes) {

        $needsRights = $fix.requiresElevation -and -not $elevated

        $items += [pscustomobject]@{
            Id          = $fix.id
            Name        = $fix.name
            Description = $fix.description
            WhenToUse   = 'When to use: ' + $fix.whenToUse
            RiskText    = '{0} risk' -f $fix.risk

            # Tile colour carries the risk, which is the one thing worth
            # seeing before reading the name.
            Glyph       = Get-TkFixGlyph  -Key $fix.risk
            TileBrush   = Get-TkTileBrush -Key ('fix-{0}' -f $fix.risk.ToLowerInvariant())

            # A fix that cannot run is shown greyed with the reason on it,
            # rather than accepting the click and reporting the refusal
            # afterwards. Which fixes need rights differs per fix, so this is
            # decided per row instead of disabling the whole page.
            CanRun      = (-not $needsRights)
            RunTooltip  = if ($needsRights) {
                              'Needs administrator rights. Use "Restart as administrator" in the header.'
                          }
                          else {
                              'Asks for confirmation, and says what it will do, before anything runs.'
                          }

            Definition  = $fix
        }
    }

    $list = Get-TkControl -Name 'FixList'

    if ($list) {

        $list.ItemsSource = $items

        # One handler for every card in the template. The alternative, naming
        # each one, does not work inside a DataTemplate.
        #
        # The card is itself the button now, and ButtonBase raises Click with
        # itself as the original source, so the identifier in Tag is reachable
        # however deep inside the card the pointer actually landed.
        $list.AddHandler(
            [System.Windows.Controls.Button]::ClickEvent,
            [System.Windows.RoutedEventHandler] {
                param($eventSource, $routedArgs)

                $fixId = $routedArgs.OriginalSource.Tag

                if ($fixId) {
                    Invoke-TkFixFromUi -FixId ([string] $fixId)
                }
            }
        )
    }

    Register-TkClick -Name 'BtnAutoLogon' -Action { Show-TkAutoLogonDialog }

    Initialize-TkPlanTab

    Register-TkClick -Name 'BtnRestorePoint' -Action {

        # A standard user gets a single UAC prompt for this one action; an
        # elevated instance runs it in place.
        $status = if (Test-TkIsElevated) { 'Creating a restore point...' } else { 'Waiting for administrator consent...' }

        Start-TkPrivilegedAction -Name 'RestorePoint' -StatusText $status
    }
}

<#
.SYNOPSIS
    Confirms and runs one fix.

.PARAMETER FixId
    Identifier from the catalog.
#>
function Invoke-TkFixFromUi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $FixId
    )

    $fix = Get-TkFix | Where-Object { $_.id -eq $FixId } | Select-Object -First 1

    if (-not $fix) {
        Set-TkStatus -Text ('Unknown fix: {0}' -f $FixId)
        return
    }

    if ($fix.requiresElevation -and -not (Test-TkIsElevated)) {
        Set-TkStatus -Text ('"{0}" requires an elevated instance.' -f $fix.name)
        return
    }

    $message = "{0}`n`n{1}`n`nRisk: {2}." -f $fix.name, $fix.description, $fix.risk

    if ($fix.requiresRestart) {
        $message += ' A restart is needed afterwards.'
    }

    $message += "`n`nRun it now?"

    if (-not (Confirm-TkAction -Title $fix.name -Message $message)) {
        return
    }

    Invoke-TkBackgroundAction -StatusText ('Running: {0}...' -f $fix.name) `
        -ArgumentList @($FixId) `
        -ScriptBlock {
            param($id)

            $definition = Get-TkFix | Where-Object { $_.id -eq $id } | Select-Object -First 1

            if (-not $definition) {
                return $false
            }

            return (Invoke-TkFix -Fix $definition -Confirm:$false)
        } `
        -OnComplete {
            param($result)

            if (@($result.Output) -contains $true) {
                Set-TkStatus -Text ('Finished: {0}' -f $fix.name)
            }
            else {
                Set-TkStatus -Text ('Failed or partly failed: {0}. See the output for details.' -f $fix.name)
            }
        }.GetNewClosure()
}

<#
.SYNOPSIS
    Shows the automatic logon dialog.

.DESCRIPTION
    A separate window rather than inline controls, because the password field
    should not sit on a page that stays open behind other work.
#>
function Show-TkAutoLogonDialog {
    [CmdletBinding()]
    param()

    if (-not (Test-TkIsElevated)) {
        Set-TkStatus -Text 'Configuring automatic logon requires an elevated instance.'
        return
    }

    $status = Get-TkAutoLogonStatus

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Automatic logon" Height="430" Width="560"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#16181D">
    <Grid Margin="22">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Automatic logon" Foreground="#E7EAF0"
                   FontSize="17" FontWeight="SemiBold" Margin="0,0,0,6" />

        <TextBlock Grid.Row="1" Foreground="#98A1B2" FontSize="12" TextWrapping="Wrap" Margin="0,0,0,16"
                   Text="The password is stored as an LSA secret, encrypted by the system, not as clear text in the registry. Automatic logon still means that anyone with physical access to this machine is signed in as this user." />

        <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,10">
            <TextBlock Text="User name" Foreground="#E7EAF0" Width="110" VerticalAlignment="Center" />
            <TextBox x:Name="AlUser" Width="330" Padding="7,5" Background="#1E2128" Foreground="#E7EAF0"
                     BorderBrush="#333845" CaretBrush="#E7EAF0" />
        </StackPanel>

        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,0,0,10">
            <TextBlock Text="Domain" Foreground="#E7EAF0" Width="110" VerticalAlignment="Center" />
            <TextBox x:Name="AlDomain" Width="330" Padding="7,5" Background="#1E2128" Foreground="#E7EAF0"
                     BorderBrush="#333845" CaretBrush="#E7EAF0" />
        </StackPanel>

        <StackPanel Grid.Row="4" Orientation="Horizontal" Margin="0,0,0,10">
            <TextBlock Text="Password" Foreground="#E7EAF0" Width="110" VerticalAlignment="Center" />
            <PasswordBox x:Name="AlPassword" Width="330" Padding="7,5" Background="#1E2128"
                         Foreground="#E7EAF0" BorderBrush="#333845" />
        </StackPanel>

        <TextBlock Grid.Row="5" x:Name="AlStatus" Foreground="#D29922" FontSize="12"
                   TextWrapping="Wrap" Margin="0,6,0,0" VerticalAlignment="Top" />

        <StackPanel Grid.Row="6" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="AlDisable" Content="Disable automatic logon" Padding="14,7" Margin="0,0,8,0"
                    Background="#262A33" Foreground="#E7EAF0" BorderBrush="#333845" />
            <Button x:Name="AlEnable" Content="Enable" Padding="20,7" Margin="0,0,8,0"
                    Background="#2A4C8A" Foreground="#E7EAF0" BorderBrush="#4C8DFF" />
            <Button x:Name="AlCancel" Content="Close" Padding="14,7"
                    Background="#262A33" Foreground="#E7EAF0" BorderBrush="#333845" />
        </StackPanel>
    </Grid>
</Window>
'@

    $reader = New-Object System.Xml.XmlNodeReader ([xml] $xaml)
    $dialog = [Windows.Markup.XamlReader]::Load($reader)
    $dialog.Owner = (Get-TkContext).Window

    $userBox     = $dialog.FindName('AlUser')
    $domainBox   = $dialog.FindName('AlDomain')
    $passwordBox = $dialog.FindName('AlPassword')
    $statusText  = $dialog.FindName('AlStatus')

    $userBox.Text   = if ($status.Enabled) { $status.UserName } else { $env:USERNAME }
    $domainBox.Text = if ($status.Enabled -and $status.Domain -ne 'Not available') { $status.Domain }
                      else { $env:COMPUTERNAME }

    if ($status.Enabled) {
        $statusText.Text = 'Automatic logon is currently enabled for {0}\{1}.' -f $status.Domain, $status.UserName
    }
    else {
        $statusText.Text = 'Automatic logon is currently disabled.'
    }

    if ($status.ClearTextPassword) {
        $statusText.Text += ' ' + $status.Warning
    }

    $dialog.FindName('AlEnable').Add_Click({

        $userName = $userBox.Text.Trim()
        $domain   = $domainBox.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($userName) -or $passwordBox.SecurePassword.Length -eq 0) {
            $statusText.Text = 'A user name and a password are both required.'
            return
        }

        $ok = Enable-TkAutoLogon -UserName $userName -Domain $domain `
                                 -Password $passwordBox.SecurePassword -Confirm:$false

        if ($ok) {
            $statusText.Text = 'Automatic logon enabled for {0}\{1}.' -f $domain, $userName
            $passwordBox.Clear()
        }
        else {
            $statusText.Text = 'The change failed. See the output panel for the reason.'
        }
    })

    $dialog.FindName('AlDisable').Add_Click({

        if (Disable-TkAutoLogon -Confirm:$false) {
            $statusText.Text = 'Automatic logon disabled and the stored secret removed.'
            $passwordBox.Clear()
        }
        else {
            $statusText.Text = 'The change failed. See the output panel for the reason.'
        }
    })

    $dialog.FindName('AlCancel').Add_Click({
        $dialog.Close()
    })

    # Clear the password field when the window closes, so the value does not
    # sit in a control that stays referenced until collection.
    $dialog.Add_Closed({ $passwordBox.Clear() })

    $dialog.ShowDialog() | Out-Null
}

# ---------------------------------------------------------------------------
# Verified plan tab
# ---------------------------------------------------------------------------

# The verdict of the last plan, shown under its steps. Set through
# Set-TkPlanVerdict: a completion handler cannot reach this file's scope.
$script:TkPlanVerdict = $null

<#
.SYNOPSIS
    Keeps the verdict of the last plan for the view.
#>
function Set-TkPlanVerdict {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [AllowNull()]
        $Verdict
    )

    if ($PSCmdlet.ShouldProcess('verified plan', 'Remember the verdict')) {
        $script:TkPlanVerdict = $Verdict
    }
}

<#
.SYNOPSIS
    Fills the Verified plan tab: the fixes to tick, and the options.
#>
function Initialize-TkPlanTab {
    [CmdletBinding()]
    param()

    $panel = Get-TkControl -Name 'PlanFixList'

    if ($panel) {

        $elevated = Test-TkIsElevated

        foreach ($fix in @(Get-TkFix)) {

            $reports = @(Get-TkPlanReport -Fix @($fix))
            $allowed = -not ($fix.requiresElevation -and -not $elevated)

            $box = New-Object System.Windows.Controls.CheckBox
            $box.Content   = $fix.name
            $box.Tag       = $fix.id
            $box.IsEnabled = $allowed
            $box.Margin    = New-Object System.Windows.Thickness(0, 0, 18, 8)
            $box.ToolTip   = if (-not $allowed) { 'Needs administrator rights. Use "Restart as administrator" in the header.' }
                             elseif ($reports.Count -gt 0) { '{0} Checked with the report(s): {1}.' -f $fix.description, ($reports -join ', ') }
                             else { '{0} No report shows its effect: it runs, unverified.' -f $fix.description }

            [void] $panel.Children.Add($box)
        }
    }

    $restore = Get-TkControl -Name 'PlanRestorePoint'
    if ($restore -and -not (Test-TkIsElevated)) {
        $restore.IsChecked = $false
        $restore.IsEnabled = $false
        $restore.ToolTip   = 'A restore point needs administrator rights.'
    }

    Register-TkClick -Name 'BtnPlanRun'     -Action { Invoke-TkPlanFromUi }
    Register-TkClick -Name 'BtnPlanStop'    -Action { Stop-TkActionQueue -Name 'VerifiedPlan' -Confirm:$false; Set-TkStatus -Text 'The plan stops after this step.' }
    Register-TkClick -Name 'BtnPlanRestore' -Action { Start-Process -FilePath ([System.IO.Path]::Combine([Environment]::SystemDirectory, 'rstrui.exe')) }

    $stop = Get-TkControl -Name 'BtnPlanStop'
    if ($stop) { $stop.IsEnabled = $false }

    $document = New-TkFlowDocument
    Add-TkParagraph -Document $document -Muted -Text 'Tick the fixes of the plan: they run in the order of this list, between a reading of the reports before and one after.'
    Set-TkDocument -ControlName 'PlanOutput' -Document $document
}

<#
.SYNOPSIS
    Confirms the whole plan, then runs it step by step.
#>
function Invoke-TkPlanFromUi {
    [CmdletBinding()]
    param()

    $panel  = Get-TkControl -Name 'PlanFixList'
    $chosen = @($panel.Children | Where-Object { $_.IsChecked -and $_.IsEnabled } | ForEach-Object { [string] $_.Tag })

    if ($chosen.Count -eq 0) {
        Set-TkStatus -Text 'Tick the fixes of the plan first.'
        return
    }

    $restore = [bool] (Get-TkControl -Name 'PlanRestorePoint').IsChecked
    $stop    = [bool] (Get-TkControl -Name 'PlanStopOnFailure').IsChecked
    $steps   = @(New-TkVerifiedPlanStep -FixId $chosen -RestorePoint:$restore)
    $fixes   = @(Get-TkFix | Where-Object { $chosen -contains $_.id })
    $reports = @(Get-TkPlanReport -Fix $fixes)

    $message = "The plan, in order:`n`n{0}`n`n" -f ((@($steps | ForEach-Object { '- ' + $_.Label })) -join "`n")
    $message += if ($reports.Count -gt 0) { 'The reports read before and after say whether the machine is better or worse. ' } else { 'No report shows the effect of these fixes: they run, unverified. ' }
    $message += if ($restore) { 'A fix has no revert of its own: the restore point is the way back.' } else { 'A fix has no revert of its own, and no restore point is taken.' }
    $message += "`n`nRun the plan?"

    if (-not (Confirm-TkAction -Title 'Run the verified plan' -Message $message)) {
        return
    }

    Set-TkPlanVerdict -Verdict $null -Confirm:$false
    (Get-TkControl -Name 'BtnPlanRun').IsEnabled  = $false
    (Get-TkControl -Name 'BtnPlanStop').IsEnabled = $true

    [void] (New-TkActionQueue -Name 'VerifiedPlan' -Step $steps -StopOnFailure $stop -Confirm:$false `
        -OnStep { param($queue, $step) $null = $step; Write-TkPlanView -Queue $queue } `
        -OnDone { param($queue) Complete-TkPlanFromUi -Queue $queue })

    Start-TkActionQueue -Name 'VerifiedPlan' -Confirm:$false
}

<#
.SYNOPSIS
    Judges a finished plan, journals it and shows the verdict.
#>
function Complete-TkPlanFromUi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Queue
    )

    $document = { param($key) $step = @($Queue.Steps | Where-Object { $_.Key -eq $key -and $_.State -eq 'Done' }) | Select-Object -First 1; if ($step -and $step.Output) { $step.Output.Document } else { $null } }

    $ids     = @($Queue.Steps | Where-Object { $_.Key -like 'fix:*' } | ForEach-Object { $_.Key.Substring(4) })
    $fixes   = @(Get-TkFix | Where-Object { $ids -contains $_.id })
    $verdict = Get-TkPlanVerdict -Before (& $document 'before') -After (& $document 'after') -Fix $fixes

    Set-TkPlanVerdict -Verdict $verdict -Confirm:$false

    $ran    = @($Queue.Steps | Where-Object { $_.Key -like 'fix:*' -and $_.State -eq 'Done' }).Count
    $failed = @($Queue.Steps | Where-Object { $_.Key -like 'fix:*' -and $_.State -eq 'Failed' }).Count
    $word   = switch ($verdict.Verdict) { 'Better' { 'better' } 'Worse' { 'worse' } 'Same' { 'no change seen' } default { 'not verified' } }

    Add-TkJournalEntry -Name ('Verified plan: {0} of {1} fix(es) run, {2}' -f $ran, $ids.Count, $word) -Category 'Fixes' -Success ($failed -eq 0 -and $verdict.Verdict -ne 'Worse') `
        -Detail ((@($verdict.Reports | ForEach-Object { '{0}: {1} to {2} ({3})' -f $_.Report, $_.Before, $_.After, $_.Direction })) -join '; ')

    (Get-TkControl -Name 'BtnPlanRun').IsEnabled  = $true
    (Get-TkControl -Name 'BtnPlanStop').IsEnabled = $false

    Write-TkPlanView -Queue $Queue
    Set-TkStatus -Text (Format-TkActionQueueProgress -Queue $Queue)
}

<#
.SYNOPSIS
    Shows the steps of the plan as they run, then its verdict.
#>
function Write-TkPlanView {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Queue
    )

    $document = New-TkFlowDocument

    Add-TkHeading   -Document $document -Text 'Verified plan' -Level 1
    Add-TkParagraph -Document $document -Muted -Text (Format-TkActionQueueProgress -Queue $Queue)

    $states = @{ Waiting = 'Waiting'; Running = 'Running...'; Done = 'Done'; Failed = 'Failed'; NotRun = 'Not run' }

    Add-TkTable -Document $document -Column @('Step', 'State', 'Note') -Weight @(3.0, 0.9, 3.0) `
        -Row @($Queue.Steps | ForEach-Object { , @($_.Label, $states[[string] $_.State], $_.Text) })

    $verdict = $script:TkPlanVerdict

    if ($Queue.Finished -and $verdict) {

        switch ($verdict.Verdict) {
            'Better'      { Add-TkSeverityLine -Document $document -Severity 'Pass'    -Heading 'Better after the plan' -Note 'The reports read after show fewer problems than before.' }
            'Same'        { Add-TkSeverityLine -Document $document -Severity 'Info'    -Heading 'No change the reports can see' -Note 'The fixes ran, and the reports read the same before and after.' }
            'Worse'       { Add-TkSeverityLine -Document $document -Severity 'Fail'    -Heading 'Worse after the plan' -Note $(if (@($Queue.Steps | Where-Object { $_.Key -eq 'restore' -and $_.State -eq 'Done' }).Count) { 'The restore point taken first is the way back: Open System Restore.' } else { 'No restore point was taken first.' }) }
            default       { Add-TkSeverityLine -Document $document -Severity 'Info'    -Heading 'Not verified' -Note 'No report was read before and after these fixes.' }
        }

        if (@($verdict.Reports).Count -gt 0) {
            Add-TkTable -Document $document -Column @('Report', 'Before', 'After', 'Result') -Weight @(1.4, 1.0, 1.0, 1.0) `
                -Row @($verdict.Reports | ForEach-Object { , @($_.Report, $_.Before, $_.After, $_.Direction) })

            $changes = @($verdict.Reports | ForEach-Object { $_.Changes } | Where-Object { $_ } | Select-Object -First 20)
            if ($changes.Count -gt 0) {
                Add-TkTable -Document $document -Column @('Report', 'What', 'Change', 'Result') -Weight @(1.0, 3.0, 1.0, 0.8) `
                    -Row @($changes | ForEach-Object { , @($_.Report, $_.Item, $_.Change, $_.Direction) })
            }
        }

        if (@($verdict.Unverified).Count -gt 0) {
            Add-TkParagraph -Document $document -Muted -Text ('No report shows the effect of: {0}.' -f (@($verdict.Unverified) -join ', '))
        }

        if (@($verdict.AwaitRestart).Count -gt 0) {
            Add-TkParagraph -Document $document -Muted -Text ('Only a restart completes: {0}. Compare again after it, from Intervention, Compare.' -f (@($verdict.AwaitRestart) -join ', '))
        }
    }

    Set-TkDocument -ControlName 'PlanOutput' -Document $document
}
