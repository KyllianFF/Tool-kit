<#
    Toolkit - UI / Before hardening (a tab of the Audit page)

    Turns Windows' audit modes on and off through a UAC prompt, and shows
    what each one recorded: who or what a hardening would have refused.
#>

# The last reading, for the view. Set through Set-TkImpactResult: a
# completion handler cannot reach this file's scope.
$script:TkImpactResult = $null

<#
.SYNOPSIS
    Keeps the last reading of the audit modes.
#>
function Set-TkImpactResult {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [AllowNull()]
        $Result
    )

    if ($PSCmdlet.ShouldProcess('before hardening', 'Remember the reading')) {
        $script:TkImpactResult = $Result
    }
}

<#
.SYNOPSIS
    Wires the Before hardening tab.
#>
function Initialize-TkImpactTab {
    [CmdletBinding()]
    param()

    $combo = Get-TkControl -Name 'ImpactProbe'
    if ($combo) {
        foreach ($probe in @(Get-TkImpactProbe)) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = '{0}: before {1}' -f $probe.Name, $probe.Action
            $item.Tag     = $probe.Id
            [void] $combo.Items.Add($item)
        }
        $combo.SelectedIndex = 0
    }

    Register-TkClick -Name 'BtnImpactStart' -Action { Invoke-TkImpactChangeFromUi -Start }
    Register-TkClick -Name 'BtnImpactStop'  -Action { Invoke-TkImpactChangeFromUi }
    Register-TkClick -Name 'BtnImpactRead'  -Action { Invoke-TkImpactReadFromUi }

    $document = New-TkFlowDocument
    Add-TkParagraph -Document $document -Muted -Text 'Read what was recorded to see, for each hardening, whether its audit mode is on and who or what it would have refused.'
    Set-TkDocument -ControlName 'ImpactOutput' -Document $document
}

<#
.SYNOPSIS
    Reads every audit mode in the background, and shows it.
#>
function Invoke-TkImpactReadFromUi {
    [CmdletBinding()]
    param()

    Invoke-TkBackgroundAction -StatusText 'Reading what the audit modes recorded...' `
        -ScriptBlock { Get-TkImpactReport } `
        -OnComplete {
            param($result)

            Set-TkImpactResult -Result @($result.Output | Where-Object { $_ -and $_.PSObject.Properties['Verdict'] }) -Confirm:$false
            Write-TkImpactView
            Set-TkStatus -Text 'Audit modes read.'
        }
}

<#
.SYNOPSIS
    Turns the chosen audit mode on or off, through a UAC prompt.
#>
function Invoke-TkImpactChangeFromUi {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch] $Start
    )

    $combo = Get-TkControl -Name 'ImpactProbe'
    $id    = if ($combo -and $combo.SelectedItem) { [string] $combo.SelectedItem.Tag } else { '' }
    $probe = @(Get-TkImpactProbe | Where-Object { $_.Id -eq $id }) | Select-Object -First 1

    if (-not $probe) {
        Set-TkStatus -Text 'Choose a hardening first.'
        return
    }

    if (@($probe.Settings).Count -eq 0) {
        Set-TkStatus -Text $probe.Description
        Invoke-TkImpactReadFromUi
        return
    }

    $message = if ($Start) {
        "Turn on the audit mode for {0}?`n`n{1}`n`nIt changes no behaviour: it only records what {2} would refuse. The log is enlarged to 32 MB if it is smaller. Turning it off puts back exactly what was there. It needs administrator rights.{3}" -f
            $probe.Name, $probe.Description, $probe.Action, $(if ($probe.NeedsRestart) { "`n`nIt takes effect after the next restart." } else { '' })
    }
    else {
        "Turn off the audit mode for {0}, and put back the values it replaced?`n`nIt needs administrator rights." -f $probe.Name
    }

    if (-not (Confirm-TkAction -Title $(if ($Start) { 'Start measuring' } else { 'Stop measuring' }) -Message $message)) {
        return
    }

    $status = if (Test-TkIsElevated) { 'Changing the audit mode...' } else { 'Waiting for administrator consent...' }

    Start-TkPrivilegedAction -Name $(if ($Start) { 'StartImpactMeasurement' } else { 'StopImpactMeasurement' }) -StatusText $status `
        -Parameters @{ Id = $probe.Id } -OnResult {
            param($outcome)
            $null = $outcome
            Invoke-TkImpactReadFromUi
        }
}

<#
.SYNOPSIS
    Shows the last reading of the audit modes.
#>
function Write-TkImpactView {
    [CmdletBinding()]
    param()

    $document = New-TkFlowDocument

    Add-TkHeading   -Document $document -Text 'Before hardening' -Level 1
    Add-TkParagraph -Document $document -Muted -Text 'What each audit mode recorded: who or what the hardening would have refused. Nothing leaves this machine, and the modes change no behaviour.'

    $modeless = @(Get-TkImpactProbe | Where-Object { @($_.Settings).Count -eq 0 } | ForEach-Object { $_.Id })

    foreach ($item in @($script:TkImpactResult)) {

        $state = if ($item.Verdict -eq 'Hardened') { '' }
                 elseif ($modeless -contains $item.Id) { 'Always recorded by Windows' }
                 elseif ($item.ByToolkit) { 'Measuring since {0}, turned on by {1}' -f ([datetime] $item.Started).ToString('yyyy-MM-dd HH:mm'), $item.StartedBy }
                 elseif ($item.Measuring) { 'Audit mode on' }
                 else { 'Audit mode off' }

        Add-TkSeverityLine -Document $document -Severity $item.Severity -Heading ('{0}  -  {1}' -f $item.Name, $item.Headline) `
            -Detail $state -Note ('{0} Audit control {1}.' -f $item.Note, $item.Control).Trim()

        $sources = @($item.Sources)
        if ($sources.Count -gt 0) {
            Add-TkTable -Document $document -Column @('Would be refused', 'Uses', 'First', 'Last', 'Detail') -Weight @(2.6, 0.5, 1.0, 1.0, 2.2) `
                -Row @($sources | Select-Object -First 15 | ForEach-Object {
                    , @($_.Key, [string] $_.Count, ([datetime] $_.First).ToString('yyyy-MM-dd HH:mm'), ([datetime] $_.Last).ToString('yyyy-MM-dd HH:mm'), $_.Detail)
                })
        }
    }

    Set-TkDocument -ControlName 'ImpactOutput' -Document $document
}
