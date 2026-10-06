<#
    Toolkit - UI / Incident triage (a tab of the Audit page)

    Collects a triage case step by step through the action queue: each step
    runs in a background task of its own, so the window stays usable, the
    technician sees what is being taken, and the run can stop between two
    steps. A step that fails does not stop the others: what could be kept is
    kept. Once the steps have ended, the manifest, the archive and its
    encryption are written in one more background task.
#>

# The case being collected, and the last one completed, for the view and for
# Open the folder. Set through Set-TkTriageState: a completion handler cannot
# reach this file's scope.
$script:TkTriageState = $null

<#
.SYNOPSIS
    Keeps the case being collected and, once completed, its result.
#>
function Set-TkTriageState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [AllowNull()] $State
    )

    if ($PSCmdlet.ShouldProcess('incident triage', 'Remember the case')) {
        $script:TkTriageState = $State
    }
}

<#
.SYNOPSIS
    Wires the Incident triage tab.
#>
function Initialize-TkTriageTab {
    [CmdletBinding()]
    param()

    $panel = Get-TkControl -Name 'TriageStepList'
    if ($panel) {
        $elevated = [bool] (Test-TkIsElevated)
        foreach ($step in @(Get-TkTriageStep)) {
            $box = New-Object System.Windows.Controls.CheckBox
            $box.Content   = $step.Title
            $box.Tag       = $step.Key
            $box.IsChecked = $true
            $box.Margin    = New-Object System.Windows.Thickness(0, 0, 18, 8)
            $box.ToolTip   = if ($step.NeedsElevation -and -not $elevated) { '{0}. {1}' -f $step.Label, $step.Partial } else { $step.Label }
            [void] $panel.Children.Add($box)
        }
    }

    Register-TkClick -Name 'BtnTriageBrowse'      -Action { Select-TkTriageDestination }
    Register-TkClick -Name 'BtnTriageCertificate' -Action { Select-TkTriageCertificateFile }
    Register-TkClick -Name 'BtnTriageRun'         -Action { Invoke-TkTriageFromUi }
    Register-TkClick -Name 'BtnTriageStop'        -Action { Stop-TkActionQueue -Name 'Triage' -Confirm:$false; Set-TkStatus -Text 'The collection stops after this step; what was taken is still packed and hashed.' }
    Register-TkClick -Name 'BtnTriageOpen'        -Action { Open-TkTriageFolder }
    Register-TkClick -Name 'BtnTriageTopic'       -Action { Invoke-TkHypothesisAction -Target @{ Kind = 'topic'; Value = 'incident-first-hour' } }

    foreach ($name in @('BtnTriageStop', 'BtnTriageOpen')) {
        $button = Get-TkControl -Name $name
        if ($button) { $button.IsEnabled = $false }
    }

    $document = New-TkFlowDocument
    Add-TkHeading   -Document $document -Text 'Incident triage' -Level 1
    Add-TkParagraph -Document $document -Text 'Keeps the state of a suspect machine for the people who handle the incident: processes, connections, sessions, persistence, accounts and event logs, most volatile first. Every file is hashed in a manifest dated in UTC that names you and this toolkit; the whole is packed in one archive and, with the responder''s certificate, encrypted for them alone.'
    Add-TkBulletList -Document $document -Item @(
        'Isolate the machine first (unplug it, or isolate it from the EDR console), and note the time. Do not power it off, reinstall it or run a cleanup tool.'
        'Write to removable media or a share rather than to this disk.'
        'No memory image and no credential is taken. The collection only reads, but leaves traces of its own, which the manifest records.'
        $(if (Test-TkIsElevated) { 'Running as administrator: every step can read what it needs.' } else { 'Without administrator rights the Security log, the other accounts'' processes and sessions and the Defender exclusions are not readable: restart as administrator first when you can.' })
    )
    Set-TkDocument -ControlName 'TriageOutput' -Document $document
}

<#
.SYNOPSIS
    Asks where to write the case.
#>
function Select-TkTriageDestination {
    [CmdletBinding()]
    param()

    $box    = Get-TkControl -Name 'TriageDestination'
    $picked = Select-TkFolderPath -Description 'Where to write the triage case: removable media is best.' -Start ([string] $box.Text)

    if ($picked) {
        $box.Text = $picked
    }
}

<#
.SYNOPSIS
    Asks for the responder's certificate.
#>
function Select-TkTriageCertificateFile {
    [CmdletBinding()]
    param()

    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title  = 'The certificate of whoever will read the evidence'
    $dialog.Filter = 'Certificates (*.cer;*.crt;*.pem;*.der)|*.cer;*.crt;*.pem;*.der|All files (*.*)|*.*'

    if ($dialog.ShowDialog((Get-TkContext).Window)) {
        (Get-TkControl -Name 'TriageCertificate').Text = $dialog.FileName
    }
}

<#
.SYNOPSIS
    Opens the folder of the last case, or the destination.
#>
function Open-TkTriageFolder {
    [CmdletBinding()]
    param()

    $state = $script:TkTriageState
    $path  = if ($state -and $state.Result -and [System.IO.Directory]::Exists([string] $state.Result.Folder)) { [string] $state.Result.Folder }
             elseif ($state -and $state.Result) { [System.IO.Path]::GetDirectoryName([string] $state.Result.Archive) }
             else { '' }

    if ($path -and [System.IO.Directory]::Exists($path)) {
        Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $path)
    }
}

<#
.SYNOPSIS
    Checks what was asked, confirms it, opens the case and starts its steps.
#>
function Invoke-TkTriageFromUi {
    [CmdletBinding()]
    param()

    $destination = ([string] (Get-TkControl -Name 'TriageDestination').Text).Trim()
    $reference   = ([string] (Get-TkControl -Name 'TriageReference').Text).Trim()
    $certificate = ([string] (Get-TkControl -Name 'TriageCertificate').Text).Trim().Trim('"')
    $removeClear = [bool] (Get-TkControl -Name 'TriageRemoveClear').IsChecked
    $chosen      = @((Get-TkControl -Name 'TriageStepList').Children | Where-Object { $_.IsChecked } | ForEach-Object { [string] $_.Tag })

    if (-not $destination) {
        Set-TkStatus -Text 'Choose where to write the case first: removable media is best.'
        return
    }

    if (-not [System.IO.Directory]::Exists($destination)) {
        Set-TkStatus -Text ('{0} does not exist: choose a folder.' -f $destination)
        return
    }

    if ($chosen.Count -eq 0) {
        Set-TkStatus -Text 'Tick at least one step.'
        return
    }

    # Read now, so a wrong certificate is said before anything is collected.
    $recipient = $null
    if ($certificate) {
        try {
            $recipient = Get-TkTriageCertificate -Path $certificate
        }
        catch {
            Set-TkStatus -Text $_.Exception.Message
            return
        }
    }

    $steps    = @(Get-TkTriageStep | Where-Object { $chosen -contains $_.Key })
    $elevated = [bool] (Test-TkIsElevated)
    $partial  = @($steps | Where-Object { $_.NeedsElevation })
    $root     = [System.IO.Path]::GetPathRoot($destination)
    $system   = [string]::Equals($root, [System.IO.Path]::GetPathRoot($env:SystemRoot), [System.StringComparison]::OrdinalIgnoreCase)

    $message = "Collect a triage case of {0} into {1}?`n`n{2} step(s), most volatile first: {3}." -f $env:COMPUTERNAME, $destination, $steps.Count, ((@($steps | ForEach-Object { $_.Title })) -join ', ')
    if (-not $elevated -and $partial.Count -gt 0) {
        $message += "`n`nWithout administrator rights these steps are partial: {0}. Restart as administrator first for a complete case." -f ((@($partial | ForEach-Object { $_.Title })) -join ', ')
    }
    if ($system) {
        $message += "`n`nThe destination is on the system drive, where the evidence lives: removable media would touch it less."
    }
    $message += if ($recipient) {
        "`n`nThe archive is encrypted for {0}; {1}" -f ($recipient.Subject -replace '^CN=([^,]+).*$', '$1'), $(if ($removeClear) { 'the clear copy is removed once every chunk has been read back.' } else { 'the clear copy is kept beside it.' })
    }
    else {
        "`n`nNo certificate: the archive stays in clear. Keep it with the care evidence needs."
    }
    $message += "`n`nThe collection only reads, but it leaves its own traces (PowerShell events, Prefetch entries, the files it writes); the manifest records them."

    if (-not (Confirm-TkAction -Title 'Collect a triage case' -Message $message)) {
        return
    }

    try {
        $case = New-TkTriageCase -Destination $destination -Reference $reference -Confirm:$false
    }
    catch {
        Set-TkStatus -Text $_.Exception.Message
        return
    }

    # Read here, on the window's thread: a background runspace does not know
    # where the toolkit was launched from.
    Set-TkTriageState -State ([pscustomobject] @{
        Case        = $case
        Toolkit     = Get-TkToolkitIdentity
        Certificate = $certificate
        RemoveClear = ($removeClear -and [bool] $recipient)
        Result      = $null
        Error       = ''
    }) -Confirm:$false

    $work  = { param($Key, $Folder, $Order) Invoke-TkTriageStep -Key $Key -Folder $Folder -Order $Order }
    $order = 0
    $queue = foreach ($step in @(Get-TkTriageStep)) {
        $order++
        if ($chosen -notcontains $step.Key) { continue }
        [pscustomobject] @{ Key = $step.Key; Label = $step.Title; Work = $work; Parameters = @{ Key = $step.Key; Folder = $case.Folder; Order = $order }; Critical = $false }
    }

    (Get-TkControl -Name 'BtnTriageRun').IsEnabled  = $false
    (Get-TkControl -Name 'BtnTriageStop').IsEnabled = $true
    (Get-TkControl -Name 'BtnTriageOpen').IsEnabled = $false

    # A step that fails must not stop the others: what can be kept is kept.
    [void] (New-TkActionQueue -Name 'Triage' -Step @($queue) -StopOnFailure $false -Confirm:$false `
        -OnStep { param($queue, $step) $null = $step; Write-TkTriageView -Queue $queue } `
        -OnDone { param($queue) Complete-TkTriageFromUi -Queue $queue })

    Start-TkActionQueue -Name 'Triage' -Confirm:$false
}

<#
.SYNOPSIS
    What each step of the queue ended with, as the manifest records it.

.DESCRIPTION
    Pure. A step that ran returns its own record; one that was not run, or
    whose task failed before it could answer, gets one that says so.

.OUTPUTS
    PSCustomObject[] with Key, Label, Started, Ended, Status, Note and Folder.
#>
function ConvertTo-TkTriageStepRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        $Queue
    )

    $labels = @{}
    foreach ($step in @(Get-TkTriageStep)) { $labels[$step.Key] = $step.Label }

    return @(foreach ($item in @($Queue.Steps)) {

        if ($item.Output -and $item.Output.PSObject.Properties['Status']) {
            $item.Output
            continue
        }

        [pscustomobject] @{
            Key     = $item.Key
            Label   = $labels[$item.Key]
            Started = $(if ($item.Started) { ([datetime] $item.Started).ToUniversalTime().ToString('o') } else { '' })
            Ended   = $(if ($item.Ended) { ([datetime] $item.Ended).ToUniversalTime().ToString('o') } else { '' })
            Status  = $(if ($item.State -eq 'NotRun') { 'NotRun' } else { 'Failed' })
            Note    = $(if ($item.State -eq 'NotRun') { 'Not run: the collection was stopped.' } elseif ($item.Text) { $item.Text } else { 'The step ended without a result.' })
            Folder  = ''
        }
    })
}

<#
.SYNOPSIS
    Writes the manifest, packs and encrypts the case, in the background.
#>
function Complete-TkTriageFromUi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Queue
    )

    $state = $script:TkTriageState
    (Get-TkControl -Name 'BtnTriageStop').IsEnabled = $false

    if (-not $state) {
        (Get-TkControl -Name 'BtnTriageRun').IsEnabled = $true
        return
    }

    Write-TkTriageView -Queue $Queue

    Invoke-TkBackgroundAction -StatusText 'Writing the manifest, packing and hashing the archive...' `
        -ScriptBlock {
            param($Case, $Step, $CertificatePath, $RemoveClear, $Toolkit)
            Complete-TkTriageCase -Case $Case -Step $Step -CertificatePath $CertificatePath -RemoveClear:$RemoveClear -Toolkit $Toolkit -Confirm:$false
        } `
        -ParameterList @{ Case = $state.Case; Step = @(ConvertTo-TkTriageStepRecord -Queue $Queue); CertificatePath = [string] $state.Certificate; RemoveClear = [bool] $state.RemoveClear; Toolkit = $state.Toolkit } `
        -OnComplete { param($result) Receive-TkTriageResult -Result $result }
}

<#
.SYNOPSIS
    Keeps what completing the case returned, and shows it.
#>
function Receive-TkTriageResult {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Result
    )

    $outcome = @(if ($Result) { $Result.Output }) | Where-Object { $_ -and $_.PSObject.Properties['ManifestSha256'] } | Select-Object -Last 1
    $failure = if ($outcome) { '' }
               elseif ($Result -and @($Result.Errors).Count) { 'The case could not be completed: {0}' -f @($Result.Errors)[0] }
               else { 'The case could not be completed.' }

    if ($script:TkTriageState) {
        $script:TkTriageState.Result = $outcome
        $script:TkTriageState.Error  = $failure
    }

    (Get-TkControl -Name 'BtnTriageRun').IsEnabled  = $true
    (Get-TkControl -Name 'BtnTriageOpen').IsEnabled = [bool] $outcome

    Write-TkTriageView -Queue $script:TkActionQueues['Triage']
    Set-TkStatus -Text $(if ($outcome) { 'Triage case {0} written: manifest SHA-256 {1}.' -f $outcome.Id, $outcome.ManifestSha256 } else { $failure })
}

<#
.SYNOPSIS
    Shows the steps as they run, then where the case is and its hashes.
#>
function Write-TkTriageView {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Queue
    )

    $state    = $script:TkTriageState
    $document = New-TkFlowDocument

    Add-TkHeading -Document $document -Text 'Incident triage' -Level 1

    if ($state -and $state.Case) {
        Add-TkParagraph -Document $document -Muted -Text ('{0}{1}, started {2} UTC, into {3}.' -f $state.Case.Id,
            $(if ($state.Case.Reference) { ' ({0})' -f $state.Case.Reference } else { '' }), ([datetime] $state.Case.Started).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $state.Case.Folder)
    }

    if ($Queue) {

        Add-TkParagraph -Document $document -Muted -Text (Format-TkActionQueueProgress -Queue $Queue)

        $states = @{ Waiting = 'Waiting'; Running = 'Running...'; Done = 'Done'; Failed = 'Failed'; NotRun = 'Not run' }
        $rows   = foreach ($item in @($Queue.Steps)) {
            $status = if ($item.Output -and $item.Output.PSObject.Properties['Status']) { [string] $item.Output.Status } else { $states[[string] $item.State] }
            $note   = if ($item.Output -and $item.Output.PSObject.Properties['Note']) { [string] $item.Output.Note } else { [string] $item.Text }
            , @($item.Label, $status, $note)
        }

        Add-TkTable -Document $document -Column @('Step', 'State', 'Note') -Weight @(1.4, 0.7, 3.6) -Row @($rows)
    }

    $result = if ($state) { $state.Result } else { $null }

    if ($state -and $state.Error) {
        Add-TkSeverityLine -Document $document -Severity 'Fail' -Heading 'The case could not be completed' -Note $state.Error
    }
    elseif ($result) {

        $severity = if ($result.EncryptionError -or $result.Failed -gt 0) { 'Warning' } elseif ($result.Partial -gt 0) { 'Info' } else { 'Pass' }
        $heading  = if ($result.EncryptionError) { 'Collected, but not encrypted' }
                    elseif ($result.Failed -gt 0) { 'Collected, with {0} step(s) failed' -f $result.Failed }
                    elseif ($result.Partial -gt 0) { 'Collected, {0} step(s) partial without administrator rights' -f $result.Partial }
                    else { 'Collected' }

        Add-TkSeverityLine -Document $document -Severity $severity -Heading $heading -Note $(if ($result.EncryptionError) { $result.EncryptionError } else { 'Write the two SHA-256 below into the incident log: they prove later that the case was not changed.' })

        $rows = New-Object System.Collections.Generic.List[object]
        $rows.Add(@('Manifest SHA-256', $result.ManifestSha256))
        $rows.Add(@('Archive SHA-256', $result.ArchiveSha256))
        $rows.Add(@('Archive', $(if ($result.ClearRemoved) { 'Removed once encrypted' } else { $result.Archive })))
        if ($result.Encrypted) {
            $rows.Add(@('Encrypted', ('{0} chunk(s) for the certificate, index {1}' -f @($result.Chunks).Count, [System.IO.Path]::GetFileName([string] $result.Index))))
        }
        $rows.Add(@('All the hashes', $result.Hashes))

        Add-TkTable -Document $document -Column @('What', 'Value') -Weight @(1.0, 4.0) -Row $rows.ToArray()

        if ($result.OnSystemDrive) {
            Add-TkParagraph -Document $document -Muted -Text 'Written to the system drive: copy the archive to removable media, and the manifest says where it was written.'
        }

        Add-TkParagraph -Document $document -Muted -Text 'Hand over the archive (or its encrypted chunks and index) and the hashes file. The format and how to rebuild an encrypted archive with openssl are in docs/TRIAGE.md.'
    }

    Set-TkDocument -ControlName 'TriageOutput' -Document $document
}
