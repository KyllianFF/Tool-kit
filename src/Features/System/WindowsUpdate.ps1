<#
    Toolkit - Features / System / Windows Update

    Finding the updates Windows Update has for this machine, and installing the
    ones chosen, through the Windows Update Agent COM API rather than a module
    that may not be present.

    The search reads only. The install changes the machine and needs
    administrator rights, so it is guarded by ShouldProcess and confirmed in the
    interface before anything is downloaded.
#>

<#
.SYNOPSIS
    Maps a Microsoft severity rating to the toolkit's own.

.PARAMETER Severity
    The MsrcSeverity of an update: Critical, Important, Moderate, Low or empty.

.OUTPUTS
    PSCustomObject with Label and Severity (Pass/Info/Warning/Fail).
#>
function Get-TkUpdateSeverity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        [string] $Severity
    )

    switch ($Severity) {
        'Critical'  { return [pscustomobject] @{ Label = 'Critical';  Severity = 'Fail' } }
        'Important' { return [pscustomobject] @{ Label = 'Important'; Severity = 'Warning' } }
        'Moderate'  { return [pscustomobject] @{ Label = 'Moderate';  Severity = 'Info' } }
        'Low'       { return [pscustomobject] @{ Label = 'Low';       Severity = 'Info' } }
        default     { return [pscustomobject] @{ Label = 'Unrated';   Severity = 'Info' } }
    }
}

<#
.SYNOPSIS
    Writes an update's download size, guarding against the placeholder value the
    Windows Update Agent sometimes reports.

.DESCRIPTION
    MaxDownloadSize is occasionally a huge placeholder (tens of gigabytes) for an
    ordinary patch rather than its real size, which would only mislead. A size
    that is zero or larger than any real single update is reported as unknown.

.PARAMETER Bytes
    The reported MaxDownloadSize.

.OUTPUTS
    System.String
#>
function Format-TkUpdateSize {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [long] $Bytes
    )

    if ($Bytes -le 0 -or $Bytes -gt 32GB) {
        return 'size not reported'
    }

    return Format-TkBytes -Bytes $Bytes
}

<#
.SYNOPSIS
    Reduces a Windows Update Agent update object to a record.

.DESCRIPTION
    Reads the fields a person needs to decide about an update: its title, its KB
    numbers, its download size, its severity, whether it will ask for a restart,
    and whether it is already downloaded. It reads only properties, so a stand-in
    object with the same shape can be used in a test.

.PARAMETER Update
    An IUpdate COM object, or an object with the same properties.

.OUTPUTS
    PSCustomObject with Title, KB, Bytes, SeverityLabel, Severity, RequiresReboot,
    IsDownloaded and UpdateId.
#>
function ConvertFrom-TkUpdateCom {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $Update
    )

    $kb = @(@($Update.KBArticleIDs) | Where-Object { $_ } | ForEach-Object { 'KB{0}' -f $_ }) -join ', '

    $reboot = 0
    if ($Update.InstallationBehavior) {
        $reboot = [int] $Update.InstallationBehavior.RebootBehavior
    }

    $severity = Get-TkUpdateSeverity -Severity ([string] $Update.MsrcSeverity)

    $categories = @(@($Update.Categories) | ForEach-Object { [string] $_.Name } | Where-Object { $_ })

    $bytes = [long] $Update.MaxDownloadSize

    return [pscustomobject] @{
        Title          = [string] $Update.Title
        KB             = $kb
        Bytes          = $bytes
        SizeText       = Format-TkUpdateSize -Bytes $bytes
        SeverityLabel  = $severity.Label
        Severity       = $severity.Severity
        RequiresReboot = ($reboot -eq 1)
        MayReboot      = ($reboot -eq 2)
        IsDownloaded   = [bool] $Update.IsDownloaded
        Categories     = $categories
        UpdateId       = [string] $Update.Identity.UpdateID
    }
}

<#
.SYNOPSIS
    Finds the updates Windows Update has for this machine.

.DESCRIPTION
    Asks the Windows Update Agent for what is not installed and not hidden. This
    reads only: nothing is downloaded or installed. It reaches out to the update
    service, so it can take a moment, and returns nothing on a machine where the
    agent cannot be reached.

.OUTPUTS
    PSCustomObject[] as ConvertFrom-TkUpdateCom returns, newest severity first.
#>
function Get-TkAvailableUpdate {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    try {
        $session  = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search('IsInstalled=0 and IsHidden=0')
    }
    catch {
        Write-TkLog -Level Warning -Category 'System' -Message ('The available updates could not be read: {0}' -f $_.Exception.Message)
        return @()
    }

    $records = foreach ($update in $result.Updates) {
        ConvertFrom-TkUpdateCom -Update $update
    }

    $rank = @{ 'Fail' = 0; 'Warning' = 1; 'Info' = 2; 'Pass' = 3 }

    return @($records | Sort-Object -Property @{ Expression = { $rank[$_.Severity] } }, Title)
}

<#
.SYNOPSIS
    Downloads and installs the chosen updates through the Windows Update Agent.

.DESCRIPTION
    Searches again so the update objects belong to a fresh session, keeps the
    ones whose id was chosen, downloads any not already downloaded, then installs
    them. It changes the machine and needs administrator rights, so it supports
    ShouldProcess and the caller confirms first.

.PARAMETER UpdateId
    The UpdateID values of the updates to install.

.OUTPUTS
    PSCustomObject with Installed, Failed and RebootRequired.
#>
function Install-TkWindowsUpdate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]] $UpdateId
    )

    $session  = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search('IsInstalled=0 and IsHidden=0')

    $wanted = New-Object -ComObject 'Microsoft.Update.UpdateColl'

    foreach ($update in $result.Updates) {
        if ($UpdateId -contains [string] $update.Identity.UpdateID) {
            if ($update.EulaAccepted -eq $false) {
                $update.AcceptEula()
            }
            [void] $wanted.Add($update)
        }
    }

    if ($wanted.Count -eq 0) {
        return [pscustomobject] @{ Installed = 0; Failed = 0; RebootRequired = $false; Message = 'None of the chosen updates are still available.' }
    }

    $titles = @(for ($i = 0; $i -lt $wanted.Count; $i++) { $wanted.Item($i).Title }) -join '; '

    if (-not $PSCmdlet.ShouldProcess($titles, 'Download and install')) {
        return [pscustomobject] @{ Installed = 0; Failed = 0; RebootRequired = $false; Message = 'Cancelled.' }
    }

    # Download whatever is not already downloaded.
    $toDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    for ($i = 0; $i -lt $wanted.Count; $i++) {
        if (-not $wanted.Item($i).IsDownloaded) {
            [void] $toDownload.Add($wanted.Item($i))
        }
    }

    if ($toDownload.Count -gt 0) {
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $toDownload
        [void] $downloader.Download()
    }

    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $wanted
    $installResult = $installer.Install()

    # ResultCode 2 is success; anything else counts as a failure per update.
    $installed = 0
    $failed    = 0
    for ($i = 0; $i -lt $wanted.Count; $i++) {
        if ($installResult.GetUpdateResult($i).ResultCode -eq 2) { $installed++ } else { $failed++ }
    }

    return [pscustomobject] @{
        Installed      = $installed
        Failed         = $failed
        RebootRequired = [bool] $installResult.RebootRequired
        Message        = ''
    }
}
