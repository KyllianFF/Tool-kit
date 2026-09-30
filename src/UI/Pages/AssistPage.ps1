<#
    Toolkit - UI / My PC (the assistance mode)

    Started with -Assist: one page, no navigation rail, no search, no
    administrator button. The verdicts in plain words on the left; on the
    right, a request for support the user prepares, sees and trims before it
    is written.
#>

# Set once by Enter-TkAssistMode, for the rest of the session.
$script:TkAssistMode = $false

# The last request written, for its summary and its folder.
$script:TkAssistRequest = $null

<#
.SYNOPSIS
    Says whether the window is in the assistance mode.
#>
function Test-TkAssistMode {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return [bool] $script:TkAssistMode
}

<#
.SYNOPSIS
    Keeps the last request written. Set through here: a completion handler
    cannot reach this file's scope.
#>
function Set-TkAssistRequest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [AllowNull()]
        $Request
    )

    if ($PSCmdlet.ShouldProcess('assistance mode', 'Remember the request')) {
        $script:TkAssistRequest = $Request
    }
}

<#
.SYNOPSIS
    Wires the My PC page: the reports it can attach, and its buttons.
#>
function Initialize-TkAssistPage {
    [CmdletBinding()]
    param()

    $includes = Get-TkControl -Name 'AssistIncludes'
    if ($includes) {
        foreach ($name in @(Get-TkAssistReportName)) {
            # A text block that wraps, with a width to wrap at: the check box
            # template lays its content out unbounded, and cut it at the edge
            # of the column.
            $label = New-Object System.Windows.Controls.TextBlock
            $label.Text         = Get-TkAssistReportLabel -Name $name
            $label.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $label.MaxWidth     = 300

            $box = New-Object System.Windows.Controls.CheckBox
            $box.Content   = $label
            $box.Tag       = $name
            $box.IsChecked = $true
            $box.Margin    = [System.Windows.Thickness]::new(0, 0, 0, 4)
            [void] $includes.Children.Add($box)
        }
    }

    Register-TkClick -Name 'BtnAssistPrepare' -Action { Invoke-TkAssistPrepareFromUi }
    Register-TkClick -Name 'BtnAssistCopy'    -Action { Copy-TkAssistSummary }
    Register-TkClick -Name 'BtnAssistShow'    -Action { Show-TkAssistFile }
}

<#
.SYNOPSIS
    Copies the summary of the last request, to paste into the ticket.
#>
function Copy-TkAssistSummary {
    [CmdletBinding()]
    param()

    if ($script:TkAssistRequest) {
        [System.Windows.Clipboard]::SetText([string] $script:TkAssistRequest.Summary)
        Set-TkStatus -Text 'The summary is copied: paste it into your ticket.'
    }
}

<#
.SYNOPSIS
    Shows the last request's file in its folder.
#>
function Show-TkAssistFile {
    [CmdletBinding()]
    param()

    if ($script:TkAssistRequest -and [System.IO.File]::Exists([string] $script:TkAssistRequest.Path)) {
        Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"{0}"' -f $script:TkAssistRequest.Path)
    }
}

<#
.SYNOPSIS
    Turns the window into the assistance mode, for the rest of the session.

.DESCRIPTION
    Hides the navigation rail, the search, the administrator button and the
    output console; shows the My PC page alone, and reads the PC.
#>
function Enter-TkAssistMode {
    [CmdletBinding()]
    param()

    $script:TkAssistMode = $true

    $collapse = [System.Windows.Visibility]::Collapsed

    foreach ($name in @('RailPanel', 'HeaderActions', 'ConsoleExpander')) {
        $control = Get-TkControl -Name $name
        if ($control) { $control.Visibility = $collapse }
    }

    $column = Get-TkControl -Name 'RailColumn'
    if ($column) { $column.Width = [System.Windows.GridLength]::new(0) }

    foreach ($page in @(Get-TkPageName)) {
        $control = Get-TkControl -Name ('Page{0}' -f $page)
        if ($control) { $control.Visibility = $collapse }
    }

    $assist = Get-TkControl -Name 'AssistPage'
    if ($assist) { $assist.Visibility = [System.Windows.Visibility]::Visible }

    $window = (Get-TkContext).Window
    if ($window) {
        $window.Title = 'My PC - Toolkit'
        $window.Width  = 1080
        $window.Height = 780
    }

    Write-TkLog -Level Information -Category 'Startup' -Message 'Assistance mode: one page, nothing that changes the PC.'
    Invoke-TkAssistReadFromUi
}

<#
.SYNOPSIS
    Reads the PC in the background, and shows the verdicts.
#>
function Invoke-TkAssistReadFromUi {
    [CmdletBinding()]
    param()

    $document = New-TkFlowDocument
    Add-TkParagraph -Document $document -Muted -Text 'Looking at your PC...'
    Set-TkDocument -ControlName 'AssistOutput' -Document $document

    Invoke-TkBackgroundAction -StatusText 'Looking at your PC...' `
        -ScriptBlock { Get-TkAssistVerdict } `
        -OnComplete {
            param($result)

            $verdicts = @($result.Output | Where-Object { $_ -and $_.PSObject.Properties['Headline'] })
            Set-TkAssistVerdictList -Verdict $verdicts -Confirm:$false
            Write-TkAssistView
            Set-TkStatus -Text $(if (@($verdicts | Where-Object { $_.Severity -in @('Fail', 'Warning') }).Count) { 'Something needs your attention: see what you can do, or ask for help.' } else { 'Nothing wrong was found on the usual points.' })
        }
}

# The verdicts last read, for the view and the request.
$script:TkAssistVerdicts = @()

<#
.SYNOPSIS
    Keeps the verdicts last read.
#>
function Set-TkAssistVerdictList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Verdict
    )

    if ($PSCmdlet.ShouldProcess('assistance mode', 'Remember the verdicts')) {
        $script:TkAssistVerdicts = @($Verdict)
    }
}

<#
.SYNOPSIS
    Shows the verdicts, each with what the user can do.
#>
function Write-TkAssistView {
    [CmdletBinding()]
    param()

    $document = New-TkFlowDocument
    $verdicts = @($script:TkAssistVerdicts)

    $problems = @($verdicts | Where-Object { $_.Severity -in @('Fail', 'Warning') }).Count
    Add-TkHeading -Document $document -Level 1 -Text $(if ($problems -gt 0) { '{0} thing(s) to look at' -f $problems } else { 'All looks fine' })

    foreach ($verdict in $verdicts) {
        Add-TkSeverityLine -Document $document -Severity $verdict.Severity -Heading $verdict.Headline `
            -Note ([string] $verdict.Detail) -Action ([string] $verdict.Advice)
    }

    Add-TkParagraph -Document $document -Muted -Text 'If it is still not right, describe it on the right and prepare your request.'

    Set-TkDocument -ControlName 'AssistOutput' -Document $document
}

<#
.SYNOPSIS
    Writes the request the user described, with what they left ticked.
#>
function Invoke-TkAssistPrepareFromUi {
    [CmdletBinding()]
    param()

    $description = ([string] (Get-TkControl -Name 'AssistDescription').Text).Trim()
    $chosen      = @((Get-TkControl -Name 'AssistIncludes').Children | Where-Object { $_.IsChecked } | ForEach-Object { [string] $_.Tag })
    $showNames   = [bool] (Get-TkControl -Name 'AssistShowNames').IsChecked

    if (-not $description) {
        (Get-TkControl -Name 'AssistResult').Text = 'Describe what happens first: it is what support reads before anything else.'
        return
    }

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title            = 'Save my request for support'
    $dialog.Filter           = 'Support request (*.json)|*.json'
    $dialog.FileName         = 'support-request-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmm')
    $dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

    if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
        return
    }

    (Get-TkControl -Name 'AssistResult').Text = 'Preparing your request...'

    Invoke-TkBackgroundAction -StatusText 'Preparing your request...' `
        -ParameterList @{ Path = $dialog.FileName; Description = $description; Report = $chosen; Verdict = @($script:TkAssistVerdicts); ShowNames = $showNames } `
        -ScriptBlock {
            param($Path, $Description, $Report, $Verdict, $ShowNames)
            New-TkAssistRequest -Path $Path -Description $Description -Report $Report -Verdict $Verdict -ShowNames:$ShowNames -Confirm:$false
        } `
        -OnComplete {
            param($result)

            $request = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Summary'] } | Select-Object -Last 1

            if (-not $request) {
                (Get-TkControl -Name 'AssistResult').Text = $(if (@($result.Errors).Count) { 'The request could not be written: {0}' -f @($result.Errors)[0] } else { 'The request could not be written.' })
                return
            }

            Set-TkAssistRequest -Request $request -Confirm:$false
            (Get-TkControl -Name 'AssistResult').Text = 'Your request is ready: {0}. Copy the summary into your ticket, and attach the file.' -f $request.Path
            (Get-TkControl -Name 'BtnAssistCopy').IsEnabled = $true
            (Get-TkControl -Name 'BtnAssistShow').IsEnabled = $true
            Set-TkStatus -Text 'Your request is ready.'
        }
}
