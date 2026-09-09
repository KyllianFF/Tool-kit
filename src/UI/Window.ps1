<#
    Toolkit - UI / Main window

    Builds the window from XAML, registers every named control in the shared
    context and wires the navigation. Feature pages are initialised by their
    own files so this one stays about the shell only.
#>

# Set by the build script for the single file release. Empty during
# development, where the XAML is read from disk instead.
$script:TkEmbeddedXaml = ''

<#
.SYNOPSIS
    Returns the main window XAML.

.DESCRIPTION
    Prefers the copy embedded at build time so a release has no external
    dependency, and falls back to the file next to the sources during
    development.

.OUTPUTS
    System.String
#>
function Get-TkMainWindowXaml {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not [string]::IsNullOrWhiteSpace($script:TkEmbeddedXaml)) {
        return $script:TkEmbeddedXaml
    }

    $candidates = @()

    if ($PSScriptRoot) {
        $candidates += (Join-Path -Path $PSScriptRoot -ChildPath 'MainWindow.xaml')
        $candidates += (Join-Path -Path $PSScriptRoot -ChildPath 'UI\MainWindow.xaml')
    }

    $candidates += (Join-Path -Path (Get-Location).Path -ChildPath 'src\UI\MainWindow.xaml')

    foreach ($candidate in $candidates) {

        if (Test-Path -LiteralPath $candidate) {
            return (Get-Content -LiteralPath $candidate -Raw -Encoding UTF8)
        }
    }

    throw 'MainWindow.xaml was not found and no XAML is embedded in this build.'
}

<#
.SYNOPSIS
    Creates the window and returns it.

.DESCRIPTION
    Parses the XAML, then walks every x:Name in the markup and stores the
    matching control in the context. Doing this once means page code can say
    $ctx.Controls['BtnRefresh'] instead of calling FindName everywhere.

.OUTPUTS
    System.Windows.Window
#>
function New-TkMainWindow {
    [CmdletBinding()]
    [OutputType([System.Windows.Window])]
    param()

    $ctx  = Get-TkContext
    $xaml = Get-TkMainWindowXaml

    try {
        $reader = New-Object System.Xml.XmlNodeReader ([xml] $xaml)
        $window = [Windows.Markup.XamlReader]::Load($reader)
    }
    catch {
        throw ('The interface could not be built from XAML: {0}' -f $_.Exception.Message)
    }

    $ctx.Window   = $window
    $ctx.Controls = @{}

    foreach ($match in [regex]::Matches($xaml, 'x:Name="(?<name>[^"]+)"')) {

        $name    = $match.Groups['name'].Value
        $control = $window.FindName($name)

        if ($null -ne $control) {
            $ctx.Controls[$name] = $control
        }
    }

    Write-TkLog -Level Debug -Category 'UI' -Message (
        '{0} named controls registered.' -f $ctx.Controls.Count
    )

    return $window
}

<#
.SYNOPSIS
    Returns a registered control by name.

.DESCRIPTION
    Returns $null rather than throwing when a control is missing, so a page
    that references a control removed from the XAML degrades instead of
    taking the whole window down.

.OUTPUTS
    System.Windows.DependencyObject
#>
function Get-TkControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    $ctx = Get-TkContext

    if ($ctx.Controls.ContainsKey($Name)) {
        return $ctx.Controls[$Name]
    }

    Write-TkLog -Level Debug -Category 'UI' -Message ('Unknown control "{0}".' -f $Name)

    return $null
}

<#
.SYNOPSIS
    Attaches a click handler to a button.

.DESCRIPTION
    Convenience wrapper that tolerates a missing control, which keeps page
    initialisation free of repeated null checks.
#>
function Register-TkClick {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [scriptblock] $Action
    )

    $control = Get-TkControl -Name $Name

    if ($null -eq $control) {
        return
    }

    $control.Add_Click($Action)
}

<#
.SYNOPSIS
    Shows one feature page and hides the others.

.PARAMETER Name
    Page key: System, Software, Tweaks, Fixes, Network or Security.
#>
function Show-TkPage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Security')]
        [string] $Name
    )

    $ctx = Get-TkContext

    foreach ($page in @('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Security')) {

        $control = Get-TkControl -Name ('Page{0}' -f $page)

        if ($null -eq $control) {
            continue
        }

        if ($page -eq $Name) {
            $control.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $control.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }

    # Highlight the active navigation entry.
    foreach ($page in @('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Security')) {

        $button = Get-TkControl -Name ('Nav{0}' -f $page)

        if ($null -eq $button) {
            continue
        }

        if ($page -eq $Name) {
            # Looked up on every call: a frozen brush captured once would keep
            # the palette that was active when the page was first shown.
            $button.Background = $ctx.Window.Resources['Selection']
            $button.FontWeight = [System.Windows.FontWeights]::SemiBold
        }
        else {
            $button.Background = [System.Windows.Media.Brushes]::Transparent
            $button.FontWeight = [System.Windows.FontWeights]::Normal
        }
    }

    $ctx.Settings['LastPage'] = $Name
}

<#
.SYNOPSIS
    Updates the status bar.

.PARAMETER Text
    Message to show.

.PARAMETER Busy
    Shows the indeterminate progress bar while an operation runs.
#>
function Set-TkStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [bool] $Busy = $false
    )

    $status = Get-TkControl -Name 'StatusText'
    $bar    = Get-TkControl -Name 'BusyBar'

    if ($status) {
        $status.Text = $Text
    }

    if ($bar) {
        $bar.Visibility = if ($Busy) { [System.Windows.Visibility]::Visible }
                          else       { [System.Windows.Visibility]::Hidden }
    }
}

<#
.SYNOPSIS
    Runs work off the UI thread and re-enables the interface when it returns.

.DESCRIPTION
    The single entry point every page uses for anything slow. It sets the
    busy state, queues the work, and restores the interface from the
    completion callback, which the task pump runs on the UI thread.

.PARAMETER ScriptBlock
    Work to run in the background runspace. Receives $ArgumentList.

.PARAMETER ArgumentList
    Positional values, scalars only. WPF objects must not cross the thread
    boundary.

.PARAMETER ParameterList
    Named parameters as a hashtable. The only safe way to pass a collection:
    a positional array is flattened by PowerShell before the call is made.

.PARAMETER OnComplete
    Runs on the UI thread with the task result.

.PARAMETER StatusText
    Message shown while the work runs.
#>
function Invoke-TkBackgroundAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock] $ScriptBlock,

        [Parameter()]
        [object[]] $ArgumentList = @(),

        [Parameter()]
        [hashtable] $ParameterList,

        [Parameter()]
        [scriptblock] $OnComplete,

        [Parameter()]
        [string] $StatusText = 'Working...'
    )

    Set-TkStatus -Text $StatusText -Busy $true

    $wrapper = {
        param($result)

        Set-TkStatus -Text 'Ready.' -Busy $false

        if ($OnComplete) {
            & $OnComplete $result
        }
    }.GetNewClosure()

    $taskParameters = @{
        ScriptBlock  = $ScriptBlock
        ArgumentList = $ArgumentList
        OnComplete   = $wrapper
        Name         = $StatusText
    }

    if ($ParameterList) {
        $taskParameters['ParameterList'] = $ParameterList
    }

    Start-TkTask @taskParameters | Out-Null
}

<#
.SYNOPSIS
    Writes text into one of the page output boxes.

.PARAMETER ControlName
    Name of the target TextBox.

.PARAMETER Text
    Content to write.

.PARAMETER Append
    Adds to the existing content instead of replacing it.
#>
function Set-TkOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ControlName,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [switch] $Append
    )

    $control = Get-TkControl -Name $ControlName

    if ($null -eq $control) {
        return
    }

    if ($Append) {
        $control.AppendText($Text + [Environment]::NewLine)
        $control.ScrollToEnd()
    }
    else {
        $control.Text = $Text
    }
}

<#
.SYNOPSIS
    Renders objects as an aligned text table.

.DESCRIPTION
    Format-Table through Out-String, with a width wide enough that columns
    are not truncated the way they are at the default console width.

.OUTPUTS
    System.String
#>
function Format-TkTableText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return '(no result)'
    }

    $items = @($InputObject)

    if ($items.Count -eq 0) {
        return '(no result)'
    }

    return ($items | Format-Table -AutoSize | Out-String -Width 400).Trim()
}

<#
.SYNOPSIS
    Copies text to the clipboard.

.OUTPUTS
    System.Boolean
#>
function Set-TkClipboard {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $false
    }

    try {
        [System.Windows.Clipboard]::SetText($Text)
        return $true
    }
    catch {
        # The clipboard can be locked by another process for a moment.
        Write-TkLog -Level Warning -Category 'UI' -Message (
            'Clipboard unavailable: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Shows a confirmation dialog for an operation that changes the system.

.OUTPUTS
    System.Boolean
#>
function Confirm-TkAction {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [Parameter()]
        [string] $Title = 'Confirm'
    )

    $ctx = Get-TkContext

    $result = [System.Windows.MessageBox]::Show(
        $ctx.Window,
        $Message,
        $Title,
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    return ($result -eq [System.Windows.MessageBoxResult]::Yes)
}

<#
.SYNOPSIS
    Wires the shell: header, navigation and window lifetime.
#>
function Initialize-TkShell {
    [CmdletBinding()]
    param()

    $ctx = Get-TkContext

    # --- Header -----------------------------------------------------------
    $version = Get-TkControl -Name 'HeaderVersion'

    if ($version) {
        $version.Text = 'v{0} ({1})' -f $ctx.Version, $ctx.Commit
    }

    $hostLabel = Get-TkControl -Name 'HeaderHost'

    if ($hostLabel) {
        $hostLabel.Text = '{0} - {1} - PowerShell {2}' -f $env:COMPUTERNAME, $ctx.OSCaption, $ctx.PSVersion
    }

    Initialize-TkThemeSelector
    Update-TkElevationBadge

    # --- Navigation -------------------------------------------------------
    foreach ($page in @('System', 'Software', 'Tweaks', 'Fixes', 'Network', 'Security')) {

        $name = 'Nav{0}' -f $page

        # Capture the page name in a closure; without GetNewClosure every
        # handler would see the last value of the loop variable.
        $handler = {
            Show-TkPage -Name $page
        }.GetNewClosure()

        Register-TkClick -Name $name -Action $handler
    }

    # --- Shell buttons ----------------------------------------------------
    Register-TkClick -Name 'BtnElevate' -Action {

        if (Test-TkIsElevated) {
            Set-TkStatus -Text 'Already running as administrator.'
            return
        }

        $context = Get-TkContext

        if (Invoke-TkElevation -SourceUri $context.SourceUri -Confirm:$false) {
            $context.Window.Close()
        }
    }

    Register-TkClick -Name 'BtnOpenLogs' -Action {
        Start-Process -FilePath 'explorer.exe' -ArgumentList (Get-TkContext).LogRoot
    }

    Register-TkClick -Name 'BtnAbout' -Action {

        $ctx = Get-TkContext

        $message = @(
            '{0} {1} ({2})' -f $ctx.AppName, $ctx.Version, $ctx.Commit,
            '',
            'A toolkit for daily system, network and security work on Windows.',
            '',
            'Repository: {0}' -f $ctx.Repository,
            'Data folder: {0}' -f $ctx.DataRoot,
            '',
            'Read only features work as a standard user. Anything that changes',
            'the machine requires an elevated instance and is written to the log.'
        ) -join [Environment]::NewLine

        [System.Windows.MessageBox]::Show($ctx.Window, $message, 'About',
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information) | Out-Null
    }

    # --- Window lifetime --------------------------------------------------
    $ctx.Window.Add_Closing({

        Write-TkLog -Level Information -Category 'UI' -Message 'Closing.'

        Save-TkSettings -Confirm:$false
        Stop-TkThreading
    })
}

<#
.SYNOPSIS
    Updates the elevation badge in the header.

.DESCRIPTION
    The badge is the honest answer to "why is that button doing nothing":
    privileged features are disabled, not hidden, and the badge says why.
#>
function Update-TkElevationBadge {
    [CmdletBinding()]
    param()

    $ctx    = Get-TkContext
    $badge  = Get-TkControl -Name 'ElevationBadge'
    $text   = Get-TkControl -Name 'ElevationText'
    $button = Get-TkControl -Name 'BtnElevate'

    if (-not $text) {
        return
    }

    if ($ctx.IsElevated) {

        $text.Text = 'Administrator'

        if ($badge) {
            $badge.BorderBrush = $ctx.Window.Resources['Success']
        }

        if ($button) {
            $button.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }
    else {
        $text.Text = 'Standard user - system changes disabled'

        if ($badge) {
            $badge.BorderBrush = $ctx.Window.Resources['Warning']
        }
    }
}
