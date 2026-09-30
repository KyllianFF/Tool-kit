<#
    Toolkit - UI / Organisation policy setting

    The Settings card where the policy is set: where it is, what makes it
    trusted, and a check that reads and verifies it and says what it asks
    for. The audit reads and verifies it again at every run.
#>

<#
.SYNOPSIS
    Wires the Organisation policy card.
#>
function Initialize-TkPolicySetting {
    [CmdletBinding()]
    param()

    $setting = Get-TkPolicySetting

    $source = Get-TkControl -Name 'PolicySource'
    if ($source) { $source.Text = $setting.Source }

    $trust = Get-TkControl -Name 'PolicyTrust'
    if ($trust) { $trust.Text = (@($setting.Trust) -join ', ') }

    Register-TkClick -Name 'BtnPolicyBrowse' -Action {
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Title  = 'Choose the organisation policy'
        $dialog.Filter = 'Toolkit policy (*.psd1)|*.psd1'
        if ($dialog.ShowDialog((Get-TkContext).Window)) {
            (Get-TkControl -Name 'PolicySource').Text = $dialog.FileName
        }
    }

    Register-TkClick -Name 'BtnPolicyCheck'    -Action { Invoke-TkPolicyCheckFromUi }
    Register-TkClick -Name 'BtnPolicyTemplate' -Action { Save-TkPolicyTemplateFromUi }
    Register-TkClick -Name 'BtnPolicyClear'    -Action { Clear-TkPolicySettingFromUi }

    $status = Get-TkControl -Name 'PolicyStatusText'
    if ($status) {
        $status.Text = if ($setting.Source) { 'Each audit reads and verifies this policy again before applying it. Check it to see what it asks for.' }
                       else { 'No organisation policy: the audit is the generic one.' }
    }
}

<#
.SYNOPSIS
    Saves where the organisation policy is and what trusts it.
#>
function Set-TkPolicySetting {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Source,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Trust = @()
    )

    if (-not $PSCmdlet.ShouldProcess('organisation policy', 'Save the setting')) {
        return
    }

    $settings = (Get-TkContext).Settings
    $settings['PolicySource'] = $Source
    $settings['PolicyTrust']  = @($Trust | Where-Object { $_ })
    Save-TkSettings
}

<#
.SYNOPSIS
    What a policy check found, for the card.
#>
function Format-TkPolicyCheck {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        $Import
    )

    if (-not $Import) {
        return 'The policy could not be read.'
    }

    if ($Import.Applied) {
        return (Format-TkPolicySummary -Policy $Import.Policy)
    }

    return ('Not applied: {0}' -f $Import.Reason)
}

<#
.SYNOPSIS
    Saves the policy typed in, then reads and verifies it in the background.
#>
function Invoke-TkPolicyCheckFromUi {
    [CmdletBinding()]
    param()

    $source = ([string] (Get-TkControl -Name 'PolicySource').Text).Trim()
    $trust  = @(([string] (Get-TkControl -Name 'PolicyTrust').Text) -split '[,;\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $status = Get-TkControl -Name 'PolicyStatusText'

    if (-not $source) {
        $status.Text = 'Choose the policy file first, or save a starting policy and fill it in.'
        return
    }

    Set-TkPolicySetting -Source $source -Trust $trust -Confirm:$false
    $status.Text = 'Reading and verifying the policy...'

    Invoke-TkBackgroundAction -StatusText 'Reading and verifying the organisation policy...' -ParameterList @{ source = $source; trust = $trust } `
        -ScriptBlock { param($source, $trust) Import-TkOrganisationPolicy -Source $source -Trust $trust } `
        -OnComplete {
            param($result)

            $import = @($result.Output) | Where-Object { $_ -and $_.PSObject.Properties['Applied'] } | Select-Object -Last 1

            (Get-TkControl -Name 'PolicyStatusText').Text = Format-TkPolicyCheck -Import $import
            Set-TkStatus -Text $(if ($import -and $import.Applied) { 'The organisation policy is verified: the next audit applies it.' } else { 'The organisation policy is not applied: the audit stays generic.' })
        }
}

<#
.SYNOPSIS
    Writes a starting policy to fill in, sign and publish.

.DESCRIPTION
    UTF-8 with a byte order mark, which Set-AuthenticodeSignature and
    Windows PowerShell 5.1 both read without guessing.
#>
function Save-TkPolicyTemplateFromUi {
    [CmdletBinding()]
    param()

    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title    = 'Save a starting policy'
    $dialog.Filter   = 'Toolkit policy (*.psd1)|*.psd1'
    $dialog.FileName = 'workstation-policy.psd1'

    if (-not $dialog.ShowDialog((Get-TkContext).Window)) {
        return
    }

    try {
        [System.IO.File]::WriteAllText($dialog.FileName, (New-TkPolicyTemplate), (New-Object System.Text.UTF8Encoding($true)))
        Set-TkStatus -Text ('Starting policy written to {0}: fill it in, then sign it or trust its SHA-256.' -f $dialog.FileName)
    }
    catch {
        Write-TkLog -Level Error -Category 'Policy' -Message ('The starting policy could not be written: {0}' -f $_.Exception.Message)
    }
}

<#
.SYNOPSIS
    Stops judging the audit against a policy.
#>
function Clear-TkPolicySettingFromUi {
    [CmdletBinding()]
    param()

    Set-TkPolicySetting -Source '' -Trust @() -Confirm:$false

    (Get-TkControl -Name 'PolicySource').Text     = ''
    (Get-TkControl -Name 'PolicyTrust').Text      = ''
    (Get-TkControl -Name 'PolicyStatusText').Text = 'No organisation policy: the audit is the generic one.'

    Set-TkStatus -Text 'The audit no longer applies an organisation policy.'
}
