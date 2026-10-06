<#
    Toolkit - UI / Language setting

    The Settings card where the language is chosen: English, French, or the
    display language of Windows. It applies at the next start, when the
    window is built in it.
#>

<#
.SYNOPSIS
    Wires the Language card.
#>
function Initialize-TkLanguageSetting {
    [CmdletBinding()]
    param()

    $combo = Get-TkControl -Name 'SettingLanguage'
    if (-not $combo) {
        return
    }

    $current = [string] (Get-TkContext).Settings['Language']
    if (-not $current) { $current = 'en' }

    $windows = [System.Globalization.CultureInfo]::CurrentUICulture.NativeName
    $choices = @(Get-TkLanguageChoice | ForEach-Object { [pscustomobject] @{ Id = $_.Id; Name = $_.Name } }) +
               @([pscustomobject] @{ Id = 'auto'; Name = (Get-TkText -Text 'Same as Windows ({0})' -ArgumentList $windows) })

    foreach ($choice in $choices) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $choice.Name
        $item.Tag     = $choice.Id
        [void] $combo.Items.Add($item)
        if ($choice.Id -eq $current) { $combo.SelectedItem = $item }
    }

    if ($null -eq $combo.SelectedItem) { $combo.SelectedIndex = 0 }

    # After the selection above, so building the list saves nothing.
    $combo.Add_SelectionChanged({ Set-TkLanguageFromUi })

    Write-TkLanguageStatus -Setting $current
}

<#
.SYNOPSIS
    Saves the language chosen, for the next start.
#>
function Set-TkLanguageFromUi {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $combo = Get-TkControl -Name 'SettingLanguage'
    if (-not $combo -or -not $combo.SelectedItem) {
        return
    }

    $id = [string] $combo.SelectedItem.Tag

    if ($PSCmdlet.ShouldProcess('language', 'Save the setting')) {
        (Get-TkContext).Settings['Language'] = $id
        Save-TkSettings
    }

    Write-TkLanguageStatus -Setting $id
}

<#
.SYNOPSIS
    Says what language the window is in, and when the choice applies.
#>
function Write-TkLanguageStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Setting
    )

    $status = Get-TkControl -Name 'SettingLanguageStatus'
    if (-not $status) {
        return
    }

    $names = @{}
    foreach ($choice in @(Get-TkLanguageChoice)) { $names[$choice.Id] = $choice.Name }

    $now  = Get-TkLanguage
    $next = Resolve-TkLanguage -Setting $Setting

    $status.Text = if ($next -eq $now) { Get-TkText -Text 'Shown in {0}.' -ArgumentList $names[$now] }
                   else { Get-TkText -Text 'Applies at the next start: restart the toolkit to see it in {0}.' -ArgumentList $names[$next] }
}
