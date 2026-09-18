<#
    Toolkit - Features / Security / Local privilege escalation

    The misconfigurations that let a standard user become SYSTEM or another
    user: an unquoted service path, AlwaysInstallElevated, an autologon password
    left in the clear, a debugger hijacking a program through Image File
    Execution Options, and the credentials stored on the machine. All read only.

    These are the checks the attack-surface audit does not already make; it
    covers the driver blocklist, memory integrity, Defender exclusions, the
    spooler, NTLM and cached logons.
#>

<#
.SYNOPSIS
    Finds the services whose path is unquoted and contains a space.

.DESCRIPTION
    When a service's ImagePath has a space and is not quoted, Windows tries each
    truncation in turn: C:\Program.exe before C:\Program Files\...\svc.exe. If an
    attacker can drop an executable at one of those earlier names, it runs as the
    service account. The fix is always to quote the path.

.PARAMETER Services
    Service records from Get-TkServiceInventory (Name, DisplayName, Path).

.OUTPUTS
    PSCustomObject[] with Name, DisplayName and Path.
#>
function Get-TkUnquotedServicePath {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [pscustomobject[]] $Services
    )

    $result = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($service in @($Services)) {

        $path = [string] $service.Path
        if (-not $path) { continue }

        $trimmed = $path.TrimStart()
        if ($trimmed.StartsWith('"')) { continue }   # already quoted

        # The executable is everything up to the first .exe; if that part has a
        # space and a path separator, the path is exploitable.
        $match = [regex]::Match($trimmed, '^(?<exe>.*?\.exe)(\s|$)', 'IgnoreCase')
        $exe   = if ($match.Success) { $match.Groups['exe'].Value } else { ($trimmed -split '\s', 2)[0] }

        if ($exe -match '\s' -and $exe -match '\\') {
            $result.Add([pscustomobject] @{
                Name        = [string] $service.Name
                DisplayName = [string] $service.DisplayName
                Path        = $path
            })
        }
    }

    return @($result)
}

<#
.SYNOPSIS
    Parses the output of cmdkey /list into stored credential entries.

.DESCRIPTION
    cmdkey's labels are localised, but every entry carries a locale-independent
    token of the form Type:target=Name, so the entries are read from those. A
    Domain entry is a stored password that helps an attacker move to another
    machine; the rest are generic tokens.

.PARAMETER Text
    The output of cmdkey /list.

.OUTPUTS
    PSCustomObject[] with Type and Target.
#>
function ConvertFrom-TkCmdkeyOutput {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $result = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($match in [regex]::Matches($Text, '(?<type>[A-Za-z]+):target=(?<target>\S+)')) {
        $result.Add([pscustomobject] @{
            Type   = $match.Groups['type'].Value
            Target = $match.Groups['target'].Value
        })
    }

    return @($result)
}

<#
.SYNOPSIS
    Reads whether AlwaysInstallElevated is enabled in both hives.

.DESCRIPTION
    When the policy is set to 1 in both HKLM and HKCU, any user can install an
    MSI package as SYSTEM, which is a direct path to full control.

.OUTPUTS
    PSCustomObject with Machine, User and Enabled (true only when both are 1).
#>
function Get-TkAlwaysInstallElevated {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $read = {
        param($hive)
        try {
            (Get-ItemProperty -Path "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name 'AlwaysInstallElevated' -ErrorAction Stop).AlwaysInstallElevated
        }
        catch {
            $null
        }
    }

    $machine = & $read 'HKLM'
    $user    = & $read 'HKCU'

    return [pscustomobject] @{
        Machine = $machine
        User    = $user
        Enabled = ($machine -eq 1 -and $user -eq 1)
    }
}

<#
.SYNOPSIS
    Reads the autologon settings, including whether a password is stored.

.OUTPUTS
    PSCustomObject with Enabled, HasPassword and User.
#>
function Get-TkAutoLogonSetting {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        $winlogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
    }
    catch {
        return [pscustomobject] @{ Enabled = $false; HasPassword = $false; User = '' }
    }

    return [pscustomobject] @{
        Enabled     = ([string] $winlogon.AutoAdminLogon -eq '1')
        HasPassword = [bool] $winlogon.DefaultPassword
        User        = [string] $winlogon.DefaultUserName
    }
}

<#
.SYNOPSIS
    Lists the Image File Execution Options entries that set a debugger.

.DESCRIPTION
    A Debugger value under a program's IFEO key makes Windows launch that
    debugger instead of the program, a classic way to hijack a trusted
    executable. Legitimate uses are rare, so each one is worth a look.

.OUTPUTS
    PSCustomObject[] with Image and Debugger.
#>
function Get-TkImageFileExecutionDebugger {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $result = New-Object System.Collections.Generic.List[pscustomobject]
    $base   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

    try {
        foreach ($key in @(Get-ChildItem -Path $base -ErrorAction Stop)) {
            $debugger = (Get-ItemProperty -Path $key.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $result.Add([pscustomobject] @{ Image = $key.PSChildName; Debugger = [string] $debugger })
            }
        }
    }
    catch {
        Write-TkLog -Level Debug -Category 'Hunting' -Message ('IFEO could not be read: {0}' -f $_.Exception.Message)
    }

    return @($result)
}

<#
.SYNOPSIS
    Lists the credentials stored on the machine, from cmdkey.

.OUTPUTS
    PSCustomObject[] as ConvertFrom-TkCmdkeyOutput returns.
#>
function Get-TkStoredCredential {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    try {
        $output = (& cmdkey.exe /list 2>&1 | Out-String)
    }
    catch {
        return @()
    }

    return @(ConvertFrom-TkCmdkeyOutput -Text $output)
}
