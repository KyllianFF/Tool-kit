<#
    Toolkit - Features / Device problems

    The devices Device Manager marks with a yellow exclamation mark, each with
    its problem code explained and the next thing to try. "My headset does not
    work" is a Code 43 far more often than anything a user would describe.

    Read only, and readable as a standard user.
#>

<#
.SYNOPSIS
    Explains a Device Manager problem code.

.DESCRIPTION
    The catalog holds every code Device Manager reports, with how serious it
    is and what to try. A hint keyed on the hardware identifier can add
    something the code alone does not say: a USB device reporting vendor 0000
    never identified itself, which points at a port, a cable or the device
    rather than at a driver.

.PARAMETER Code
    The ConfigManagerErrorCode of the device.

.PARAMETER HardwareId
    The device instance identifier, for the hints.

.OUTPUTS
    PSCustomObject with Code, Name, Severity, Meaning, Action and Hint.
#>
function Get-TkDeviceProblemInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $Code,

        [Parameter()]
        [AllowEmptyString()]
        [string] $HardwareId = ''
    )

    $catalog = Import-TkCatalog -Name 'device-problems'
    $entry   = if ($catalog) { @($catalog.problems) | Where-Object { [int] $_.code -eq $Code } | Select-Object -First 1 } else { $null }

    $hint = ''

    if ($catalog -and $HardwareId) {

        foreach ($candidate in @($catalog.hints)) {

            if ($HardwareId -match [string] $candidate.pattern) {
                $hint = [string] $candidate.note
                break
            }
        }
    }

    if ($null -eq $entry) {

        return [pscustomobject] @{
            Code     = $Code
            Name     = ''
            Severity = 'Warning'
            Meaning  = 'Device Manager reports problem code {0}, which is not in the catalog.' -f $Code
            Action   = 'Open Device Manager and read the device status.'
            Hint     = $hint
        }
    }

    return [pscustomobject] @{
        Code     = $Code
        Name     = [string] $entry.name
        Severity = [string] $entry.severity
        Meaning  = [string] $entry.meaning
        Action   = [string] $entry.action
        Hint     = $hint
    }
}

<#
.SYNOPSIS
    Lists the devices that report a problem.

.OUTPUTS
    PSCustomObject[] with Severity, Name, Class, Code, ProblemName, Meaning,
    Action, Hint and DeviceId, the most serious first.
#>
function Get-TkDeviceProblem {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $devices = Get-TkCimInstanceSafe -ClassName 'Win32_PnPEntity' -Filter 'ConfigManagerErrorCode <> 0' -All

    $rank = @{ Fail = 0; Warning = 1; Info = 2 }

    $rows = foreach ($device in @($devices | Where-Object { $_ })) {

        $info = Get-TkDeviceProblemInfo -Code ([int] $device.ConfigManagerErrorCode) -HardwareId ([string] $device.DeviceID)

        [pscustomobject] @{
            Severity    = $info.Severity
            Name        = $(if ($device.Name) { [string] $device.Name } else { [string] $device.DeviceID })
            Class       = [string] $device.PNPClass
            Code        = $info.Code
            ProblemName = $info.Name
            Meaning     = $info.Meaning
            Action      = $info.Action
            Hint        = $info.Hint
            DeviceId    = [string] $device.DeviceID
        }
    }

    return @($rows | Sort-Object -Property @{ Expression = { $rank[$_.Severity] } }, Name)
}
