<#
    Toolkit - Features / Diagnostics / Drivers

    The third-party drivers on this machine, with their provider, version, date
    and whether they are signed. An old or unsigned driver is a common cause of
    crashes and a route in for an attacker, and the built-in Windows drivers are
    left out so the list is short enough to read. Read only.
#>

<#
.SYNOPSIS
    Reads a WMI datetime into a DateTime.

.DESCRIPTION
    WMI writes a date as yyyymmddHHMMSS.ffffff followed by the UTC offset. Only
    the leading fourteen digits are needed for a driver date, and reading them
    by hand avoids depending on the WMI datetime converter, which is not present
    everywhere.

.PARAMETER Value
    The WMI datetime string.

.OUTPUTS
    System.Nullable[datetime], $null when the value is empty or malformed.
#>
function ConvertFrom-TkCimDate {
    [CmdletBinding()]
    [OutputType([System.Nullable[datetime]])]
    param(
        [Parameter()]
        [AllowNull()]
        [string] $Value
    )

    if (-not $Value -or $Value.Length -lt 8) {
        return $null
    }

    $digits = $Value.Substring(0, [Math]::Min(14, $Value.Length))

    try {
        $format = ('yyyyMMddHHmmss').Substring(0, $digits.Length)
        return [datetime]::ParseExact($digits, $format, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        return $null
    }
}

<#
.SYNOPSIS
    Reduces a Win32_PnPSignedDriver instance to a record.

.PARAMETER Driver
    A Win32_PnPSignedDriver instance, or an object with the same properties.

.OUTPUTS
    PSCustomObject with Device, Provider, Version, Date, Signed, Class and Inf.
#>
function ConvertFrom-TkDriverCim {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object] $Driver
    )

    return [pscustomobject] @{
        Device   = [string] $Driver.DeviceName
        Provider = [string] $Driver.DriverProviderName
        Version  = [string] $Driver.DriverVersion
        Date     = ConvertFrom-TkCimDate -Value ([string] $Driver.DriverDate)
        Signed   = [bool]   $Driver.IsSigned
        Class    = [string] $Driver.DeviceClass
        Inf      = [string] $Driver.InfName
    }
}

<#
.SYNOPSIS
    Lists the third-party and unsigned drivers on this machine.

.DESCRIPTION
    Reads Win32_PnPSignedDriver and keeps the drivers worth a look: those from a
    provider other than Microsoft, and any that are not signed whoever they are
    from. A driver with no name or provider (a placeholder entry) is dropped.

.OUTPUTS
    PSCustomObject[] as ConvertFrom-TkDriverCim returns, provider then device.
#>
function Get-TkDriverInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $drivers = @(Get-TkCimInstanceSafe -ClassName 'Win32_PnPSignedDriver' -All)

    $records = foreach ($driver in $drivers) {

        $record = ConvertFrom-TkDriverCim -Driver $driver

        if (-not $record.Device -or -not $record.Provider) { continue }

        $thirdParty = $record.Provider -notmatch '^(Microsoft|Windows| ?$)'
        if ($thirdParty -or -not $record.Signed) {
            $record
        }
    }

    # De-duplicate: the same driver package backs many device entries.
    return @($records |
             Sort-Object -Property Provider, Device, Version -Unique |
             Sort-Object -Property Provider, Device)
}
