<#
    Toolkit - Features / Vendor support and BIOS

    Turns the serial number read from SMBIOS into a direct link to the right
    vendor page, and drives the vendor supplied update utilities.

    Deliberate limitation: the toolkit never downloads or flashes firmware on
    its own. A BIOS flash from an unverified source is the fastest way to
    brick a fleet, so the toolkit installs the vendor tool through winget and
    hands over. This is a safety decision, not a missing feature.
#>

<#
.SYNOPSIS
    Finds the support profile matching a manufacturer.

.DESCRIPTION
    Looks the manufacturer up in the vendor-support catalog using its match
    patterns, so "Dell Inc.", "Dell Inc" and "Dell" all resolve to the same
    entry.

.PARAMETER Manufacturer
    Manufacturer string as reported by Win32_ComputerSystem.

.OUTPUTS
    PSCustomObject, or $null when the vendor is unknown.
#>
function Get-TkVendorProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Manufacturer
    )

    $catalog = Import-TkCatalog -Name 'vendor-support'

    if (-not $catalog) {
        return $null
    }

    foreach ($vendor in $catalog.vendors) {

        foreach ($pattern in $vendor.match) {

            if ($Manufacturer -like ('*{0}*' -f $pattern)) {
                return $vendor
            }
        }
    }

    return $null
}

<#
.SYNOPSIS
    Opens the vendor support page for the current machine.

.DESCRIPTION
    Builds the URL from the vendor template, substituting the serial number
    where the vendor accepts one. The serial is URL encoded before insertion.

.PARAMETER Kind
    Which page to open: Drivers, Warranty or Manual.

.PARAMETER Identity
    Machine identity from Get-TkMachineIdentity. Queried when omitted.

.OUTPUTS
    System.Boolean
#>
function Open-TkVendorSupport {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [ValidateSet('Drivers', 'Warranty', 'Manual')]
        [string] $Kind = 'Drivers',

        [Parameter()]
        $Identity
    )

    if (-not $Identity) {
        $Identity = Get-TkMachineIdentity
    }

    $vendor = Get-TkVendorProfile -Manufacturer $Identity.Manufacturer

    if (-not $vendor) {

        Write-TkLog -Level Warning -Category 'Vendor' -Message (
            'No support profile for "{0}". Falling back to a web search.' -f $Identity.Manufacturer
        )

        $query = [uri]::EscapeDataString(
            '{0} {1} support drivers' -f $Identity.Manufacturer, $Identity.Model
        )

        return (Open-TkUri -Uri ('https://duckduckgo.com/?q={0}' -f $query))
    }

    $template = switch ($Kind) {
        'Drivers'  { $vendor.driversUrl  ; break }
        'Warranty' { $vendor.warrantyUrl ; break }
        'Manual'   { $vendor.manualUrl   ; break }
    }

    if ([string]::IsNullOrWhiteSpace($template)) {

        Write-TkLog -Level Warning -Category 'Vendor' -Message (
            '{0} has no {1} URL in the catalog.' -f $vendor.name, $Kind
        )

        return $false
    }

    $url = Expand-TkVendorUrl -Template $template -Identity $Identity

    Write-TkLog -Level Information -Category 'Vendor' -Message (
        'Opening {0} {1} page.' -f $vendor.name, $Kind.ToLower()
    )

    return (Open-TkUri -Uri $url)
}

<#
.SYNOPSIS
    Substitutes machine facts into a vendor URL template.

.DESCRIPTION
    Supported tokens: {serial}, {model}, {assettag}. Every substituted value
    is URL encoded, which matters because model names routinely contain
    spaces and slashes.

.OUTPUTS
    System.String
#>
function Expand-TkVendorUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Template,

        [Parameter(Mandatory)]
        $Identity
    )

    $serial = $Identity.SerialNumber
    $model  = $Identity.Model
    $asset  = $Identity.AssetTag

    # A placeholder value must never end up inside a support URL.
    foreach ($name in @('serial', 'model', 'asset')) {

        $value = Get-Variable -Name $name -ValueOnly

        if ($value -eq 'Not available') {
            Set-Variable -Name $name -Value ''
        }
    }

    $url = $Template
    $url = $url -replace '\{serial\}',   [uri]::EscapeDataString($serial)
    $url = $url -replace '\{model\}',    [uri]::EscapeDataString($model)
    $url = $url -replace '\{assettag\}', [uri]::EscapeDataString($asset)

    return $url
}

<#
.SYNOPSIS
    Compares the installed BIOS against its release date and reports age.

.DESCRIPTION
    There is no vendor neutral way to query the latest available BIOS, so the
    toolkit reports what it can verify locally: the installed version and how
    old it is. Anything older than two years on a fleet machine is worth a
    look, which is what the returned recommendation says.

.OUTPUTS
    PSCustomObject
#>
function Get-TkBiosStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $bios = Get-TkCimInstanceSafe -ClassName 'Win32_BIOS'

    $releaseDate = $null
    $ageDays     = $null

    if ($bios -and $bios.ReleaseDate) {

        try {
            $releaseDate = [datetime] $bios.ReleaseDate
            $ageDays     = [int] ((Get-Date) - $releaseDate).TotalDays
        }
        catch {
            # Malformed CIM date; the age simply stays unknown.
            $null = $_
        }
    }

    $recommendation = 'BIOS age could not be determined.'

    if ($null -ne $ageDays) {

        if ($ageDays -gt 730) {
            $recommendation = 'This BIOS is more than two years old. Check the vendor page for a newer release.'
        }
        elseif ($ageDays -gt 365) {
            $recommendation = 'This BIOS is over a year old. A firmware review is reasonable.'
        }
        else {
            $recommendation = 'This BIOS is recent. No action expected.'
        }
    }

    return [pscustomobject]@{
        Vendor         = Format-TkValue $bios.Manufacturer
        Version        = Format-TkValue $bios.SMBIOSBIOSVersion
        ReleaseDate    = Format-TkBiosDate -Value $bios.ReleaseDate
        AgeDays        = $ageDays
        Recommendation = $recommendation
    }
}

<#
.SYNOPSIS
    Installs the vendor firmware update utility through winget.

.DESCRIPTION
    Each vendor profile names the winget package that manages its firmware
    (Dell Command Update, Lenovo System Update, HP Support Assistant and so
    on). The toolkit installs it and lets the vendor tool own the flash.

.PARAMETER Identity
    Machine identity. Queried when omitted.

.OUTPUTS
    System.Boolean
#>
function Install-TkVendorUpdateTool {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter()]
        $Identity
    )

    if (-not (Assert-TkElevated -Operation 'Install the vendor update utility')) {
        return $false
    }

    if (-not $Identity) {
        $Identity = Get-TkMachineIdentity
    }

    $vendor = Get-TkVendorProfile -Manufacturer $Identity.Manufacturer

    if (-not $vendor -or [string]::IsNullOrWhiteSpace($vendor.updateToolPackage)) {

        Write-TkLog -Level Warning -Category 'Vendor' -Message (
            'No firmware utility is known for "{0}". Use the vendor support page instead.' -f $Identity.Manufacturer
        )

        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($vendor.updateToolPackage, 'Install vendor update utility')) {
        return $false
    }

    Write-TkLog -Level Information -Category 'Vendor' -Message (
        'Installing {0} ({1}).' -f $vendor.updateToolName, $vendor.updateToolPackage
    )

    return (Install-TkWingetPackage -PackageId $vendor.updateToolPackage)
}

<#
.SYNOPSIS
    Exports the full machine inventory to a file.

.DESCRIPTION
    Produces the report a technician attaches to a ticket. JSON keeps the
    structure for later processing; text is what gets pasted into a comment.

.PARAMETER Path
    Destination file.

.PARAMETER Format
    Json or Text.

.OUTPUTS
    System.String - the path written, or $null on failure.
#>
function Export-TkSystemReport {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [ValidateSet('Json', 'Text')]
        [string] $Format = 'Json'
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write system report')) {
        return $null
    }

    $report = [ordered]@{
        GeneratedAt = (Get-Date).ToString('s')
        Toolkit     = (Get-TkContext).Version
        Identity    = Get-TkMachineIdentity
        OS          = Get-TkOperatingSystemInfo
        Hardware    = Get-TkHardwareInfo
        Security    = Get-TkPlatformSecurityInfo
        Bios        = Get-TkBiosStatus
    }

    try {
        if ($Format -eq 'Json') {
            $report | ConvertTo-Json -Depth 6 |
                Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
        }
        else {
            $lines = @()

            foreach ($section in $report.Keys) {

                $lines += ''
                $lines += ('=== {0} ===' -f $section.ToUpper())

                $value = $report[$section]

                if ($value -is [string] -or $value -is [datetime]) {
                    $lines += ('  {0}' -f $value)
                }
                else {
                    $lines += ($value | Format-List | Out-String).TrimEnd()
                }
            }

            $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
        }

        Write-TkLog -Level Information -Category 'Inventory' -Message ('Report written to {0}' -f $Path)

        return $Path
    }
    catch {
        Write-TkLog -Level Error -Category 'Inventory' -Message (
            'Could not write the report: {0}' -f $_.Exception.Message
        )

        return $null
    }
}
