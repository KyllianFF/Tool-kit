<#
    Toolkit - Features / Crash analysis

    What a blue screen was, in words a technician can act on: the stop code
    named and explained, how often it came back, and which kernel drivers were
    registered in the days before it.

    Everything comes from the event logs, which a standard user can read and
    which carry the same stop code and parameters as the dump. The dumps
    themselves sit in a folder only an administrator can open, and reading one
    properly needs a debugger and symbols; the report names the dump file and
    says how to analyse it instead of guessing at its contents.

    Every function here is read only.
#>

<#
.SYNOPSIS
    Formats a stop code the way Microsoft documents it.

.PARAMETER Code
    The stop code as a number.

.OUTPUTS
    System.String, for example 0x000000F7.
#>
function Format-TkBugCheckCode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [long] $Code
    )

    # Masked to 32 bits: a code written as a literal, 0xC000021A for one, is a
    # negative number to PowerShell and would print sixteen digits.
    return ('0x{0:X8}' -f ($Code -band 4294967295))
}

<#
.SYNOPSIS
    Reads the stop code and its parameters from bug check text.

.DESCRIPTION
    The first property of the bug check event (System log, event 1001 from
    Microsoft-Windows-WER-SystemErrorReporting) holds the code and the four
    parameters in a fixed form that is not translated:

        0x000000f7 (0xffffc18bfc43e460, 0x00005eafe2bb4f1b, 0xffffa1501d44b0e4, 0x0000000000000000)

    The message around it is translated, which is why the property is read
    rather than the message.

.PARAMETER Text
    The text holding the code.

.OUTPUTS
    PSCustomObject with Code, CodeHex and Parameters, or $null when the text
    holds no stop code.
#>
function ConvertFrom-TkBugCheckText {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $match = [regex]::Match($Text, '0x(?<code>[0-9a-fA-F]{1,8})\s*\((?<parameters>[^)]*)\)')

    if (-not $match.Success) {
        return $null
    }

    $code = [Convert]::ToInt64($match.Groups['code'].Value, 16)

    $parameters = @($match.Groups['parameters'].Value -split ',' |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ })

    return [pscustomobject] @{
        Code       = $code
        CodeHex    = Format-TkBugCheckCode -Code $code
        Parameters = $parameters
    }
}

<#
.SYNOPSIS
    Names and explains a stop code.

.DESCRIPTION
    The name comes from the full list Microsoft publishes. The explanation and
    the first steps exist for the codes a support call actually meets, grouped
    by what usually causes them, so that adding a code means naming its family
    rather than writing its advice again.

.PARAMETER Code
    The stop code as a number.

.OUTPUTS
    PSCustomObject with CodeHex, Name, Kind, KindName, Meaning, Steps and
    Reference. A code missing from the catalogs still gets its number and the
    reference, never an invented name.
#>
function Get-TkBugCheckInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [long] $Code
    )

    $hex     = Format-TkBugCheckCode -Code $Code
    $names   = Import-TkCatalog -Name 'bug-check-names'
    $details = Import-TkCatalog -Name 'bug-checks'

    $name = ''

    if ($names -and $names.names.PSObject.Properties[$hex]) {
        $name = [string] $names.names.$hex
    }

    $detail = if ($details) { @($details.codes) | Where-Object { $_.code -eq $hex } | Select-Object -First 1 } else { $null }
    $kind   = if ($detail -and $details) { @($details.kinds) | Where-Object { $_.id -eq $detail.kind } | Select-Object -First 1 } else { $null }

    return [pscustomobject] @{
        CodeHex   = $hex
        Name      = $(if ($name) { $name } else { 'Stop code not in the published list' })
        Kind      = $(if ($detail) { [string] $detail.kind } else { '' })
        KindName  = $(if ($kind) { [string] $kind.name } else { '' })
        Meaning   = $(if ($detail) { [string] $detail.meaning } else { '' })
        Steps     = @($(if ($kind) { $kind.steps } else { @() }))
        Reference = $(if ($details) { [string] $details.reference } else { '' })
    }
}

<#
.SYNOPSIS
    Lists the kernel drivers registered with Windows in a period.

.DESCRIPTION
    Read from the Service Control Manager event 7045, "a service was
    installed". Hardware monitoring, overclocking, RGB and anti-cheat tools
    register their kernel driver each time they start, which is exactly the
    kind of driver behind a stop code such as 0xF7.

    A driver is told from a service by its account, which is empty for a
    driver and names an account for a service. The service type would say it
    too, but Windows writes it in the display language.

.PARAMETER Since
    Start of the period.

.PARAMETER Until
    End of the period.

.OUTPUTS
    PSCustomObject[] with Name, ImagePath, When and Count, most recent first,
    one row per driver.
#>
function Get-TkKernelDriverRegistration {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [datetime] $Since,

        [Parameter(Mandatory)]
        [datetime] $Until
    )

    $records = Get-TkWinEvent -LogName 'System' -Id 7045 -Since $Since -MaxEvents 500 |
               Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.TimeCreated -le $Until }

    $drivers = foreach ($record in $records) {

        $values = @($record.Properties | ForEach-Object { [string] $_.Value })

        # ServiceName, ImagePath, ServiceType, StartType, AccountName.
        if ($values.Count -ge 5 -and [string]::IsNullOrWhiteSpace($values[4])) {

            [pscustomobject] @{
                Name      = $values[0]
                ImagePath = $values[1]
                When      = $record.TimeCreated
            }
        }
    }

    $rows = foreach ($group in (@($drivers) | Where-Object { $_ } | Group-Object -Property Name)) {

        $latest = $group.Group | Sort-Object -Property When -Descending | Select-Object -First 1

        [pscustomobject] @{
            Name      = $group.Name
            ImagePath = $latest.ImagePath
            When      = $latest.When
            Count     = $group.Count
        }
    }

    return @($rows | Sort-Object -Property When -Descending)
}

<#
.SYNOPSIS
    Reads the crash history: blue screens and hard resets.

.DESCRIPTION
    Two sources, joined:

    - the bug check event 1001, written at the next start when a dump was
      saved, with the code, the parameters and the dump path;
    - Kernel-Power event 41, written when the previous session did not end
      cleanly. Its BugcheckCode is the stop code when there was one, which
      covers a blue screen that saved no dump, and 0 when the machine simply
      lost power or was reset.

    An event 41 within ten minutes of a bug check event describes the same
    crash and is not counted twice.

.PARAMETER Days
    How far back to look.

.PARAMETER DriverWindowDays
    How many days before each crash to list registered kernel drivers.

.OUTPUTS
    PSCustomObject[] with When, Kind, Severity, Code, Info, Parameters,
    DumpPath and Drivers, most recent first.
#>
function Get-TkCrashHistory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int] $Days = 90,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int] $DriverWindowDays = 7
    )

    $since   = (Get-Date).AddDays(-$Days)
    $crashes = @()

    # --- Blue screens with a dump ----------------------------------------
    $bugChecks = Get-TkWinEvent -LogName 'System' -Id 1001 -Since $since -MaxEvents 100 |
                 Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting' }

    foreach ($record in $bugChecks) {

        $values = @($record.Properties | ForEach-Object { [string] $_.Value })
        $parsed = if ($values.Count -gt 0) { ConvertFrom-TkBugCheckText -Text $values[0] } else { $null }

        if ($null -eq $parsed) {
            continue
        }

        $crashes += [pscustomobject] @{
            When       = $record.TimeCreated
            Kind       = 'Blue screen'
            Severity   = 'Fail'
            Code       = $parsed.Code
            Parameters = $parsed.Parameters
            DumpPath   = $(if ($values.Count -gt 1) { $values[1] } else { '' })
        }
    }

    # --- Unclean ends of session -----------------------------------------
    $powerEvents = Get-TkWinEvent -LogName 'System' -Id 41 -Since $since -MaxEvents 100 |
                   Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' }

    foreach ($record in $powerEvents) {

        $data = @{}

        try {
            foreach ($item in ([xml] $record.ToXml()).Event.EventData.Data) {
                $data[[string] $item.Name] = [string] $item.'#text'
            }
        }
        catch {
            continue
        }

        $code = 0L
        [void] [long]::TryParse([string] $data['BugcheckCode'], [ref] $code)

        $sameCrash = @($crashes | Where-Object {
            [math]::Abs(($_.When - $record.TimeCreated).TotalMinutes) -le 10
        }).Count -gt 0

        if ($sameCrash) {
            continue
        }

        if ($code -ne 0) {

            $crashes += [pscustomobject] @{
                When       = $record.TimeCreated
                Kind       = 'Blue screen, no dump saved'
                Severity   = 'Fail'
                Code       = $code
                Parameters = @(1..4 | ForEach-Object { [string] $data[('BugcheckParameter{0}' -f $_)] })
                DumpPath   = ''
            }
        }
        else {

            $crashes += [pscustomobject] @{
                When       = $record.TimeCreated
                Kind       = 'Power lost or reset'
                Severity   = 'Warning'
                Code       = 0L
                Parameters = @()
                DumpPath   = ''
            }
        }
    }

    # --- Meaning and the drivers registered before each one ---------------
    $results = foreach ($crash in ($crashes | Sort-Object -Property When -Descending)) {

        [pscustomobject] @{
            When       = $crash.When
            Kind       = $crash.Kind
            Severity   = $crash.Severity
            Code       = $crash.Code
            Info       = $(if ($crash.Code -ne 0) { Get-TkBugCheckInfo -Code $crash.Code } else { $null })
            Parameters = $crash.Parameters
            DumpPath   = $crash.DumpPath
            Drivers    = $(if ($crash.Code -ne 0) {
                              @(Get-TkKernelDriverRegistration -Since $crash.When.AddDays(-$DriverWindowDays) -Until $crash.When)
                          } else { @() })
        }
    }

    return @($results)
}

<#
.SYNOPSIS
    Finds the kernel drivers registered before more than one blue screen.

.DESCRIPTION
    One driver registered before one crash proves little: tools register
    theirs every time they start. The same driver in front of several crashes
    is the pattern worth acting on first. Still a correlation, and the report
    says so.

.PARAMETER Crash
    Output of Get-TkCrashHistory.

.OUTPUTS
    PSCustomObject[] with Name, ImagePath and Crashes, the number of blue
    screens it preceded, most first. Empty with fewer than two blue screens.
#>
function Get-TkRecurringCrashDriver {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Crash
    )

    $blueScreens = @($Crash | Where-Object { $_ -and $_.Code -ne 0 })

    if ($blueScreens.Count -lt 2) {
        return @()
    }

    $seen = @{}
    $path = @{}

    foreach ($screen in $blueScreens) {

        # Once per crash, however often the driver was registered before it.
        foreach ($name in (@($screen.Drivers) | Where-Object { $_ } | ForEach-Object { $_.Name } | Sort-Object -Unique)) {
            $seen[$name] = 1 + [int] $seen[$name]
        }

        foreach ($driver in @($screen.Drivers | Where-Object { $_ })) {
            if (-not $path.ContainsKey($driver.Name)) { $path[$driver.Name] = $driver.ImagePath }
        }
    }

    $rows = foreach ($name in $seen.Keys) {

        if ($seen[$name] -ge 2) {
            [pscustomobject] @{
                Name      = $name
                ImagePath = $path[$name]
                Crashes   = $seen[$name]
            }
        }
    }

    return @($rows | Sort-Object -Property @{ Expression = 'Crashes'; Descending = $true }, Name)
}
