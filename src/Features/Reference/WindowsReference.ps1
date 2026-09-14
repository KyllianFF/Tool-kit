<#
    Toolkit - Features / Windows reference

    What a code means, without leaving the machine: the Windows Update,
    servicing, setup, network and sign-in error codes a support call meets,
    and the event IDs worth knowing, each with what usually causes it and
    what to try.

    Both come from catalogs written from Microsoft's own references. A code
    the catalog does not hold is still decoded: an HRESULT carries a facility
    and a code, and a Win32 code has a system message, which Windows writes
    in the display language. Nothing is given a name it does not have.
#>

<#
.SYNOPSIS
    Reads an error code written any of the ways tools print it.

.DESCRIPTION
    0x80070005, 80070005, -2147024891 (as a signed integer, the way the update
    history returns it) and 2147942405 are one code. A small number such as 5
    is a Win32 error, whose HRESULT is 0x80070005.

.PARAMETER Text
    The code as typed or read.

.OUTPUTS
    PSCustomObject with Value, Hex and Win32, or $null when it is not a code.
#>
function ConvertTo-TkErrorCode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $clean = $Text.Trim()
    $value = $null
    $win32 = $null

    if ($clean -match '^0[xX](?<hex>[0-9A-Fa-f]{1,8})$') {
        $value = [Convert]::ToUInt32($Matches['hex'], 16)
    }
    elseif ($clean -match '^[0-9A-Fa-f]{8}$' -and $clean -match '[A-Fa-f]|^[89]') {

        # Eight hexadecimal digits without the prefix, as setup and some logs
        # print them. Eight decimal digits starting 1 to 7 stay a number.
        $value = [Convert]::ToUInt32($clean, 16)
    }
    elseif ($clean -match '^-\d{1,10}$') {

        $signed = 0L

        if (-not [long]::TryParse($clean, [ref] $signed) -or $signed -lt [int]::MinValue) {
            return $null
        }

        $value = [uint32] ($signed -band 4294967295)
    }
    elseif ($clean -match '^\d{1,10}$') {

        $number = 0L

        if (-not [long]::TryParse($clean, [ref] $number) -or $number -gt 4294967295) {
            return $null
        }

        # A Win32 error is at most 0xFFFF. Its HRESULT sets the severity bit
        # and facility 7: 0x80070000 plus the code.
        if ($number -gt 0 -and $number -le 65535) {
            $win32 = [int] $number
            $value = [uint32] (2147942400 + $number)
        }
        else {
            $value = [uint32] $number
        }
    }
    else {
        return $null
    }

    if ($null -eq $win32 -and ($value -band 4294901760) -eq 2147942400) {
        $win32 = [int] ($value -band 65535)
    }

    return [pscustomobject] @{
        Value = [uint32] $value
        Hex   = ('0x{0:X8}' -f [uint32] $value)
        Win32 = $win32
    }
}

<#
.SYNOPSIS
    Splits an error code into what its bits say.

.DESCRIPTION
    An HRESULT has a severity bit, an 11-bit facility and a 16-bit code. A
    value starting with C follows the NTSTATUS layout, with a 12-bit facility:
    sign-in failures and setup result codes such as 0xC1900101 are written
    this way.

.PARAMETER Value
    The code.

.OUTPUTS
    PSCustomObject with Kind, Facility, FacilityName and Code.
#>
function Get-TkErrorCodePart {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [uint32] $Value
    )

    $top = [int] ($Value -shr 28)

    $kind = if ($Value -eq 0) { 'Success' }
            elseif ($top -ge 12) { 'NTSTATUS' }
            elseif ($top -ge 8) { 'HRESULT error' }
            elseif (($Value -shr 16) -ne 0) { 'HRESULT success' }
            else { 'Number' }

    $facility = if ($kind -eq 'NTSTATUS') { [int] (($Value -shr 16) -band 4095) } else { [int] (($Value -shr 16) -band 2047) }

    $name    = ''
    $catalog = Import-TkCatalog -Name 'windows-errors'

    if ($catalog -and $kind -like 'HRESULT*') {

        $match = @($catalog.facilities) | Where-Object { [int] $_.id -eq $facility } | Select-Object -First 1

        if ($match) {
            $name = [string] $match.name
        }
    }

    return [pscustomobject] @{
        Kind         = $kind
        Facility     = $facility
        FacilityName = $name
        Code         = [int] ($Value -band 65535)
    }
}

<#
.SYNOPSIS
    Explains an error code.

.PARAMETER Code
    The code, in any form ConvertTo-TkErrorCode reads.

.OUTPUTS
    PSCustomObject with Hex, Value, Known, Name, Meaning, Action, GroupName,
    Steps, Kind, Facility, FacilityName, Win32, SystemMessage and Reference,
    or $null when the text is not a code.
#>
function Get-TkErrorCodeInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Code
    )

    $parsed = ConvertTo-TkErrorCode -Text ([string] $Code)

    if (-not $parsed) {
        return $null
    }

    $catalog = Import-TkCatalog -Name 'windows-errors'
    $entry   = if ($catalog) { @($catalog.codes) | Where-Object { [string] $_.code -eq $parsed.Hex } | Select-Object -First 1 } else { $null }
    $group   = if ($entry -and $entry.group) { @($catalog.groups) | Where-Object { $_.id -eq $entry.group } | Select-Object -First 1 } else { $null }
    $parts   = Get-TkErrorCodePart -Value $parsed.Value

    # The system message, in the display language, for a Win32 error. An
    # unknown code comes back as "Unknown error (0x...)", which says nothing.
    $message = ''

    if ($null -ne $parsed.Win32) {

        try {
            $message = (New-Object System.ComponentModel.Win32Exception($parsed.Win32)).Message
        }
        catch {
            $message = ''
        }

        # A message with an insert such as %1 is a template of some component,
        # found because the number happens to match, not a description.
        if ($message -match '\(0x[0-9A-Fa-f]+\)\s*$' -or $message -match '%\d') {
            $message = ''
        }
    }

    return [pscustomobject] @{
        Hex           = $parsed.Hex
        Value         = $parsed.Value
        Known         = [bool] $entry
        Name          = $(if ($entry) { [string] $entry.name } else { '' })
        Meaning       = $(if ($entry) { [string] $entry.meaning } else { '' })
        Action        = $(if ($entry -and $entry.PSObject.Properties['action']) { [string] $entry.action } else { '' })
        GroupName     = $(if ($group) { [string] $group.name } else { '' })
        Steps         = @($(if ($group) { $group.steps } else { @() }))
        Kind          = $parts.Kind
        Facility      = $parts.Facility
        FacilityName  = $parts.FacilityName
        Win32         = $parsed.Win32
        SystemMessage = [string] $message
        Reference     = $(if ($catalog) { [string] $catalog.reference } else { '' })
    }
}

<#
.SYNOPSIS
    Explains an error code in one line, for a report.

.PARAMETER Code
    The code.

.OUTPUTS
    System.String: the name and the meaning, the system message, or ''.
#>
function Get-TkErrorCodeSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Code
    )

    $info = Get-TkErrorCodeInfo -Code $Code

    if (-not $info) {
        return ''
    }

    $text = if ($info.Known) { $info.Meaning } elseif ($info.SystemMessage) { $info.SystemMessage } else { '' }

    if ($info.Name -and $text) {
        return ('{0}: {1}' -f $info.Name, $text)
    }

    return $text
}

<#
.SYNOPSIS
    Reads the reason of a failed sign-in from event 4625.

.DESCRIPTION
    The sub status is the precise reason, such as a wrong password under the
    generic "user name or password" status. When it is zero the status says
    it all.

.PARAMETER Status
    The Status field of the event.

.PARAMETER SubStatus
    The SubStatus field of the event.

.OUTPUTS
    System.String: the code as 0x........, or ''.
#>
function Get-TkLogonFailureCode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] $Status,
        [Parameter()] [AllowNull()] $SubStatus
    )

    foreach ($candidate in @($SubStatus, $Status)) {

        if ($null -eq $candidate) {
            continue
        }

        $parsed = ConvertTo-TkErrorCode -Text ([string] $candidate)

        if ($parsed -and $parsed.Value -ne 0) {
            return $parsed.Hex
        }
    }

    return ''
}

<#
.SYNOPSIS
    Finds what the reference knows about an event ID.

.DESCRIPTION
    The same number means different things from different sources: 1001 is a
    blue screen from BugCheck and a problem report from Windows Error
    Reporting. Every entry of an ID is returned unless a source or a log
    narrows it.

.PARAMETER Id
    The event ID.

.PARAMETER Source
    The source as Event Viewer shows it, or the provider name.

.PARAMETER Log
    The log name.

.OUTPUTS
    PSCustomObject[] from the catalog.
#>
function Get-TkEventReference {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [int] $Id,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Source = '',

        [Parameter()]
        [AllowEmptyString()]
        [string] $Log = ''
    )

    $catalog = Import-TkCatalog -Name 'windows-events'

    if (-not $catalog) {
        return @()
    }

    $rows = @(@($catalog.events) | Where-Object { [int] $_.id -eq $Id })

    if ($Log) {
        $rows = @($rows | Where-Object { [string] $_.log -eq $Log })
    }

    if ($Source) {
        $rows = @($rows | Where-Object {
            [string] $_.provider -eq $Source -or @(([string] $_.source) -split ',\s*') -contains $Source
        })
    }

    return $rows
}

<#
.SYNOPSIS
    Writes the title an error code has in the list and in the search.

.DESCRIPTION
    One function for both, so a search result opens the tab on the row it
    names.

.PARAMETER Hex
    The code as 0x........

.PARAMETER Name
    Its name, or ''.

.PARAMETER Meaning
    Its meaning, used when it has no name.
#>
function Get-TkErrorCodeTitle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Hex,
        [Parameter()] [AllowEmptyString()] [string] $Name = '',
        [Parameter()] [AllowEmptyString()] [string] $Meaning = ''
    )

    $label = if ($Name) { $Name } elseif ($Meaning.Length -gt 70) { $Meaning.Substring(0, 67) + '...' } else { $Meaning }

    return ('{0}  {1}' -f $Hex, $label).TrimEnd()
}

<#
.SYNOPSIS
    Writes the title an event has in the list and in the search.

.PARAMETER Entry
    An event of the catalog.
#>
function Get-TkEventTitle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Entry
    )

    return ('Event {0}  {1} ({2})' -f $Entry.id, $Entry.name, $Entry.source)
}

<#
.SYNOPSIS
    Searches the reference for a code, an event ID or words.

.DESCRIPTION
    A code is decoded even when the catalog does not know it, and always comes
    first. A number up to 65535 is also an event ID. Words search the names,
    the meanings and the actions of both catalogs.

.PARAMETER Query
    What was typed.

.OUTPUTS
    PSCustomObject[] with Kind (Error code or Event), Title, Detail, Key and
    Entry. Key is the hexadecimal code for a code; Entry is the catalog entry
    of an event.
#>
function Find-TkWindowsReference {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Query
    )

    $text = $Query.Trim()

    if (-not $text) {
        return @()
    }

    $codes  = Import-TkCatalog -Name 'windows-errors'
    $events = Import-TkCatalog -Name 'windows-events'
    $rows   = New-Object System.Collections.Generic.List[object]

    $codeRow = {
        param($hex, $name, $meaning)
        [pscustomobject] @{ Kind = 'Error code'; Title = (Get-TkErrorCodeTitle -Hex $hex -Name $name -Meaning $meaning); Detail = $meaning; Key = $hex; Entry = $null }
    }

    $eventRow = {
        param($entry)
        [pscustomobject] @{ Kind = 'Event'; Title = (Get-TkEventTitle -Entry $entry); Detail = [string] $entry.meaning; Key = [string] $entry.id; Entry = $entry }
    }

    # A short number is far more often an event ID than a Win32 error, so its
    # events come first and the code reading of the number follows.
    if ($text -match '^\d{1,5}$') {
        foreach ($entry in @(Get-TkEventReference -Id ([int] $text))) {
            $rows.Add((& $eventRow $entry))
        }
    }

    $code = ConvertTo-TkErrorCode -Text $text

    if ($code) {
        $info = Get-TkErrorCodeInfo -Code $text
        $rows.Add((& $codeRow $info.Hex $info.Name $(if ($info.Known) { $info.Meaning } elseif ($info.SystemMessage) { $info.SystemMessage } else { 'Not in the reference' })))
    }

    # Words, unless what was typed is only a number or a code.
    if ($text -notmatch '^(0[xX])?[0-9A-Fa-f]+$' -and $text -notmatch '^-?\d+$') {

        $words = @($text.ToLowerInvariant() -split '\s+' | Where-Object { $_.Length -ge 2 })

        if ($words.Count -gt 0) {

            foreach ($entry in @($codes.codes)) {

                $haystack = ('{0} {1} {2} {3}' -f $entry.code, $entry.name, $entry.meaning, $entry.action).ToLowerInvariant()

                if (@($words | Where-Object { -not $haystack.Contains($_) }).Count -eq 0) {
                    $rows.Add((& $codeRow ([string] $entry.code) ([string] $entry.name) ([string] $entry.meaning)))
                }
            }

            foreach ($entry in @($events.events)) {

                $haystack = ('event {0} {1} {2} {3} {4} {5} {6}' -f $entry.id, $entry.name, $entry.source, $entry.provider, $entry.log, $entry.meaning, $entry.action).ToLowerInvariant()

                if (@($words | Where-Object { -not $haystack.Contains($_) }).Count -eq 0) {
                    $rows.Add((& $eventRow $entry))
                }
            }
        }
    }

    # One row per title, in the order found.
    $seen   = @{}
    $result = foreach ($row in $rows) {

        if ($seen.ContainsKey($row.Title)) {
            continue
        }

        $seen[$row.Title] = $true
        $row
    }

    return @($result)
}

<#
.SYNOPSIS
    Writes the command that reads an event on this machine.

.PARAMETER Entry
    An event of the catalog.

.OUTPUTS
    System.String
#>
function Get-TkEventQueryCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Entry
    )

    return ("Get-WinEvent -FilterHashtable @{{ LogName = '{0}'; Id = {1} }} -MaxEvents 20 | Format-List TimeCreated, ProviderName, Message" -f $Entry.log, $Entry.id)
}
