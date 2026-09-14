<#
    Toolkit - UI / Windows codes

    The Windows codes tab of the Knowledge base. Type an error code in any
    form, an event ID or words; choose a row; read what it means and what to
    try, and for an event the command that reads it on this machine.
#>

# The rows in the list, by title, so a selection finds what it names.
$script:TkReferenceRows = @{}

<#
.SYNOPSIS
    Wires the Windows codes tab.
#>
function Initialize-TkWindowsReference {
    [CmdletBinding()]
    param()

    $search = Get-TkControl -Name 'ReferenceSearch'
    $list   = Get-TkControl -Name 'ReferenceList'

    if (-not $search -or -not $list) {
        return
    }

    $search.Add_TextChanged({
        Update-TkReferenceList -Query (Get-TkControl -Name 'ReferenceSearch').Text
    })

    $list.Add_SelectionChanged({

        $selected = (Get-TkControl -Name 'ReferenceList').SelectedItem

        if ($null -ne $selected) {
            Show-TkReferenceEntry -Title ([string] $selected)
        }
    })

    Show-TkReferenceWelcome
}

<#
.SYNOPSIS
    Fills the list with what matches the search.

.PARAMETER Query
    What was typed.
#>
function Update-TkReferenceList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Query
    )

    $list = Get-TkControl -Name 'ReferenceList'

    if (-not $list) {
        return
    }

    $list.Items.Clear()
    $script:TkReferenceRows = @{}

    if ([string]::IsNullOrWhiteSpace($Query)) {
        Show-TkReferenceWelcome
        return
    }

    foreach ($row in @(Find-TkWindowsReference -Query $Query | Select-Object -First 200)) {
        $script:TkReferenceRows[$row.Title] = $row
        [void] $list.Items.Add($row.Title)
    }

    if ($list.Items.Count -eq 0) {

        $document = New-TkFlowDocument
        Add-TkParagraph -Document $document -Muted -Text 'Nothing in the reference matches. A code can be typed as 0x80070005, 80070005, -2147024891 or 5; an event as its number.'
        Set-TkDocument -ControlName 'ReferenceContent' -Document $document

        return
    }

    # A whole code or an event ID shows its first row at once.
    if ($Query.Trim() -match '^(0[xX])?[0-9A-Fa-f]{8}$|^-\d{6,}$|^\d{1,5}$') {
        $list.SelectedIndex = 0
    }
}

<#
.SYNOPSIS
    Shows what the tab is for, before anything is typed.
#>
function Show-TkReferenceWelcome {
    [CmdletBinding()]
    param()

    $codes  = Import-TkCatalog -Name 'windows-errors'
    $events = Import-TkCatalog -Name 'windows-events'

    $document = New-TkFlowDocument

    Add-TkHeading   -Document $document -Text 'Windows codes' -Level 1
    Add-TkParagraph -Document $document -Text 'Type an error code, an event ID or words in the box. A code can be written the way any tool prints it:'

    Add-TkBulletList -Document $document -Item @(
        '0x80070005 or 80070005, as Windows Update and setup show them',
        '-2147024891, as the update history and many scripts return them',
        '5, a Win32 error number',
        '41 or 4625, an event ID',
        'words such as proxy, component store or locked out'
    )

    Add-TkParagraph -Document $document -Muted -Text (
        '{0} error codes and {1} events, written from Microsoft''s references. A code that is not among them is still decoded into its parts.' -f @($codes.codes).Count, @($events.events).Count
    )

    Set-TkDocument -ControlName 'ReferenceContent' -Document $document
}

<#
.SYNOPSIS
    Shows the row chosen in the list.

.PARAMETER Title
    The title of the row.
#>
function Show-TkReferenceEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Title
    )

    $row = $script:TkReferenceRows[$Title]

    if (-not $row) {
        return
    }

    if ($row.Kind -eq 'Error code') {
        Show-TkErrorCodeEntry -Info (Get-TkErrorCodeInfo -Code $row.Key)
    }
    else {
        Show-TkEventEntry -Entry $row.Entry
    }
}

<#
.SYNOPSIS
    Shows an error code: its meaning, what to try, and its parts.

.PARAMETER Info
    Output of Get-TkErrorCodeInfo.
#>
function Show-TkErrorCodeEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Info
    )

    $document = New-TkFlowDocument

    Add-TkHeading -Document $document -Text $(if ($Info.Name) { '{0}  {1}' -f $Info.Hex, $Info.Name } else { $Info.Hex }) -Level 1

    if ($Info.Known) {
        Add-TkParagraph -Document $document -Text $Info.Meaning
    }
    else {
        Add-TkParagraph -Document $document -Muted -Text 'This code is not in the reference the toolkit carries, so it gets no name here. What the code itself says is below; search the whole code on Microsoft Learn for the rest.'
    }

    if ($Info.SystemMessage) {
        Add-TkParagraph -Document $document -Text ('Windows message, in the display language: {0}' -f $Info.SystemMessage)
    }

    if ($Info.Action) {
        Add-TkHeading   -Document $document -Text 'What to try' -Level 2
        Add-TkParagraph -Document $document -Text $Info.Action
    }

    $steps = @($Info.Steps | Where-Object { $_ })

    if ($steps.Count -gt 0) {

        $heading = if ($Info.Action) { 'If that is not it: {0}' -f $Info.GroupName.ToLowerInvariant() } else { 'Usual cause: {0}' -f $Info.GroupName.ToLowerInvariant() }

        Add-TkHeading    -Document $document -Text $heading -Level 2
        Add-TkBulletList -Document $document -Item $steps
    }

    Add-TkHeading -Document $document -Text 'The code itself' -Level 2

    $code = [int] ($Info.Value -band 65535)

    $rows = @(
        , @('Kind', [string] $Info.Kind)
        , @('Facility', $(if ($Info.FacilityName) { '{0} ({1})' -f [string] $Info.Facility, $Info.FacilityName } else { [string] $Info.Facility }))
        , @('Code', ('{0} (0x{1:X4})' -f [string] $code, $code))
    )

    if ($null -ne $Info.Win32) {
        $rows += , @('Win32 error', [string] $Info.Win32)
    }

    Add-TkTable -Document $document -Column @('Part', 'Value') -Weight @(1.0, 3.0) -Row $rows

    $catalog = Import-TkCatalog -Name 'windows-errors'

    if ($catalog -and $catalog.references) {
        Add-TkParagraph -Document $document -Muted -Text ('Written from: {0}' -f (@($catalog.references) -join ', '))
    }

    Set-TkDocument -ControlName 'ReferenceContent' -Document $document
}

<#
.SYNOPSIS
    Shows an event: what it means, what to do, and how to read it here.

.PARAMETER Entry
    An event of the catalog.
#>
function Show-TkEventEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Entry
    )

    $document = New-TkFlowDocument

    Add-TkHeading -Document $document -Text ('Event {0}, {1}' -f $Entry.id, $Entry.source) -Level 1

    Add-TkSeverityLine -Document $document -Severity ([string] $Entry.severity) -Heading ([string] $Entry.name) `
        -Detail ('{0} log' -f $Entry.log)

    Add-TkParagraph -Document $document -Text ([string] $Entry.meaning)

    if ($Entry.action) {
        Add-TkHeading   -Document $document -Text 'What to do' -Level 2
        Add-TkParagraph -Document $document -Text ([string] $Entry.action)
    }

    Add-TkHeading -Document $document -Text 'Read it on this machine' -Level 2

    if ($Entry.log -eq 'Security') {
        Add-TkParagraph -Document $document -Muted -Text 'The Security log is only readable from an elevated PowerShell.'
    }

    Add-TkCodeBlock -Document $document -Text (Get-TkEventQueryCommand -Entry $Entry)

    $notes = @(
        $(if ($Entry.provider) { 'Provider: {0}.' -f $Entry.provider })
        $(if ($Entry.reference) { 'Source: {0}' -f $Entry.reference })
    ) | Where-Object { $_ }

    if (@($notes).Count -gt 0) {
        Add-TkParagraph -Document $document -Muted -Text ($notes -join ' ')
    }

    Set-TkDocument -ControlName 'ReferenceContent' -Document $document
}
