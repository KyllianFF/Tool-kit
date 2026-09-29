<#
    Toolkit - Features / Diagnostics: timeline of changes

    "It worked yesterday": the first question of a support call is what
    changed. The answers already exist, spread over logs and reports: a
    program installed, an update, a driver, a service, a start that followed a
    power loss, a threat caught, a firewall rule, a fix run with the toolkit.
    This puts them on one line, newest first.

    Every source is a row of a table, read through Get-WinEvent with a
    FilterHashtable, and its fields are read from the event data, never from
    the message Windows translates: a French and an English log give the same
    timeline. A source that cannot be read (a log turned off, the Security log
    without administrator rights) is said, never passed over. Repeats of the
    same change within the hour, such as an updater rewriting its firewall
    rules, are folded into one line with their count.
#>

<#
.SYNOPSIS
    The categories of the timeline, in the order they are shown.

.OUTPUTS
    PSCustomObject[] with Name and Label.
#>
function Get-TkTimelineCategory {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'Software'; Label = 'Programs' }
        [pscustomobject] @{ Name = 'Updates';  Label = 'Windows updates' }
        [pscustomobject] @{ Name = 'Drivers';  Label = 'Drivers' }
        [pscustomobject] @{ Name = 'Services'; Label = 'Services and tasks' }
        [pscustomobject] @{ Name = 'Startups'; Label = 'Starts and crashes' }
        [pscustomobject] @{ Name = 'Security'; Label = 'Security' }
        [pscustomobject] @{ Name = 'Firewall'; Label = 'Firewall rules' }
        [pscustomobject] @{ Name = 'Toolkit';  Label = 'Done with the toolkit' }
    )
}

<#
.SYNOPSIS
    One line of the timeline, as a source's converter returns it.

.OUTPUTS
    PSCustomObject with Title, Detail and Severity.
#>
function New-TkTimelineLine {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)] [AllowEmptyString()] [AllowNull()] [string] $Title = '',
        [Parameter(Position = 1)] [AllowEmptyString()] [AllowNull()] [string] $Detail = '',
        [Parameter(Position = 2)] [ValidateSet('Info', 'Warning', 'Fail')] [string] $Severity = 'Info'
    )

    return [pscustomobject] @{ Title = ([string] $Title).Trim(); Detail = ([string] $Detail).Trim(); Severity = $Severity }
}

<#
.SYNOPSIS
    The event sources of the timeline, each with what turns an event into a line.

.DESCRIPTION
    Convert receives one event as an object with Id, Time, Field (the named
    fields of its event and user data) and Value (its values in order), and
    returns Title, Detail and Severity, or nothing to leave the event out.
    Report names the Diagnostics report that deals with the line.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkTimelineSource {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $source = {
        param($category, $label, $log, $provider, $id, $elevated, $report, $convert)
        [pscustomobject] @{ Category = $category; Label = $label; Log = $log; Provider = $provider; Id = @($id); Elevated = $elevated; Report = $report; Convert = $convert }
    }

    return @(
        (& $source 'Software' 'Programs installed and removed by Windows Installer' 'Application' 'MsiInstaller' @(1033, 1034) $false 'Software support' {
            param($fact)
            $product = [string] $fact.Value[0]
            $version = [string] $fact.Value[1]
            $status  = [string] $fact.Value[3]
            $failed  = $status -and $status -ne '0'
            $verb    = if ($fact.Id -eq 1034) { 'Removed' } else { 'Installed' }
            New-TkTimelineLine ('{0} {1}' -f $verb, $product) $(if ($failed) { 'Version {0}, Windows Installer status {1}: it did not complete' -f $version, $status } else { 'Version {0}' -f $version }) $(if ($failed) { 'Warning' } else { 'Info' })
        })

        (& $source 'Updates' 'Windows updates installed or failed' 'System' 'Microsoft-Windows-WindowsUpdateClient' @(19, 20) $false 'Update history' {
            param($fact)
            $title = [string] $fact.Field['updateTitle']
            if ($fact.Id -eq 20) { New-TkTimelineLine ('Update failed: {0}' -f $title) ('Error {0}' -f $fact.Field['errorCode']) 'Warning' }
            else { New-TkTimelineLine ('Update installed: {0}' -f $title) '' 'Info' }
        })

        (& $source 'Drivers' 'Drivers installed' 'System' 'Microsoft-Windows-UserPnp' @(20001) $false 'Drivers' {
            param($fact)
            $name = @($fact.Field['DriverDescription'], $fact.Field['DriverName'], $fact.Field['DriverFileName']) | Where-Object { $_ } | Select-Object -First 1
            $status = [string] $fact.Field['InstallStatus']
            New-TkTimelineLine ('Driver installed: {0}' -f $name) ('{0} {1} {2}' -f $fact.Field['DriverProvider'], $fact.Field['DriverVersion'], $fact.Field['DeviceInstanceID']) $(if ($status -and $status -ne '0') { 'Warning' } else { 'Info' })
        })

        (& $source 'Services' 'Services installed' 'System' 'Service Control Manager' @(7045) $false 'Services' {
            param($fact)
            $image = [string] $fact.Field['ImagePath']
            # A service from a folder a user can write to is how persistence is set.
            $suspect = $image -match '(?i)\\(Users|AppData|Temp|ProgramData)\\'
            $account = [string] $fact.Field['AccountName']
            New-TkTimelineLine ('Service installed: {0}' -f $fact.Field['ServiceName']) $(if ($account) { '{0}, runs as {1}' -f $image, $account } else { $image }) $(if ($suspect) { 'Warning' } else { 'Info' })
        })

        (& $source 'Services' 'Scheduled tasks registered' 'Microsoft-Windows-TaskScheduler/Operational' '' @(106) $false '' {
            param($fact)
            New-TkTimelineLine ('Scheduled task registered: {0}' -f $fact.Field['TaskName']) ('By {0}' -f $fact.Field['UserContext']) 'Info'
        })

        (& $source 'Startups' 'Starts of Windows' 'System' 'Microsoft-Windows-Kernel-General' @(12) $false 'Restarts and shutdowns' {
            param($fact)
            New-TkTimelineLine 'Windows started' '' 'Info'
        })

        (& $source 'Startups' 'Stops without a shutdown' 'System' 'Microsoft-Windows-Kernel-Power' @(41) $false 'Restarts and shutdowns' {
            param($fact)
            $code = [int64] ('0' + [string] $fact.Field['BugcheckCode'])
            if ($code -ne 0) { New-TkTimelineLine 'Restarted after a blue screen' ('Stop code 0x{0:X}' -f $code) 'Fail' }
            else { New-TkTimelineLine 'Stopped without shutting down' 'Power lost, forced off or hung' 'Warning' }
        })

        (& $source 'Startups' 'Blue screens' 'System' 'Microsoft-Windows-WER-SystemErrorReporting' @(1001) $false 'Crashes' {
            param($fact)
            New-TkTimelineLine 'Blue screen' ('Stop code {0}' -f $fact.Value[0]) 'Fail'
        })

        (& $source 'Startups' 'Application crashes' 'Application' 'Application Error' @(1000) $false 'Crashes' {
            param($fact)
            New-TkTimelineLine ('Application crashed: {0}' -f $fact.Field['AppName']) ('In {0}, exception {1}' -f $fact.Field['ModuleName'], $fact.Field['ExceptionCode']) 'Warning'
        })

        (& $source 'Security' 'Threats Microsoft Defender caught' 'Microsoft-Windows-Windows Defender/Operational' '' @(1116, 1117) $false '' {
            param($fact)
            $name = [string] $fact.Field['Threat Name']
            if ($fact.Id -eq 1116) { New-TkTimelineLine ('Threat detected: {0}' -f $name) ([string] $fact.Field['Path']) 'Fail' }
            else { New-TkTimelineLine ('Threat acted on: {0}' -f $name) ([string] $fact.Field['Action Name']) 'Warning' }
        })

        (& $source 'Security' 'Local groups changed' 'Security' '' @(4732, 4733) $true 'Local accounts' {
            param($fact)
            $member = @($fact.Field['MemberName'], $fact.Field['MemberSid']) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 1
            $verb   = if ($fact.Id -eq 4732) { 'Added to' } else { 'Removed from' }
            New-TkTimelineLine ('{0} {1}: {2}' -f $verb, $fact.Field['TargetUserName'], $member) ('By {0}' -f $fact.Field['SubjectUserName']) 'Warning'
        })

        # The identifiers changed with Windows 11: 2004 to 2006 before, 2097, 2099 and 2052 after.
        (& $source 'Firewall' 'Firewall rules added, changed or deleted' 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' '' @(2004, 2005, 2006, 2097, 2099, 2052) $false '' {
            param($fact)
            $verb = switch ($fact.Id) { { $_ -in 2004, 2097 } { 'added' } { $_ -in 2005, 2099 } { 'changed' } default { 'deleted' } }
            # A deleted rule is sometimes logged with its identifier only.
            $rule = @($fact.Field['RuleName'], $fact.Field['RuleId']) | Where-Object { $_ } | Select-Object -First 1
            New-TkTimelineLine ('Firewall rule {0}: {1}' -f $verb, $rule) ([string] $(if ($fact.Field['ApplicationPath']) { $fact.Field['ApplicationPath'] } else { $fact.Field['ModifyingApplication'] })) 'Info'
        })
    )
}

<#
.SYNOPSIS
    Reads one event into the shape a timeline converter takes.

.DESCRIPTION
    The values in order come from the record; the named fields from its event
    data, and from its user data, where providers such as UserPnp put them.

.OUTPUTS
    PSCustomObject with Id, Time, Field and Value.
#>
function ConvertFrom-TkTimelineEvent {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Record
    )

    $field = @{}

    try {
        $xml = [xml] $Record.ToXml()

        foreach ($data in @($xml.Event.EventData.Data)) {
            if ($data -is [System.Xml.XmlElement] -and $data.Name) {
                $field[[string] $data.Name] = [string] $data.InnerText
            }
        }

        if ($xml.Event.UserData) {
            foreach ($holder in @($xml.Event.UserData.ChildNodes)) {
                foreach ($child in @($holder.ChildNodes)) {
                    if ($child -is [System.Xml.XmlElement]) { $field[[string] $child.LocalName] = [string] $child.InnerText }
                }
            }
        }
    }
    catch {
        $null = $_
    }

    # Added one by one: a pipeline would unroll a binary value into its
    # bytes and move every value after it.
    $values = New-Object System.Collections.Generic.List[object]
    foreach ($property in @($Record.Properties)) {
        $values.Add($property.Value)
    }

    return [pscustomobject] @{
        Id    = [int] $Record.Id
        Time  = $Record.TimeCreated
        Field = $field
        Value = $values.ToArray()
    }
}

<#
.SYNOPSIS
    Folds repeats of the same change within the hour into one line.

.DESCRIPTION
    Pure. Lines of the same category and title less than an hour apart are
    one line, at the time of the first, with how many there were.

.OUTPUTS
    PSCustomObject[], newest first.
#>
function Merge-TkTimelineRow {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Row,

        [Parameter()]
        [int] $WindowMinutes = 60
    )

    $kept = New-Object System.Collections.Generic.List[object]
    $last = @{}

    foreach ($item in @($Row | Where-Object { $_ } | Sort-Object -Property Time)) {

        $key = '{0}|{1}' -f $item.Category, $item.Title

        if ($last.ContainsKey($key) -and ($item.Time - $last[$key].LastTime).TotalMinutes -lt $WindowMinutes) {
            $last[$key].Count++
            $last[$key].LastTime = $item.Time
            continue
        }

        $copy = [pscustomobject] @{
            Time = $item.Time; Category = $item.Category; Title = $item.Title; Detail = $item.Detail; Severity = $item.Severity
            Count = 1; LastTime = $item.Time; DayOnly = [bool] $item.DayOnly; Source = $item.Source; Report = $item.Report
        }

        $last[$key] = $copy
        $kept.Add($copy)
    }

    return @($kept.ToArray() | Sort-Object -Property Time -Descending)
}

<#
.SYNOPSIS
    What changed on this machine over a period, newest first.

.PARAMETER Days
    How far back, from 1 to 30 days.

.PARAMETER Category
    The categories to read; all of them when not given.

.OUTPUTS
    PSCustomObject with Since, Until, Days, Entries and Sources, each source
    with its State: Read, Empty, Off, NeedsElevation, Missing or Failed.
#>
function Get-TkTimeline {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateRange(1, 30)]
        [int] $Days = 14,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Category = @()
    )

    $until    = Get-Date
    $since    = $until.AddDays(-$Days)
    $wanted   = if (@($Category | Where-Object { $_ }).Count -gt 0) { @($Category) } else { @(Get-TkTimelineCategory | ForEach-Object { $_.Name }) }
    $elevated = [bool] (Test-TkIsElevated)
    $rows     = New-Object System.Collections.Generic.List[object]
    $sources  = New-Object System.Collections.Generic.List[object]
    $status   = { param($item, $state, $count, $note) $sources.Add([pscustomobject] @{ Category = $item.Category; Label = $item.Label; State = $state; Count = $count; Note = $note }) }

    foreach ($item in @(Get-TkTimelineSource | Where-Object { $wanted -contains $_.Category })) {

        if ($item.Elevated -and -not $elevated) {
            & $status $item 'NeedsElevation' 0 'Needs administrator rights.'
            continue
        }

        try {
            $log = Get-WinEvent -ListLog $item.Log -ErrorAction Stop
        }
        catch {
            & $status $item 'Missing' 0 'This log is not on this machine.'
            continue
        }

        if (-not $log.IsEnabled -and $log.RecordCount -eq 0) {
            & $status $item 'Off' 0 'This log is turned off, so it records nothing.'
            continue
        }

        $filter = @{ LogName = $item.Log; Id = $item.Id; StartTime = $since }
        if ($item.Provider) { $filter['ProviderName'] = $item.Provider }

        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 2000 -ErrorAction Stop)
        }
        catch {
            # Told apart by the error identifier, not the message, which Windows translates.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { & $status $item 'Empty' 0 '' }
            elseif ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.InnerException -is [System.UnauthorizedAccessException]) { & $status $item 'NeedsElevation' 0 'Needs administrator rights.' }
            else { & $status $item 'Failed' 0 $_.Exception.Message }
            continue
        }

        $count = 0

        foreach ($record in $events) {
            try {
                $read = ConvertFrom-TkTimelineEvent -Record $record
                $made = & $item.Convert $read

                if ($made -and $made.Title) {
                    $rows.Add([pscustomobject] @{
                        Time = $read.Time; Category = $item.Category; Title = $made.Title; Detail = $made.Detail; Severity = $made.Severity
                        DayOnly = $false; Source = ('{0} {1}' -f $item.Log, $read.Id); Report = $item.Report
                    })
                    $count++
                }
            }
            catch {
                $null = $_
            }
        }

        & $status $item 'Read' $count $(if ($events.Count -ge 2000) { 'The 2000 most recent only.' } else { '' })
    }

    # Programs that do not go through Windows Installer: the uninstall entry
    # records the day, not the time, of the install or the last update.
    if ($wanted -contains 'Software') {

        $installed = @($rows | Where-Object { $_.Category -eq 'Software' } | ForEach-Object { ($_.Title -replace '^(Installed|Removed) ', '').ToLowerInvariant() })
        $count     = 0

        foreach ($entry in @(Get-TkUninstallEntry | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and $_.InstallDate -match '^\d{8}$' })) {

            $day = [datetime]::MinValue
            if (-not [datetime]::TryParseExact([string] $entry.InstallDate, 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref] $day)) { continue }
            if ($day -lt $since.Date -or $installed -contains ([string] $entry.DisplayName).ToLowerInvariant()) { continue }

            $rows.Add([pscustomobject] @{
                Time = $day; Category = 'Software'; Title = ('Installed or updated {0}' -f $entry.DisplayName); Detail = ('Version {0}; the uninstall entry gives the day only' -f $entry.DisplayVersion)
                Severity = 'Info'; DayOnly = $true; Source = 'Uninstall entries'; Report = 'Software support'
            })
            $count++
        }

        $sources.Add([pscustomobject] @{ Category = 'Software'; Label = 'Programs by their uninstall entry'; State = $(if ($count) { 'Read' } else { 'Empty' }); Count = $count; Note = '' })
    }

    # What was run with the toolkit itself.
    if ($wanted -contains 'Toolkit') {

        $count = 0

        foreach ($entry in @(Get-TkJournalEntry -Since $since)) {
            $rows.Add([pscustomobject] @{
                Time = [datetime] $entry.Time; Category = 'Toolkit'; Title = [string] $entry.Name; Detail = ('{0}, {1}' -f $entry.Kind, $entry.Outcome)
                Severity = $(if ($entry.Outcome -eq 'Done') { 'Info' } else { 'Warning' }); DayOnly = $false; Source = 'Intervention journal'; Report = ''
            })
            $count++
        }

        $sources.Add([pscustomobject] @{ Category = 'Toolkit'; Label = 'The intervention journal'; State = $(if ($count) { 'Read' } else { 'Empty' }); Count = $count; Note = '' })
    }

    return [pscustomobject] @{
        Since   = $since
        Until   = $until
        Days    = $Days
        Entries = @(Merge-TkTimelineRow -Row @($rows.ToArray()))
        Sources = @($sources.ToArray())
    }
}
