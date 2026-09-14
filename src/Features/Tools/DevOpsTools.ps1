<#
    Toolkit - Features / Linux and DevOps tools

    A crontab expression read back in words with its next runs, and a docker
    run command turned into the Compose service it describes. Both are the
    kind of thing that is written once from memory, wrongly, and then trusted.

    Pure functions, called by the Tools page and asserted by the tests.
#>

# ---------------------------------------------------------------------------
# Crontab
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Describes the five fields of a cron expression.

.OUTPUTS
    PSCustomObject[] with Name, Minimum, Maximum and Names.
#>
function Get-TkCronField {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Name = 'minute';           Minimum = 0; Maximum = 59; Names = @() }
        [pscustomobject] @{ Name = 'hour';             Minimum = 0; Maximum = 23; Names = @() }
        [pscustomobject] @{ Name = 'day of the month'; Minimum = 1; Maximum = 31; Names = @() }
        [pscustomobject] @{ Name = 'month';            Minimum = 1; Maximum = 12; Names = @('JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC') }
        [pscustomobject] @{ Name = 'day of the week';  Minimum = 0; Maximum = 7;  Names = @('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT') }
    )
}

<#
.SYNOPSIS
    Lists common schedules for the preset list.

.OUTPUTS
    PSCustomObject[] with Label and Expression; Custom has none.
#>
function Get-TkCronPreset {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Custom';                              Expression = '' }
        [pscustomobject] @{ Label = 'Every minute';                        Expression = '* * * * *' }
        [pscustomobject] @{ Label = 'Every 5 minutes';                     Expression = '*/5 * * * *' }
        [pscustomobject] @{ Label = 'Every 15 minutes';                    Expression = '*/15 * * * *' }
        [pscustomobject] @{ Label = 'Every hour';                          Expression = '0 * * * *' }
        [pscustomobject] @{ Label = 'Every day at 02:00';                  Expression = '0 2 * * *' }
        [pscustomobject] @{ Label = 'Every weekday at 08:30';              Expression = '30 8 * * 1-5' }
        [pscustomobject] @{ Label = 'Every Sunday at 03:00';               Expression = '0 3 * * 0' }
        [pscustomobject] @{ Label = 'On the first of every month at 00:00'; Expression = '0 0 1 * *' }
        [pscustomobject] @{ Label = 'When the machine starts';             Expression = '@reboot' }
    )
}

<#
.SYNOPSIS
    Reads one field of a cron expression.

.PARAMETER Text
    The field as written: *, 5, 1-5, */15, 1,15, MON-FRI.

.PARAMETER Field
    The description of the field, from Get-TkCronField.

.OUTPUTS
    PSCustomObject with Text, Values, Any and Error.
#>
function ConvertFrom-TkCronField {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Text,
        [Parameter(Mandatory)] [pscustomobject] $Field
    )

    $values = New-Object 'System.Collections.Generic.SortedSet[int]'
    $failed = { param($message) [pscustomobject] @{ Text = $Text; Values = [int[]] @(); Any = $false; Error = ('The {0} field: {1}' -f $Field.Name, $message) } }

    foreach ($part in $Text.Split(',')) {

        if (-not $part) {
            return (& $failed 'a list has an empty item.')
        }

        $step  = 1
        $range = $part

        if ($part -match '^(?<range>[^/]+)/(?<step>\d+)$') {
            $range = $Matches['range']
            $step  = [int] $Matches['step']

            if ($step -lt 1) {
                return (& $failed 'a step of 0 never moves.')
            }
        }
        elseif ($part.Contains('/')) {
            return (& $failed ('"{0}" is not a step: write it as */n or a-b/n.' -f $part))
        }

        $resolve = {
            param($token)

            if ($token -match '^\d+$') { return [int] $token }

            $position = [array]::IndexOf([string[]] $Field.Names, $token.ToUpperInvariant())

            if ($position -ge 0) {
                # Month names count from 1, day names from 0, as the fields do.
                return ($position + $Field.Minimum)
            }

            return $null
        }

        if ($range -eq '*') {
            $from = $Field.Minimum
            $to   = $Field.Maximum
        }
        elseif ($range -match '^(?<from>[^-]+)-(?<to>[^-]+)$') {
            $fromText = $Matches['from']
            $toText   = $Matches['to']
            $from     = & $resolve $fromText
            $to       = & $resolve $toText
        }
        else {
            $from = & $resolve $range
            $to   = if ($part.Contains('/')) { $Field.Maximum } else { $from }
        }

        if ($null -eq $from -or $null -eq $to) {
            return (& $failed ('"{0}" is not a number{1}.' -f $range, $(if ($Field.Names.Count -gt 0) { ' or a name such as ' + $Field.Names[0] } else { '' })))
        }

        if ($from -lt $Field.Minimum -or $to -gt $Field.Maximum) {
            return (& $failed ('{0} is outside {1} to {2}.' -f $range, $Field.Minimum, $Field.Maximum))
        }

        if ($from -gt $to) {
            return (& $failed ('the range {0} runs backwards.' -f $range))
        }

        for ($value = $from; $value -le $to; $value += $step) {
            [void] $values.Add($value)
        }
    }

    # Day 7 of the week is Sunday, as 0 is.
    if ($Field.Name -eq 'day of the week' -and $values.Contains(7)) {
        [void] $values.Remove(7)
        [void] $values.Add(0)
    }

    return [pscustomobject] @{
        Text   = $Text
        Values = [int[]] @($values)
        Any    = $Text.StartsWith('*')
        Error  = ''
    }
}

<#
.SYNOPSIS
    Writes a list of values in words, runs of three or more as ranges.

.PARAMETER Values
    Sorted values.

.PARAMETER Names
    Names for the values, if they have some.

.PARAMETER Offset
    The value of the first name.
#>
function Format-TkCronValueList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [int[]] $Values,
        [Parameter()] [string[]] $Names = @(),
        [Parameter()] [int] $Offset = 0
    )

    $label = {
        param($value)
        if ($Names.Count -gt 0) { $Names[$value - $Offset] } else { [string] $value }
    }

    $parts = New-Object System.Collections.Generic.List[string]
    $index = 0

    while ($index -lt $Values.Count) {

        $end = $index

        while ($end + 1 -lt $Values.Count -and $Values[$end + 1] -eq $Values[$end] + 1) {
            $end++
        }

        if ($end - $index -ge 2) {
            $parts.Add(('{0} to {1}' -f (& $label $Values[$index]), (& $label $Values[$end])))
            $index = $end + 1
        }
        else {
            $parts.Add((& $label $Values[$index]))
            $index++
        }
    }

    if ($parts.Count -le 1) {
        return ($parts -join '')
    }

    return ('{0} and {1}' -f ($parts.GetRange(0, $parts.Count - 1) -join ', '), $parts[$parts.Count - 1])
}

<#
.SYNOPSIS
    Says in words when a cron schedule runs.

.PARAMETER Schedule
    What ConvertFrom-TkCronExpression returns.

.OUTPUTS
    System.String
#>
function Get-TkCronDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Schedule
    )

    $months = @('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')
    $days   = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')

    $every = {
        param($field)
        if ($field.Text -match '^\*/(\d+)$') { [int] $Matches[1] } else { 0 }
    }

    $join = {
        param($items)
        $items = @($items)
        if ($items.Count -le 1) { $items -join '' } else { '{0} and {1}' -f ($items[0..($items.Count - 2)] -join ', '), $items[-1] }
    }

    $minute = $Schedule.Minute
    $hour   = $Schedule.Hour

    $time = if ($minute.Values.Count -eq 1 -and $hour.Text -ne '*' -and -not (& $every $hour) -and $hour.Values.Count -le 6) {
                'At ' + (& $join @($hour.Values | ForEach-Object { '{0:00}:{1:00}' -f $_, $minute.Values[0] }))
            }
            elseif ($minute.Text -eq '*' -and $hour.Text -eq '*') {
                'Every minute'
            }
            elseif ((& $every $minute) -and $hour.Text -eq '*') {
                'Every {0} minutes' -f (& $every $minute)
            }
            elseif ($minute.Values.Count -eq 1 -and $hour.Text -eq '*') {
                'At minute {0} past every hour' -f $minute.Values[0]
            }
            elseif ($minute.Values.Count -eq 1 -and (& $every $hour)) {
                'At minute {0} past every {1} hours' -f $minute.Values[0], (& $every $hour)
            }
            else {
                $minutePart = if ($minute.Text -eq '*') { 'Every minute' }
                              elseif (& $every $minute) { 'Every {0} minutes' -f (& $every $minute) }
                              else { 'At minute {0}' -f (Format-TkCronValueList -Values $minute.Values) }

                $hourPart = if ($hour.Text -eq '*') { '' }
                            elseif (& $every $hour) { ' past every {0} hours' -f (& $every $hour) }
                            else { ' past hour {0}' -f (Format-TkCronValueList -Values $hour.Values) }

                $minutePart + $hourPart
            }

    $dom   = $Schedule.DayOfMonth
    $dow   = $Schedule.DayOfWeek
    $month = $Schedule.Month

    $domText = if (& $every $dom) { 'every {0} days' -f (& $every $dom) }
               elseif (-not $dom.Any) { 'on day {0} of the month' -f (Format-TkCronValueList -Values $dom.Values) }
               else { '' }

    $dowText = if (-not $dow.Any) { 'on {0}' -f (Format-TkCronValueList -Values $dow.Values -Names $days) } else { '' }

    # Both days restricted: cron runs when either matches.
    $dayText = if (-not $dom.Any -and -not $dow.Any) { '{0} or {1}' -f $domText, $dowText }
               else { (@($domText, $dowText) | Where-Object { $_ }) -join ' ' }

    $monthText = if (& $every $month) { 'every {0} months' -f (& $every $month) }
                 elseif (-not $month.Any) { 'in {0}' -f (Format-TkCronValueList -Values $month.Values -Names $months -Offset 1) }
                 else { '' }

    $sentence = $time

    if ($dayText)   { $sentence += ' ' + $dayText }
    if ($monthText) { $sentence += ', ' + $monthText }

    return $sentence
}

<#
.SYNOPSIS
    Reads a cron expression.

.DESCRIPTION
    The five fields of a crontab, with names of months and days, and the
    @hourly, @daily, @weekly, @monthly, @yearly and @reboot shortcuts.

.PARAMETER Expression
    The expression, without the command.

.OUTPUTS
    PSCustomObject with Valid, Expression, Macro, Reboot, the five fields,
    Description and Error.
#>
function ConvertFrom-TkCronExpression {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Expression
    )

    $clean = ($Expression.Trim() -replace '\s+', ' ')

    if (-not $clean) {
        return [pscustomobject] @{ Valid = $false; Error = 'Type a cron expression, such as */15 * * * *.' }
    }

    $macros = @{
        '@yearly' = '0 0 1 1 *'; '@annually' = '0 0 1 1 *'; '@monthly' = '0 0 1 * *'
        '@weekly' = '0 0 * * 0'; '@daily' = '0 0 * * *'; '@midnight' = '0 0 * * *'; '@hourly' = '0 * * * *'
    }

    if ($clean -eq '@reboot') {
        return [pscustomobject] @{ Valid = $true; Expression = $clean; Macro = $clean; Reboot = $true; Description = 'Once, when the cron daemon starts with the machine'; Error = '' }
    }

    $macro = ''

    if ($macros.ContainsKey($clean)) {
        $macro = $clean
        $clean = $macros[$clean]
    }

    $parts = $clean.Split(' ')

    if ($parts.Count -ne 5) {
        return [pscustomobject] @{
            Valid = $false
            Error = ('A cron expression has five fields, minute, hour, day of the month, month and day of the week; this one has {0}.{1}' -f $parts.Count,
                     $(if ($parts.Count -eq 6) { ' Six fields is the Quartz or Spring form with seconds first, which crontab does not read.' } else { '' }))
        }
    }

    $fields = @(Get-TkCronField)
    $read   = @()

    for ($index = 0; $index -lt 5; $index++) {

        $field = ConvertFrom-TkCronField -Text $parts[$index] -Field $fields[$index]

        if ($field.Error) {
            return [pscustomobject] @{ Valid = $false; Error = $field.Error }
        }

        $read += $field
    }

    $schedule = [pscustomobject] @{
        Valid       = $true
        Expression  = $clean
        Macro       = $macro
        Reboot      = $false
        Minute      = $read[0]
        Hour        = $read[1]
        DayOfMonth  = $read[2]
        Month       = $read[3]
        DayOfWeek   = $read[4]
        Description = ''
        Error       = ''
    }

    $schedule.Description = Get-TkCronDescription -Schedule $schedule

    return $schedule
}

<#
.SYNOPSIS
    Lists the next times a cron schedule runs.

.PARAMETER Schedule
    What ConvertFrom-TkCronExpression returns.

.PARAMETER From
    Where to start, in the time of the machine that runs cron.

.PARAMETER Count
    How many runs.

.OUTPUTS
    System.DateTime[]
#>
function Get-TkCronNextRun {
    [CmdletBinding()]
    [OutputType([datetime[]])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Schedule,
        [Parameter()] [datetime] $From = (Get-Date),
        [Parameter()] [ValidateRange(1, 100)] [int] $Count = 5
    )

    if (-not $Schedule.Valid -or $Schedule.Reboot) {
        return @()
    }

    $runs  = New-Object System.Collections.Generic.List[datetime]
    $time  = [datetime]::new($From.Year, $From.Month, $From.Day, $From.Hour, $From.Minute, 0).AddMinutes(1)

    # A 29 February on a given weekday can be decades away; nine years covers
    # every day of the calendar.
    $limit = $time.AddYears(9)

    # Vixie cron: when both day fields are restricted, either one matching is
    # enough; when one of them starts with *, both have to match.
    $either = -not $Schedule.DayOfMonth.Any -and -not $Schedule.DayOfWeek.Any

    while ($runs.Count -lt $Count -and $time -lt $limit) {

        if ($Schedule.Month.Values -notcontains $time.Month) {
            $time = [datetime]::new($time.Year, $time.Month, 1).AddMonths(1)
            continue
        }

        $dayOfMonth = $Schedule.DayOfMonth.Values -contains $time.Day
        $dayOfWeek  = $Schedule.DayOfWeek.Values -contains [int] $time.DayOfWeek
        $day        = if ($either) { $dayOfMonth -or $dayOfWeek } else { $dayOfMonth -and $dayOfWeek }

        if (-not $day) {
            $time = $time.Date.AddDays(1)
            continue
        }

        if ($Schedule.Hour.Values -notcontains $time.Hour) {
            $time = $time.Date.AddHours($time.Hour + 1)
            continue
        }

        if ($Schedule.Minute.Values -notcontains $time.Minute) {
            $time = $time.AddMinutes(1)
            continue
        }

        $runs.Add($time)
        $time = $time.AddMinutes(1)
    }

    return $runs.ToArray()
}

# ---------------------------------------------------------------------------
# docker run to Compose
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Splits a command line into words, the way a POSIX shell does.

.DESCRIPTION
    Single quotes keep everything, double quotes let a backslash escape a
    quote, a backslash outside quotes escapes the next character, and a line
    ending in a backslash, a backtick or a caret continues on the next one.

.PARAMETER Text
    The command.

.OUTPUTS
    System.String[]
#>
function Split-TkShellWord {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $joined  = $Text -replace '[\\`^]\r?\n', ' '
    $words   = New-Object System.Collections.Generic.List[string]
    $current = New-Object System.Text.StringBuilder
    $quote   = [char] 0
    $started = $false

    for ($index = 0; $index -lt $joined.Length; $index++) {

        $character = $joined[$index]

        if ($quote -ne [char] 0) {

            if ($character -eq $quote) {
                $quote = [char] 0
            }
            elseif ($quote -eq [char] '"' -and $character -eq [char] '\' -and $index + 1 -lt $joined.Length -and '"\$`'.Contains([string] $joined[$index + 1])) {
                $index++
                [void] $current.Append($joined[$index])
            }
            else {
                [void] $current.Append($character)
            }
        }
        elseif ($character -eq [char] '"' -or $character -eq [char] "'") {
            $quote   = $character
            $started = $true
        }
        elseif ($character -eq [char] '\' -and $index + 1 -lt $joined.Length) {
            $index++
            [void] $current.Append($joined[$index])
            $started = $true
        }
        elseif ([char]::IsWhiteSpace($character)) {
            if ($started) {
                $words.Add($current.ToString())
                [void] $current.Clear()
                $started = $false
            }
        }
        else {
            [void] $current.Append($character)
            $started = $true
        }
    }

    if ($quote -ne [char] 0) {
        throw ('A {0} quote is never closed.' -f $(if ($quote -eq [char] '"') { 'double' } else { 'single' }))
    }

    if ($started) {
        $words.Add($current.ToString())
    }

    return $words.ToArray()
}

<#
.SYNOPSIS
    Lists the options of docker run, and whether each takes a value.

.DESCRIPTION
    Knowing which options take a value is what tells an option's value from
    the image name that follows the options.

.OUTPUTS
    PSCustomObject[] with Long, Short and TakesValue.
#>
function Get-TkDockerRunOption {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $valued = @(
        'add-host', 'annotation', 'attach|a', 'blkio-weight', 'blkio-weight-device', 'cap-add', 'cap-drop', 'cgroup-parent', 'cgroupns', 'cidfile',
        'cpu-period', 'cpu-quota', 'cpu-rt-period', 'cpu-rt-runtime', 'cpu-shares|c', 'cpus', 'cpuset-cpus', 'cpuset-mems', 'detach-keys',
        'device', 'device-cgroup-rule', 'device-read-bps', 'device-read-iops', 'device-write-bps', 'device-write-iops', 'dns', 'dns-option',
        'dns-search', 'domainname', 'entrypoint', 'env|e', 'env-file', 'expose', 'gpus', 'group-add', 'health-cmd', 'health-interval',
        'health-retries', 'health-start-interval', 'health-start-period', 'health-timeout', 'hostname|h', 'ip', 'ip6', 'ipc', 'isolation',
        'kernel-memory', 'label|l', 'label-file', 'link', 'link-local-ip', 'log-driver', 'log-opt', 'mac-address', 'memory|m',
        'memory-reservation', 'memory-swap', 'memory-swappiness', 'mount', 'name', 'network', 'net', 'network-alias', 'net-alias',
        'oom-score-adj', 'pid', 'pids-limit', 'platform', 'publish|p', 'pull', 'restart', 'runtime', 'security-opt', 'shm-size',
        'stop-signal', 'stop-timeout', 'storage-opt', 'sysctl', 'tmpfs', 'ulimit', 'user|u', 'userns', 'uts', 'volume|v', 'volume-driver',
        'volumes-from', 'workdir|w'
    )

    $flags = @(
        'detach|d', 'disable-content-trust', 'init', 'interactive|i', 'no-healthcheck', 'oom-kill-disable', 'privileged', 'publish-all|P',
        'quiet|q', 'read-only', 'rm', 'sig-proxy', 'tty|t', 'use-api-socket'
    )

    $make = {
        param($spec, $takesValue)
        $parts = $spec -split '\|'
        [pscustomobject] @{ Long = $parts[0]; Short = $(if ($parts.Count -gt 1) { $parts[1] } else { '' }); TakesValue = $takesValue }
    }

    return @(@($valued | ForEach-Object { & $make $_ $true }) + @($flags | ForEach-Object { & $make $_ $false }))
}

<#
.SYNOPSIS
    Writes a value as a YAML scalar, quoted only when it has to be.

.PARAMETER Value
    A string, a number or a boolean.

.PARAMETER Quote
    Quotes it anyway, as Compose advises for ports.
#>
function ConvertTo-TkYamlScalar {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] $Value,
        [Parameter()] [switch] $Quote
    )

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [int] -or $Value -is [long]) { return [string] $Value }

    $text = [string] $Value

    # A plain scalar is fine unless YAML would read it as something else: a
    # number, a boolean, a mapping, a comment, or a sexagesimal like 22:22.
    $plain = -not $Quote -and $text -ne '' -and
             $text -notmatch '^\s|\s$' -and
             $text -notmatch '^[-?:,\[\]{}#&*!|>''"%@`]' -and
             $text -notmatch ':\s|:$|\s#' -and
             $text -notmatch '^(?i)(true|false|yes|no|on|off|y|n|null|~)$' -and
             $text -notmatch '^[-+]?(\d[\d_]*(\.\d*)?|\.\d+)([eE][-+]?\d+)?$' -and
             $text -notmatch '^\d+(:[0-5]?\d)+$' -and
             $text -notmatch '[\r\n\t]'

    if ($plain) {
        return $text
    }

    return ('"{0}"' -f (((($text -replace '\\', '\\') -replace '"', '\"') -replace "`r", '\r' -replace "`n", '\n') -replace "`t", '\t'))
}

<#
.SYNOPSIS
    Turns a docker run command into a Compose file.

.DESCRIPTION
    Each option becomes its Compose key: -p ports, -v volumes, -e environment,
    --restart, --network, the health check, the limits. Named volumes and
    user-defined networks are declared at the top level, the networks as
    external since docker run needed them to exist already. The options that
    have no Compose place are returned as notes, never dropped silently.

.PARAMETER Command
    The docker run command, on one line or continued with \ or a backtick.

.OUTPUTS
    PSCustomObject with Yaml, ServiceName, Image and Notes.
#>
function ConvertFrom-TkDockerRun {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Command
    )

    $words = @(Split-TkShellWord -Text $Command)
    $index = 0

    if ($index -lt $words.Count -and $words[$index] -eq 'sudo') { $index++ }

    if ($index -ge $words.Count -or $words[$index] -notmatch '^(?i)(docker|podman)(\.exe)?$') {
        throw 'Paste a command that starts with docker run.'
    }

    $index++

    if ($index -lt $words.Count -and $words[$index] -eq 'container') { $index++ }

    if ($index -ge $words.Count -or $words[$index] -ne 'run') {
        throw 'Only docker run is converted: the other docker commands do not describe a service.'
    }

    $index++

    $long  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $short = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)

    foreach ($option in (Get-TkDockerRunOption)) {
        $long[$option.Long] = $option
        if ($option.Short) { $short[$option.Short] = $option }
    }

    $service  = [ordered] @{}
    $notes    = New-Object System.Collections.Generic.List[string]
    $volumes  = New-Object System.Collections.Generic.List[string]
    $networks = New-Object System.Collections.Generic.List[string]

    $list = {
        param($key, $value)
        if (-not $service.Contains($key)) { $service[$key] = New-Object System.Collections.Generic.List[object] }
        $service[$key].Add($value)
    }

    $map = {
        param($key, $entry, $value)
        if (-not $service.Contains($key)) { $service[$key] = [ordered] @{} }
        $service[$key][$entry] = $value
    }

    $apply = {
        param($option, $value)

        switch ($option) {
            'name'                  { $service['container_name'] = $value }
            'publish'               { & $list 'ports' $value }
            'publish-all'           { $notes.Add('-P publishes every exposed port on a random host port; Compose needs each port listed under ports.') }
            'expose'                { & $list 'expose' $value }
            'volume' {
                & $list 'volumes' $value
                $source = if ($value -match '^(?<source>[A-Za-z]:[\\/][^:]*):') { $Matches['source'] } else { ($value -split ':')[0] }
                if ($value.Contains(':') -and $source -notmatch '[\\/]|^[.~$]' -and -not $volumes.Contains($source)) { $volumes.Add($source) }
            }
            'mount' {
                $fields = @{}
                foreach ($pair in ($value -split ',')) {
                    $pieces = $pair -split '=', 2
                    $fields[$pieces[0].Trim().ToLowerInvariant()] = $(if ($pieces.Count -gt 1) { $pieces[1] } else { 'true' })
                }
                $type     = if ($fields['type']) { $fields['type'] } else { 'volume' }
                $source   = @($fields['source'], $fields['src']) | Where-Object { $_ } | Select-Object -First 1
                $target   = @($fields['target'], $fields['destination'], $fields['dst']) | Where-Object { $_ } | Select-Object -First 1
                $readOnly = @($fields['readonly'], $fields['ro']) | Where-Object { $_ -and $_ -ne 'false' } | Select-Object -First 1
                if ($type -eq 'tmpfs' -and $target) { & $list 'tmpfs' $target }
                elseif ($source -and $target) {
                    & $list 'volumes' ('{0}:{1}{2}' -f $source, $target, $(if ($readOnly) { ':ro' } else { '' }))
                    if ($type -eq 'volume' -and -not $volumes.Contains($source)) { $volumes.Add($source) }
                }
                elseif ($target) { & $list 'volumes' $target }
                else { $notes.Add(('--mount {0} names no target and was left out.' -f $value)) }
            }
            'tmpfs'                 { & $list 'tmpfs' $value }
            'env'                   { & $list 'environment' $value }
            'env-file'              { & $list 'env_file' $value }
            'restart'               { $service['restart'] = $value }
            { $_ -in @('network', 'net') } {
                if ($value -in @('host', 'none', 'bridge') -or $value -like 'container:*') { $service['network_mode'] = $value }
                else {
                    & $list 'networks' $value
                    if (-not $networks.Contains($value)) { $networks.Add($value) }
                }
            }
            { $_ -in @('network-alias', 'net-alias') } { $notes.Add(('The network alias {0} goes under networks: <network>: aliases: in Compose; add it by hand.' -f $value)) }
            'hostname'              { $service['hostname'] = $value }
            'domainname'            { $service['domainname'] = $value }
            'workdir'               { $service['working_dir'] = $value }
            'user'                  { $service['user'] = $value }
            'entrypoint'            { $service['entrypoint'] = $value }
            'label'                 { & $list 'labels' $value }
            'cap-add'               { & $list 'cap_add' $value }
            'cap-drop'              { & $list 'cap_drop' $value }
            'privileged'            { $service['privileged'] = $true }
            'read-only'             { $service['read_only'] = $true }
            'init'                  { $service['init'] = $true }
            'interactive'           { $service['stdin_open'] = $true }
            'tty'                   { $service['tty'] = $true }
            'device'                { & $list 'devices' $value }
            'add-host'              { & $list 'extra_hosts' $value }
            'dns'                   { & $list 'dns' $value }
            'dns-search'            { & $list 'dns_search' $value }
            'dns-option'            { & $list 'dns_opt' $value }
            'security-opt'          { & $list 'security_opt' $value }
            'group-add'             { & $list 'group_add' $value }
            'volumes-from'          { & $list 'volumes_from' $value }
            'link'                  { & $list 'links' $value }
            'sysctl'                { & $list 'sysctls' $value }
            'log-driver'            { & $map 'logging' 'driver' $value }
            'log-opt' {
                $pieces = $value -split '=', 2
                if (-not $service.Contains('logging')) { $service['logging'] = [ordered] @{} }
                if (-not $service['logging'].Contains('options')) { $service['logging']['options'] = [ordered] @{} }
                $service['logging']['options'][$pieces[0]] = $(if ($pieces.Count -gt 1) { $pieces[1] } else { '' })
            }
            'ulimit' {
                $pieces = $value -split '=', 2
                $limits = if ($pieces.Count -gt 1) { $pieces[1] -split ':' } else { @() }
                if ($limits.Count -eq 2) { & $map 'ulimits' $pieces[0] ([ordered] @{ soft = [long] $limits[0]; hard = [long] $limits[1] }) }
                elseif ($limits.Count -eq 1) { & $map 'ulimits' $pieces[0] ([long] $limits[0]) }
                else { $notes.Add(('--ulimit {0} has no value and was left out.' -f $value)) }
            }
            'memory'                { $service['mem_limit'] = $value }
            'memory-reservation'    { $service['mem_reservation'] = $value }
            'memory-swap'           { $service['memswap_limit'] = $value }
            'cpus'                  { $service['cpus'] = $value }
            'cpu-shares'            { $service['cpu_shares'] = $value }
            'cpuset-cpus'           { $service['cpuset'] = $value }
            'pids-limit'            { $service['pids_limit'] = $value }
            'shm-size'              { $service['shm_size'] = $value }
            'health-cmd'            { & $map 'healthcheck' 'test' @('CMD-SHELL', $value) }
            'health-interval'       { & $map 'healthcheck' 'interval' $value }
            'health-timeout'        { & $map 'healthcheck' 'timeout' $value }
            'health-retries'        { & $map 'healthcheck' 'retries' ([int] $value) }
            'health-start-period'   { & $map 'healthcheck' 'start_period' $value }
            'health-start-interval' { & $map 'healthcheck' 'start_interval' $value }
            'no-healthcheck'        { & $map 'healthcheck' 'disable' $true }
            'stop-signal'           { $service['stop_signal'] = $value }
            'stop-timeout'          { $service['stop_grace_period'] = '{0}s' -f $value }
            'pull'                  { $service['pull_policy'] = $value }
            'platform'              { $service['platform'] = $value }
            'runtime'               { $service['runtime'] = $value }
            'pid'                   { $service['pid'] = $value }
            'ipc'                   { $service['ipc'] = $value }
            'uts'                   { $service['uts'] = $value }
            'userns'                { $service['userns_mode'] = $value }
            'isolation'             { $service['isolation'] = $value }
            'oom-score-adj'         { $service['oom_score_adj'] = [int] $value }
            'mac-address'           { $service['mac_address'] = $value }
            'detach'                { $notes.Add('-d is what docker compose up -d does; it has no place in the file.') }
            'rm'                    { $notes.Add('--rm has no Compose key: docker compose down removes the containers.') }
            default                 { $notes.Add(('--{0} has no direct Compose equivalent and was left out.' -f $option)) }
        }
    }

    while ($index -lt $words.Count) {

        $word = $words[$index]

        if ($word -eq '--') {
            $index++
            break
        }

        if (-not $word.StartsWith('-') -or $word -eq '-') {
            break
        }

        if ($word.StartsWith('--')) {

            $optionName = $word.Substring(2)
            $value      = $null
            $equals     = $optionName.IndexOf('=')

            if ($equals -ge 0) {
                $value      = $optionName.Substring($equals + 1)
                $optionName = $optionName.Substring(0, $equals)
            }

            if (-not $long.ContainsKey($optionName)) {
                $notes.Add(('--{0} is not a docker run option this converter knows, and was left out.' -f $optionName))
                $index++
                continue
            }

            $option = $long[$optionName]

            if ($option.TakesValue -and $null -eq $value) {
                $index++
                if ($index -ge $words.Count) { throw ('--{0} needs a value.' -f $optionName) }
                $value = $words[$index]
            }

            & $apply $option.Long $value
        }
        else {

            # Short options can be grouped (-dit) and take their value attached (-p8080:80).
            $letters = $word.Substring(1)

            for ($position = 0; $position -lt $letters.Length; $position++) {

                $letter = [string] $letters[$position]

                if (-not $short.ContainsKey($letter)) {
                    $notes.Add(('-{0} is not a docker run option this converter knows, and was left out.' -f $letter))
                    continue
                }

                $option = $short[$letter]

                if ($option.TakesValue) {

                    $value = $letters.Substring($position + 1).TrimStart('=')

                    if (-not $value) {
                        $index++
                        if ($index -ge $words.Count) { throw ('-{0} needs a value.' -f $letter) }
                        $value = $words[$index]
                    }

                    & $apply $option.Long $value
                    break
                }

                & $apply $option.Long $null
            }
        }

        $index++
    }

    if ($index -ge $words.Count) {
        throw 'No image was found after the options.'
    }

    $image = $words[$index]

    if ($index + 1 -lt $words.Count) {
        $service['command'] = [string[]] @($words[($index + 1)..($words.Count - 1)])
    }

    $serviceName = if ($service.Contains('container_name')) { [string] $service['container_name'] }
                   else { ((($image -split '@')[0] -split '/')[-1] -split ':')[0] }

    $serviceName = ($serviceName.ToLowerInvariant() -replace '[^a-z0-9_.-]', '-').Trim('-')

    if (-not $serviceName) {
        $serviceName = 'app'
    }

    $order = @(
        'container_name', 'hostname', 'domainname', 'restart', 'user', 'working_dir', 'entrypoint', 'command', 'ports', 'expose',
        'volumes', 'volumes_from', 'tmpfs', 'environment', 'env_file', 'networks', 'network_mode', 'extra_hosts', 'dns', 'dns_search',
        'dns_opt', 'labels', 'cap_add', 'cap_drop', 'privileged', 'read_only', 'security_opt', 'devices', 'group_add', 'init',
        'stdin_open', 'tty', 'mem_limit', 'mem_reservation', 'memswap_limit', 'cpus', 'cpu_shares', 'cpuset', 'pids_limit', 'shm_size',
        'ulimits', 'sysctls', 'logging', 'healthcheck', 'stop_signal', 'stop_grace_period', 'pull_policy', 'platform', 'runtime', 'pid',
        'ipc', 'uts', 'userns_mode', 'isolation', 'oom_score_adj', 'mac_address', 'links'
    )

    $flow = {
        param($items)
        '[{0}]' -f ((@($items) | ForEach-Object { ConvertTo-TkYamlScalar -Value ([string] $_) -Quote }) -join ', ')
    }

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add('services:')
    $lines.Add(('  {0}:' -f $serviceName))
    $lines.Add(('    image: {0}' -f (ConvertTo-TkYamlScalar -Value $image)))

    foreach ($key in $order) {

        if (-not $service.Contains($key)) { continue }

        $value = $service[$key]

        if ($value -is [array]) {
            $lines.Add(('    {0}: {1}' -f $key, (& $flow $value)))
        }
        elseif ($value -is [System.Collections.Generic.List[object]]) {
            $lines.Add(('    {0}:' -f $key))
            foreach ($item in $value) {
                $lines.Add(('      - {0}' -f (ConvertTo-TkYamlScalar -Value $item -Quote:($key -in @('ports', 'expose')))))
            }
        }
        elseif ($value -is [System.Collections.Specialized.OrderedDictionary]) {
            $lines.Add(('    {0}:' -f $key))
            foreach ($entry in $value.Keys) {
                $inner = $value[$entry]
                if ($inner -is [System.Collections.Specialized.OrderedDictionary]) {
                    $lines.Add(('      {0}:' -f $entry))
                    foreach ($innerKey in $inner.Keys) {
                        $lines.Add(('        {0}: {1}' -f $innerKey, (ConvertTo-TkYamlScalar -Value $inner[$innerKey])))
                    }
                }
                elseif ($inner -is [array]) {
                    $lines.Add(('      {0}: {1}' -f $entry, (& $flow $inner)))
                }
                else {
                    $lines.Add(('      {0}: {1}' -f $entry, (ConvertTo-TkYamlScalar -Value $inner)))
                }
            }
        }
        else {
            $lines.Add(('    {0}: {1}' -f $key, (ConvertTo-TkYamlScalar -Value $value)))
        }
    }

    if ($volumes.Count -gt 0) {
        $lines.Add('volumes:')
        foreach ($volume in $volumes) { $lines.Add(('  {0}:' -f $volume)) }
    }

    if ($networks.Count -gt 0) {
        $lines.Add('networks:')
        foreach ($network in $networks) {
            $lines.Add(('  {0}:' -f $network))
            $lines.Add('    external: true')
        }
        $notes.Add('The networks are marked external, because docker run needed them to exist already; remove external: true to let Compose create them.')
    }

    return [pscustomobject] @{
        Yaml        = $lines -join [Environment]::NewLine
        ServiceName = $serviceName
        Image       = $image
        Notes       = $notes.ToArray()
    }
}
