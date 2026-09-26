<#
    Toolkit - Features / Command path (PATH)

    PATH decides which program runs when a name is typed, and it rots quietly:
    folders of uninstalled tools stay in it, "setx PATH %PATH%;..." copies the
    whole system PATH into the user one every time it is run, a Store alias
    shadows the Python actually installed.

    It is also a security boundary. Services running as SYSTEM search the
    system PATH too, so a folder in it that a standard account can write, or a
    missing one it can create, lets that account plant a program or a DLL that
    runs with the highest rights. Folders from one user's profile in the system
    PATH are the usual way this happens.

    Read only: the permissions are read, nothing is written to test them.
#>

<#
.SYNOPSIS
    Says whether a security identifier is one only administrators or Windows itself hold.
#>
function Test-TkPrivilegedSid {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Sid
    )

    return [bool] ($Sid -match '^(S-1-5-18|S-1-5-19|S-1-5-20|S-1-5-32-544|S-1-5-32-549|S-1-3-0|S-1-5-80-.+|S-1-15-2-.+|S-1-5-21-\d+-\d+-\d+-(512|519))$')
}

<#
.SYNOPSIS
    Lists the accounts other than administrators that hold some rights on a folder itself.

.PARAMETER Path
    An existing folder.

.PARAMETER Rights
    The access bits to look for: 0x2 creates a file, 0x4 creates a folder.

.OUTPUTS
    System.String[] of account names, empty when none, $null when the
    permissions cannot be read.
#>
function Get-TkNonAdminWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [int] $Rights = 0x2
    )

    try {
        $rules = @((Get-Acl -LiteralPath $Path -ErrorAction Stop).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    }
    catch {
        return $null
    }

    $names = New-Object System.Collections.Generic.List[string]

    foreach ($rule in $rules) {

        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        # An inherit-only entry applies to what the folder holds, not to the folder.
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }

        $sid = $rule.IdentityReference.Value

        if (Test-TkPrivilegedSid -Sid $sid) { continue }

        $bits = [long] $rule.FileSystemRights -band 0xFFFFFFFFL

        # The generic rights an entry can carry grant the specific ones too.
        if (($bits -band ($Rights -bor 0x10000000 -bor 0x40000000)) -eq 0) { continue }

        $name = Get-TkShareSidName -Sid $sid

        if (-not $names.Contains($name)) {
            $names.Add($name)
        }
    }

    return @($names.ToArray())
}

<#
.SYNOPSIS
    Splits a PATH value into its entries and notes what is odd about each.

.DESCRIPTION
    Pure apart from the variable expansion. Each entry keeps its position, its
    text as written, the folder it expands to, and a key to spot the same
    folder written twice.

.PARAMETER Value
    The PATH as stored, variables not expanded.

.PARAMETER Scope
    Machine or User.

.PARAMETER ValueKind
    The registry type of the value: a String does not expand its variables.

.OUTPUTS
    PSCustomObject[] with Scope, Position, Raw, Expanded, Key, Empty, Quoted,
    Relative, Unexpandable, ProfileVariable (written with %APPDATA% and the
    like, which each account expands to its own profile) and InUserProfile
    (a literal path into one user's profile).
#>
function ConvertFrom-TkPathValue {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter(Mandatory)]
        [ValidateSet('Machine', 'User')]
        [string] $Scope,

        [Parameter()]
        [string] $ValueKind = 'ExpandString'
    )

    $entries  = New-Object System.Collections.Generic.List[object]
    $position = 0

    foreach ($raw in ($Value -split ';')) {

        $position++

        $text     = $raw.Trim()
        $quoted   = $text.Contains('"')
        $clean    = $text.Trim('"').Trim()
        $expanded = if ($ValueKind -eq 'String') { $clean } else { [Environment]::ExpandEnvironmentVariables($clean) }

        $entries.Add([pscustomobject] @{
            Scope         = $Scope
            Position      = $position
            Raw           = $text
            Expanded      = $expanded
            Key           = $expanded.TrimEnd('\').ToLowerInvariant()
            Empty         = $clean.Length -eq 0
            Quoted        = $quoted
            Relative      = $clean.Length -gt 0 -and -not ($expanded -match '^[A-Za-z]:\\' -or $expanded -match '^\\\\')
            Unexpandable  = $ValueKind -eq 'String' -and $clean.Contains('%')
            ProfileVariable = $clean -match '%(USERPROFILE|APPDATA|LOCALAPPDATA|HOMEPATH)%'
            InUserProfile   = $clean -notmatch '%(USERPROFILE|APPDATA|LOCALAPPDATA|HOMEPATH)%' -and
                              ($expanded -match '^[A-Za-z]:\\Users\\(?!Public\\|Public$|Default\\|Default$)[^\\]+')
        })
    }

    return @($entries.ToArray())
}

<#
.SYNOPSIS
    Judges one PATH entry from the facts gathered about it.

.DESCRIPTION
    Pure. The security findings only concern the system PATH, which services
    running as SYSTEM search; a user's own PATH is theirs to write.

.OUTPUTS
    PSCustomObject with Severity, State and Note.
#>
function Get-TkPathEntryVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Entry,
        [Parameter()] [bool] $Exists = $true,
        [Parameter()] [int] $DuplicateOf = 0,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Writers = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Creators = @()
    )

    $verdict = { param($severity, $state, $note) [pscustomobject] @{ Severity = $severity; State = $state; Note = $note } }
    $machine = $Entry.Scope -eq 'Machine'

    if ($Entry.Empty) {
        return (& $verdict 'Info' 'Empty' 'An empty entry, left by a doubled ";". Harmless, but it is the kind of edit that goes wrong.')
    }

    if ($Entry.Relative) {
        return (& $verdict 'Fail' 'Relative' 'Not a full path, so it is looked up from whatever folder is current: a program dropped in any folder a command is run from wins.')
    }

    if ($machine -and $Writers.Count -gt 0) {
        return (& $verdict 'Fail' 'Writable' ('{0} can add files to this system PATH folder, and services running as SYSTEM search it: a program or DLL left here runs with the highest rights.' -f ($Writers -join ', ')))
    }

    if ($machine -and -not $Exists -and $Creators.Count -gt 0) {
        return (& $verdict 'Fail' 'Missing, can be created' ('The folder does not exist and {0} can create it, then fill it with programs that services running as SYSTEM would find.' -f ($Creators -join ', ')))
    }

    if ($Entry.Unexpandable) {
        return (& $verdict 'Warning' 'Not expanded' 'The PATH is stored as a plain string, so the %variable% in it is never replaced and the folder is never searched.')
    }

    if ($machine -and $Entry.ProfileVariable) {
        return (& $verdict 'Warning' 'User variable' 'Written with a profile variable, so every account, SYSTEM included, reads it as a folder of its own profile: harmless for services, but it belongs in the user PATH of whoever uses the tool.')
    }

    if ($machine -and $Entry.InUserProfile) {
        return (& $verdict 'Warning' 'In a user profile' 'A folder of one user''s profile in the system PATH, the same folder for every account: that user decides what the others find there.')
    }

    if ($Entry.Quoted) {
        return (& $verdict 'Warning' 'Quoted' 'Quotes are not part of a PATH entry. The command prompt strips them, many programs do not and never search this folder.')
    }

    if ($DuplicateOf -gt 0) {
        return (& $verdict 'Info' 'Duplicate' ('The same folder as entry {0}: only the first is ever used.' -f $DuplicateOf))
    }

    if (-not $Exists) {
        return (& $verdict 'Info' 'Missing' 'The folder does not exist, usually left by a tool that was uninstalled. Every command typed checks it for nothing.')
    }

    return (& $verdict 'Pass' 'OK' '')
}

<#
.SYNOPSIS
    Finds the commands present in more than one PATH folder, and which one wins.

.DESCRIPTION
    Pure: the folders in search order and what each holds are passed in. The
    first folder holding a command is the one that runs; a Store alias in
    WindowsApps found before an installed program is called out, since it
    opens the Microsoft Store instead of running the program.

.PARAMETER Folders
    The existing PATH folders, in search order, without repeats.

.PARAMETER Files
    For each folder, the file names found in it.

.PARAMETER Commands
    The command names to look for.

.OUTPUTS
    PSCustomObject[] with Command, Winner, Others, StoreAlias.
#>
function Find-TkShadowedCommand {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Folders,
        [Parameter(Mandatory)] [hashtable] $Files,
        [Parameter(Mandatory)] [string[]] $Commands
    )

    $extensions = @('.com', '.exe', '.bat', '.cmd')
    $results    = New-Object System.Collections.Generic.List[object]

    foreach ($command in $Commands) {

        $found = New-Object System.Collections.Generic.List[string]

        foreach ($folder in $Folders) {

            $present = @($Files[$folder])

            foreach ($extension in $extensions) {
                if ($present -contains ($command + $extension)) {
                    $found.Add(('{0}\{1}{2}' -f $folder.TrimEnd('\'), $command, $extension))
                    break
                }
            }
        }

        if ($found.Count -lt 2) {
            continue
        }

        $results.Add([pscustomobject] @{
            Command    = $command
            Winner     = $found[0]
            Others     = @($found | Select-Object -Skip 1)
            StoreAlias = $found[0] -match '\\Microsoft\\WindowsApps\\'
        })
    }

    return @($results.ToArray())
}

<#
.SYNOPSIS
    Reads the system and user PATH and judges every entry.

.OUTPUTS
    PSCustomObject with Machine and User (Length, Kind), Entries (with Exists,
    Severity, State and Note), SetxCopies, Shadowed and the counts.
#>
function Get-TkPathAudit {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $read = {
        param($hive, $key)
        try {
            $handle = $hive.OpenSubKey($key)
            if (-not $handle) { return @{ Value = ''; Kind = 'ExpandString' } }
            $value = [string] $handle.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind  = if ($value) { [string] $handle.GetValueKind('Path') } else { 'ExpandString' }
            $handle.Close()
            return @{ Value = $value; Kind = $kind }
        }
        catch {
            return @{ Value = ''; Kind = 'ExpandString' }
        }
    }

    $machine = & $read ([Microsoft.Win32.Registry]::LocalMachine) 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $user    = & $read ([Microsoft.Win32.Registry]::CurrentUser)  'Environment'

    $entries = @(
        ConvertFrom-TkPathValue -Value $machine.Value -Scope Machine -ValueKind $machine.Kind
        $(if ($user.Value) { ConvertFrom-TkPathValue -Value $user.Value -Scope User -ValueKind $user.Kind })
    )

    # A malformed entry must not stop the report: Test-Path throws on some.
    $isFolder = {
        param($path)
        try { Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop } catch { $false }
    }

    # The first place each folder appears, over the whole search order.
    $first   = @{}
    $index   = 0
    $judged  = New-Object System.Collections.Generic.List[object]

    foreach ($entry in $entries) {

        $index++
        $exists = -not $entry.Empty -and -not $entry.Relative -and (& $isFolder $entry.Expanded)

        $duplicateOf = 0
        if (-not $entry.Empty -and $entry.Key) {
            if ($first.ContainsKey($entry.Key)) { $duplicateOf = $first[$entry.Key] } else { $first[$entry.Key] = $index }
        }

        $writers  = @()
        $creators = @()

        # Every literal system entry is checked, a repeated one included: a
        # duplicate is searched all the same. An entry written with a profile
        # variable points SYSTEM at its own profile, so it is not checked.
        if ($entry.Scope -eq 'Machine' -and -not $entry.Empty -and -not $entry.Relative -and -not $entry.ProfileVariable) {

            if ($exists) {
                $writers = @(Get-TkNonAdminWriter -Path $entry.Expanded -Rights 0x2 | Where-Object { $_ })
            }
            else {
                # The nearest folder that exists: whoever can create a folder in
                # it can create the missing path.
                $parent = Split-Path -Path $entry.Expanded -Parent

                while ($parent -and -not (& $isFolder $parent)) {
                    $parent = Split-Path -Path $parent -Parent
                }

                if ($parent) {
                    $creators = @(Get-TkNonAdminWriter -Path $parent -Rights 0x4 | Where-Object { $_ })
                }
            }
        }

        $verdict = Get-TkPathEntryVerdict -Entry $entry -Exists $exists -DuplicateOf $duplicateOf -Writers $writers -Creators $creators

        $judged.Add([pscustomobject] @{
            Order       = $index
            Scope       = $entry.Scope
            Position    = $entry.Position
            Raw         = $entry.Raw
            Expanded    = $entry.Expanded
            Exists      = $exists
            DuplicateOf = $duplicateOf
            Who         = (@($writers) + @($creators) | Select-Object -Unique) -join ', '
            Severity    = $verdict.Severity
            State       = $verdict.State
            Note        = $verdict.Note
        })
    }

    $all = @($judged.ToArray())

    # "setx PATH %PATH%;..." writes the system PATH into the user one.
    $machineKeys = @($entries | Where-Object { $_.Scope -eq 'Machine' -and -not $_.Empty } | ForEach-Object { $_.Key } | Select-Object -Unique)
    $setxCopies  = @($entries | Where-Object { $_.Scope -eq 'User' -and -not $_.Empty -and $machineKeys -contains $_.Key }).Count

    # Commands found in more than one folder.
    $folders = @($all | Where-Object { $_.Exists -and $_.DuplicateOf -eq 0 } | ForEach-Object { $_.Expanded })
    $commands = @('python', 'python3', 'py', 'pip', 'git', 'node', 'npm', 'java', 'javac', 'pwsh', 'code', 'dotnet',
                  'go', 'cargo', 'ruby', 'perl', 'php', 'curl', 'ssh', 'scp', 'tar', 'openssl', 'kubectl', 'docker',
                  'az', 'aws', 'terraform', 'winget', 'choco', 'gh')
    $files = @{}

    foreach ($folder in $folders) {
        $files[$folder] = @(foreach ($command in $commands) {
            foreach ($extension in @('.com', '.exe', '.bat', '.cmd')) {
                if (Test-Path -LiteralPath (Join-Path $folder ($command + $extension)) -PathType Leaf) { $command + $extension }
            }
        })
    }

    return [pscustomobject] @{
        Machine    = [pscustomobject] @{ Length = $machine.Value.Length; Kind = $machine.Kind }
        User       = [pscustomobject] @{ Length = $user.Value.Length;    Kind = $user.Kind }
        Entries    = $all
        SetxCopies = $setxCopies
        Shadowed   = @(Find-TkShadowedCommand -Folders $folders -Files $files -Commands $commands)
        Failures   = @($all | Where-Object { $_.Severity -eq 'Fail' }).Count
        Missing    = @($all | Where-Object { $_.State -eq 'Missing' }).Count
        Duplicates = @($all | Where-Object { $_.State -eq 'Duplicate' }).Count
        Empty      = @($all | Where-Object { $_.State -eq 'Empty' }).Count
    }
}
