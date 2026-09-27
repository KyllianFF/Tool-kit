<#
    Toolkit - Features / Migration: from one profile to another on the same machine

    A user who gets a new account on the same PC (a new domain, a renamed
    account, a local account moved to Entra ID) needs the files of the old
    profile in the new one. Reading another profile and writing in it takes
    administrator rights, so the copy runs in the elevated worker.

    The copied files must be the new account's, not the administrator's who
    ran the copy: robocopy copies no permissions, so each file takes those of
    the folder it lands in, and the owner of what was created is set to the
    new account. Nothing at the destination is overwritten.

    A move deletes a source file only once its copy has been read back and
    its SHA-256 matches; any file that cannot be verified stays where it was.
#>

<#
.SYNOPSIS
    Shapes Win32_UserProfile instances into the profiles a copy can use.

.DESCRIPTION
    Pure. System and service profiles are left out, and so is a profile
    whose folder is gone. The account name is given by the caller's
    resolver, since an account deleted from the domain no longer resolves;
    the folder name stands in for it.

.OUTPUTS
    PSCustomObject[] with Sid, Path, Name, Loaded and Current, by name.
#>
function ConvertTo-TkLocalProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Instance = @(),
        [Parameter()] [scriptblock] $Resolve = { param($sid) $null = $sid; '' },
        [Parameter()] [scriptblock] $Exists = { param($path) [System.IO.Directory]::Exists($path) },
        [Parameter()] [string] $CurrentSid = ''
    )

    return @($Instance | Where-Object {
            $_ -and -not $_.Special -and $_.LocalPath -and [string] $_.SID -match '^S-1-(5-21|12-1)-' -and (& $Exists ([string] $_.LocalPath))
        } | ForEach-Object {
            $name = [string] (& $Resolve ([string] $_.SID))
            [pscustomobject] @{
                Sid     = [string] $_.SID
                Path    = ([string] $_.LocalPath).TrimEnd('\')
                Name    = $(if ($name) { $name } else { Split-Path -Path ([string] $_.LocalPath) -Leaf })
                Loaded  = [bool] $_.Loaded
                Current = ([string] $_.SID -eq $CurrentSid)
            }
        } | Sort-Object -Property Name)
}

<#
.SYNOPSIS
    Lists the user profiles of this machine.

.OUTPUTS
    PSCustomObject[] with Sid, Path, Name, Loaded and Current.
#>
function Get-TkLocalProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $resolve = {
        param($sid)
        try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { '' }
    }

    return @(ConvertTo-TkLocalProfile -Instance @(Get-TkCimInstanceSafe -ClassName 'Win32_UserProfile' -All) -Resolve $resolve `
                                      -CurrentSid ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
}

<#
.SYNOPSIS
    Works out where the personal folders of a profile are.

.DESCRIPTION
    Pure. The values come from that account's User Shell Folders, when its
    registry is loaded (the account is signed in, or it is this one), where
    %USERPROFILE% means that profile's folder, not the caller's. A value
    that still names another variable is not trusted, and a folder with no
    value is the usual one inside the profile.

.OUTPUTS
    PSCustomObject[] with Key and Path.
#>
function ConvertTo-TkProfileFolder {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $ProfilePath,
        [Parameter()] [AllowNull()] [object] $ShellFolder = $null
    )

    $values = [ordered] @{
        Desktop   = 'Desktop'
        Documents = 'Personal'
        Pictures  = 'My Pictures'
        Videos    = 'My Video'
        Music     = 'My Music'
        Downloads = '{374DE290-123F-4565-9164-39C4925E467B}'
    }

    return @(foreach ($key in $values.Keys) {
        $raw  = if ($ShellFolder -and $ShellFolder.PSObject.Properties[$values[$key]]) { [string] $ShellFolder.($values[$key]) } else { '' }
        $path = [regex]::Replace($raw, '%USERPROFILE%', $ProfilePath.TrimEnd('\').Replace('$', '$$'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $path -or $path -match '%') { $path = [System.IO.Path]::Combine($ProfilePath, $key) }
        [pscustomobject] @{ Key = $key; Path = $path.TrimEnd('\') }
    })
}

<#
.SYNOPSIS
    The personal folders of one profile.

.OUTPUTS
    PSCustomObject[] with Key, Path and Exists.
#>
function Get-TkProfileFolder {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $UserProfile
    )

    $key   = 'Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -f $UserProfile.Sid
    $shell = try { Get-ItemProperty -LiteralPath $key -ErrorAction Stop } catch { $null }

    return @(ConvertTo-TkProfileFolder -ProfilePath $UserProfile.Path -ShellFolder $shell | ForEach-Object {
        # Directory.Exists, not Test-Path: without administrator rights another
        # profile's folders are denied, and that must read as unknown, not fail.
        [pscustomobject] @{ Key = $_.Key; Path = $_.Path; Exists = [System.IO.Directory]::Exists($_.Path) }
    })
}

<#
.SYNOPSIS
    Checks a copy from one profile to another before anything is written.

.DESCRIPTION
    Each folder must come from inside the source profile and go inside the
    destination profile, the two profiles must differ, and no source may
    hold a destination or the other way round, which would copy a folder
    into itself or, for a move, delete what was just copied. A row with no
    destination is left out. -SkipSourceCheck is for the window, which
    cannot see inside another profile without administrator rights; the
    elevated worker checks again without it.

.OUTPUTS
    PSCustomObject with Steps (Key, Name, Source, Target) and Errors.
#>
function New-TkProfileCopyPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Row = @(),
        [Parameter()] [AllowNull()] [object] $SourceProfile,
        [Parameter()] [AllowNull()] [object] $TargetProfile,
        [Parameter()] [switch] $SkipSourceCheck,

        # Pins or bookmarks are copied too, so no folder at all is fine.
        [Parameter()] [switch] $AllowNoFolder
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $steps  = New-Object System.Collections.Generic.List[object]

    if (-not $SourceProfile -or -not $TargetProfile) {
        $errors.Add('Pick the profile to copy from and the one to copy to.')
    }
    elseif ($SourceProfile.Sid -eq $TargetProfile.Sid -or $SourceProfile.Path -eq $TargetProfile.Path) {
        $errors.Add('The two profiles are the same: pick another destination.')
    }
    else {
        foreach ($item in ($Row | Where-Object { $_ -and [string] $_.Target })) {

            $source = ([string] $item.Source).TrimEnd('\')
            $target = ([string] $item.Target).TrimEnd('\')

            if (-not [System.IO.Path]::IsPathRooted($target) -or $target -match '[<>"|?*]') {
                $errors.Add(('{0}: the destination is not a full path.' -f $item.Name)); continue
            }
            if (-not (Test-TkPathUnder -Path $source -Root @($SourceProfile.Path))) {
                $errors.Add(('{0}: {1} is not inside the profile {2}.' -f $item.Name, $source, $SourceProfile.Path)); continue
            }
            if (-not (Test-TkPathUnder -Path $target -Root @($TargetProfile.Path))) {
                $errors.Add(('{0}: the destination must be inside the profile {1}.' -f $item.Name, $TargetProfile.Path)); continue
            }
            if (-not $SkipSourceCheck -and -not [System.IO.Directory]::Exists($source)) {
                $errors.Add(('{0}: {1} does not exist.' -f $item.Name, $source)); continue
            }

            $steps.Add([pscustomobject] @{ Key = [string] $item.Key; Name = [string] $item.Name; Source = $source; Target = $target })
        }

        $sources = @($steps | ForEach-Object Source)
        $targets = @($steps | ForEach-Object Target)
        foreach ($step in $steps) {
            if ((Test-TkPathUnder -Path $step.Target -Root $sources) -or (Test-TkPathUnder -Path $step.Source -Root $targets)) {
                $errors.Add(('{0}: its source and a destination overlap.' -f $step.Name))
            }
        }

        if ($steps.Count -eq 0 -and $errors.Count -eq 0 -and -not $AllowNoFolder) {
            $errors.Add('No folder is selected.')
        }
    }

    return [pscustomobject] @{ Steps = @($steps.ToArray()); Errors = @($errors.ToArray()) }
}

<#
.SYNOPSIS
    Sorts the files of a folder by what the copy will do with each.

.DESCRIPTION
    Walks the source as robocopy will: junctions are not followed, and files
    kept online only by a cloud client are left out so none is downloaded.
    A file missing at the destination is New; one there with the same size
    and time is Same; one there that differs is a Conflict and is left alone.
    NewRoot lists the top folders the copy will create, and Loose the new
    files that land in a folder that already exists: together, everything
    the copy creates and nothing else.

.OUTPUTS
    PSCustomObject with New, Same, Conflict, NewRoot, Loose (relative paths),
    Online (count) and TargetExisted.
#>
function Get-TkProfileCopyItem {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Target
    )

    $new      = New-Object System.Collections.Generic.List[string]
    $same     = New-Object System.Collections.Generic.List[string]
    $conflict = New-Object System.Collections.Generic.List[string]
    $newRoot  = New-Object System.Collections.Generic.List[string]
    $loose    = New-Object System.Collections.Generic.List[string]
    $online   = 0

    $reparse  = [int] [System.IO.FileAttributes]::ReparsePoint
    # Offline, and the two recall attributes of cloud placeholders.
    $cloud    = [int] [System.IO.FileAttributes]::Offline -bor 0x40000 -bor 0x400000
    $existed  = [System.IO.Directory]::Exists($Target)

    if (-not $existed) { $newRoot.Add('') }

    # Relative paths are carried down the walk: see Find-TkMigrationConflict.
    $pending = New-Object System.Collections.Generic.Stack[object]
    $pending.Push(@((New-Object System.IO.DirectoryInfo($Source)), '', (-not $existed)))

    while ($pending.Count -gt 0) {

        $pair      = $pending.Pop()
        $directory = $pair[0]
        $relative  = $pair[1]
        $created   = $pair[2]

        try {
            foreach ($child in $directory.EnumerateDirectories()) {
                if (([int] $child.Attributes -band $reparse) -ne 0) { continue }
                $path  = [System.IO.Path]::Combine($relative, $child.Name)
                $fresh = $created -or -not [System.IO.Directory]::Exists([System.IO.Path]::Combine($Target, $path))
                if ($fresh -and -not $created) { $newRoot.Add($path) }
                $pending.Push(@($child, $path, $fresh))
            }

            foreach ($here in $directory.EnumerateFiles()) {

                if (([int] $here.Attributes -band $cloud) -ne 0) { $online++; continue }

                $path        = [System.IO.Path]::Combine($relative, $here.Name)
                $destination = [System.IO.Path]::Combine($Target, $path)

                if (-not [System.IO.File]::Exists($destination)) {
                    $new.Add($path)
                    if (-not $created) { $loose.Add($path) }
                    continue
                }

                $there = New-Object System.IO.FileInfo($destination)
                if ($there.Length -eq $here.Length -and [math]::Abs(($there.LastWriteTimeUtc - $here.LastWriteTimeUtc).TotalSeconds) -le 2) {
                    $same.Add($path)
                }
                else {
                    $conflict.Add($path)
                }
            }
        }
        catch {
            # A folder that cannot be read is skipped; robocopy reports it in its log.
            $null = $_
        }
    }

    return [pscustomobject] @{
        New = @($new.ToArray()); Same = @($same.ToArray()); Conflict = @($conflict.ToArray())
        NewRoot = @($newRoot.ToArray()); Loose = @($loose.ToArray()); Online = $online; TargetExisted = $existed
    }
}

<#
.SYNOPSIS
    Makes the destination account the owner of what the copy created.

.DESCRIPTION
    Files written by an administrator belong to the Administrators group.
    icacls /setowner gives each new folder (with all it holds) and each new
    file in a folder that was already there to the destination account;
    files that were at the destination before are not touched.

.OUTPUTS
    System.Int32, the number of icacls runs that reported an error.
#>
function Set-TkCopiedOwner {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [pscustomobject] $Item,
        [Parameter(Mandatory)] [ValidatePattern('^S-1-[0-9-]+$')] [string] $Sid
    )

    if (-not $PSCmdlet.ShouldProcess($Target, ('Set the owner to {0}' -f $Sid))) { return 0 }

    $failed = 0
    $runs   = @(@($Item.NewRoot) | ForEach-Object { , @(([System.IO.Path]::Combine($Target, $_)).TrimEnd('\'), '/T') }) +
              @(@($Item.Loose) | ForEach-Object { , @([System.IO.Path]::Combine($Target, $_)) })

    foreach ($run in $runs) {
        if (-not ([System.IO.Directory]::Exists($run[0]) -or [System.IO.File]::Exists($run[0]))) { continue }
        $arguments = @($run[0], '/setowner', ('*{0}' -f $Sid)) + @($run | Select-Object -Skip 1) + @('/C', '/Q')
        $result = Invoke-TkProcess -FilePath 'icacls.exe' -ArgumentList $arguments -TimeoutSeconds 0
        if ($result.ExitCode -ne 0) { $failed++ }
    }

    return $failed
}

<#
.SYNOPSIS
    Says whether an account may change what is in a folder.

.DESCRIPTION
    Reads the folder's permissions for an allow entry of that account, or of
    a group every signed-in user is in, that grants at least Modify, and no
    deny entry of the account.

.OUTPUTS
    System.Boolean
#>
function Test-TkProfileAccess {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Sid,
        [Parameter()] [AllowNull()] [object] $Acl = $null
    )

    if (-not $Acl) {
        try { $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
        catch { return $false }
    }

    $modify = [int] [System.Security.AccessControl.FileSystemRights]::Modify
    $who    = @($Sid, 'S-1-5-11', 'S-1-5-32-545')
    $allow  = $false

    foreach ($rule in $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $value = $rule.IdentityReference.Value
        if ($rule.AccessControlType -eq 'Deny' -and $value -eq $Sid -and ([int] $rule.FileSystemRights -band $modify) -ne 0) { return $false }
        if ($rule.AccessControlType -eq 'Allow' -and $who -contains $value -and ([int] $rule.FileSystemRights -band $modify) -eq $modify) { $allow = $true }
    }

    return $allow
}

<#
.SYNOPSIS
    Deletes the source files whose copy is verified, and nothing else.

.DESCRIPTION
    Each file is read back at the destination and its SHA-256 compared with
    the source's; only a match deletes the source file. A missing copy, a
    different hash, or a file that cannot be read stays where it was, and is
    counted. Folders left empty by the move are removed, deepest first; the
    source folder itself is kept.

.OUTPUTS
    PSCustomObject with Moved, Kept and Reasons (the first few).
#>
function Remove-TkVerifiedSource {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Relative = @()
    )

    $moved   = 0
    $kept    = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $note    = { param($text) if ($reasons.Count -lt 20) { $reasons.Add($text) } }

    if (-not $PSCmdlet.ShouldProcess($Source, 'Delete the files whose copy is verified')) {
        return [pscustomobject] @{ Moved = 0; Kept = @($Relative).Count; Reasons = @('Cancelled.') }
    }

    # The copy and its source must be apart, or a check would compare a file with itself.
    if ((Test-TkPathUnder -Path $Target -Root @($Source)) -or (Test-TkPathUnder -Path $Source -Root @($Target))) {
        return [pscustomobject] @{ Moved = 0; Kept = @($Relative).Count; Reasons = @('The source and the destination overlap: nothing was deleted.') }
    }

    foreach ($path in $Relative) {

        $from = [System.IO.Path]::Combine($Source, $path)
        $to   = [System.IO.Path]::Combine($Target, $path)

        try {
            if (-not [System.IO.File]::Exists($to)) { $kept++; & $note ('{0}: not at the destination' -f $path); continue }

            $a = (Get-FileHash -LiteralPath $from -Algorithm SHA256 -ErrorAction Stop).Hash
            $b = (Get-FileHash -LiteralPath $to -Algorithm SHA256 -ErrorAction Stop).Hash

            if (-not $a -or $a -ne $b) { $kept++; & $note ('{0}: the copy differs' -f $path); continue }

            $file = New-Object System.IO.FileInfo($from)
            if ($file.IsReadOnly) { $file.IsReadOnly = $false }
            $file.Delete()
            $moved++
        }
        catch {
            $kept++
            & $note ('{0}: {1}' -f $path, $_.Exception.Message)
        }
    }

    # Empty folders that the copy has too, deepest first; a folder with anything left stays.
    $reparse = [int] [System.IO.FileAttributes]::ReparsePoint
    $folders = New-Object System.Collections.Generic.List[string]
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push('')
    while ($pending.Count -gt 0) {
        $here = $pending.Pop()
        try {
            foreach ($child in (New-Object System.IO.DirectoryInfo([System.IO.Path]::Combine($Source, $here))).EnumerateDirectories()) {
                if (([int] $child.Attributes -band $reparse) -ne 0) { continue }
                $path = [System.IO.Path]::Combine($here, $child.Name)
                $folders.Add($path)
                $pending.Push($path)
            }
        }
        catch { $null = $_ }
    }
    foreach ($folder in @($folders.ToArray() | Sort-Object -Property Length -Descending)) {
        $from = [System.IO.Path]::Combine($Source, $folder)
        try {
            if ([System.IO.Directory]::Exists([System.IO.Path]::Combine($Target, $folder)) -and
                -not [System.IO.Directory]::EnumerateFileSystemEntries($from).GetEnumerator().MoveNext()) {
                [System.IO.Directory]::Delete($from, $false)
            }
        }
        catch { $null = $_ }
    }

    return [pscustomobject] @{ Moved = $moved; Kept = $kept; Reasons = @($reasons.ToArray()) }
}

<#
.SYNOPSIS
    Copies, or moves, folders into another profile, with its permissions.

.DESCRIPTION
    Runs in the elevated worker. For each folder: the files are sorted
    first, robocopy copies only what is missing (/XC /XN /XO, never
    overwriting) without permissions (/COPY:DAT) in backup mode (/B) so a
    file the administrator cannot open is still read, the owner of what was
    created is set to the destination account, and that account's access
    to the folder is checked. With -Move, the source files whose copy is
    verified by SHA-256 are then deleted; a conflict is never deleted.

.OUTPUTS
    PSCustomObject with Ok, Message and Steps (Name, Ok, Text, Log).
#>
function Copy-TkProfileData {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [object[]] $Step,
        [Parameter(Mandatory)] [ValidatePattern('^S-1-[0-9-]+$')] [string] $Sid,
        [Parameter()] [string] $AccountName = '',
        [Parameter()] [switch] $Move,
        [Parameter()] [string] $LogFolder = (Get-TkContext).LogRoot
    )

    $account = if ($AccountName) { $AccountName } else { $Sid }
    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($item in ($Step | Where-Object { $_ })) {

        if (-not $PSCmdlet.ShouldProcess($item.Target, ('Copy {0}' -f $item.Source))) { continue }

        $log = [System.IO.Path]::Combine($LogFolder, ('profile-copy-{0}-{1}.log' -f $item.Key, $stamp))

        try {
            $files = Get-TkProfileCopyItem -Source $item.Source -Target $item.Target
            New-Item -ItemType Directory -Path $item.Target -Force -ErrorAction Stop | Out-Null

            $run = Invoke-TkProcess -FilePath 'robocopy.exe' -TimeoutSeconds 0 -ArgumentList @(
                $item.Source, $item.Target, '/E', '/COPY:DAT', '/DCOPY:DAT', '/XC', '/XN', '/XO', '/XJ', '/XA:O', '/B', '/R:1', '/W:1', '/MT:8', '/NP', ('/LOG:{0}' -f $log)
            )
            $exit = ConvertFrom-TkRobocopyExit -Code $run.ExitCode

            $ownerErrors = Set-TkCopiedOwner -Target $item.Target -Item $files -Sid $Sid -Confirm:$false
            $access      = Test-TkProfileAccess -Path $item.Target -Sid $Sid

            $text = @('{0} new file(s), {1} already there' -f @($files.New).Count, @($files.Same).Count)
            if (@($files.Conflict).Count -gt 0) { $text += '{0} conflict(s) left alone at both places' -f @($files.Conflict).Count }
            if ($files.Online -gt 0) { $text += '{0} file(s) kept online only, not downloaded' -f $files.Online }
            $text += $exit.Text
            $text += if ($ownerErrors -eq 0) { 'owner set to {0}' -f $account } else { 'the owner could not be set on some items' }
            $text += if ($access) { '{0} has access' -f $account } else { '{0} has no Modify permission on the folder: check it' -f $account }

            $ok = $exit.Ok -and $ownerErrors -eq 0 -and $access

            if ($Move) {
                if ($exit.Ok) {
                    $gone = Remove-TkVerifiedSource -Source $item.Source -Target $item.Target -Relative (@($files.New) + @($files.Same)) -Confirm:$false
                    $text += 'moved {0} file(s) after a SHA-256 check, {1} kept at the source' -f $gone.Moved, ($gone.Kept + @($files.Conflict).Count + $files.Online)
                    if ($gone.Kept -gt 0) { $text += 'kept: ' + (@($gone.Reasons | Select-Object -First 5) -join ', ') ; $ok = $false }
                }
                else {
                    $text += 'nothing deleted at the source, since the copy reported errors'
                }
            }

            $results.Add([pscustomobject] @{ Name = $item.Name; Ok = $ok; Text = ($text -join '; '); Log = $log })
        }
        catch {
            $results.Add([pscustomobject] @{ Name = $item.Name; Ok = $false; Text = $_.Exception.Message; Log = '' })
        }
    }

    $verb = if ($Move) { 'moved' } else { 'copied' }
    Add-TkJournalEntry -Name ('Profile data {0} to {1}' -f $verb, $account) -Category 'Migration' -Detail (
        (@($results | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Text })) -join ' | '
    )

    $good = @($results | Where-Object Ok).Count
    return [pscustomobject] @{
        Ok      = ($results.Count -gt 0 -and $good -eq $results.Count)
        Message = ('{0} of {1} folder(s) {2} to {3} without a problem.' -f $good, $results.Count, $verb, $account)
        Steps   = @($results.ToArray())
    }
}

<#
.SYNOPSIS
    Moves the key headers of a .reg file from one hive to another.

.DESCRIPTION
    Pure. Only the [key] lines change: an export read from one account's
    hive becomes an import into another's. Values are left as they are.

.OUTPUTS
    System.String
#>
function ConvertTo-TkTaskbandHive {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [string] $From,
        [Parameter(Mandatory)] [string] $To
    )

    $pattern = '(?im)^\[(-?)' + [regex]::Escape($From.TrimEnd('\')) + '(?=\\|\])'
    return [regex]::Replace($Text, $pattern, ('[$1' + $To.TrimEnd('\').Replace('$', '$$')))
}

<#
.SYNOPSIS
    Makes the registry of another account readable, loading its hive if it is not.

.DESCRIPTION
    A signed-in account has its hive under HKEY_USERS\<SID> already. Another
    one's NTUSER.DAT is loaded with reg load under a name of the toolkit's,
    and must be unloaded with Dismount-TkUserHive once done.

.OUTPUTS
    PSCustomObject with Ok, Root (HKEY_USERS\...), Short (HKU\...), Mounted and Error.
#>
function Mount-TkUserHive {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $UserProfile,
        [Parameter(Mandatory)] [ValidatePattern('^Toolkit-[A-Za-z0-9-]+$')] [string] $MountName
    )

    if ($UserProfile.Loaded) {
        return [pscustomobject] @{ Ok = $true; Root = ('HKEY_USERS\{0}' -f $UserProfile.Sid); Short = ('HKU\{0}' -f $UserProfile.Sid); Mounted = $false; Error = '' }
    }

    $file = [System.IO.Path]::Combine($UserProfile.Path, 'NTUSER.DAT')
    if (-not $PSCmdlet.ShouldProcess($file, 'Load the registry hive')) {
        return [pscustomobject] @{ Ok = $false; Root = ''; Short = ''; Mounted = $false; Error = 'Cancelled.' }
    }

    $run = Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('load', ('HKU\{0}' -f $MountName), $file) -TimeoutSeconds 60
    if ($run.ExitCode -ne 0) {
        return [pscustomobject] @{ Ok = $false; Root = ''; Short = ''; Mounted = $false; Error = ('its registry could not be loaded ({0})' -f ([string] $run.StandardError).Trim()) }
    }

    return [pscustomobject] @{ Ok = $true; Root = ('HKEY_USERS\{0}' -f $MountName); Short = ('HKU\{0}' -f $MountName); Mounted = $true; Error = '' }
}

<#
.SYNOPSIS
    Unloads a hive Mount-TkUserHive loaded, trying again while it is busy.

.DESCRIPTION
    A hive left loaded would make that account sign in to a temporary
    profile until the machine restarts, so the unload is tried a few times.

.OUTPUTS
    System.Boolean, true when nothing is left loaded.
#>
function Dismount-TkUserHive {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowNull()] [object] $Hive,
        [Parameter()] [int] $Attempt = 5,
        [Parameter()] [int] $DelayMilliseconds = 700
    )

    if (-not $Hive -or -not $Hive.Mounted) { return $true }
    if (-not $PSCmdlet.ShouldProcess($Hive.Short, 'Unload the registry hive')) { return $false }

    for ($i = 1; $i -le $Attempt; $i++) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        $run = Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('unload', $Hive.Short) -TimeoutSeconds 60
        if ($run.ExitCode -eq 0) { return $true }
        if ($i -lt $Attempt) { Start-Sleep -Milliseconds $DelayMilliseconds }
    }

    Write-TkLog -Level Error -Category 'Migration' -Message ('The hive {0} could not be unloaded.' -f $Hive.Short)
    return $false
}

<#
.SYNOPSIS
    Gives files and folders the toolkit wrote in another profile to that account.

.OUTPUTS
    System.Int32, the number of icacls runs that reported an error.
#>
function Set-TkOwnerPath {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $Path = @(),
        [Parameter(Mandatory)] [ValidatePattern('^S-1-[0-9-]+$')] [string] $Sid
    )

    $failed = 0
    foreach ($item in ($Path | Where-Object { $_ })) {
        $folder = [System.IO.Directory]::Exists($item)
        if (-not $folder -and -not [System.IO.File]::Exists($item)) { continue }
        if (-not $PSCmdlet.ShouldProcess($item, ('Set the owner to {0}' -f $Sid))) { continue }
        $arguments = @($item.TrimEnd('\'), '/setowner', ('*{0}' -f $Sid)) + $(if ($folder) { @('/T') } else { @() }) + @('/C', '/Q')
        if ((Invoke-TkProcess -FilePath 'icacls.exe' -ArgumentList $arguments -TimeoutSeconds 0).ExitCode -ne 0) { $failed++ }
    }
    return $failed
}

<#
.SYNOPSIS
    Copies the pins of one profile into another: Quick Access, jump lists, taskbar and Start.

.DESCRIPTION
    Runs in the elevated worker. The destination account must be signed
    out, or its Explorer would write its own pins back over them. Its pins
    are saved first to the toolkit data folder. Taskbar shortcuts it already
    has are kept. The taskbar order (the Taskband key) is read from the
    source account's registry and written to the destination's, loading
    either hive when its account is signed out and unloading it after; the
    .reg text is checked to write that key and nothing else.

.OUTPUTS
    PSCustomObject with Name, Ok, Text and Log.
#>
function Copy-TkProfilePin {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $SourceProfile,
        [Parameter(Mandatory)] [pscustomobject] $TargetProfile,
        [Parameter()] [string] $BackupRoot = (Get-TkContext).DataRoot
    )

    if ($TargetProfile.Loaded) {
        return [pscustomobject] @{ Name = 'Pins'; Ok = $false; Log = ''
                                   Text = ('{0} is signed in: sign it out and copy the pins again, or its Explorer writes its own back.' -f $TargetProfile.Name) }
    }
    if (-not $PSCmdlet.ShouldProcess($TargetProfile.Path, 'Copy the pins')) {
        return [pscustomobject] @{ Name = 'Pins'; Ok = $false; Text = 'Cancelled.'; Log = '' }
    }

    $at     = { param($userProfile) Get-TkPinLocation -AppData ([System.IO.Path]::Combine($userProfile.Path, 'AppData\Roaming')) -LocalAppData ([System.IO.Path]::Combine($userProfile.Path, 'AppData\Local')) }
    $from   = & $at $SourceProfile
    $to     = & $at $TargetProfile
    $leaf   = Split-Path -Path $TargetProfile.Path -Leaf
    $backup = [System.IO.Path]::Combine($BackupRoot, ('pins-backup-{0}-{1:yyyyMMdd-HHmmss}' -f $leaf, (Get-Date)))
    $lines  = New-Object System.Collections.Generic.List[string]
    $ok     = $true
    $key    = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband'

    # --- The destination's pins, saved first ------------------------------
    [void] (Copy-TkPinFile -From $to.Automatic -To ([System.IO.Path]::Combine($backup, 'AutomaticDestinations')) -Filter '*.automaticDestinations-ms')
    [void] (Copy-TkPinFile -From $to.Custom -To ([System.IO.Path]::Combine($backup, 'CustomDestinations')) -Filter '*.customDestinations-ms')
    [void] (Copy-TkPinFile -From $to.Taskbar -To ([System.IO.Path]::Combine($backup, 'TaskBar')) -Filter '*.lnk')
    $targetStart = [System.IO.Path]::Combine($to.Start, 'start2.bin')
    if ([System.IO.File]::Exists($targetStart)) { [System.IO.File]::Copy($targetStart, [System.IO.Path]::Combine($backup, 'start2.bin'), $true) }

    # --- The files ---------------------------------------------------------
    $automatic = Copy-TkPinFile -From $from.Automatic -To $to.Automatic -Filter '*.automaticDestinations-ms'
    $custom    = Copy-TkPinFile -From $from.Custom -To $to.Custom -Filter '*.customDestinations-ms'
    $taskbar   = Copy-TkPinFile -From $from.Taskbar -To $to.Taskbar -Filter '*.lnk' -KeepExisting
    $lines.Add(('{0} Quick Access and jump list file(s), {1} taskbar shortcut(s)' -f ($automatic + $custom), $taskbar))

    $sourceStart = [System.IO.Path]::Combine($from.Start, 'start2.bin')
    if ([System.IO.File]::Exists($sourceStart) -and [System.IO.Directory]::Exists($to.Start)) {
        [System.IO.File]::Copy($sourceStart, $targetStart, $true)
        $lines.Add('Start menu pins')
    }
    elseif ([System.IO.File]::Exists($sourceStart)) {
        $lines.Add(('Start menu pins not copied: {0} has not opened its Start menu yet' -f $TargetProfile.Name))
    }

    # --- The taskbar order, from one registry to the other -----------------
    $sourceHive = $null
    $targetHive = $null
    $exported   = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('toolkit-taskband-{0}.reg' -f [guid]::NewGuid()))
    $imported   = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('toolkit-taskband-{0}.reg' -f [guid]::NewGuid()))
    try {
        $sourceHive = Mount-TkUserHive -UserProfile $SourceProfile -MountName 'Toolkit-Source' -Confirm:$false
        $targetHive = Mount-TkUserHive -UserProfile $TargetProfile -MountName 'Toolkit-Target' -Confirm:$false

        if (-not $sourceHive.Ok -or -not $targetHive.Ok) {
            $lines.Add(('taskbar order not copied: {0}' -f (@($sourceHive.Error, $targetHive.Error) | Where-Object { $_ } | Select-Object -First 1)))
        }
        else {
            [void] (Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('export', ('{0}\{1}' -f $targetHive.Short, $key), ([System.IO.Path]::Combine($backup, 'Taskband.reg')), '/y') -TimeoutSeconds 30)
            [void] (Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('export', ('{0}\{1}' -f $sourceHive.Short, $key), $exported, '/y') -TimeoutSeconds 30)

            if (-not [System.IO.File]::Exists($exported)) {
                $lines.Add('no taskbar order to copy')
            }
            else {
                $text = ConvertTo-TkTaskbandHive -Text ([System.IO.File]::ReadAllText($exported)) -From $sourceHive.Root -To $targetHive.Root
                if (Test-TkTaskbandRegFile -Text $text -Hive $targetHive.Root) {
                    [System.IO.File]::WriteAllText($imported, $text, [System.Text.Encoding]::Unicode)
                    $run = Invoke-TkProcess -FilePath 'reg.exe' -ArgumentList @('import', $imported) -TimeoutSeconds 30
                    $lines.Add($(if ($run.ExitCode -eq 0) { 'taskbar order' } else { 'the taskbar order could not be written' }))
                }
                else {
                    $lines.Add('the taskbar order was refused: its .reg text touches more than the taskbar key')
                }
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $exported, $imported -Force -ErrorAction SilentlyContinue
        foreach ($hive in @($sourceHive, $targetHive)) {
            if (-not (Dismount-TkUserHive -Hive $hive -Confirm:$false)) {
                $ok = $false
                $lines.Add(('the registry {0} is still loaded: restart the machine before signing in to that account' -f $hive.Short))
            }
        }
    }

    # --- The copies belong to the destination account -----------------------
    $owner = Set-TkOwnerPath -Path @($to.Automatic, $to.Custom, $to.Taskbar, $targetStart) -Sid $TargetProfile.Sid -Confirm:$false
    if ($owner -gt 0) { $ok = $false; $lines.Add('the owner could not be set on some pins') }

    $lines.Add(('its pins before are saved in {0}' -f $backup))
    return [pscustomobject] @{ Name = 'Pins'; Ok = $ok; Text = ($lines -join '; '); Log = '' }
}

<#
.SYNOPSIS
    Copies the browser bookmarks of one profile into another.

.DESCRIPTION
    Runs in the elevated worker. The bookmarks of the source account are
    exported to a temporary folder as for a package, then imported into
    the destination account's browsers the way a package is: merged into a
    folder named after the source account, never replacing, with the HTML
    file on its desktop. The files written belong to the destination
    account. A browser is only checked for being open when its account is
    signed in.

.OUTPUTS
    PSCustomObject[] with Name, Ok, Text and Log.
#>
function Copy-TkProfileBookmark {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $SourceProfile,
        [Parameter(Mandatory)] [pscustomobject] $TargetProfile
    )

    if (-not $PSCmdlet.ShouldProcess($TargetProfile.Path, 'Copy the browser bookmarks')) { return @() }

    $roots   = { param($userProfile) @{ LocalAppData = [System.IO.Path]::Combine($userProfile.Path, 'AppData\Local'); AppData = [System.IO.Path]::Combine($userProfile.Path, 'AppData\Roaming') } }
    $from    = & $roots $SourceProfile
    $to      = & $roots $TargetProfile
    $leaf    = Split-Path -Path $SourceProfile.Path -Leaf
    $desktop = [string] (@(Get-TkProfileFolder -UserProfile $TargetProfile) | Where-Object Key -eq 'Desktop' | Select-Object -First 1).Path
    $temp    = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('toolkit-bookmarks-{0}' -f [guid]::NewGuid()))
    $rows    = New-Object System.Collections.Generic.List[object]

    try {
        $found = Export-TkMigrationBookmark -Root $temp -Definition @(Get-TkBrowserDefinition @from) -LocalAppData $from.LocalAppData `
                                            -SkipProcessCheck:(-not $SourceProfile.Loaded) -Confirm:$false

        if (@($found.blocked).Count -gt 0) {
            $rows.Add([pscustomobject] @{ Name = 'Bookmarks'; Ok = $false; Log = ''
                                          Text = ('{0} refused access to {1}: export them from the browser (as an HTML file) or use its sync' -f $found.blockedBy, (@($found.blocked) -join ', ')) })
        }
        if (@($found.busy).Count -gt 0) {
            $rows.Add([pscustomobject] @{ Name = 'Bookmarks'; Ok = $false; Log = ''; Text = ('close Firefox in {0} and copy again for {1}' -f $SourceProfile.Name, (@($found.busy) -join ', ')) })
        }
        if ($found.duckduckgo) {
            $rows.Add([pscustomobject] @{ Name = 'Bookmarks: DuckDuckGo'; Ok = $true; Log = ''; Text = 'its own store is not copied: use its Sync and Backup, or import the HTML file' })
        }

        if (@($found.copied).Count -eq 0) {
            if ($rows.Count -eq 0) { $rows.Add([pscustomobject] @{ Name = 'Bookmarks'; Ok = $true; Text = 'no browser profile with bookmarks was found'; Log = '' }) }
        }
        else {
            $done = @(Import-TkMigrationBookmark -Root $temp -Computer $leaf -Desktop $desktop -Definition @(Get-TkBrowserDefinition @to) `
                                                 -SkipProcessCheck:(-not $TargetProfile.Loaded) -Confirm:$false)
            foreach ($item in $done) {
                $owner = Set-TkOwnerPath -Path @($item.Created) -Sid $TargetProfile.Sid -Confirm:$false
                $rows.Add([pscustomobject] @{ Name = ('Bookmarks: {0}' -f $item.Browser); Ok = ($item.Ok -and $owner -eq 0); Text = $item.Text; Log = '' })
            }
        }
    }
    finally {
        # The export held another account's bookmarks: it does not outlive the copy.
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }

    return @($rows.ToArray())
}

<#
.SYNOPSIS
    Runs a copy to another profile: the folders, then the pins and the bookmarks.

.OUTPUTS
    PSCustomObject with Ok, Message and Steps (Name, Ok, Text, Log).
#>
function Invoke-TkProfileCopy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Step = @(),
        [Parameter(Mandatory)] [pscustomobject] $SourceProfile,
        [Parameter(Mandatory)] [pscustomobject] $TargetProfile,
        [Parameter()] [switch] $Move,
        [Parameter()] [switch] $Pins,
        [Parameter()] [switch] $Bookmarks
    )

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $PSCmdlet.ShouldProcess($TargetProfile.Path, 'Copy from another profile')) {
        return [pscustomobject] @{ Ok = $false; Message = 'Cancelled.'; Steps = @() }
    }

    if (@($Step | Where-Object { $_ }).Count -gt 0) {
        $copied = Copy-TkProfileData -Step @($Step) -Sid $TargetProfile.Sid -AccountName $TargetProfile.Name -Move:$Move -Confirm:$false
        foreach ($item in @($copied.Steps)) { $rows.Add($item) }
    }
    if ($Pins) { $rows.Add((Copy-TkProfilePin -SourceProfile $SourceProfile -TargetProfile $TargetProfile -Confirm:$false)) }
    if ($Bookmarks) { foreach ($item in @(Copy-TkProfileBookmark -SourceProfile $SourceProfile -TargetProfile $TargetProfile -Confirm:$false)) { $rows.Add($item) } }

    $good = @($rows | Where-Object Ok).Count
    return [pscustomobject] @{
        Ok      = ($rows.Count -gt 0 -and $good -eq $rows.Count)
        Message = ('{0} of {1} item(s) done for {2} without a problem.' -f $good, $rows.Count, $TargetProfile.Name)
        Steps   = @($rows.ToArray())
    }
}
