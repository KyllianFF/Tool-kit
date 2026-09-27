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
        [Parameter()] [switch] $SkipSourceCheck
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

        if ($steps.Count -eq 0 -and $errors.Count -eq 0) {
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
