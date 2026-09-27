<#
    Toolkit - Features / Migration: browser bookmarks

    Signed in to its browser, a user gets the bookmarks back by themselves.
    Many are not signed in. The export copies the bookmark files of Edge,
    Chrome, Brave and Firefox, and writes one bookmarks.html in the format
    every browser imports, DuckDuckGo included, whose own store is not a
    documented file. The import merges the Chromium bookmarks into a folder
    of the same browser on the new machine, never replacing what is there.

    Some security products (ESET among them) refuse every read of browser
    data by any other program, to stop credential stealers. The toolkit does
    not try to get around that: it says which product refused, and points at
    the browser's own export or its sync instead.
#>

<#
.SYNOPSIS
    The browsers the migration handles, and where each keeps its profiles.

.OUTPUTS
    PSCustomObject[] with Name, Kind, Root, File and Process.
#>
function Get-TkBrowserDefinition {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA,
        [Parameter()] [string] $AppData = $env:APPDATA
    )

    return @(
        [pscustomobject] @{ Name = 'Edge';    Kind = 'Chromium'; Root = [System.IO.Path]::Combine($LocalAppData, 'Microsoft\Edge\User Data');                File = 'Bookmarks';     Process = 'msedge' }
        [pscustomobject] @{ Name = 'Chrome';  Kind = 'Chromium'; Root = [System.IO.Path]::Combine($LocalAppData, 'Google\Chrome\User Data');                 File = 'Bookmarks';     Process = 'chrome' }
        [pscustomobject] @{ Name = 'Brave';   Kind = 'Chromium'; Root = [System.IO.Path]::Combine($LocalAppData, 'BraveSoftware\Brave-Browser\User Data');   File = 'Bookmarks';     Process = 'brave' }
        [pscustomobject] @{ Name = 'Firefox'; Kind = 'Firefox';  Root = [System.IO.Path]::Combine($AppData, 'Mozilla\Firefox\Profiles');                   File = 'places.sqlite'; Process = 'firefox' }
    )
}

<#
.SYNOPSIS
    Says whether the DuckDuckGo browser is installed for this account.

.OUTPUTS
    System.Boolean
#>
function Test-TkDuckDuckGoInstalled {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA
    )

    return [bool] @(Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($LocalAppData, 'Packages')) -Directory -Filter 'DuckDuckGo.DesktopBrowser*' -ErrorAction SilentlyContinue).Count
}

<#
.SYNOPSIS
    Decompresses a Firefox .jsonlz4 bookmark backup.

.DESCRIPTION
    Pure. The mozLz40 format is an 8-byte magic, the decompressed size, then
    one LZ4 block: runs of literal bytes, each followed by a copy of earlier
    output given as an offset and a length.

.OUTPUTS
    System.String, the JSON text.
#>
function ConvertFrom-TkMozLz4 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -lt 12 -or [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 8) -ne "mozLz40`0") {
        throw 'Not a mozLz4 file.'
    }

    $size   = [BitConverter]::ToUInt32($Bytes, 8)
    $output = New-Object byte[] $size
    $in     = 12
    $out    = 0

    while ($in -lt $Bytes.Length) {

        $token   = $Bytes[$in]; $in++
        $literal = $token -shr 4

        if ($literal -eq 15) {
            do { $extra = $Bytes[$in]; $in++; $literal += $extra } while ($extra -eq 255)
        }

        if ($out + $literal -gt $size -or $in + $literal -gt $Bytes.Length) { throw 'The mozLz4 data is damaged.' }
        [Array]::Copy($Bytes, $in, $output, $out, $literal)
        $in  += $literal
        $out += $literal

        if ($in -ge $Bytes.Length) { break }

        $offset = [int] $Bytes[$in] -bor ([int] $Bytes[$in + 1] -shl 8)
        $in    += 2
        $match  = $token -band 15

        if ($match -eq 15) {
            do { $extra = $Bytes[$in]; $in++; $match += $extra } while ($extra -eq 255)
        }
        $match += 4

        $from = $out - $offset
        if ($offset -eq 0 -or $from -lt 0 -or $out + $match -gt $size) { throw 'The mozLz4 data is damaged.' }

        # Byte by byte: a copy may overlap the bytes it is writing.
        for ($k = 0; $k -lt $match; $k++) { $output[$out + $k] = $output[$from + $k] }
        $out += $match
    }

    return [System.Text.Encoding]::UTF8.GetString($output, 0, $out)
}

<#
.SYNOPSIS
    Reads a Chromium Bookmarks file into folders and links.

.OUTPUTS
    PSCustomObject[] of nodes: Title, Url (empty for a folder), Children.
#>
function ConvertFrom-TkChromiumBookmark {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Json
    )

    $data = $Json | ConvertFrom-Json

    $walk = $null
    $walk = {
        param($node)
        if ([string] $node.type -eq 'url') {
            return [pscustomobject] @{ Title = [string] $node.name; Url = [string] $node.url; Children = @() }
        }
        return [pscustomobject] @{ Title = [string] $node.name; Url = ''; Children = @(@($node.children) | Where-Object { $_ } | ForEach-Object { & $walk $_ }) }
    }

    $labels = [ordered] @{ bookmark_bar = 'Bookmarks bar'; other = 'Other bookmarks'; synced = 'Mobile bookmarks' }

    return @(foreach ($key in $labels.Keys) {
        $root = $data.roots.$key
        if ($root -and @($root.children).Count -gt 0) {
            $node = & $walk $root
            $node.Title = $labels[$key]
            $node
        }
    })
}

<#
.SYNOPSIS
    Reads a Firefox bookmark backup (JSON) into folders and links.

.OUTPUTS
    PSCustomObject[] of nodes: Title, Url, Children.
#>
function ConvertFrom-TkFirefoxBookmark {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Json
    )

    $data   = $Json | ConvertFrom-Json
    $labels = @{ menu = 'Bookmarks menu'; toolbar = 'Bookmarks toolbar'; unfiled = 'Other bookmarks'; mobile = 'Mobile bookmarks' }

    $walk = $null
    $walk = {
        param($node)
        switch ([string] $node.type) {
            'text/x-moz-place' { return [pscustomobject] @{ Title = [string] $node.title; Url = [string] $node.uri; Children = @() } }
            'text/x-moz-place-container' {
                return [pscustomobject] @{ Title = [string] $node.title; Url = ''; Children = @(@($node.children) | Where-Object { $_ } | ForEach-Object { & $walk $_ } | Where-Object { $_ }) }
            }
            default { return $null }
        }
    }

    return @(foreach ($root in @($data.children)) {
        if (@($root.children).Count -eq 0) { continue }
        $node = & $walk $root
        if ($labels.ContainsKey([string] $root.title)) { $node.Title = $labels[[string] $root.title] }
        $node
    })
}

<#
.SYNOPSIS
    Writes bookmarks as the HTML file every browser imports.

.DESCRIPTION
    Pure. The Netscape bookmark format, with every title and address escaped.

.PARAMETER Group
    Objects with Title (the browser and profile) and Nodes.

.OUTPUTS
    System.String
#>
function ConvertTo-TkBookmarkHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Group = @()
    )

    $escape  = { param($text) [System.Net.WebUtility]::HtmlEncode([string] $text) }
    $builder = New-Object System.Text.StringBuilder
    [void] $builder.AppendLine('<!DOCTYPE NETSCAPE-Bookmark-file-1>')
    [void] $builder.AppendLine('<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">')
    [void] $builder.AppendLine('<TITLE>Bookmarks</TITLE>')
    [void] $builder.AppendLine('<H1>Bookmarks</H1>')
    [void] $builder.AppendLine('<DL><p>')

    $write = $null
    $write = {
        param($node, $depth)
        $pad = '    ' * $depth
        if ($node.Url) {
            [void] $builder.AppendLine(('{0}<DT><A HREF="{1}">{2}</A>' -f $pad, (& $escape $node.Url), (& $escape $node.Title)))
        }
        else {
            [void] $builder.AppendLine(('{0}<DT><H3>{1}</H3>' -f $pad, (& $escape $node.Title)))
            [void] $builder.AppendLine(('{0}<DL><p>' -f $pad))
            foreach ($child in @($node.Children)) { & $write $child ($depth + 1) }
            [void] $builder.AppendLine(('{0}</DL><p>' -f $pad))
        }
    }

    foreach ($item in ($Group | Where-Object { $_ })) {
        & $write ([pscustomobject] @{ Title = $item.Title; Url = ''; Children = @($item.Nodes) }) 1
    }

    [void] $builder.AppendLine('</DL><p>')
    return $builder.ToString()
}

<#
.SYNOPSIS
    Merges Chromium bookmarks into another Chromium Bookmarks file, in a folder of their own.

.DESCRIPTION
    Pure. The imported bookmarks go into a new folder under "Other
    bookmarks", with fresh ids and GUIDs so they cannot collide with the
    ones already there; nothing already there is changed. The checksum is
    dropped, since the browser recomputes it.

.OUTPUTS
    System.String, the merged JSON.
#>
function Merge-TkChromiumBookmark {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $TargetJson,
        [Parameter(Mandatory)] [string] $SourceJson,
        [Parameter(Mandatory)] [string] $FolderName,
        [Parameter()] [datetime] $Now = (Get-Date)
    )

    $target = $TargetJson | ConvertFrom-Json
    $source = $SourceJson | ConvertFrom-Json

    $ids = New-Object System.Collections.Generic.List[long]
    $collect = $null
    $collect = {
        param($node)
        $value = 0L
        if ($node.PSObject.Properties['id'] -and [long]::TryParse([string] $node.id, [ref] $value)) { $ids.Add($value) }
        foreach ($child in @($node.children)) { if ($child) { & $collect $child } }
    }
    foreach ($property in $target.roots.PSObject.Properties) { & $collect $property.Value }

    # A hashtable, so the recursive copy below shares one counter.
    $counter = @{ Next = $(if ($ids.Count -gt 0) { [long] ($ids | Measure-Object -Maximum).Maximum + 1 } else { 1L }) }
    $stamp = [string] ([long] ($Now.ToUniversalTime().ToFileTimeUtc() / 10))

    $copy = $null
    $copy = {
        param($node)
        $id = [string] $counter.Next
        $counter.Next++
        $added = if ($node.PSObject.Properties['date_added'] -and $node.date_added) { [string] $node.date_added } else { $stamp }

        if ([string] $node.type -eq 'url') {
            return [pscustomobject] [ordered] @{ date_added = $added; guid = [guid]::NewGuid().ToString(); id = $id; name = [string] $node.name; type = 'url'; url = [string] $node.url }
        }

        return [pscustomobject] [ordered] @{
            children      = @(@($node.children) | Where-Object { $_ } | ForEach-Object { & $copy $_ })
            date_added    = $added
            date_modified = $stamp
            guid          = [guid]::NewGuid().ToString()
            id            = $id
            name          = [string] $node.name
            type          = 'folder'
        }
    }

    $children = foreach ($key in @('bookmark_bar', 'other', 'synced')) {
        $root = $source.roots.$key
        if ($root -and @($root.children).Count -gt 0) {
            $folder = & $copy $root
            $folder.name = @{ bookmark_bar = 'Bookmarks bar'; other = 'Other bookmarks'; synced = 'Mobile bookmarks' }[$key]
            $folder
        }
    }

    $imported = [pscustomobject] [ordered] @{
        children      = @($children)
        date_added    = $stamp
        date_modified = $stamp
        guid          = [guid]::NewGuid().ToString()
        id            = [string] $counter.Next
        name          = $FolderName
        type          = 'folder'
    }

    $target.roots.other.children = @(@($target.roots.other.children) | Where-Object { $_ }) + $imported
    [void] $target.PSObject.Properties.Remove('checksum')

    return ($target | ConvertTo-Json -Depth 100)
}

<#
.SYNOPSIS
    Names the security products running, for the message when one refuses access.

.OUTPUTS
    System.String
#>
function Get-TkBlockingProductName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $names = @(try { Get-TkAntivirusProduct | Where-Object { $_.RealTimeEnabled -and $_.Name -notmatch 'Windows Defender|Microsoft Defender' } | ForEach-Object { $_.Name } } catch { @() })
    return $(if ($names.Count -gt 0) { $names -join ', ' } else { 'a security product' })
}

<#
.SYNOPSIS
    Copies the bookmarks of every browser profile into the package, and writes bookmarks.html.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary, the manifest section:
    copied, blocked (with the product that refused), busy, html, duckduckgo.
#>
function Export-TkMigrationBookmark {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter()] [object[]] $Definition = @(Get-TkBrowserDefinition),
        [Parameter()] [string] $LocalAppData = $env:LOCALAPPDATA,
        [Parameter()] [switch] $SkipProcessCheck
    )

    $folder = [System.IO.Path]::Combine($Root, 'bookmarks')

    if (-not $PSCmdlet.ShouldProcess($folder, 'Copy the browser bookmarks')) {
        return [ordered] @{}
    }

    $copied  = New-Object System.Collections.Generic.List[string]
    $blocked = New-Object System.Collections.Generic.List[string]
    $busy    = New-Object System.Collections.Generic.List[string]
    $groups  = New-Object System.Collections.Generic.List[object]

    foreach ($browser in $Definition) {

        foreach ($profileFolder in @(Get-ChildItem -LiteralPath $browser.Root -Directory -ErrorAction SilentlyContinue)) {

            $file = [System.IO.Path]::Combine($profileFolder.FullName, $browser.File)
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }

            $label  = '{0} - {1}' -f $browser.Name, $profileFolder.Name
            $target = [System.IO.Path]::Combine($folder, $browser.Name, $profileFolder.Name)

            # Firefox keeps places.sqlite open while it runs; a copy then is not consistent.
            if ($browser.Kind -eq 'Firefox' -and -not $SkipProcessCheck -and (Get-Process -Name $browser.Process -ErrorAction SilentlyContinue)) {
                $busy.Add($label)
                continue
            }

            try {
                New-Item -ItemType Directory -Path $target -Force | Out-Null
                [System.IO.File]::Copy($file, [System.IO.Path]::Combine($target, $browser.File), $true)
                $copied.Add($label)

                if ($browser.Kind -eq 'Chromium') {
                    $groups.Add([pscustomobject] @{ Title = $label; Nodes = @(ConvertFrom-TkChromiumBookmark -Json ([System.IO.File]::ReadAllText([System.IO.Path]::Combine($target, $browser.File)))) })
                }
                else {
                    $backup = @(Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($profileFolder.FullName, 'bookmarkbackups')) -Filter '*.jsonlz4' -File -ErrorAction SilentlyContinue |
                                Sort-Object LastWriteTime -Descending) | Select-Object -First 1
                    if ($backup) {
                        $bytes = [System.IO.File]::ReadAllBytes($backup.FullName)
                        [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($target, 'bookmarks.jsonlz4'), $bytes)
                        $groups.Add([pscustomobject] @{ Title = $label; Nodes = @(ConvertFrom-TkFirefoxBookmark -Json (ConvertFrom-TkMozLz4 -Bytes $bytes)) })
                    }
                }
            }
            catch [System.UnauthorizedAccessException] {
                $blocked.Add($label)
            }
            catch {
                if ($_.Exception.InnerException -is [System.UnauthorizedAccessException] -or $_.Exception -is [System.UnauthorizedAccessException]) { $blocked.Add($label) }
                else { Write-TkLog -Level Warning -Category 'Migration' -Message ('{0}: {1}' -f $label, $_.Exception.Message) }
            }
        }
    }

    $html = ''
    if ($groups.Count -gt 0) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        [System.IO.File]::WriteAllText([System.IO.Path]::Combine($folder, 'bookmarks.html'), (ConvertTo-TkBookmarkHtml -Group @($groups.ToArray())), (New-Object System.Text.UTF8Encoding($false)))
        $html = 'bookmarks\bookmarks.html'
    }

    return [ordered] @{
        copied     = @($copied.ToArray())
        blocked    = @($blocked.ToArray())
        blockedBy  = $(if ($blocked.Count -gt 0) { Get-TkBlockingProductName } else { '' })
        busy       = @($busy.ToArray())
        html       = $html
        duckduckgo = (Test-TkDuckDuckGoInstalled -LocalAppData $LocalAppData)
    }
}

<#
.SYNOPSIS
    Reads the bookmarks part of a package, from its fixed layout.

.OUTPUTS
    PSCustomObject with Folder, Html and Files (Browser, Profile, Path), or $null.
#>
function Read-TkMigrationBookmark {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter()] [object[]] $Definition = @(Get-TkBrowserDefinition)
    )

    $folder = [System.IO.Path]::Combine($Root, 'bookmarks')
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return $null }

    $files = foreach ($browser in $Definition) {
        foreach ($profileFolder in @(Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($folder, $browser.Name)) -Directory -ErrorAction SilentlyContinue)) {
            if ($profileFolder.Name -notmatch '^[A-Za-z0-9 ._-]{1,64}$') { continue }
            $path = [System.IO.Path]::Combine($profileFolder.FullName, $browser.File)
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [pscustomobject] @{ Browser = $browser.Name; Kind = $browser.Kind; Profile = $profileFolder.Name; Path = $path }
            }
        }
    }

    $html = [System.IO.Path]::Combine($folder, 'bookmarks.html')

    return [pscustomobject] @{ Folder = $folder; Html = $(if (Test-Path -LiteralPath $html) { $html } else { '' }); Files = @($files) }
}

<#
.SYNOPSIS
    Puts the bookmarks of a package into the browsers of this machine.

.DESCRIPTION
    Chromium bookmarks are merged into the same browser, into its Default
    profile, in a folder named after the old machine; the file there is
    saved beside it first. A browser that is open is skipped, since it would
    write its own file back on closing. Firefox bookmarks replace nothing: a
    Firefox that already has its database keeps it, and gets the HTML file.
    The HTML file is put on the desktop, never over another file.

.OUTPUTS
    PSCustomObject[] with Browser, Ok, Text and Created (the files it wrote).
#>
function Import-TkMigrationBookmark {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter()] [string] $Computer = 'the old PC',
        [Parameter()] [string] $Desktop = [Environment]::GetFolderPath('Desktop'),
        [Parameter()] [object[]] $Definition = @(Get-TkBrowserDefinition),
        [Parameter()] [switch] $SkipProcessCheck
    )

    $package = Read-TkMigrationBookmark -Root $Root -Definition $Definition
    $results = New-Object System.Collections.Generic.List[object]
    if (-not $package) { return @() }

    if (-not $PSCmdlet.ShouldProcess('the browsers of this account', 'Merge the bookmarks')) { return @() }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $name  = 'Imported from {0} ({1:yyyy-MM-dd})' -f $Computer, (Get-Date)

    foreach ($file in @($package.Files)) {

        $browser = @($Definition | Where-Object Name -eq $file.Browser) | Select-Object -First 1
        $label   = '{0} ({1})' -f $file.Browser, $file.Profile

        if (-not $SkipProcessCheck -and (Get-Process -Name $browser.Process -ErrorAction SilentlyContinue)) {
            $results.Add([pscustomobject] @{ Browser = $label; Ok = $false; Text = ('{0} is open: close it and import again.' -f $file.Browser); Created = @() })
            continue
        }

        try {
            if ($file.Kind -eq 'Chromium') {
                $profileDir = [System.IO.Path]::Combine($browser.Root, 'Default')
                if (-not (Test-Path -LiteralPath $profileDir -PathType Container)) {
                    $results.Add([pscustomobject] @{ Browser = $label; Ok = $false; Text = ('Open {0} once on this machine, close it, then import again; or use the HTML file.' -f $file.Browser); Created = @() })
                    continue
                }

                $target = [System.IO.Path]::Combine($profileDir, 'Bookmarks')
                $source = [System.IO.File]::ReadAllText($file.Path)

                if (Test-Path -LiteralPath $target) {
                    $saved = '{0}.toolkit-{1}.bak' -f $target, $stamp
                    [System.IO.File]::Copy($target, $saved, $false)
                    $merged = Merge-TkChromiumBookmark -TargetJson ([System.IO.File]::ReadAllText($target)) -SourceJson $source -FolderName ('{0} - {1}' -f $name, $file.Profile)
                    [System.IO.File]::WriteAllText($target, $merged, (New-Object System.Text.UTF8Encoding($false)))
                    $results.Add([pscustomobject] @{ Browser = $label; Ok = $true; Text = ('Merged into "{0}", under Other bookmarks; the bookmarks there were saved beside the file first.' -f $name); Created = @($saved) })
                }
                else {
                    [System.IO.File]::Copy($file.Path, $target, $false)
                    $results.Add([pscustomobject] @{ Browser = $label; Ok = $true; Text = 'Copied: this browser had no bookmarks yet.'; Created = @($target) })
                }
            }
            else {
                $profileDir = @(Get-ChildItem -LiteralPath $browser.Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*.default-release' }) | Select-Object -First 1
                if ($profileDir -and -not (Test-Path -LiteralPath ([System.IO.Path]::Combine($profileDir.FullName, 'places.sqlite')))) {
                    $places = [System.IO.Path]::Combine($profileDir.FullName, 'places.sqlite')
                    [System.IO.File]::Copy($file.Path, $places, $false)
                    $results.Add([pscustomobject] @{ Browser = $label; Ok = $true; Text = 'Copied into the Firefox profile, which had no bookmarks yet.'; Created = @($places) })
                }
                else {
                    $results.Add([pscustomobject] @{ Browser = $label; Ok = $false; Text = 'Firefox already has its bookmarks here and they are not replaced: import the HTML file (Bookmarks, Manage bookmarks, Import and backup).'; Created = @() })
                }
            }
        }
        catch {
            $denied = $_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.InnerException -is [System.UnauthorizedAccessException]
            $results.Add([pscustomobject] @{ Browser = $label; Ok = $false; Text = $(if ($denied) { '{0} refused access to the browser files: use the HTML file, or ask for an exception.' -f (Get-TkBlockingProductName) } else { $_.Exception.Message }); Created = @() })
        }
    }

    if ($package.Html -and (Test-Path -LiteralPath $Desktop -PathType Container)) {
        $copy = [System.IO.Path]::Combine($Desktop, ('Bookmarks from {0}.html' -f $Computer))
        $n = 1
        while (Test-Path -LiteralPath $copy) { $n++; $copy = [System.IO.Path]::Combine($Desktop, ('Bookmarks from {0} ({1}).html' -f $Computer, $n)) }
        [System.IO.File]::Copy($package.Html, $copy, $false)
        $results.Add([pscustomobject] @{ Browser = 'HTML file'; Ok = $true; Text = ('{0} is on the desktop: any browser imports it, DuckDuckGo included (Settings, Import bookmarks).' -f (Split-Path -Path $copy -Leaf)); Created = @($copy) })
    }

    Add-TkJournalEntry -Name 'Migration bookmarks imported' -Category 'Migration' -Detail ((@($results | ForEach-Object { '{0}: {1}' -f $_.Browser, $_.Text })) -join '; ')

    return @($results.ToArray())
}
