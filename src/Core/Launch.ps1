<#
    Toolkit - Core / Launch

    The one liner runs whatever its address serves. Two things make that
    defensible: an address that does not move (a release tag rather than
    main), and an SHA-256 checked before the downloaded text runs.

    The verified launch command below does both in memory, with no file
    written: it downloads the bytes, hashes them, and runs them only when the
    hash is the expected one. It then hands its address and its hash to the
    toolkit, so that Restart as administrator and every per-action UAC prompt
    replay the same check. The elevated process runs the same build, or
    nothing.

    The address and the hash end up inside a command line that an elevated
    process runs, so both are checked against a strict form first: a quote,
    a space or a dollar sign in either could otherwise change that command.
#>

<#
.SYNOPSIS
    Says whether an address may be replayed to start the toolkit.

.DESCRIPTION
    Pure. HTTPS only, and only the characters a published file address
    needs: no quote, space, semicolon, dollar sign or backtick, since the
    address is written into a command line.

.OUTPUTS
    System.Boolean
#>
function Test-TkSourceUri {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Uri
    )

    return ($Uri -cmatch '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%+/-]*)?$')
}

<#
.SYNOPSIS
    Says whether a text is an SHA-256 written in hexadecimal.

.OUTPUTS
    System.Boolean
#>
function Test-TkSha256Text {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    return ($Value -match '^[A-Fa-f0-9]{64}$')
}

<#
.SYNOPSIS
    Writes a value as a single-quoted PowerShell string.

.DESCRIPTION
    Pure. The language's own escaping, which also doubles the typographic
    quotes PowerShell reads as single quotes, so no value can close the
    string early.

.OUTPUTS
    System.String
#>
function ConvertTo-TkPsLiteral {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    return "'{0}'" -f [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Value)
}

<#
.SYNOPSIS
    Builds the PowerShell command that starts the toolkit from an address.

.DESCRIPTION
    Pure. Without a hash: the plain one liner, or its script block form when
    parameters follow. With a hash: the verified launch, which downloads the
    bytes, checks their SHA-256 and runs them only on a match, all in memory,
    then passes -SourceUri and -ExpectedSha256 on so an elevation replays the
    same check. The command holds no double quote, so it can be handed to
    powershell.exe -Command as one argument.

.PARAMETER SourceUri
    The HTTPS address of the build.

.PARAMETER Sha256
    The expected SHA-256 of the build, or empty.

.PARAMETER Parameter
    Named parameters for the toolkit, in order, such as RunAction.

.OUTPUTS
    System.String
#>
function New-TkLaunchCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $SourceUri,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Sha256 = '',

        [Parameter()]
        [System.Collections.IDictionary] $Parameter = @{}
    )

    if (-not (Test-TkSourceUri -Uri $SourceUri)) {
        throw ('Not an address a launch command can carry: {0}' -f $SourceUri)
    }

    if ($Sha256 -and -not (Test-TkSha256Text -Value $Sha256)) {
        throw 'The expected hash is not an SHA-256.'
    }

    $extra = New-Object System.Text.StringBuilder

    foreach ($key in $Parameter.Keys) {

        if ([string] $key -notmatch '^[A-Za-z][A-Za-z0-9]*$') {
            throw ('Not a parameter name: {0}' -f $key)
        }

        [void] $extra.AppendFormat(' -{0} {1}', $key, (ConvertTo-TkPsLiteral -Value ([string] $Parameter[$key])))
    }

    if (-not $Sha256) {

        if ($extra.Length -eq 0) {
            return ('irm {0} | iex' -f (ConvertTo-TkPsLiteral -Value $SourceUri))
        }

        return ('& ([scriptblock]::Create((irm {0}))){1}' -f (ConvertTo-TkPsLiteral -Value $SourceUri), $extra.ToString())
    }

    $template = '$u = {0}; $h = {1}; ' +
                '$b = (Invoke-WebRequest -Uri $u -UseBasicParsing).RawContentStream.ToArray(); ' +
                'if (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)) -replace ''-'') -ne $h) ' +
                '{{ throw ''SHA-256 mismatch: this is not the expected build, and nothing was run.'' }}; ' +
                '& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) -SourceUri $u -ExpectedSha256 $h{2}'

    return ($template -f (ConvertTo-TkPsLiteral -Value $SourceUri), (ConvertTo-TkPsLiteral -Value $Sha256.ToUpperInvariant()), $extra.ToString())
}

<#
.SYNOPSIS
    The arguments that start PowerShell again on the same toolkit.

.DESCRIPTION
    Pure. A script file is run again with -File. A download is started again
    with the launch command, verified when a hash is known.

.PARAMETER EntryScript
    The script file the operator ran, or empty.

.PARAMETER Parameter
    Named parameters for the toolkit, in order.

.PARAMETER Sta
    Adds -STA, which Windows PowerShell needs for the window.

.OUTPUTS
    System.String[]
#>
function Get-TkRelaunchArgument {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $EntryScript = '',
        [Parameter()] [AllowEmptyString()] [string] $SourceUri = '',
        [Parameter()] [AllowEmptyString()] [string] $Sha256 = '',
        [Parameter()] [System.Collections.IDictionary] $Parameter = @{},
        [Parameter()] [switch] $Sta
    )

    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    if ($Sta) { $arguments += '-STA' }

    if ($EntryScript) {
        $arguments += @('-File', ('"{0}"' -f $EntryScript))
        foreach ($key in $Parameter.Keys) {
            $arguments += @(('-{0}' -f $key), ('"{0}"' -f $Parameter[$key]))
        }
        return $arguments
    }

    return ($arguments + @('-Command', ('"{0}"' -f (New-TkLaunchCommand -SourceUri $SourceUri -Sha256 $Sha256 -Parameter $Parameter))))
}

<#
.SYNOPSIS
    Says where this instance came from, and what was checked about it.

.DESCRIPTION
    A file is described with its Authenticode signature. A download is
    described with its address: pinned to a release, or following main, and
    whether its SHA-256 is checked again at every elevation. The toolkit
    cannot hash its own running text, so a hash is reported as the expected
    one the launch command checked, never as one it measured itself.

.OUTPUTS
    PSCustomObject with Kind (File, Verified, Remote, Unknown), Source,
    Sha256, Pinned, CanCopy and Text.
#>
function Get-TkLaunchProvenance {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [hashtable] $Context = (Get-TkContext),

        [Parameter()]
        [scriptblock] $Signature = { param($path) Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop }
    )

    $make = {
        param($kind, $source, $sha, $pinned, $text)
        [pscustomobject] @{ Kind = $kind; Source = [string] $source; Sha256 = [string] $sha; Pinned = [bool] $pinned; CanCopy = ($kind -eq 'Verified'); Text = $text }
    }

    if ($Context.EntryScript) {

        $signed = try { & $Signature $Context.EntryScript } catch { $null }
        $state  = if (-not $signed) { 'Its signature could not be read.' }
                  elseif ([string] $signed.Status -eq 'Valid') {
                      'Its Authenticode signature is valid: {0} (certificate {1}).' -f ([string] $signed.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1'), $signed.SignerCertificate.Thumbprint
                  }
                  elseif ([string] $signed.Status -eq 'NotSigned') { 'It is not signed.' }
                  else { 'Its signature is not valid ({0}).' -f $signed.Status }

        return (& $make 'File' $Context.EntryScript '' $true ('Run from the file {0}. {1}' -f $Context.EntryScript, $state))
    }

    if ($Context.SourceUri) {

        $moving = [string] $Context.SourceUri -match '/(main|master)/'

        if ($Context.SourceSha256) {
            $where = if ($moving) { 'from main, the latest build' } else { 'pinned to one release' }
            return (& $make 'Verified' $Context.SourceUri $Context.SourceSha256 (-not $moving) (
                'Downloaded {0}: {1}, with the expected SHA-256 {2}. Every elevation downloads it again and runs it only if that hash still matches.' -f
                    $where, $Context.SourceUri, $Context.SourceSha256))
        }

        return (& $make 'Remote' $Context.SourceUri '' (-not $moving) (
            'Downloaded from {0}, with no hash to check: an elevation downloads the address again, which may then serve a newer build. The verified launch command of a release pins the build and checks it.' -f $Context.SourceUri))
    }

    return (& $make 'Unknown' '' '' $false 'Where this instance came from is not known.')
}

<#
.SYNOPSIS
    What identifies the build that produced a document: version, commit,
    where it came from, and its SHA-256 when it is known.

.DESCRIPTION
    Written into what has to say which tool made it, a triage manifest or an
    evidence pack. A file that ran is hashed here; a download carries the
    SHA-256 its launch command checked, never one measured afterwards. Call
    it on the window's thread: a background runspace builds a context of its
    own, which does not know where the toolkit was launched from.

.OUTPUTS
    PSCustomObject with Version, Commit, Source, Sha256 and Proof.
#>
function Get-TkToolkitIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $ctx    = Get-TkContext
    $source = ''
    $sha    = ''
    $how    = ''

    if ($ctx.EntryScript -and [System.IO.File]::Exists([string] $ctx.EntryScript)) {
        $source = [string] $ctx.EntryScript
        $sha    = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $how    = 'The file that ran, hashed when this was written.'
    }
    elseif ($ctx.SourceUri) {
        $source = [string] $ctx.SourceUri
        $sha    = [string] $ctx.SourceSha256
        $how    = if ($sha) { 'Downloaded and run only after this SHA-256 was checked.' } else { 'Downloaded without a pinned SHA-256: the build that ran cannot be proven.' }
    }
    else {
        $how = 'Neither the file nor the address the toolkit was started from is known: the build that ran cannot be proven.'
    }

    return [pscustomobject] @{ Version = [string] $ctx.Version; Commit = [string] $ctx.Commit; Source = $source; Sha256 = $sha; Proof = $how }
}
