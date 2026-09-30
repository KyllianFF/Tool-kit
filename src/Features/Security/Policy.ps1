<#
    Toolkit - Features / Organisation policy

    The audit applies the toolkit's own controls, the same on every machine.
    A policy is what one organisation expects on top of them: the controls it
    does not require, the software a machine must run or must not, the
    administrators that belong, the least Windows build and the oldest patch
    it tolerates, and its exceptions, each with a reason, an owner and the
    day it ends.

    A policy is a signed data pack (Core/DataPack.ps1). It changes nothing on
    the machine and nothing in the findings' results or the score: it adds a
    verdict against the organisation's expectations, and says on each finding
    what the policy makes of it. An exception past its date counts again by
    itself. A policy that cannot be trusted is not applied at all: the audit
    is then the generic one, and says why.
#>

<#
.SYNOPSIS
    The name and version of the policy format this toolkit reads.
#>
function Get-TkPolicySchema {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject] @{ Name = 'toolkit-policy'; Version = '1.0' }
}

<#
.SYNOPSIS
    A value of a policy as a list of trimmed, non-empty texts.
#>
function ConvertTo-TkPolicyList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return , [string[]] @()
    }

    return , [string[]] @(@($Value) | ForEach-Object { ([string] $_).Trim() } | Where-Object { $_ })
}

<#
.SYNOPSIS
    Says whether a text is a wildcard pattern PowerShell can use.
#>
function Test-TkPolicyWildcard {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Pattern
    )

    try {
        [void] ([System.Management.Automation.WildcardPattern]::new($Pattern, [System.Management.Automation.WildcardOptions]::IgnoreCase)).IsMatch('')
        return $true
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Says whether a computer is within an exception's scope.

.DESCRIPTION
    Pure. No pattern means every machine the policy applies to.
#>
function Test-TkPolicyScope {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Computer,

        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $Pattern = @()
    )

    $patterns = @($Pattern | Where-Object { $_ })

    if ($patterns.Count -eq 0) {
        return $true
    }

    return (@($patterns | Where-Object { $Computer -like $_ }).Count -gt 0)
}

<#
.SYNOPSIS
    Checks a policy read from its data pack, and puts it in one shape.

.DESCRIPTION
    Pure. A policy of another format, of a later major version, or without a
    name and a version is refused whole. Inside a policy the toolkit can
    read, an entry it cannot use (a key it does not know, a rule that names
    nothing, an exception without an owner or an end) is left out and named
    in Problems, rather than refusing the rest or guessing what was meant.

.PARAMETER Data
    The hashtable of the data pack.

.PARAMETER Pack
    The data pack it came from, for where it came from and what trusted it.

.OUTPUTS
    PSCustomObject
#>
function ConvertTo-TkPolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Data,

        [Parameter()]
        [AllowNull()]
        $Pack
    )

    $schema = Get-TkPolicySchema

    if ([string] $Data['Schema'] -ne $schema.Name) {
        throw ("It is not a toolkit policy: its Schema is '{0}' where '{1}' was expected." -f [string] $Data['Schema'], $schema.Name)
    }

    $format = [string] $Data['SchemaVersion']

    if ($format -notmatch '^(\d+)\.(\d+)$') {
        throw ("Its SchemaVersion '{0}' is not written major.minor." -f $format)
    }

    if ([int] $Matches[1] -gt [int] ($schema.Version -split '\.')[0]) {
        throw ('It was written for a newer toolkit: policy format {0}, where this one reads {1}.' -f $format, $schema.Version)
    }

    foreach ($field in @('Name', 'Version')) {
        if (-not ([string] $Data[$field]).Trim()) {
            throw ('It has no {0}: a policy is named and versioned, so the journal can say which one was applied.' -f $field)
        }
    }

    $problems = New-Object System.Collections.Generic.List[string]
    $idPattern = '^[A-Z][A-Z0-9_-]{1,31}$'

    $known = @('Schema', 'SchemaVersion', 'Name', 'Version', 'Owner', 'Published', 'Description', 'Audit', 'Administrators', 'Windows', 'Software', 'Exceptions')
    foreach ($key in @($Data.Keys)) {
        if ($known -notcontains [string] $key) {
            $problems.Add(('{0} is not part of the policy format: it was ignored.' -f $key))
        }
    }

    $sections = @{}
    foreach ($name in @('Audit', 'Windows', 'Software')) {
        $value = $Data[$name]
        if ($null -eq $value) {
            $sections[$name] = @{}
        }
        elseif ($value -is [System.Collections.IDictionary]) {
            $sections[$name] = $value
        }
        else {
            $problems.Add(('{0} must be a @{{ }} section: it was ignored.' -f $name))
            $sections[$name] = @{}
        }
    }

    # --- Audit --------------------------------------------------------------
    $audit = $sections['Audit']
    $level = if ($audit['Level']) { [string] $audit['Level'] } else { 'Essential' }
    if (@('Essential', 'Full') -notcontains $level) {
        $problems.Add(('Audit.Level is Essential or Full, not {0}: Essential is used.' -f $level))
        $level = 'Essential'
    }
    $level = (Get-Culture).TextInfo.ToTitleCase($level.ToLowerInvariant())

    $notRequired = New-Object System.Collections.Generic.List[string]
    foreach ($id in (ConvertTo-TkPolicyList -Value $audit['NotRequired'])) {
        $upper = $id.ToUpperInvariant()
        if ($upper -notmatch $idPattern) {
            $problems.Add(('Audit.NotRequired: "{0}" is not a control identifier.' -f $id))
        }
        elseif (-not $notRequired.Contains($upper)) {
            $notRequired.Add($upper)
        }
    }

    $warningsBlock = $false
    if ($null -ne $audit['WarningsBlock']) {
        if ($audit['WarningsBlock'] -is [bool]) {
            $warningsBlock = [bool] $audit['WarningsBlock']
        }
        else {
            $problems.Add('Audit.WarningsBlock is $true or $false: warnings do not block.')
        }
    }

    # --- Windows ------------------------------------------------------------
    $windows = $sections['Windows']
    $whole = {
        param($name, $value, $least, $most)
        if ($null -eq $value) { return 0 }
        if (($value -is [int] -or $value -is [long]) -and $value -ge $least -and $value -le $most) { return [int] $value }
        $problems.Add(('Windows.{0} is a whole number from {1} to {2}: it was ignored.' -f $name, $least, $most))
        return 0
    }
    $minimumBuild = & $whole 'MinimumBuild' $windows['MinimumBuild'] 1 999999
    $maxPatchAge  = & $whole 'MaxPatchAgeDays' $windows['MaxPatchAgeDays'] 1 365

    # --- Software -----------------------------------------------------------
    $software = $sections['Software']
    $rules    = New-Object System.Collections.Generic.List[object]
    $ids      = New-Object System.Collections.Generic.HashSet[string]

    foreach ($kind in @('Required', 'Forbidden')) {

        $number = 0

        foreach ($entry in @($software[$kind] | Where-Object { $null -ne $_ })) {

            $number++
            $where = 'Software.{0} #{1}' -f $kind, $number

            if ($entry -isnot [System.Collections.IDictionary]) {
                $problems.Add(('{0} must be a @{{ }} entry: it was ignored.' -f $where))
                continue
            }

            $package = ([string] $entry['Package']).Trim()
            $service = ([string] $entry['Service']).Trim()
            $name    = ([string] $entry['Name']).Trim()
            if (-not $name) { $name = if ($package) { $package } else { $service } }

            if (-not $package -and -not $service) {
                $problems.Add(('{0} names neither a Package nor a Service: it was ignored.' -f $where))
                continue
            }

            if ($package -and -not (Test-TkPolicyWildcard -Pattern $package)) {
                $problems.Add(('{0}: "{1}" is not a usable wildcard pattern: it was ignored.' -f $where, $package))
                continue
            }

            if ($service -and $service -notmatch '^[A-Za-z0-9_.-][A-Za-z0-9 _.-]{0,79}$') {
                $problems.Add(('{0}: "{1}" is not a service name: it was ignored.' -f $where, $service))
                continue
            }

            $id = ([string] $entry['Id']).Trim().ToUpperInvariant()
            if (-not $id) { $id = 'POL-{0}-{1}' -f $(if ($kind -eq 'Required') { 'REQ' } else { 'BAN' }), $number }

            if ($id -notmatch $idPattern) {
                $problems.Add(('{0}: "{1}" is not an identifier (a letter, then letters, digits, - or _): it was ignored.' -f $where, $id))
                continue
            }

            if (-not $ids.Add($id)) {
                $problems.Add(('{0}: the identifier {1} is already used: it was ignored.' -f $where, $id))
                continue
            }

            $rules.Add([pscustomobject] @{
                Id      = $id
                Kind    = $kind
                Name    = $name
                Package = $package
                Service = $service
                Why     = ([string] $entry['Why']).Trim()
            })
        }
    }

    # --- Exceptions ---------------------------------------------------------
    $exceptions = New-Object System.Collections.Generic.List[object]
    $number     = 0

    foreach ($entry in @($Data['Exceptions'] | Where-Object { $null -ne $_ })) {

        $number++
        $where = 'Exceptions #{0}' -f $number

        if ($entry -isnot [System.Collections.IDictionary]) {
            $problems.Add(('{0} must be a @{{ }} entry: it was ignored.' -f $where))
            continue
        }

        $control = ([string] $entry['Control']).Trim().ToUpperInvariant()
        $reason  = ([string] $entry['Reason']).Trim()
        $owner   = ([string] $entry['Owner']).Trim()
        $ends    = [datetime]::MinValue

        if ($control -notmatch $idPattern) {
            $problems.Add(('{0} names no control: it was ignored.' -f $where))
            continue
        }

        if (-not $reason -or -not $owner) {
            $problems.Add(('{0} ({1}) has no Reason or no Owner: an exception is justified and owned, or it is not one. It was ignored.' -f $where, $control))
            continue
        }

        if (-not [datetime]::TryParseExact(([string] $entry['Expires']).Trim(), 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref] $ends)) {
            $problems.Add(('{0} ({1}) has no Expires date written yyyy-MM-dd: an exception without an end is not accepted. It was ignored.' -f $where, $control))
            continue
        }

        $computers = ConvertTo-TkPolicyList -Value $entry['Computers']
        $unusable  = @($computers | Where-Object { -not (Test-TkPolicyWildcard -Pattern $_) })

        if ($unusable.Count -gt 0) {
            $problems.Add(('{0} ({1}): "{2}" is not a usable wildcard pattern. It was ignored.' -f $where, $control, $unusable[0]))
            continue
        }

        $exceptions.Add([pscustomobject] @{
            Control   = $control
            Computers = $computers
            Reason    = $reason
            Owner     = $owner
            Expires   = $ends.Date
            Ticket    = ([string] $entry['Ticket']).Trim()
        })
    }

    $from = { param($name) if ($Pack -and $Pack.PSObject.Properties[$name]) { [string] $Pack.$name } else { '' } }

    return [pscustomobject] @{
        Name            = ([string] $Data['Name']).Trim()
        Version         = ([string] $Data['Version']).Trim()
        Owner           = ([string] $Data['Owner']).Trim()
        Published       = ([string] $Data['Published']).Trim()
        Description     = ([string] $Data['Description']).Trim()
        SchemaVersion   = $format
        Source          = & $from 'Source'
        Sha256          = & $from 'Sha256'
        VerifiedBy      = & $from 'VerifiedBy'
        Signer          = & $from 'Signer'
        Thumbprint      = & $from 'Thumbprint'
        Level           = $level
        NotRequired     = [string[]] $notRequired.ToArray()
        WarningsBlock   = $warningsBlock
        Administrators  = ConvertTo-TkPolicyList -Value $Data['Administrators']
        MinimumBuild    = $minimumBuild
        MaxPatchAgeDays = $maxPatchAge
        Software        = $rules.ToArray()
        Exceptions      = $exceptions.ToArray()
        Problems        = [string[]] $problems.ToArray()
    }
}

<#
.SYNOPSIS
    What identifies a policy in a report and in the journal.
#>
function Get-TkPolicyIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Policy
    )

    return [pscustomobject] @{
        Name       = $Policy.Name
        Version    = $Policy.Version
        Owner      = $Policy.Owner
        Published  = $Policy.Published
        Source     = $Policy.Source
        Sha256     = $Policy.Sha256
        VerifiedBy = $Policy.VerifiedBy
        Signer     = $Policy.Signer
        Thumbprint = $Policy.Thumbprint
    }
}

<#
.SYNOPSIS
    Says what a policy was trusted by, in a sentence.
#>
function Format-TkPolicyTrust {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Policy
    )

    if ($Policy.VerifiedBy -eq 'Signature') {
        return ('the signature of {0} (certificate {1})' -f $Policy.Signer, $Policy.Thumbprint)
    }

    return ('its pinned SHA-256 {0}' -f $Policy.Sha256)
}

<#
.SYNOPSIS
    Reads, verifies and checks the organisation policy.

.DESCRIPTION
    Never throws. Applied is false, with the reason, when the policy cannot be
    read, is not trusted, or is not a policy this toolkit can apply.

.PARAMETER Source
    A file, a share or an https:// address.

.PARAMETER Trust
    Pinned certificate thumbprints and SHA-256 hashes.

.OUTPUTS
    PSCustomObject with Applied, Reason, Policy and Pack.
#>
function Import-TkOrganisationPolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $Trust = @(),

        [Parameter()]
        [scriptblock] $Signature,

        [Parameter()]
        [scriptblock] $Download
    )

    $read = @{ Source = $Source; Trust = @($Trust) }
    if ($Signature) { $read['Signature'] = $Signature }
    if ($Download)  { $read['Download']  = $Download }

    $pack = Read-TkSignedDataPack @read

    if (-not $pack.Accepted) {
        return [pscustomobject] @{ Applied = $false; Reason = $pack.Reason; Policy = $null; Pack = $pack }
    }

    try {
        $policy = ConvertTo-TkPolicy -Data $pack.Data -Pack $pack
    }
    catch {
        return [pscustomobject] @{ Applied = $false; Reason = ('It is trusted, but it is not a policy this toolkit can apply: {0}' -f $_.Exception.Message); Policy = $null; Pack = $pack }
    }

    return [pscustomobject] @{ Applied = $true; Reason = ''; Policy = $policy; Pack = $pack }
}

<#
.SYNOPSIS
    Reads what the policy's own rules need to know about this machine.

.DESCRIPTION
    Only what the policy asks about: the installed programs when a rule names
    a package, the services it names, the last update when it bounds the
    patch age, the build when it sets a least one. Packages is null when the
    programs could not be read, so a rule on them is not assessed rather than
    failed.
#>
function Get-TkPolicyFact {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Policy
    )

    $packages = $null
    if (@($Policy.Software | Where-Object { $_.Package }).Count -gt 0) {
        try {
            $packages = [string[]] @(Get-TkUninstallEntry | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName } | Sort-Object -Unique)
        }
        catch {
            $packages = $null
        }
    }

    $services = @{}
    foreach ($name in @($Policy.Software | Where-Object { $_.Service } | ForEach-Object { $_.Service } | Select-Object -Unique)) {
        $found = Get-Service -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        $services[$name] = if ($found) { [string] $found.Status } else { '' }
    }

    $lastUpdate = $null
    if ($Policy.MaxPatchAgeDays -gt 0) {
        try {
            $last = Select-TkLastHotFix -HotFix @(Get-HotFix -ErrorAction Stop)
            if ($last) { $lastUpdate = [datetime] $last.InstalledOn }
        }
        catch {
            $lastUpdate = $null
        }
    }

    $build = 0
    if ($Policy.MinimumBuild -gt 0) {
        try { $build = [int] (Get-TkWindowsVersionFact).Build } catch { $build = 0 }
    }

    return [pscustomobject] @{
        Computer   = $env:COMPUTERNAME
        Packages   = $packages
        Services   = $services
        LastUpdate = $lastUpdate
        Build      = $build
    }
}

<#
.SYNOPSIS
    Judges the policy's own rules: software, least build, patch age.

.DESCRIPTION
    Pure. Each rule becomes a finding of the Policy category, shaped as the
    audit's are, so the same cards and the same report show them; they stay
    out of the audit's score, which measures the machine and not the policy.

.PARAMETER Fact
    As returned by Get-TkPolicyFact.

.OUTPUTS
    PSCustomObject[] as built by New-TkAuditFinding.
#>
function Get-TkPolicyRuleFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Policy,

        [Parameter(Mandatory)]
        [pscustomobject] $Fact,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $out = New-Object System.Collections.Generic.List[object]

    foreach ($rule in @($Policy.Software)) {

        $title = '{0}: {1}' -f $rule.Kind, $rule.Name
        $make  = {
            param($status, $measured, $detail)
            New-TkAuditFinding -Id $rule.Id -Name $title -Category 'Policy' -Status $status -Measured $measured -Detail $detail -Recommendation $rule.Why
        }

        if ($rule.Package -and $null -eq $Fact.Packages) {
            $out.Add((& $make 'NotAssessed' 'Not readable' 'The installed programs could not be read.'))
            continue
        }

        $matched = @(if ($rule.Package) { @($Fact.Packages | Where-Object { $_ -like $rule.Package }) })
        $state   = if ($rule.Service) { [string] $Fact.Services[$rule.Service] } else { '' }

        if ($rule.Kind -eq 'Required') {

            $missing = New-Object System.Collections.Generic.List[string]
            if ($rule.Package -and $matched.Count -eq 0) {
                $missing.Add(('no installed program matches {0}' -f $rule.Package))
            }
            if ($rule.Service -and $state -ne 'Running') {
                $missing.Add($(if ($state) { 'the {0} service is {1}' -f $rule.Service, $state.ToLowerInvariant() } else { 'there is no {0} service' -f $rule.Service }))
            }

            if ($missing.Count -gt 0) {
                $out.Add((& $make 'Fail' $(if ($state -and $matched.Count -gt 0) { 'Not running' } else { 'Missing' }) ('Required by the policy, but {0}.' -f ($missing -join ', and '))))
                continue
            }

            $seen = New-Object System.Collections.Generic.List[string]
            if ($matched.Count -gt 0) { $seen.Add(('installed as {0}' -f ((@($matched | Select-Object -First 3)) -join ', '))) }
            if ($rule.Service) { $seen.Add(('the {0} service runs' -f $rule.Service)) }
            $out.Add((& $make 'Pass' 'Present' ('Required by the policy: {0}.' -f ($seen -join ', and '))))
            continue
        }

        $found = New-Object System.Collections.Generic.List[string]
        if ($matched.Count -gt 0) { $found.Add(('installed as {0}' -f ((@($matched | Select-Object -First 3)) -join ', '))) }
        if ($state) { $found.Add(('the {0} service exists ({1})' -f $rule.Service, $state.ToLowerInvariant())) }

        if ($found.Count -gt 0) {
            $out.Add((& $make 'Fail' 'Present' ('Forbidden by the policy, and {0}.' -f ($found -join ', and '))))
        }
        else {
            $out.Add((& $make 'Pass' 'Absent' 'Forbidden by the policy, and not found here.'))
        }
    }

    if ($Policy.MinimumBuild -gt 0) {

        $out.Add($(
            if (-not $Fact.Build) {
                New-TkAuditFinding -Id 'POL-WIN-BUILD' -Name 'Windows build' -Category 'Policy' -Status 'NotAssessed' -Measured 'Not readable' -Detail 'The Windows build could not be read.'
            }
            elseif ($Fact.Build -lt $Policy.MinimumBuild) {
                New-TkAuditFinding -Id 'POL-WIN-BUILD' -Name 'Windows build' -Category 'Policy' -Status 'Fail' -Measured ('Build {0}' -f $Fact.Build) `
                    -Detail ('The policy asks for Windows build {0} or later, and this machine runs build {1}.' -f $Policy.MinimumBuild, $Fact.Build) `
                    -Recommendation 'Upgrade Windows to a release the policy accepts.'
            }
            else {
                New-TkAuditFinding -Id 'POL-WIN-BUILD' -Name 'Windows build' -Category 'Policy' -Status 'Pass' -Measured ('Build {0}' -f $Fact.Build) `
                    -Detail ('The policy asks for Windows build {0} or later.' -f $Policy.MinimumBuild)
            }
        ))
    }

    if ($Policy.MaxPatchAgeDays -gt 0) {

        $out.Add($(
            if (-not $Fact.LastUpdate) {
                New-TkAuditFinding -Id 'POL-PATCH-AGE' -Name 'Patch age' -Category 'Policy' -Status 'NotAssessed' -Measured 'Not readable' -Detail 'No dated update was found in the hotfix list.'
            }
            else {
                $days = [int] [math]::Floor(($Now - [datetime] $Fact.LastUpdate).TotalDays)
                if ($days -gt $Policy.MaxPatchAgeDays) {
                    New-TkAuditFinding -Id 'POL-PATCH-AGE' -Name 'Patch age' -Category 'Policy' -Status 'Fail' -Measured ('{0} days' -f $days) `
                        -Detail ('The policy tolerates {0} days since the last update, and the last one was installed {1} days ago.' -f $Policy.MaxPatchAgeDays, $days) `
                        -Recommendation 'Install the pending updates.'
                }
                else {
                    New-TkAuditFinding -Id 'POL-PATCH-AGE' -Name 'Patch age' -Category 'Policy' -Status 'Pass' -Measured ('{0} days' -f $days) `
                        -Detail ('The policy tolerates {0} days since the last update.' -f $Policy.MaxPatchAgeDays)
                }
            }
        ))
    }

    return $out.ToArray()
}

<#
.SYNOPSIS
    Judges the audit and the policy's rules against the policy.

.DESCRIPTION
    Pure. Each finding is copied, never changed, and the copy says what the
    policy makes of it in a Policy property:

    - Blocking: a failure (or a warning, when the policy says so) that makes
      the machine non compliant;
    - Accepted: the same, covered by an exception for this machine that has
      not ended;
    - Expired: covered only by exceptions that have ended, so it blocks again;
    - NotRequired: a control the policy does not require;
    - Tolerated: a warning the policy lets pass;
    - NotAssessed: a control that could not be read, which blocks nothing;
    - Met: the rest.

    An exception holds through the day of its Expires date.

.OUTPUTS
    PSCustomObject with Verdict (Compliant, CompliantWithExceptions,
    NonCompliant), Until, Policy, the counts, Items, Rules, Unused, Problems
    and Findings, the audit findings annotated.
#>
function Resolve-TkPolicyCompliance {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Policy,

        [Parameter()]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Rule = @(),

        [Parameter()]
        [AllowEmptyString()]
        [string] $Computer = $env:COMPUTERNAME,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $today  = $Now.Date
    $scoped = @($Policy.Exceptions | Where-Object { Test-TkPolicyScope -Computer $Computer -Pattern $_.Computers })
    $used   = New-Object System.Collections.Generic.List[int]

    $items    = New-Object System.Collections.Generic.List[object]
    $rules    = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    $all = @(@($Rule | Where-Object { $_ } | ForEach-Object { [pscustomobject] @{ Item = $_; IsRule = $true } }) +
             @($Finding | Where-Object { $_ } | ForEach-Object { [pscustomobject] @{ Item = $_; IsRule = $false } }))

    foreach ($entry in $all) {

        $item      = $entry.Item
        $id        = ([string] $item.Id).ToUpperInvariant()
        $state     = 'Met'
        $exception = $null

        $blocks = ($item.Status -eq 'Fail') -or ($item.Status -eq 'Warning' -and $Policy.WarningsBlock)

        if (-not $entry.IsRule -and @($Policy.NotRequired) -contains $id) {
            $state = 'NotRequired'
        }
        elseif ($blocks) {
            $matching = @(for ($index = 0; $index -lt $scoped.Count; $index++) { if ($scoped[$index].Control -eq $id) { $index } })
            $active   = @($matching | Where-Object { $scoped[$_].Expires -ge $today } | Sort-Object -Property @{ Expression = { $scoped[$_].Expires } } -Descending)

            if ($active.Count -gt 0) {
                $state     = 'Accepted'
                $exception = $scoped[$active[0]]
                $used.Add($active[0])
            }
            elseif ($matching.Count -gt 0) {
                $state     = 'Expired'
                $exception = $scoped[(@($matching | Sort-Object -Property @{ Expression = { $scoped[$_].Expires } } -Descending))[0]]
                foreach ($index in $matching) { $used.Add($index) }
            }
            else {
                $state = 'Blocking'
            }
        }
        elseif ($item.Status -eq 'Warning') {
            $state = 'Tolerated'
        }
        elseif ($item.Status -eq 'NotAssessed') {
            $state = 'NotAssessed'
        }

        $note = [pscustomobject] @{
            State     = $state
            Exception = $(if ($exception) {
                [pscustomobject] @{ Reason = $exception.Reason; Owner = $exception.Owner; Expires = $exception.Expires.ToString('yyyy-MM-dd'); Ticket = $exception.Ticket }
            } else { $null })
        }

        $copy = $item | Select-Object -Property *
        Add-Member -InputObject $copy -NotePropertyName 'Policy' -NotePropertyValue $note -Force

        if ($entry.IsRule) { $rules.Add($copy) } else { $findings.Add($copy) }

        if ($state -in @('Blocking', 'Expired', 'Accepted') -or ($state -eq 'NotRequired' -and $item.Status -in @('Fail', 'Warning'))) {
            $items.Add([pscustomobject] @{
                Id      = [string] $item.Id
                Name    = [string] $item.Name
                Status  = [string] $item.Status
                State   = $state
                Reason  = $(if ($exception) { $exception.Reason } else { '' })
                Owner   = $(if ($exception) { $exception.Owner } else { '' })
                Expires = $(if ($exception) { $exception.Expires.ToString('yyyy-MM-dd') } else { '' })
                Ticket  = $(if ($exception) { $exception.Ticket } else { '' })
            })
        }
    }

    $count    = { param($name) @($items | Where-Object { $_.State -eq $name }).Count }
    $accepted = & $count 'Accepted'
    $expired  = & $count 'Expired'
    $blocking = (& $count 'Blocking') + $expired

    $until = ''
    if ($accepted -gt 0) {
        $until = (@($items | Where-Object { $_.State -eq 'Accepted' } | ForEach-Object { $_.Expires }) | Sort-Object | Select-Object -First 1)
    }

    $unused = New-Object System.Collections.Generic.List[object]
    for ($index = 0; $index -lt $scoped.Count; $index++) {
        if (-not $used.Contains($index) -and $scoped[$index].Expires -ge $today) {
            $unused.Add([pscustomobject] @{ Control = $scoped[$index].Control; Owner = $scoped[$index].Owner; Expires = $scoped[$index].Expires.ToString('yyyy-MM-dd') })
        }
    }

    $verdict = if ($blocking -gt 0) { 'NonCompliant' } elseif ($accepted -gt 0) { 'CompliantWithExceptions' } else { 'Compliant' }

    return [pscustomobject] @{
        Verdict     = $verdict
        Until       = [string] $until
        Reason      = ''
        Policy      = Get-TkPolicyIdentity -Policy $Policy
        Blocking    = $blocking
        Expired     = $expired
        Accepted    = $accepted
        NotRequired = @($findings | Where-Object { $_.Policy.State -eq 'NotRequired' }).Count
        NotAssessed = @($rules | Where-Object { $_.Policy.State -eq 'NotAssessed' }).Count + @($findings | Where-Object { $_.Policy.State -eq 'NotAssessed' }).Count
        Items       = $items.ToArray()
        Rules       = $rules.ToArray()
        Unused      = $unused.ToArray()
        Problems    = [string[]] @($Policy.Problems)
        Findings    = $findings.ToArray()
    }
}

<#
.SYNOPSIS
    The compliance of an audit whose policy was not applied.
#>
function New-TkPolicyRefusal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Import
    )

    $pack = $Import.Pack

    return [pscustomobject] @{
        Verdict     = 'PolicyRefused'
        Until       = ''
        Reason      = $Import.Reason
        Policy      = [pscustomobject] @{
            Name = ''; Version = ''; Owner = ''; Published = ''
            Source     = $(if ($pack) { $pack.Source } else { '' })
            Sha256     = $(if ($pack) { $pack.Sha256 } else { '' })
            VerifiedBy = ''
            Signer     = $(if ($pack) { $pack.Signer } else { '' })
            Thumbprint = $(if ($pack) { $pack.Thumbprint } else { '' })
        }
        Blocking    = 0
        Expired     = 0
        Accepted    = 0
        NotRequired = 0
        NotAssessed = 0
        Items       = @()
        Rules       = @()
        Unused      = @()
        Problems    = @()
    }
}

<#
.SYNOPSIS
    The organisation policy set for this Windows account.

.OUTPUTS
    PSCustomObject with Source and Trust.
#>
function Get-TkPolicySetting {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $settings = $null
    try { $settings = (Get-TkContext).Settings } catch { $settings = $null }

    if ($null -eq $settings) {
        return [pscustomobject] @{ Source = ''; Trust = [string[]] @() }
    }

    return [pscustomobject] @{
        Source = ([string] $settings['PolicySource']).Trim()
        Trust  = [string[]] @($settings['PolicyTrust'] | Where-Object { $_ } | ForEach-Object { [string] $_ })
    }
}

<#
.SYNOPSIS
    Runs the audit, under the organisation policy when one is given.

.DESCRIPTION
    The one path for the interface and the headless mode. With a policy that
    is trusted, the audit runs at least at the policy's level, with its
    administrators left out of the account controls next to the operator's,
    and the verdict is added. With one that is not, the audit is the generic
    one and the verdict says PolicyRefused, with the reason. Either way the
    journal records it: the policy applied, named with its version and the
    hash of the file, or the refusal.

.OUTPUTS
    PSCustomObject with Level, ExcludedAccount, Score, Findings and
    Compliance (null without a policy).
#>
function Invoke-TkPolicyAudit {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('Essential', 'Full')]
        [string] $Level = 'Essential',

        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $ExcludedAccount = @(),

        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $PolicySource = '',

        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $PolicyTrust = @()
    )

    $operator   = @($ExcludedAccount | Where-Object { $_ })
    $excluded   = $operator
    $policy     = $null
    $compliance = $null

    if ($PolicySource) {

        $import = Import-TkOrganisationPolicy -Source $PolicySource -Trust @($PolicyTrust)

        if ($import.Applied) {

            $policy = $import.Policy

            if ($policy.Level -eq 'Full') { $Level = 'Full' }
            $excluded = @(@($operator) + @($policy.Administrators) | Where-Object { $_ } | Select-Object -Unique)

            $trusted = if ($policy.VerifiedBy -eq 'Signature') { Format-TkPolicyTrust -Policy $policy } else { 'this pinned hash' }
            $detail  = '{0} {1}{2}, SHA-256 {3}, trusted by {4}, from {5}.' -f $policy.Name, $policy.Version,
                $(if ($policy.Owner) { ' ({0})' -f $policy.Owner } else { '' }), $policy.Sha256, $trusted, $policy.Source

            Write-TkLog -Level Information -Category 'Policy' -Message ('Organisation policy applied: {0}' -f $detail)
            Add-TkJournalEntry -Name 'Organisation policy applied' -Category 'Policy' -Detail $detail
        }
        else {

            Write-TkLog -Level Warning -Category 'Policy' -Message ('Organisation policy refused ({0}): {1} The audit is the generic one.' -f $PolicySource, $import.Reason)
            Add-TkJournalEntry -Name 'Organisation policy refused' -Category 'Policy' -Success $false -Detail ('{0}: {1}' -f $PolicySource, $import.Reason)

            $compliance = New-TkPolicyRefusal -Import $import
        }
    }

    $findings = @(Invoke-TkSecurityAudit -Level $Level -ExcludedAccount $excluded)

    if ($policy) {

        $rules    = @(Get-TkPolicyRuleFinding -Policy $policy -Fact (Get-TkPolicyFact -Policy $policy))
        $resolved = Resolve-TkPolicyCompliance -Policy $policy -Finding $findings -Rule $rules

        $findings = @($resolved.Findings)
        $resolved.PSObject.Properties.Remove('Findings')
        $compliance = $resolved

        Write-TkLog -Level Information -Category 'Policy' -Message (
            '{0} under {1} {2}: {3} blocking, {4} accepted by an exception.' -f $compliance.Verdict, $policy.Name, $policy.Version, $compliance.Blocking, $compliance.Accepted)
    }

    return [pscustomobject] @{
        Level           = $Level
        ExcludedAccount = [string[]] $excluded
        Score           = Get-TkAuditScore -Finding $findings
        Findings        = $findings
        Compliance      = $compliance
    }
}

<#
.SYNOPSIS
    The verdict of a policy, in one line.
#>
function Format-TkComplianceHeadline {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Compliance
    )

    $policy = '{0} {1}' -f $Compliance.Policy.Name, $Compliance.Policy.Version

    switch ([string] $Compliance.Verdict) {
        'Compliant'               { return ('Compliant with {0}' -f $policy) }
        'CompliantWithExceptions' { return ('Compliant with {0}, with {1} exception(s) until {2}' -f $policy, $Compliance.Accepted, $Compliance.Until) }
        'NonCompliant'            { return ('Not compliant with {0}: {1} point(s) to correct' -f $policy, $Compliance.Blocking) }
        'PolicyRefused'           { return 'The organisation policy was not applied: this is the generic audit' }
    }

    return [string] $Compliance.Verdict
}

<#
.SYNOPSIS
    The severity a verdict is shown with.
#>
function Get-TkComplianceSeverity {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $Verdict
    )

    switch ($Verdict) {
        'Compliant'               { return 'Pass' }
        'CompliantWithExceptions' { return 'Warning' }
        'NonCompliant'            { return 'Fail' }
        'PolicyRefused'           { return 'Warning' }
    }

    return 'Info'
}

<#
.SYNOPSIS
    What the policy makes of one finding, in a sentence; empty when nothing.
#>
function Format-TkFindingPolicyNote {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Finding
    )

    if (-not $Finding.PSObject.Properties['Policy'] -or -not $Finding.Policy) {
        return ''
    }

    $exception = $Finding.Policy.Exception
    $ticket    = if ($exception -and $exception.Ticket) { ', {0}' -f $exception.Ticket } else { '' }

    switch ([string] $Finding.Policy.State) {
        'Accepted'    { return ('Policy: exception accepted until {0} ({1}{2}): {3}' -f $exception.Expires, $exception.Owner, $ticket, $exception.Reason) }
        'Expired'     { return ('Policy: its exception ended on {0} ({1}{2}), so it counts against compliance again.' -f $exception.Expires, $exception.Owner, $ticket) }
        'NotRequired' { return 'Policy: not required by the organisation policy.' }
        'Blocking'    { return 'Policy: required, and it makes this machine non compliant.' }
    }

    return ''
}

<#
.SYNOPSIS
    What the policy makes of a finding, in a few words for a table.
#>
function Format-TkPolicyState {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string] $State
    )

    switch ($State) {
        'Blocking'    { return 'Blocks compliance' }
        'Expired'     { return 'Exception ended' }
        'Accepted'    { return 'Exception accepted' }
        'NotRequired' { return 'Not required' }
        'Tolerated'   { return 'Tolerated' }
        'NotAssessed' { return 'Not assessed' }
        'Met'         { return 'Met' }
    }

    return $State
}

<#
.SYNOPSIS
    The exception on one item of the verdict, in a sentence; empty without one.
#>
function Format-TkComplianceException {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Item
    )

    if (-not $Item.Expires) {
        return ''
    }

    return ('{0} {1} ({2}{3}): {4}' -f $(if ($Item.State -eq 'Expired') { 'Ended' } else { 'Until' }), $Item.Expires, $Item.Owner,
        $(if ($Item.Ticket) { ', ' + $Item.Ticket } else { '' }), $Item.Reason)
}

<#
.SYNOPSIS
    What a policy asks, in a few lines, for the one who checks it.
#>
function Format-TkPolicySummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Policy,

        [Parameter()]
        [datetime] $Now = (Get-Date)
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add(('{0} {1}{2}, trusted by {3}.' -f $Policy.Name, $Policy.Version, $(if ($Policy.Owner) { ', from {0}' -f $Policy.Owner } else { '' }), (Format-TkPolicyTrust -Policy $Policy)))

    $asks = New-Object System.Collections.Generic.List[string]
    $asks.Add(('the audit at the {0} level at least' -f $Policy.Level.ToLowerInvariant()))
    if (@($Policy.NotRequired).Count) { $asks.Add(('{0} control(s) not required ({1})' -f @($Policy.NotRequired).Count, (@($Policy.NotRequired) -join ', '))) }
    if ($Policy.WarningsBlock) { $asks.Add('warnings count as failures') }
    $required  = @($Policy.Software | Where-Object { $_.Kind -eq 'Required' }).Count
    $forbidden = @($Policy.Software | Where-Object { $_.Kind -eq 'Forbidden' }).Count
    if ($required)  { $asks.Add(('{0} program(s) required' -f $required)) }
    if ($forbidden) { $asks.Add(('{0} program(s) forbidden' -f $forbidden)) }
    if (@($Policy.Administrators).Count) { $asks.Add(('{0} expected administrator(s)' -f @($Policy.Administrators).Count)) }
    if ($Policy.MinimumBuild) { $asks.Add(('Windows build {0} or later' -f $Policy.MinimumBuild)) }
    if ($Policy.MaxPatchAgeDays) { $asks.Add(('updates at most {0} days old' -f $Policy.MaxPatchAgeDays)) }
    $lines.Add(('It asks for {0}.' -f ($asks -join ', ')))

    $exceptions = @($Policy.Exceptions)
    if ($exceptions.Count -gt 0) {
        $active = @($exceptions | Where-Object { $_.Expires -ge $Now.Date })
        $next   = @($active | Sort-Object -Property Expires | Select-Object -First 1)
        $lines.Add(('{0} exception(s), {1} still running{2}.' -f $exceptions.Count, $active.Count, $(if ($next.Count) { ', the next to end on {0}' -f $next[0].Expires.ToString('yyyy-MM-dd') } else { '' })))
    }

    foreach ($problem in @($Policy.Problems)) {
        $lines.Add(('Left out: {0}' -f $problem))
    }

    return ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
    The policy section of the audit's HTML report.

.DESCRIPTION
    Pure. Every value is HTML encoded: the policy's names and reasons are
    data written by someone else.

.OUTPUTS
    System.String
#>
function ConvertTo-TkComplianceHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Compliance
    )

    $e        = { param($text) ConvertTo-TkHtmlEncoded ([string] $text) }
    $severity = Get-TkHtmlSeverityMap
    $meta     = $severity[(Get-TkComplianceSeverity -Verdict $Compliance.Verdict)]
    $html     = New-Object System.Text.StringBuilder

    [void] $html.AppendLine('<h2 class="section">Organisation policy</h2>')
    [void] $html.AppendLine(('<div class="card {0}"><div class="head"><span class="pill {0}">{1}</span><span class="name">{2}</span></div>' -f
        $meta.Class, (& $e $Compliance.Verdict), (& $e (Format-TkComplianceHeadline -Compliance $Compliance))))

    if ($Compliance.Verdict -eq 'PolicyRefused') {
        [void] $html.AppendLine(('<p class="detail">{0}</p>' -f (& $e $Compliance.Reason)))
    }
    else {
        $identity = $Compliance.Policy
        $trust    = if ($identity.VerifiedBy -eq 'Signature') { 'the signature of {0} (certificate {1})' -f $identity.Signer, $identity.Thumbprint } else { 'its pinned SHA-256' }
        [void] $html.AppendLine(('<p class="detail">{0}{1}, trusted by {2}. SHA-256 of the file: {3}.</p>' -f
            (& $e $identity.Source), $(if ($identity.Owner) { ' - ' + (& $e $identity.Owner) } else { '' }), (& $e $trust), (& $e $identity.Sha256)))
    }
    [void] $html.AppendLine('</div>')

    foreach ($rule in @($Compliance.Rules)) {
        $ruleMeta = $severity[[string] $rule.Status]
        if (-not $ruleMeta) { $ruleMeta = @{ Label = [string] $rule.Status; Class = 'sev-info' } }
        [void] $html.AppendLine(('<div class="card {0}"><div class="head"><span class="pill {0}">{1}</span><span class="code">{2}</span><span class="name">{3}</span><span class="measured">{4}</span></div>' -f
            $ruleMeta.Class, (& $e $ruleMeta.Label), (& $e $rule.Id), (& $e $rule.Name), (& $e $rule.Measured)))
        [void] $html.AppendLine(('<p class="detail">{0}</p>' -f (& $e $rule.Detail)))
        $note = Format-TkFindingPolicyNote -Finding $rule
        if ($note) { [void] $html.AppendLine(('<p class="policy">{0}</p>' -f (& $e $note))) }
        if ($rule.Recommendation) { [void] $html.AppendLine(('<p class="reco"><strong>Why:</strong> {0}</p>' -f (& $e $rule.Recommendation))) }
        [void] $html.AppendLine('</div>')
    }

    $items = @($Compliance.Items)
    if ($items.Count -gt 0) {
        [void] $html.AppendLine('<table class="grid"><tr><th>Control</th><th>Result</th><th>Under the policy</th><th>Exception</th></tr>')
        foreach ($item in $items) {
            [void] $html.AppendLine(('<tr><td>{0} {1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (& $e $item.Id), (& $e $item.Name), (& $e $item.Status),
                (& $e (Format-TkPolicyState -State $item.State)), (& $e (Format-TkComplianceException -Item $item))))
        }
        [void] $html.AppendLine('</table>')
    }

    foreach ($unused in @($Compliance.Unused)) {
        [void] $html.AppendLine(('<p class="note">The exception on {0} ({1}, until {2}) covers nothing on this machine: it can be withdrawn here.</p>' -f (& $e $unused.Control), (& $e $unused.Owner), (& $e $unused.Expires)))
    }

    foreach ($problem in @($Compliance.Problems)) {
        [void] $html.AppendLine(('<p class="note">Left out of the policy: {0}</p>' -f (& $e $problem)))
    }

    return $html.ToString()
}

<#
.SYNOPSIS
    A starting policy to fill in, sign and publish.

.OUTPUTS
    System.String
#>
function New-TkPolicyTemplate {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
# Toolkit organisation policy.
#
# Data only: the toolkit parses it and never runs it, and applies it only
# once its signature or its SHA-256 is trusted, in Settings or with
# -PolicyTrust. Either sign it:
#   Set-AuthenticodeSignature -FilePath .\policy.psd1 -Certificate $certificate -TimestampServer http://timestamp.digicert.com
# and trust the certificate's thumbprint, or trust the file's SHA-256:
#   (Get-FileHash .\policy.psd1 -Algorithm SHA256).Hash
# Any change to the file needs a new signature, or the new SHA-256.
@{
    Schema        = 'toolkit-policy'
    SchemaVersion = '1.0'
    Name          = 'Workstation policy'
    Version       = '2026.1'
    Owner         = 'Security team'

    Audit = @{
        # Essential or Full: the least the audit runs at under this policy.
        Level         = 'Full'
        # Controls this organisation does not require, by their Id (PRN-001...).
        NotRequired   = @()
        # $true: a warning makes the machine non compliant, as a failure does.
        WarningsBlock = $false
    }

    # Members of the local Administrators group that belong there, left out
    # of the account controls.
    Administrators = @()

    Windows = @{
        # The least Windows build: 19045 is Windows 10 22H2, 26100 Windows 11 24H2.
        MinimumBuild    = 19045
        # The most days since the last update was installed.
        MaxPatchAgeDays = 45
    }

    Software = @{
        # Package: a wildcard on an installed program's name. Service: a
        # service name, which must be running. Id: how reports name the rule.
        Required  = @(
            # @{ Id = 'ORG-EDR'; Name = 'EDR sensor'; Service = 'CSAgent'; Why = 'Every workstation runs the EDR.' }
        )
        Forbidden = @(
            # @{ Id = 'ORG-REMOTE'; Name = 'AnyDesk'; Package = 'AnyDesk*'; Why = 'Remote access goes through the approved tool.' }
        )
    }

    # One per accepted risk: the control, the machines (wildcards, all when
    # left out), why, who owns it, and the day it ends. Past that day the
    # control counts against compliance again.
    Exceptions = @(
        # @{ Control = 'RDP-001'; Computers = @('LAB-*'); Reason = 'Lab machines are administered over RDP.'; Owner = 'J. Martin'; Expires = '2026-12-31'; Ticket = 'CHG-1234' }
    )
}
'@
}
