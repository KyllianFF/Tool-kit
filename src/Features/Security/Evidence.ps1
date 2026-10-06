<#
    Toolkit - Features / Framework mapping and evidence pack

    An ISO 27001 audit, a NIS2 programme or a cyber insurer asks for technical
    evidence requirement by requirement. The security audit measures the
    machine control by control; this file says which requirement each control
    contributes to (data/frameworks.json), and writes an evidence pack: for
    each requirement, the controls measured, their value and method, when,
    on which machine, by whom and with which build of the toolkit, then the
    SHA-256 of the pack and, when a certificate is given, its signature.

    It never says a requirement is met. A requirement is met by an
    organisation's measures as a whole, which one workstation's settings
    never show: the pack contributes evidence, an auditor judges. The words
    it uses say so, and a test keeps "compliant" out of them.

    The signature is CMS (SignedCms, detached, SHA-256), which openssl and
    .NET both verify, with no cryptography of the toolkit's own.
#>

<#
.SYNOPSIS
    The framework catalog: the frameworks, and each control's mapping.
#>
function Get-TkFrameworkCatalog {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return (Import-TkCatalog -Name 'frameworks')
}

<#
.SYNOPSIS
    The frameworks a control can be mapped to, with their requirements.

.PARAMETER Id
    The framework ids to return; all of them when empty.
#>
function Get-TkFramework {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [string[]] $Id = @()
    )

    $all    = @((Get-TkFrameworkCatalog).frameworks)
    $wanted = @($Id | ForEach-Object { [string] $_ -split '[,;\s]+' } | Where-Object { $_ })

    if ($wanted.Count -eq 0) {
        return $all
    }

    $known = @($all | ForEach-Object { [string] $_.id })
    foreach ($name in $wanted) {
        if (@($known | Where-Object { $_ -eq $name }).Count -eq 0) {
            throw ('{0} is not a framework. The frameworks are: {1}.' -f $name, ($known -join ', '))
        }
    }

    return @($all | Where-Object { $wanted -contains [string] $_.id })
}

<#
.SYNOPSIS
    What one control is mapped to.

.OUTPUTS
    PSCustomObject with Method and References (Framework, Short,
    Requirement, Title), empty when the control has no mapping.
#>
function Get-TkControlMapping {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Id
    )

    $catalog = Get-TkFrameworkCatalog
    $control = @($catalog.controls | Where-Object { [string] $_.id -eq $Id }) | Select-Object -First 1
    $refs    = New-Object System.Collections.Generic.List[object]

    if ($control) {
        foreach ($framework in @($catalog.frameworks)) {
            $property = $control.maps.PSObject.Properties[[string] $framework.id]
            if (-not $property) { continue }

            foreach ($requirement in @($property.Value | Where-Object { $_ })) {
                $entry = @($framework.requirements | Where-Object { [string] $_.id -eq [string] $requirement }) | Select-Object -First 1
                $refs.Add([pscustomobject] @{
                    Framework   = [string] $framework.id
                    Short       = [string] $framework.short
                    Requirement = [string] $requirement
                    Title       = $(if ($entry) { [string] $entry.title } else { '' })
                })
            }
        }
    }

    return [pscustomobject] @{
        Method     = $(if ($control) { [string] $control.method } else { '' })
        References = $refs.ToArray()
    }
}

<#
.SYNOPSIS
    A control's references in one line: "ISO 27001 8.1, 8.24; NIS2 21(2)(h)".

.OUTPUTS
    System.String, empty when the control has no mapping.
#>
function Format-TkControlReference {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Id
    )

    # In the catalog's order, not Group-Object's, which sorts.
    $refs  = @((Get-TkControlMapping -Id $Id).References)
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($ref in $refs) {
        if (-not $order.Contains($ref.Short)) { $order.Add($ref.Short) }
    }

    $parts = foreach ($short in $order) {
        '{0} {1}' -f $short, ((@($refs | Where-Object { $_.Short -eq $short } | ForEach-Object { $_.Requirement })) -join ', ')
    }

    return ((@($parts)) -join '; ')
}

<#
.SYNOPSIS
    What the controls measured say about one requirement.

.DESCRIPTION
    Pure. A failure the organisation accepted by an exception that has not
    ended reads as an accepted risk; a control the policy does not require
    is shown but not weighed. The words never claim the requirement is met:
    the best this can say is that the evidence supports it.

.PARAMETER Control
    The controls of the requirement that ran: Status and, when audited under
    a policy, PolicyState and ExceptionUntil.

.PARAMETER NotRun
    The ids of the requirement's controls that were not in this audit.

.PARAMETER FullOnly
    The controls not run all belong to the Full level, and the audit was an
    Essential one: the Full audit would run them.

.OUTPUTS
    PSCustomObject with Observation (Supported, Weakness, Gap, AcceptedRisk,
    NotAssessed, NotRequired, NotCovered), Label and Text.
#>
function Resolve-TkRequirementObservation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Control,
        [Parameter()] [AllowEmptyCollection()] [string[]] $NotRun = @(),
        [Parameter()] [switch] $FullOnly
    )

    $make = {
        param($key, $label, $text)
        $tail = if (@($NotRun).Count -gt 0 -and $key -notin @('NotCovered')) { ' Not in this audit: {0}.' -f (@($NotRun) -join ', ') } else { '' }
        [pscustomobject] @{ Observation = $key; Label = $label; Text = ($text + $tail).Trim() }
    }

    $ids = { param($items) (@($items | ForEach-Object { $_.Id })) -join ', ' }
    $all = @($Control | Where-Object { $_ })

    if ($all.Count -eq 0) {
        return (& $make 'NotCovered' 'Not covered' ('None of its controls was in this audit: {0}.{1}' -f (@($NotRun) -join ', '), $(if ($FullOnly) { ' The Full audit runs them.' } else { '' })))
    }

    $judged = @($all | Where-Object { [string] $_.PolicyState -ne 'NotRequired' })

    if ($judged.Count -eq 0) {
        return (& $make 'NotRequired' 'Not required' 'The organisation policy does not require its controls.')
    }

    $fails    = @($judged | Where-Object { $_.Status -eq 'Fail' -and [string] $_.PolicyState -ne 'Accepted' })
    $accepted = @($judged | Where-Object { $_.Status -in @('Fail', 'Warning') -and [string] $_.PolicyState -eq 'Accepted' })
    $warnings = @($judged | Where-Object { $_.Status -eq 'Warning' -and [string] $_.PolicyState -ne 'Accepted' })
    $assessed = @($judged | Where-Object { $_.Status -in @('Pass', 'Fail', 'Warning', 'Info') })

    if ($fails.Count -gt 0) {
        return (& $make 'Gap' 'Gap' ('Failing: {0}.' -f (& $ids $fails)))
    }

    if ($accepted.Count -gt 0) {
        $until = @($accepted | ForEach-Object { [string] $_.ExceptionUntil } | Where-Object { $_ } | Sort-Object) | Select-Object -First 1
        return (& $make 'AcceptedRisk' 'Accepted risk' ('Falling short under an exception the organisation accepted{0}: {1}.' -f $(if ($until) { ' until {0}' -f $until } else { '' }), (& $ids $accepted)))
    }

    if ($warnings.Count -gt 0) {
        return (& $make 'Weakness' 'Weakness' ('Only partly in place: {0}.' -f (& $ids $warnings)))
    }

    if ($assessed.Count -eq 0) {
        return (& $make 'NotAssessed' 'Not assessed' ('Could not be read on this machine: {0}.' -f (& $ids $judged)))
    }

    return (& $make 'Supported' 'Evidence' ('Measured, and supporting it: {0}.' -f (& $ids $assessed)))
}

<#
.SYNOPSIS
    Builds the evidence pack of an audit.

.DESCRIPTION
    Pure but for the machine's own identity: everything that says who, when
    and with what is handed in, so the window's thread can read what a
    background runspace cannot (where the toolkit came from).

.PARAMETER Finding
    The audit findings, as Invoke-TkPolicyAudit returns them (annotated by
    the policy when there was one).

.PARAMETER Framework
    The framework ids to include; all of them when empty.

.PARAMETER Journal
    The journal check (Test-TkJournalChain), whose head ties the pack to the
    record of what was done on the machine.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
function New-TkEvidencePack {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter()] [ValidateSet('Essential', 'Full')] [string] $Level = 'Essential',
        [Parameter()] [AllowNull()] [pscustomobject] $Compliance = $null,
        [Parameter()] [AllowEmptyCollection()] [string[]] $ExcludedAccount = @(),
        [Parameter()] [datetime] $AuditedAt = ([datetime]::UtcNow),
        [Parameter()] [AllowEmptyCollection()] [string[]] $Framework = @(),
        [Parameter(Mandatory)] [pscustomobject] $Toolkit,
        [Parameter()] [AllowNull()] [object] $Journal = $null,
        [Parameter()] [bool] $Elevated = $false,
        [Parameter()] [datetime] $Now = ([datetime]::UtcNow)
    )

    $catalog    = Get-TkFrameworkCatalog
    $frameworks = @(Get-TkFramework -Id $Framework)
    $findings   = @($Finding | Where-Object { $_ })
    $byId       = @{}
    $levels     = @{}
    foreach ($item in $findings) { $byId[[string] $item.Id] = $item }
    foreach ($row in @(Get-TkAuditControl)) { $levels[[string] $row.Id] = [string] $row.Level }

    $policyState = {
        param($item)
        if ($item.PSObject.Properties['Policy'] -and $item.Policy) { [string] $item.Policy.State } else { '' }
    }

    $exception = {
        param($item)
        if ($item.PSObject.Properties['Policy'] -and $item.Policy -and $item.Policy.PSObject.Properties['Exception'] -and $item.Policy.Exception) {
            $e = $item.Policy.Exception
            [ordered] @{ Until = [string] $e.Expires; Owner = [string] $e.Owner; Ticket = [string] $e.Ticket; Reason = [string] $e.Reason }
        }
        else { $null }
    }

    # Every control of the run once, with its method and what it contributes to.
    $controls = foreach ($item in $findings) {
        $mapping = Get-TkControlMapping -Id ([string] $item.Id)
        [ordered] @{
            Id             = [string] $item.Id
            Name           = [string] $item.Name
            Category       = [string] $item.Category
            Status         = [string] $item.Status
            Measured       = [string] $item.Measured
            Detail         = [string] $item.Detail
            Recommendation = [string] $item.Recommendation
            Level          = [string] $item.Level
            Weight         = $item.Weight
            Method         = $mapping.Method
            References     = @($mapping.References | Where-Object { @($frameworks | ForEach-Object { [string] $_.id }) -contains $_.Framework } | ForEach-Object { '{0} {1}' -f $_.Framework, $_.Requirement })
            Policy         = $(if (& $policyState $item) { [ordered] @{ State = (& $policyState $item); Exception = (& $exception $item) } } else { $null })
        }
    }

    # Requirement by requirement, the controls mapped to it: those of the run,
    # and those the run did not include. The loop variable is not named
    # $framework: that is the -Framework parameter, typed string[].
    $sections = foreach ($set in $frameworks) {
        $requirements = foreach ($requirement in @($set.requirements)) {
            $mapped = @($catalog.controls | Where-Object {
                $property = $_.maps.PSObject.Properties[[string] $set.id]
                $property -and @($property.Value) -contains [string] $requirement.id
            } | ForEach-Object { [string] $_.id })

            $ran    = @($mapped | Where-Object { $byId.ContainsKey($_) })
            $notRun = @($mapped | Where-Object { -not $byId.ContainsKey($_) })

            $records = @($ran | ForEach-Object {
                $item = $byId[$_]
                $e    = & $exception $item
                [pscustomobject] @{ Id = $_; Status = [string] $item.Status; PolicyState = (& $policyState $item); ExceptionUntil = $(if ($e) { $e.Until } else { '' }) }
            })

            # Said only when true: a control of the Essential level that did
            # not run failed to, and the Full audit would not change that.
            $fullOnly    = $Level -eq 'Essential' -and $notRun.Count -gt 0 -and @($notRun | Where-Object { $levels[$_] -ne 'Full' }).Count -eq 0
            $observation = Resolve-TkRequirementObservation -Control $records -NotRun $notRun -FullOnly:$fullOnly

            [ordered] @{
                Id          = [string] $requirement.id
                Title       = [string] $requirement.title
                Observation = $observation.Observation
                Label       = $observation.Label
                Text        = $observation.Text
                Controls    = @($ran | ForEach-Object { $item = $byId[$_]; [ordered] @{ Id = $_; Name = [string] $item.Name; Status = [string] $item.Status; Measured = [string] $item.Measured } })
                NotInAudit  = $notRun
            }
        }

        [ordered] @{
            Id           = [string] $set.id
            Name         = [string] $set.name
            Edition      = [string] $set.edition
            Indicative   = [bool] $set.indicative
            Requirements = @($requirements)
        }
    }

    $score = Get-TkAuditScore -Finding @($findings)
    $os    = Get-TkCimInstanceSafe -ClassName 'Win32_OperatingSystem'
    $utc   = $Now.ToUniversalTime()

    return [ordered] @{
        Schema        = 'toolkit-evidence'
        SchemaVersion = '1.0'
        Id            = 'evidence-{0}-{1}' -f ($env:COMPUTERNAME -replace '[^A-Za-z0-9-]', '_'), $utc.ToString('yyyyMMddTHHmmssZ')
        GeneratedAt   = $utc.ToString('o')
        Notice        = 'This pack contributes technical evidence; it does not establish that any requirement is met. {0}' -f [string] $catalog.notice
        Machine       = [ordered] @{
            Computer  = $env:COMPUTERNAME
            MachineId = Get-TkMachineId
            Os        = $(if ($os) { '{0} {1}' -f $os.Caption, $os.BuildNumber } else { '' })
        }
        Operator      = [ordered] @{ User = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME); Elevated = $Elevated }
        Toolkit       = $Toolkit
        Mapping       = [ordered] @{ Version = [string] $catalog.version; Frameworks = @($frameworks | ForEach-Object { [string] $_.id }) }
        Audit         = [ordered] @{
            Level           = $Level
            AuditedAt       = $AuditedAt.ToUniversalTime().ToString('o')
            Score           = [ordered] @{ Score = $score.Score; Passed = $score.Passed; Failed = $score.Failed; Warnings = $score.Warnings; NotAssessed = $score.NotAssessed }
            Controls        = $findings.Count
            ExcludedAccount = @($ExcludedAccount | Where-Object { $_ })
            Policy          = $(if ($Compliance) { [ordered] @{ Verdict = [string] $Compliance.Verdict; Until = [string] $Compliance.Until; Name = [string] $Compliance.Policy.Name; Version = [string] $Compliance.Policy.Version; VerifiedBy = [string] $Compliance.Policy.VerifiedBy; Sha256 = [string] $Compliance.Policy.Sha256 } } else { $null })
        }
        Journal       = $(if ($Journal) { [ordered] @{ Valid = [bool] $Journal.Valid; Entries = $Journal.Entries; Head = [string] $Journal.Head } } else { $null })
        Frameworks    = @($sections)
        Controls      = @($controls)
    }
}

<#
.SYNOPSIS
    The CSS class and label of an observation, for the HTML page.
#>
function Get-TkObservationStyle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Observation
    )

    switch ($Observation) {
        'Supported'    { return 'sev-pass' }
        'Weakness'     { return 'sev-warning' }
        'Gap'          { return 'sev-fail' }
        'AcceptedRisk' { return 'sev-info' }
        default        { return 'sev-notassessed' }
    }
}

<#
.SYNOPSIS
    The evidence pack as a printable, self-contained HTML page.

.DESCRIPTION
    Requirement by requirement, then each control with its value and method.
    The page cannot hold its own hash: the .sha256 file beside it does, and
    the page says how to check it.
#>
function ConvertTo-TkEvidencePackHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Pack
    )

    $e        = { param($text) ConvertTo-TkHtmlEncoded -Text ([string] $text) }
    $severity = Get-TkHtmlSeverityMap
    $body     = New-Object System.Text.StringBuilder

    foreach ($framework in @($Pack.Frameworks)) {

        [void] $body.AppendLine(('<h2 class="section">{0}</h2>' -f (& $e $framework.Name)))
        if ($framework.Indicative) {
            [void] $body.AppendLine('<p class="note">Indicative: the directive lists risk-management measures, not technical settings.</p>')
        }

        [void] $body.AppendLine('<table class="grid"><tr><th>Requirement</th><th>Observation</th><th>Controls measured</th></tr>')
        foreach ($requirement in @($framework.Requirements)) {
            $lines = @($requirement.Controls | ForEach-Object {
                $status = if ($severity[[string] $_.Status]) { $severity[[string] $_.Status].Label } else { [string] $_.Status }
                '{0} {1}: {2}{3}' -f (& $e $_.Id), (& $e $_.Name), (& $e $status), $(if ($_.Measured) { ' ({0})' -f (& $e $_.Measured) } else { '' })
            })
            [void] $body.AppendLine(('<tr><td><strong>{0}</strong> {1}</td><td><span class="pill {2}">{3}</span><br />{4}</td><td>{5}</td></tr>' -f
                (& $e $requirement.Id), (& $e $requirement.Title), (Get-TkObservationStyle -Observation $requirement.Observation), (& $e $requirement.Label), (& $e $requirement.Text),
                $(if ($lines.Count) { $lines -join '<br />' } else { '-' })))
        }
        [void] $body.AppendLine('</table>')
    }

    [void] $body.AppendLine('<h2 class="section">Controls, as measured</h2>')
    foreach ($control in @($Pack.Controls)) {
        $meta = $severity[[string] $control.Status]
        if (-not $meta) { $meta = @{ Label = [string] $control.Status; Class = 'sev-info' } }

        [void] $body.AppendLine(('<div class="card {0}"><div class="head"><span class="pill {0}">{1}</span><span class="code">{2}</span><span class="name">{3}</span>{4}</div>' -f
            $meta.Class, (& $e $meta.Label), (& $e $control.Id), (& $e $control.Name), $(if ($control.Measured) { '<span class="measured">{0}</span>' -f (& $e $control.Measured) } else { '' })))
        if ($control.Detail) { [void] $body.AppendLine(('<p class="detail">{0}</p>' -f (& $e $control.Detail))) }
        if ($control.Method) { [void] $body.AppendLine(('<p class="policy"><strong>Method:</strong> {0}</p>' -f (& $e $control.Method))) }
        if (@($control.References).Count) { [void] $body.AppendLine(('<p class="policy"><strong>Contributes to:</strong> {0}</p>' -f (& $e ((@($control.References)) -join '; ')))) }
        if ($control.Policy) {
            $exception = $control.Policy.Exception
            $state     = Format-TkPolicyState -State ([string] $control.Policy.State)
            if ($exception) {
                $ticket = if ($exception.Ticket) { ', ' + $exception.Ticket } else { '' }
                $state += ', exception until {0} ({1}{2}): {3}' -f $exception.Until, $exception.Owner, $ticket, $exception.Reason
            }
            [void] $body.AppendLine(('<p class="policy"><strong>Organisation policy:</strong> {0}</p>' -f (& $e $state)))
        }
        [void] $body.AppendLine('</div>')
    }

    [void] $body.AppendLine('<h2 class="section">Integrity</h2>')
    [void] $body.AppendLine(('<p>The SHA-256 of {0}.json and of this page are in {0}.sha256. When the pack is signed, {0}.json.p7s holds a detached CMS signature of the JSON: <code>openssl cms -verify -binary -inform DER -in {0}.json.p7s -content {0}.json -purpose any -CAfile issuer.pem -out /dev/null</code>, or Test-TkEvidencePack in the toolkit.</p>' -f (& $e $Pack.Id)))

    $toolkit = $Pack.Toolkit
    $meta    = [ordered] @{
        'Computer'          = $Pack.Machine.Computer
        'Machine ID'        = $Pack.Machine.MachineId
        'Operating system'  = $Pack.Machine.Os
        'Generated (UTC)'   = ([datetime] $Pack.GeneratedAt).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        'Audited (UTC)'     = ([datetime] $Pack.Audit.AuditedAt).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        'Operator'          = '{0}{1}' -f $Pack.Operator.User, $(if ($Pack.Operator.Elevated) { ', as administrator' } else { '' })
        'Toolkit'           = '{0} ({1})' -f $toolkit.Version, $toolkit.Commit
        'Toolkit SHA-256'   = $(if ($toolkit.Sha256) { '{0} - {1}' -f $toolkit.Sha256, $toolkit.Proof } else { $toolkit.Proof })
        'Audit'             = '{0}, {1} / 100, {2} controls' -f $Pack.Audit.Level, $Pack.Audit.Score.Score, $Pack.Audit.Controls
    }
    if ($Pack.Audit.Policy) { $meta['Organisation policy'] = '{0} {1}: {2}' -f $Pack.Audit.Policy.Name, $Pack.Audit.Policy.Version, $Pack.Audit.Policy.Verdict }
    if (@($Pack.Audit.ExcludedAccount).Count) { $meta['Excluded accounts'] = (@($Pack.Audit.ExcludedAccount)) -join ', ' }
    if ($Pack.Journal) {
        $meta['Journal head'] = if ($Pack.Journal.Head) { '{0} ({1} entries, chain {2})' -f $Pack.Journal.Head, $Pack.Journal.Entries, $(if ($Pack.Journal.Valid) { 'intact' } else { 'broken' }) } else { 'No entry yet' }
    }
    $meta['Mapping'] = 'version {0}' -f $Pack.Mapping.Version

    return New-TkHtmlReport -Title 'Evidence pack' -Subtitle ('{0} - {1}' -f $Pack.Machine.Computer, ([datetime] $Pack.GeneratedAt).ToUniversalTime().ToString('yyyy-MM-dd')) `
        -Meta $meta -Note $Pack.Notice -Body $body.ToString()
}

<#
.SYNOPSIS
    The certificates an evidence pack can be signed with.

.DESCRIPTION
    Certificates of this account and of the machine that hold their private
    key and are valid now. With a thumbprint, that one or an error; without,
    those made for signing documents or code, the longest valid first.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2[]
#>
function Get-TkEvidenceSigningCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param(
        [Parameter()] [AllowEmptyString()] [string] $Thumbprint = ''
    )

    $now = Get-Date
    $all = @(foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now }
    })

    if ($Thumbprint) {
        $wanted = ($Thumbprint -replace '\s', '').ToUpperInvariant()
        $match  = @($all | Where-Object { $_.Thumbprint -eq $wanted }) | Select-Object -First 1
        if (-not $match) {
            throw ('No valid certificate with a private key and the thumbprint {0} in the stores of this account or machine.' -f $wanted)
        }
        return $match
    }

    $signing = @('1.3.6.1.4.1.311.10.3.12', '1.3.6.1.5.5.7.3.3')
    return @($all | Where-Object {
        $usages = @($_.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
        @($usages | Where-Object { $signing -contains $_ }).Count -gt 0
    } | Sort-Object -Property NotAfter -Descending)
}

<#
.SYNOPSIS
    Writes an evidence pack: JSON, HTML, their SHA-256, and a signature.

.DESCRIPTION
    The privacy of exports applies, the same pseudonyms on both files. The
    signature is a detached CMS signature of the JSON as written, with the
    signing time; it is read back before the pack is said to be signed.
    The pack and its hash go into the journal.

.OUTPUTS
    PSCustomObject with Id, Json, Html, Hashes, Signature, JsonSha256,
    HtmlSha256, Signer and Privacy.
#>
function Export-TkEvidencePack {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Pack,
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter()] [ValidateSet('None', 'Personal', 'Strict')] [string] $Privacy = 'None',
        [Parameter()] [AllowNull()] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate = $null
    )

    if (-not [System.IO.Directory]::Exists($Folder)) {
        throw ('{0} does not exist: choose a folder.' -f $Folder)
    }

    $base = [System.IO.Path]::Combine((Resolve-Path -LiteralPath $Folder).ProviderPath, [string] $Pack.Id)

    if (-not $PSCmdlet.ShouldProcess($base, 'Write the evidence pack')) {
        return $null
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $seed = if ($Privacy -ne 'None') { Get-TkRedactionSeed -Level $Privacy } else { $null }
    $json = (Protect-TkExportText -Text (ConvertTo-Json -InputObject (ConvertTo-TkPlainData -InputObject $Pack) -Depth 12) -Level $Privacy -Label 'evidence-pack' -Seed $seed).Text
    $html = (Protect-TkExportText -Text (ConvertTo-TkEvidencePackHtml -Pack $Pack) -Level $Privacy -Label 'evidence-pack' -Seed $seed).Text

    $jsonPath = '{0}.json' -f $base
    $htmlPath = '{0}.html' -f $base
    [System.IO.File]::WriteAllText($jsonPath, $json, $utf8)
    [System.IO.File]::WriteAllText($htmlPath, $html, $utf8)

    $jsonSha = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash
    $htmlSha = (Get-FileHash -LiteralPath $htmlPath -Algorithm SHA256).Hash
    $lines   = New-Object System.Collections.Generic.List[string]
    $lines.Add(('{0}  {1}' -f $jsonSha, [System.IO.Path]::GetFileName($jsonPath)))
    $lines.Add(('{0}  {1}' -f $htmlSha, [System.IO.Path]::GetFileName($htmlPath)))

    $signature = ''
    $signer    = ''
    if ($Certificate) {
        $signature = '{0}.p7s' -f $jsonPath
        [System.IO.File]::WriteAllBytes($signature, (New-TkDetachedSignature -Content ([System.IO.File]::ReadAllBytes($jsonPath)) -Certificate $Certificate))
        $check = Test-TkDetachedSignature -Content ([System.IO.File]::ReadAllBytes($jsonPath)) -Signature ([System.IO.File]::ReadAllBytes($signature))
        if (-not $check.Valid) {
            Remove-Item -LiteralPath $signature -Force
            throw ('The signature did not read back: {0}' -f $check.Reason)
        }
        $signer = '{0} ({1})' -f ($Certificate.Subject -replace '^CN=([^,]+).*$', '$1'), $Certificate.Thumbprint
        $lines.Add(('{0}  {1}' -f (Get-FileHash -LiteralPath $signature -Algorithm SHA256).Hash, [System.IO.Path]::GetFileName($signature)))
    }

    # Line feeds only: sha256sum -c reads a carriage return as part of the name.
    $hashes = '{0}.sha256' -f $base
    [System.IO.File]::WriteAllText($hashes, (($lines -join "`n") + "`n"), $utf8)

    $observed = @($Pack.Frameworks | ForEach-Object { $_.Requirements } | Group-Object -Property { $_.Observation } | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
    $detail   = '{0}: {1} over {2}; JSON SHA-256 {3}{4}.' -f $Pack.Id, ($observed -join ', '), ((@($Pack.Mapping.Frameworks)) -join ', '), $jsonSha, $(if ($signer) { '; signed by {0}' -f $signer } else { '; not signed' })

    Write-TkLog -Level Information -Category 'Evidence' -Message ('Evidence pack: {0}' -f $detail)
    Add-TkJournalEntry -Name 'Evidence pack' -Category 'Evidence' -Detail $detail

    return [pscustomobject] @{
        Id         = [string] $Pack.Id
        Json       = $jsonPath
        Html       = $htmlPath
        Hashes     = $hashes
        Signature  = $signature
        JsonSha256 = $jsonSha
        HtmlSha256 = $htmlSha
        Signer     = $signer
        Privacy    = $Privacy
    }
}

<#
.SYNOPSIS
    A detached CMS signature (SHA-256, with the signing time) of some bytes.
#>
function New-TkDetachedSignature {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]] $Content,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -AssemblyName System.Security
    }

    if (-not $Certificate.HasPrivateKey) {
        throw ('The certificate {0} has no private key here: it cannot sign.' -f $Certificate.Thumbprint)
    }

    $cms    = New-Object System.Security.Cryptography.Pkcs.SignedCms((New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $Content)), $true)
    $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner($Certificate)
    $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
    $signer.IncludeOption   = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    [void] $signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime([datetime]::UtcNow)))

    $cms.ComputeSignature($signer, $true)

    return , $cms.Encode()
}

<#
.SYNOPSIS
    Checks a detached CMS signature over some bytes.

.DESCRIPTION
    The signature is checked first on its own: the bytes are those signed,
    by the key of the certificate it carries. Whether Windows trusts that
    certificate's chain is said apart, since a company's own signing
    certificate is often trusted only inside it.

.OUTPUTS
    PSCustomObject with Valid, ChainTrusted, Signer, Thumbprint, SigningTime
    and Reason.
#>
function Test-TkDetachedSignature {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [byte[]] $Content,
        [Parameter(Mandatory)] [byte[]] $Signature
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -AssemblyName System.Security
    }

    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms((New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $Content)), $true)

    try {
        $cms.Decode($Signature)
        $cms.CheckSignature($true)
    }
    catch {
        return [pscustomobject] @{ Valid = $false; ChainTrusted = $false; Signer = ''; Thumbprint = ''; SigningTime = ''; Reason = $_.Exception.Message }
    }

    $info    = $cms.SignerInfos[0]
    $time    = @($info.SignedAttributes | Where-Object { $_.Oid.Value -eq '1.2.840.113549.1.9.5' } | ForEach-Object { $_.Values } | Select-Object -First 1)
    $trusted = try { $cms.CheckSignature($false); $true } catch { $false }

    return [pscustomobject] @{
        Valid        = $true
        ChainTrusted = $trusted
        Signer       = $(if ($info.Certificate) { $info.Certificate.Subject } else { '' })
        Thumbprint   = $(if ($info.Certificate) { $info.Certificate.Thumbprint } else { '' })
        SigningTime  = $(if ($time.Count -and $time[0].PSObject.Properties['SigningTime']) { $time[0].SigningTime.ToUniversalTime().ToString('o') } else { '' })
        Reason       = ''
    }
}

<#
.SYNOPSIS
    Checks an evidence pack: its files against their SHA-256, and its signature.

.OUTPUTS
    PSCustomObject with Valid, Files (Name, Expected, Actual, Match),
    Signed, Signature (as Test-TkDetachedSignature returns it) and Reason.
#>
function Test-TkEvidencePack {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    $json   = (Resolve-Path -LiteralPath $Path).ProviderPath
    $folder = [System.IO.Path]::GetDirectoryName($json)
    $hashes = [System.IO.Path]::ChangeExtension($json, '.sha256')

    if (-not [System.IO.File]::Exists($hashes)) {
        return [pscustomobject] @{ Valid = $false; Files = @(); Signed = $false; Signature = $null; Reason = ('{0} is missing: the pack cannot be checked.' -f [System.IO.Path]::GetFileName($hashes)) }
    }

    $files = foreach ($line in @([System.IO.File]::ReadAllLines($hashes) | Where-Object { $_ -match '^([0-9A-Fa-f]{64})\s+(.+)$' })) {
        $null   = $line -match '^([0-9A-Fa-f]{64})\s+(.+)$'
        $name   = $Matches[2].Trim()
        $file   = [System.IO.Path]::Combine($folder, $name)
        $actual = if ([System.IO.File]::Exists($file)) { (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash } else { '' }
        [pscustomobject] @{ Name = $name; Expected = $Matches[1].ToUpperInvariant(); Actual = $actual; Match = ($actual -eq $Matches[1].ToUpperInvariant()) }
    }

    $p7s       = '{0}.p7s' -f $json
    $signature = if ([System.IO.File]::Exists($p7s)) { Test-TkDetachedSignature -Content ([System.IO.File]::ReadAllBytes($json)) -Signature ([System.IO.File]::ReadAllBytes($p7s)) } else { $null }
    $broken    = @($files | Where-Object { -not $_.Match })

    $reason = if ($broken.Count) { 'Changed or missing since the pack was written: {0}.' -f ((@($broken | ForEach-Object { $_.Name })) -join ', ') }
              elseif ($signature -and -not $signature.Valid) { 'The signature does not match the JSON: {0}' -f $signature.Reason }
              else { '' }

    return [pscustomobject] @{
        Valid     = (-not $reason -and @($files).Count -gt 0)
        Files     = @($files)
        Signed    = [bool] ($signature -and $signature.Valid)
        Signature = $signature
        Reason    = $reason
    }
}

<#
.SYNOPSIS
    Runs the audit and writes its evidence pack, without a window.

.DESCRIPTION
    For an RMM or a scheduled task: the audit at the level asked for, under
    the organisation policy given or set in Settings, then the pack into the
    destination. Destination List returns the frameworks instead. The audit
    reads what only an administrator can, so the run refuses without those
    rights rather than produce evidence two thirds of which is unread.

.OUTPUTS
    System.String: the JSON result, or the full path of the file written.
#>
function Invoke-TkHeadlessEvidence {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Framework = @(),
        [Parameter()] [ValidateSet('Essential', 'Full')] [string] $AuditLevel = 'Essential',
        [Parameter()] [AllowEmptyString()] [string] $Policy = '',
        [Parameter()] [AllowEmptyCollection()] [string[]] $PolicyTrust = @(),
        [Parameter()] [AllowEmptyString()] [string] $Certificate = '',
        [Parameter()] [ValidateSet('None', 'Personal', 'Strict')] [string] $Redact = 'None',
        [Parameter()] [AllowEmptyString()] [string] $OutFile = ''
    )

    if ($Destination -eq 'List') {

        $json = ConvertTo-Json -InputObject @(Get-TkFramework | ForEach-Object {
            [ordered] @{ Id = [string] $_.id; Name = [string] $_.name; Edition = [string] $_.edition; Indicative = [bool] $_.indicative; Requirements = @($_.requirements).Count }
        }) -Depth 4
    }
    else {

        # Everything that can be refused is refused before the audit runs.
        $frameworks = @(Get-TkFramework -Id $Framework | ForEach-Object { [string] $_.id })
        $signing    = if ($Certificate) { @(Get-TkEvidenceSigningCertificate -Thumbprint $Certificate)[0] } else { $null }

        if (-not [System.IO.Directory]::Exists($Destination)) {
            throw ('{0} does not exist: choose a folder.' -f $Destination)
        }

        if (-not (Test-TkIsElevated)) {
            throw 'The evidence pack comes from the security audit, which reads what only an administrator can: run it elevated, or as SYSTEM.'
        }

        $source = $Policy
        $trust  = @($PolicyTrust | Where-Object { $_ })
        if (-not $source) {
            $setting = Get-TkPolicySetting
            $source  = $setting.Source
            $trust   = @($setting.Trust)
        }

        $excluded = @(if (Get-Command -Name 'Get-TkAuditExclusion' -ErrorAction SilentlyContinue) { Get-TkAuditExclusion })
        $audit    = Invoke-TkPolicyAudit -Level $AuditLevel -ExcludedAccount $excluded -PolicySource $source -PolicyTrust $trust
        $pack     = New-TkEvidencePack -Finding @($audit.Findings) -Level $audit.Level -Compliance $audit.Compliance -ExcludedAccount @($audit.ExcludedAccount) `
                        -Framework $frameworks -Toolkit (Get-TkToolkitIdentity) -Journal (Test-TkJournalChain) -Elevated $true
        $written  = Export-TkEvidencePack -Pack $pack -Folder $Destination -Privacy $Redact -Certificate $signing -Confirm:$false
        $context  = Get-TkContext

        $observations = [ordered] @{}
        foreach ($group in @($pack.Frameworks | ForEach-Object { $_.Requirements } | Group-Object -Property { $_.Observation })) { $observations[$group.Name] = $group.Count }

        $document = [ordered] @{
            Schema        = 'toolkit-evidence-result'
            SchemaVersion = '1.0'
            Computer      = $env:COMPUTERNAME
            MachineId     = Get-TkMachineId
            GeneratedAt   = [datetime]::UtcNow.ToString('o')
            Toolkit       = [ordered] @{ Version = [string] $context.Version; Commit = [string] $context.Commit }
            Audit         = $pack.Audit
            Observations  = $observations
            Pack          = $written
        }

        $json = ConvertTo-Json -InputObject (ConvertTo-TkPlainData -InputObject $document) -Depth 8
        if ($Redact -ne 'None') {
            $json = (Protect-TkExportText -Text $json -Level $Redact -Label 'evidence-result').Text
        }
    }

    if (-not $OutFile) {
        return $json
    }

    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))

    return $path
}
