<#
    Toolkit - Features / Secret scanner

    The credential someone pasted into a config file, a script or a ticket and
    forgot to take back out. This reads a blob and flags what looks like a
    secret: the cloud and service tokens that announce themselves with a prefix,
    a private key block, a password on an assignment or in a connection string.
    Each is named and masked, so the report itself does not carry the secret on.

    It is a first pass, not a vault scanner: it matches shape, so it can miss a
    secret with no recognisable form and can flag a value that is not one. Read
    on the machine; nothing is sent anywhere.
#>

<#
.SYNOPSIS
    The patterns the scanner looks for, and where the secret sits in each.

.DESCRIPTION
    The specific tokens come first so a GitHub token is named as one rather than
    caught by the general assignment rule below it. A rule with a "v" group hides
    only that group; otherwise the whole match is the secret.

.OUTPUTS
    PSCustomObject[] with Type and Pattern.
#>
function Get-TkSecretRule {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $rule = { param($type, $pattern) [pscustomobject] @{ Type = $type; Pattern = $pattern } }

    return @(
        (& $rule 'AWS access key ID'        'AKIA[0-9A-Z]{16}')
        (& $rule 'AWS secret access key'    '(?i)aws_secret_access_key\s*[:=]\s*["'']?(?<v>[A-Za-z0-9/+]{40})')
        (& $rule 'GitHub token'             'gh[posru]_[A-Za-z0-9]{36,}')
        (& $rule 'GitHub fine-grained PAT'  'github_pat_[A-Za-z0-9_]{50,}')
        (& $rule 'Slack token'              'xox[baprs]-[A-Za-z0-9-]{10,}')
        (& $rule 'Slack webhook'            'https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{20,}')
        (& $rule 'Google API key'           'AIza[0-9A-Za-z_\-]{35}')
        (& $rule 'Stripe secret key'        '[sr]k_live_[0-9a-zA-Z]{20,}')
        (& $rule 'SendGrid API key'         'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}')
        (& $rule 'npm token'                'npm_[A-Za-z0-9]{36}')
        (& $rule 'JSON Web Token'           'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
        (& $rule 'Private key block'        '-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----')
        (& $rule 'Password or secret'       '(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token)\s*[:=]\s*["'']?(?<v>[^\s"'';]{6,})')
    )
}

<#
.SYNOPSIS
    Says whether a value is an obvious placeholder rather than a real secret.
#>
function Test-TkSecretPlaceholder {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    return [bool] ($Value -match '(?i)^(changeme|change_me|password|passwd|secret|token|placeholder|example.*|your[_-].*|xxx+|\*+|<.*>|\$\{.*\}|%.*%|null|none|true|false|\d+)$')
}

<#
.SYNOPSIS
    Masks a secret, keeping only enough of the ends to recognise it.

.OUTPUTS
    System.String
#>
function Protect-TkSecretValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $length = $Value.Length

    if ($length -le 8) {
        return ('*' * [math]::Max(4, $length))
    }

    return $Value.Substring(0, 4) + ('*' * [math]::Min(12, $length - 6)) + $Value.Substring($length - 2)
}

<#
.SYNOPSIS
    Finds the likely secrets in a text.

.PARAMETER Text
    The blob to scan.

.OUTPUTS
    PSCustomObject[] with Type, Line, Value and Masked.
#>
function Get-TkSecretFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $findings = New-Object System.Collections.Generic.List[pscustomobject]
    $seen     = New-Object System.Collections.Generic.HashSet[string]

    foreach ($rule in @(Get-TkSecretRule)) {

        foreach ($match in [regex]::Matches($Text, $rule.Pattern)) {

            $group = $match.Groups['v']
            $value = if ($group.Success) { $group.Value } else { $match.Value }

            if (-not $value) { continue }
            if (Test-TkSecretPlaceholder -Value $value) { continue }

            # A secret already named by a specific rule is not caught again by the
            # general assignment rules that follow.
            if (-not $seen.Add($value)) { continue }

            $line = ([regex]::Matches($Text.Substring(0, $match.Index), "`n")).Count + 1

            $findings.Add([pscustomobject] @{
                Type   = $rule.Type
                Line   = $line
                Value  = $value
                Masked = if ($rule.Type -eq 'Private key block') { '(a private key block)' } else { Protect-TkSecretValue -Value $value }
            })
        }
    }

    return @($findings | Sort-Object Line)
}

<#
.SYNOPSIS
    Writes the secret scan as lines of text, the secrets masked.

.OUTPUTS
    System.String[]
#>
function Format-TkSecretReport {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('Paste a config, a script or a log to scan it for exposed secrets.')
    }

    $findings = @(Get-TkSecretFinding -Text $Text)
    $lines    = New-Object System.Collections.Generic.List[string]

    if ($findings.Count -eq 0) {
        $lines.Add('No secret found by shape. This does not prove there is none: a secret with no recognisable form is not caught.')
        return $lines.ToArray()
    }

    $lines.Add(('{0} potential secret(s) found:' -f $findings.Count))
    $lines.Add('')

    foreach ($finding in $findings) {
        $lines.Add(('  L{0,-4} {1,-32} {2}' -f $finding.Line, $finding.Type, $finding.Masked))
    }

    $lines.Add('')
    $lines.Add('Rotate anything real that appears here, and keep it out of source control. Values are masked, but the file you pasted from is not.')

    return $lines.ToArray()
}
