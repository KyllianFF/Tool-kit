<#
    Toolkit - Features / VirusTotal

    Reputation lookups against the VirusTotal v3 API.

    Two privacy rules are built into this module and stated in the interface:

      1. The default action sends a hash, never the file. A hash discloses
         nothing about the contents; uploading a file publishes it to a
         service other researchers can download from. Company documents,
         configuration exports and internal installers must not be uploaded,
         so the upload path exists but is explicit and separate.

      2. The API key is stored with DPAPI under the current user account. It
         is written encrypted, it does not follow the user to another machine,
         and it never appears in a log line or a command line.
#>

$script:TkVirusTotalBaseUri = 'https://www.virustotal.com/api/v3'

<#
.SYNOPSIS
    Stores the VirusTotal API key, encrypted for the current user.

.DESCRIPTION
    ConvertFrom-SecureString without a key uses DPAPI, which ties the
    ciphertext to this user on this machine. Copying the file elsewhere
    yields nothing usable.

.PARAMETER ApiKey
    The key, as a SecureString.

.OUTPUTS
    System.Boolean
#>
function Set-TkVirusTotalApiKey {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [securestring] $ApiKey
    )

    $ctx  = Get-TkContext
    $path = Join-Path -Path $ctx.DataRoot -ChildPath 'virustotal.key'

    if (-not $PSCmdlet.ShouldProcess($path, 'Store the API key')) {
        return $false
    }

    try {
        ConvertFrom-SecureString -SecureString $ApiKey |
            Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop

        $ctx.Settings['VirusTotalKeyStored'] = $true
        Save-TkSettings -Confirm:$false

        Write-TkLog -Level Information -Category 'VirusTotal' -Message (
            'API key stored, encrypted for the current user.'
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'VirusTotal' -Message (
            'Could not store the API key: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Reads the stored API key.

.DESCRIPTION
    Returns the key as plain text because the HTTP header needs it that way.
    Callers must not log it or write it to disk.

.OUTPUTS
    System.String, or $null when no key is stored.
#>
function Get-TkVirusTotalApiKey {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx  = Get-TkContext
    $path = Join-Path -Path $ctx.DataRoot -ChildPath 'virustotal.key'

    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }

    try {
        # Trimmed: Set-Content appends a newline, and ConvertTo-SecureString
        # rejects the trailing character, so the key failed to decrypt
        # immediately after it was saved.
        $stored = (Get-Content -LiteralPath $path -Raw).Trim()
        $secure = ConvertTo-SecureString -String $stored -ErrorAction Stop
        $bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)

        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    catch {
        # Decryption fails when the file was copied from another profile.
        Write-TkLog -Level Error -Category 'VirusTotal' -Message (
            'The stored key could not be decrypted for this account. Enter it again.'
        )

        return $null
    }
}

<#
.SYNOPSIS
    Removes the stored API key.

.OUTPUTS
    System.Boolean
#>
function Remove-TkVirusTotalApiKey {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    $ctx  = Get-TkContext
    $path = Join-Path -Path $ctx.DataRoot -ChildPath 'virustotal.key'

    if (-not $PSCmdlet.ShouldProcess($path, 'Delete the stored API key')) {
        return $false
    }

    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }

    $ctx.Settings['VirusTotalKeyStored'] = $false
    Save-TkSettings -Confirm:$false

    Write-TkLog -Level Information -Category 'VirusTotal' -Message 'Stored API key removed.'

    return $true
}

<#
.SYNOPSIS
    Looks a file up on VirusTotal by hash.

.DESCRIPTION
    Computes the SHA256 locally and queries the reputation of that hash. The
    file itself never leaves the machine.

    A "not found" answer is not a clean bill of health: it means nobody has
    submitted this file before, which for a freshly built internal installer
    is entirely expected and for an email attachment is a warning sign.

.PARAMETER Path
    File to look up.

.OUTPUTS
    PSCustomObject
#>
function Get-TkVirusTotalFileReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-TkLog -Level Error -Category 'VirusTotal' -Message ('File not found: {0}' -f $Path)
        return $null
    }

    $apiKey = Get-TkVirusTotalApiKey

    if (-not $apiKey) {

        Write-TkLog -Level Error -Category 'VirusTotal' -Message (
            'No API key stored. Add one in the Security page first.'
        )

        return $null
    }

    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash

    Write-TkLog -Level Information -Category 'VirusTotal' -Message (
        'Looking up the SHA256 of {0}. The file is not being uploaded.' -f (Split-Path $Path -Leaf)
    )

    $report = Invoke-TkVirusTotalRequest -Endpoint ('files/{0}' -f $hash) -ApiKey $apiKey

    if ($null -eq $report) {

        return [pscustomobject]@{
            FileName    = Split-Path $Path -Leaf
            Sha256      = $hash
            Known       = $false
            Malicious   = 0
            Suspicious  = 0
            Harmless    = 0
            Undetected  = 0
            Verdict     = 'Unknown to VirusTotal'
            Detail      = 'No analysis exists for this hash. That is normal for a file built in house and suspicious for one received from outside.'
            Permalink   = ('https://www.virustotal.com/gui/file/{0}' -f $hash)
        }
    }

    $stats = $report.data.attributes.last_analysis_stats

    $verdict = 'Clean'

    if ($stats.malicious -ge 1) {
        $verdict = 'MALICIOUS'
    }
    elseif ($stats.suspicious -ge 1) {
        $verdict = 'Suspicious'
    }

    Write-TkLog -Level $(if ($stats.malicious -ge 1) { 'Warning' } else { 'Information' }) `
                -Category 'VirusTotal' -Message (
        '{0}: {1} ({2} malicious of {3} engines).' -f
            (Split-Path $Path -Leaf), $verdict, $stats.malicious,
            ($stats.malicious + $stats.suspicious + $stats.harmless + $stats.undetected)
    )

    return [pscustomobject]@{
        FileName    = Split-Path $Path -Leaf
        Sha256      = $hash
        Known       = $true
        Malicious   = [int] $stats.malicious
        Suspicious  = [int] $stats.suspicious
        Harmless    = [int] $stats.harmless
        Undetected  = [int] $stats.undetected
        Verdict     = $verdict
        TypeTag     = $report.data.attributes.type_description
        FirstSeen   = ConvertFrom-TkUnixTime -Seconds $report.data.attributes.first_submission_date
        LastAnalysis = ConvertFrom-TkUnixTime -Seconds $report.data.attributes.last_analysis_date
        Names       = @($report.data.attributes.names | Select-Object -First 5)
        Detail      = '{0} engines flagged this file as malicious.' -f $stats.malicious
        Permalink   = ('https://www.virustotal.com/gui/file/{0}' -f $hash)
    }
}

<#
.SYNOPSIS
    Looks a URL, domain or IP address up on VirusTotal.

.PARAMETER Value
    The URL, domain or IPv4 address to query.

.OUTPUTS
    PSCustomObject
#>
function Get-TkVirusTotalIndicatorReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Value
    )

    $apiKey = Get-TkVirusTotalApiKey

    if (-not $apiKey) {
        Write-TkLog -Level Error -Category 'VirusTotal' -Message 'No API key stored.'
        return $null
    }

    $trimmed = $Value.Trim()

    # Pick the endpoint from the shape of the indicator.
    if ($trimmed -match '^\d{1,3}(\.\d{1,3}){3}$') {

        $endpoint = 'ip_addresses/{0}' -f $trimmed
        $kind     = 'IP address'
    }
    elseif ($trimmed -match '^https?://') {

        # The v3 API addresses a URL by the base64url of the URL itself,
        # stripped of padding.
        $bytes    = [System.Text.Encoding]::UTF8.GetBytes($trimmed)
        $id       = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $endpoint = 'urls/{0}' -f $id
        $kind     = 'URL'
    }
    else {
        $endpoint = 'domains/{0}' -f $trimmed
        $kind     = 'Domain'
    }

    Write-TkLog -Level Information -Category 'VirusTotal' -Message (
        'Querying the reputation of a {0}.' -f $kind.ToLower()
    )

    $report = Invoke-TkVirusTotalRequest -Endpoint $endpoint -ApiKey $apiKey

    if ($null -eq $report) {

        return [pscustomobject]@{
            Indicator = $trimmed
            Kind      = $kind
            Known     = $false
            Verdict   = 'Unknown to VirusTotal'
        }
    }

    $stats = $report.data.attributes.last_analysis_stats

    return [pscustomobject]@{
        Indicator   = $trimmed
        Kind        = $kind
        Known       = $true
        Malicious   = [int] $stats.malicious
        Suspicious  = [int] $stats.suspicious
        Harmless    = [int] $stats.harmless
        Undetected  = [int] $stats.undetected
        Reputation  = $report.data.attributes.reputation
        Verdict     = if ($stats.malicious -ge 1) { 'MALICIOUS' }
                      elseif ($stats.suspicious -ge 1) { 'Suspicious' }
                      else { 'Clean' }
    }
}

<#
.SYNOPSIS
    Performs an authenticated GET against the VirusTotal API.

.DESCRIPTION
    Central place for the API key header, the rate limit handling and the
    404 case. The key is passed in a header and never in the URL, so it does
    not end up in a proxy log.

.OUTPUTS
    The parsed response, or $null when the object is unknown.
#>
function Invoke-TkVirusTotalRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Endpoint,

        [Parameter(Mandatory)]
        [string] $ApiKey
    )

    $uri = '{0}/{1}' -f $script:TkVirusTotalBaseUri, $Endpoint

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30 -ErrorAction Stop `
                                      -Headers @{ 'x-apikey' = $ApiKey; 'Accept' = 'application/json' }

        return $response
    }
    catch {
        $statusCode = $null

        if ($_.Exception.Response) {
            $statusCode = [int] $_.Exception.Response.StatusCode
        }

        switch ($statusCode) {

            404 {
                # Unknown object: a normal answer, not a failure.
                return $null
            }

            401 {
                Write-TkLog -Level Error -Category 'VirusTotal' -Message (
                    'The API key was rejected. Check it in your VirusTotal account settings.'
                )
                return $null
            }

            429 {
                Write-TkLog -Level Warning -Category 'VirusTotal' -Message (
                    'Rate limit reached. The free tier allows 4 requests per minute and 500 per day.'
                )
                return $null
            }

            default {
                Write-TkLog -Level Error -Category 'VirusTotal' -Message (
                    'Request failed ({0}): {1}' -f $statusCode, $_.Exception.Message
                )
                return $null
            }
        }
    }
}

<#
.SYNOPSIS
    Converts a Unix timestamp into a local DateTime.

.OUTPUTS
    System.DateTime, or $null.
#>
function ConvertFrom-TkUnixTime {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Seconds
    )

    if ($null -eq $Seconds -or $Seconds -le 0) {
        return $null
    }

    return ([System.DateTimeOffset]::FromUnixTimeSeconds([int64] $Seconds)).LocalDateTime
}
