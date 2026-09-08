<#
    Toolkit - Features / SSH key management

    Wraps the OpenSSH client that ships with Windows 10 1809 and later.

    Defaults are opinionated on purpose: ed25519, a passphrase, and a refusal
    to silently overwrite an existing key. Overwriting a private key with no
    warning is unrecoverable, and generating a key without a passphrase turns
    any file read into a lateral movement primitive.
#>

<#
.SYNOPSIS
    Returns the state of the OpenSSH client.

.OUTPUTS
    PSCustomObject
#>
function Get-TkSshStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $available = Test-TkCommand -Name 'ssh-keygen'
    $version   = ''

    if ($available) {
        # ssh writes its version banner to stderr, which is expected.
        $result  = Invoke-TkProcess -FilePath 'ssh' -ArgumentList @('-V') -TimeoutSeconds 15
        $version = ($result.StandardError + $result.StandardOutput).Trim()
    }

    $sshDirectory = Join-Path -Path $env:USERPROFILE -ChildPath '.ssh'

    return [pscustomobject]@{
        Available    = $available
        Version      = $version
        SshDirectory = $sshDirectory
        AgentStatus  = (Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue).Status
    }
}

<#
.SYNOPSIS
    Installs the Windows OpenSSH client feature.

.OUTPUTS
    System.Boolean
#>
function Install-TkOpenSshClient {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Install the OpenSSH client')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install OpenSSH.Client')) {
        return $false
    }

    try {
        $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Client*' -ErrorAction Stop |
                      Select-Object -First 1

        if ($capability.State -eq 'Installed') {
            Write-TkLog -Level Information -Category 'SSH' -Message 'The OpenSSH client is already installed.'
            return $true
        }

        Add-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null

        Write-TkLog -Level Information -Category 'SSH' -Message 'OpenSSH client installed.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'SSH' -Message (
            'Could not install the OpenSSH client: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Generates an SSH key pair.

.DESCRIPTION
    ed25519 is the default: it is fast, small, and has no parameter choices
    to get wrong. RSA is offered at 4096 bits for the appliances and older
    servers that still refuse anything else; 2048 is deliberately not an
    option here.

.PARAMETER Name
    File name of the key inside the .ssh directory.

.PARAMETER Type
    ed25519, ecdsa or rsa.

.PARAMETER Comment
    Key comment. Defaults to user@host, which is what identifies the key in
    an authorized_keys file six months later.

.PARAMETER Passphrase
    Passphrase protecting the private key. An empty one is accepted only with
    -AllowEmptyPassphrase.

.PARAMETER AllowEmptyPassphrase
    Explicit acknowledgement that the key will be unprotected on disk.

.OUTPUTS
    PSCustomObject with PrivateKeyPath, PublicKeyPath, PublicKey, Fingerprint.
#>
function New-TkSshKey {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
        [string] $Name,

        [Parameter()]
        [ValidateSet('ed25519', 'ecdsa', 'rsa')]
        [string] $Type = 'ed25519',

        [Parameter()]
        [string] $Comment = ('{0}@{1}' -f $env:USERNAME, $env:COMPUTERNAME),

        [Parameter()]
        [securestring] $Passphrase,

        [Parameter()]
        [switch] $AllowEmptyPassphrase
    )

    if (-not (Test-TkCommand -Name 'ssh-keygen')) {

        Write-TkLog -Level Error -Category 'SSH' -Message (
            'ssh-keygen was not found. Install the OpenSSH client first.'
        )

        return $null
    }

    $sshDirectory = Join-Path -Path $env:USERPROFILE -ChildPath '.ssh'

    if (-not (Test-Path -LiteralPath $sshDirectory)) {
        New-Item -Path $sshDirectory -ItemType Directory -Force | Out-Null
    }

    $privateKeyPath = Join-Path -Path $sshDirectory -ChildPath $Name

    # Never overwrite an existing private key: the loss is not recoverable.
    if (Test-Path -LiteralPath $privateKeyPath) {

        Write-TkLog -Level Error -Category 'SSH' -Message (
            'Refused: {0} already exists. Choose another name or remove it deliberately.' -f $privateKeyPath
        )

        return $null
    }

    # --- Passphrase handling ---------------------------------------------
    $plainPassphrase = ''

    if ($Passphrase) {

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)

        try {
            $plainPassphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    if ([string]::IsNullOrEmpty($plainPassphrase) -and -not $AllowEmptyPassphrase) {

        Write-TkLog -Level Error -Category 'SSH' -Message (
            'Refused: a key with no passphrase is unprotected at rest. Pass -AllowEmptyPassphrase to accept that.'
        )

        return $null
    }

    if (-not $PSCmdlet.ShouldProcess($privateKeyPath, ('Generate {0} key' -f $Type))) {
        return $null
    }

    $arguments = @(
        '-t', $Type,
        '-f', $privateKeyPath,
        '-C', $Comment,
        '-N', $plainPassphrase
    )

    if ($Type -eq 'rsa') {
        $arguments += @('-b', '4096')
    }

    $stopwatch = Start-TkOperation -Name ('Generate {0} key' -f $Type) -Category 'SSH'
    $result    = Invoke-TkProcess -FilePath 'ssh-keygen' -ArgumentList $arguments -TimeoutSeconds 120

    # Clear the passphrase from this scope as soon as it is no longer needed.
    $plainPassphrase = $null
    $arguments       = $null

    $success = ($result.ExitCode -eq 0) -and (Test-Path -LiteralPath $privateKeyPath)

    Stop-TkOperation -Name ('Generate {0} key' -f $Type) -Stopwatch $stopwatch -Category 'SSH' -Success $success

    if (-not $success) {

        Write-TkLog -Level Error -Category 'SSH' -Message (
            'ssh-keygen failed: {0}' -f (Get-TkFirstLine -Text $result.StandardError)
        )

        return $null
    }

    $publicKeyPath = $privateKeyPath + '.pub'

    # Tighten the ACL: OpenSSH refuses to use a private key that other
    # accounts can read, and so should we.
    Protect-TkPrivateKeyFile -Path $privateKeyPath

    return [pscustomobject]@{
        Name           = $Name
        Type           = $Type
        PrivateKeyPath = $privateKeyPath
        PublicKeyPath  = $publicKeyPath
        PublicKey      = (Get-Content -LiteralPath $publicKeyPath -Raw).Trim()
        Fingerprint    = Get-TkSshKeyFingerprint -Path $publicKeyPath
    }
}

<#
.SYNOPSIS
    Restricts a private key file to its owner.

.DESCRIPTION
    Removes inheritance and grants the current user alone. This is exactly
    the check ssh performs before it agrees to use a key on Windows.

.OUTPUTS
    System.Boolean
#>
function Protect-TkPrivateKeyFile {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Restrict permissions to the owner')) {
        return $false
    }

    try {
        $acl      = Get-Acl -LiteralPath $Path
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

        # $true, $false: protect from inheritance and drop the inherited ACEs.
        $acl.SetAccessRuleProtection($true, $false)

        foreach ($rule in @($acl.Access)) {
            [void] $acl.RemoveAccessRule($rule)
        }

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'None', 'None', 'Allow'
        )

        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop

        Write-TkLog -Level Information -Category 'SSH' -Message (
            'Permissions on {0} restricted to {1}.' -f (Split-Path $Path -Leaf), $identity
        )

        return $true
    }
    catch {
        Write-TkLog -Level Warning -Category 'SSH' -Message (
            'Could not tighten permissions on {0}: {1}' -f $Path, $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Returns the fingerprint of a public key.

.OUTPUTS
    System.String
#>
function Get-TkSshKeyFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-TkCommand -Name 'ssh-keygen')) {
        return ''
    }

    $result = Invoke-TkProcess -FilePath 'ssh-keygen' -ArgumentList @('-lf', $Path) -TimeoutSeconds 30

    if ($result.ExitCode -ne 0) {
        return ''
    }

    return $result.StandardOutput.Trim()
}

<#
.SYNOPSIS
    Lists the SSH key pairs found in the user profile.

.OUTPUTS
    PSCustomObject[]
#>
function Get-TkSshKey {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    $sshDirectory = Join-Path -Path $env:USERPROFILE -ChildPath '.ssh'

    if (-not (Test-Path -LiteralPath $sshDirectory)) {
        return , @()
    }

    $results = @()

    foreach ($publicKey in (Get-ChildItem -LiteralPath $sshDirectory -Filter '*.pub' -File -ErrorAction SilentlyContinue)) {

        $privateKeyPath = $publicKey.FullName -replace '\.pub$', ''
        $content        = (Get-Content -LiteralPath $publicKey.FullName -Raw).Trim()
        $parts          = $content -split '\s+', 3

        $results += [pscustomobject]@{
            Name           = Split-Path -Path $privateKeyPath -Leaf
            Algorithm      = $parts[0]
            Comment        = if ($parts.Count -ge 3) { $parts[2] } else { '' }
            PublicKey      = $content
            PublicKeyPath  = $publicKey.FullName
            PrivateKeyPath = $privateKeyPath
            HasPrivateKey  = Test-Path -LiteralPath $privateKeyPath
            Fingerprint    = Get-TkSshKeyFingerprint -Path $publicKey.FullName
            Created        = $publicKey.CreationTime
        }
    }

    return , $results
}

<#
.SYNOPSIS
    Starts the ssh-agent service and adds a key to it.

.OUTPUTS
    System.Boolean
#>
function Add-TkSshKeyToAgent {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $PrivateKeyPath
    )

    if (-not (Test-Path -LiteralPath $PrivateKeyPath)) {
        Write-TkLog -Level Error -Category 'SSH' -Message ('Key not found: {0}' -f $PrivateKeyPath)
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($PrivateKeyPath, 'Add to ssh-agent')) {
        return $false
    }

    $agent = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue

    if (-not $agent) {
        Write-TkLog -Level Error -Category 'SSH' -Message 'The ssh-agent service is not present.'
        return $false
    }

    if ($agent.StartType -eq 'Disabled') {

        if (-not (Set-TkServiceStartup -Name 'ssh-agent' -StartupType Manual -Confirm:$false)) {
            return $false
        }
    }

    if ($agent.Status -ne 'Running') {
        Start-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
    }

    # ssh-add prompts for the passphrase on the console it inherits, which is
    # the correct place for it: the toolkit never handles it here.
    $result = Invoke-TkProcess -FilePath 'ssh-add' -ArgumentList @($PrivateKeyPath) -TimeoutSeconds 120

    $success = ($result.ExitCode -eq 0)

    if ($success) {
        Write-TkLog -Level Information -Category 'SSH' -Message ('Key added to the agent: {0}' -f $PrivateKeyPath)
    }
    else {
        Write-TkLog -Level Warning -Category 'SSH' -Message (
            'ssh-add failed. A passphrase protected key must be added from a console: {0}' -f
                (Get-TkFirstLine -Text $result.StandardError)
        )
    }

    return $success
}
