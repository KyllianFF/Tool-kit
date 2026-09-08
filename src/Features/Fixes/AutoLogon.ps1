<#
    Toolkit - Features / Automatic logon

    Configures Windows to sign a user in without a prompt. Common on kiosks,
    lab benches, digital signage and staging machines.

    Security design.

    The naive implementation writes DefaultPassword under Winlogon, where the
    password sits in clear text and is readable by every local user. This
    module refuses to do that. The password is stored in the LSA private data
    store under the DefaultPassword key, which is the same mechanism the
    Sysinternals Autologon tool uses: the secret is encrypted by the system
    and only readable by SYSTEM.

    Be clear about what this still is: automatic logon means anyone with
    physical access is that user. The secret is protected at rest, not from
    someone sitting at the keyboard.
#>

<#
.SYNOPSIS
    Loads the LSA interop helper used to store the logon secret.

.DESCRIPTION
    Compiled once per session. Wraps LsaOpenPolicy, LsaStorePrivateData and
    LsaClose, which is the supported way to write an LSA secret.
#>
function Initialize-TkLsaInterop {
    [CmdletBinding()]
    param()

    if ('TkLsaSecret' -as [type]) {
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

public static class TkLsaSecret
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    // POLICY_CREATE_SECRET is the least privilege needed to write a secret.
    private const uint POLICY_CREATE_SECRET = 0x00000020;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaOpenPolicy(
        IntPtr systemName,
        ref LSA_OBJECT_ATTRIBUTES objectAttributes,
        uint desiredAccess,
        out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaStorePrivateData(
        IntPtr policyHandle,
        ref LSA_UNICODE_STRING keyName,
        IntPtr privateData);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(uint status);

    private static LSA_UNICODE_STRING BuildString(string value)
    {
        LSA_UNICODE_STRING result = new LSA_UNICODE_STRING();
        result.Buffer = Marshal.StringToHGlobalUni(value);
        result.Length = (ushort)(value.Length * 2);
        result.MaximumLength = (ushort)((value.Length + 1) * 2);
        return result;
    }

    /// <summary>
    /// Writes an LSA private data entry. A null value deletes the entry.
    /// </summary>
    public static void Store(string key, string value)
    {
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

        IntPtr policyHandle;
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, POLICY_CREATE_SECRET, out policyHandle);

        if (status != 0)
        {
            throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(status));
        }

        LSA_UNICODE_STRING keyName = BuildString(key);
        IntPtr dataPointer = IntPtr.Zero;
        IntPtr dataStruct = IntPtr.Zero;

        try
        {
            if (value != null)
            {
                LSA_UNICODE_STRING data = BuildString(value);
                dataPointer = data.Buffer;

                dataStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                Marshal.StructureToPtr(data, dataStruct, false);
            }

            status = LsaStorePrivateData(policyHandle, ref keyName, dataStruct);

            if (status != 0)
            {
                throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(status));
            }
        }
        finally
        {
            // Zero the secret in unmanaged memory before releasing it so it
            // does not linger in the process working set.
            if (dataPointer != IntPtr.Zero && value != null)
            {
                for (int i = 0; i < value.Length; i++)
                {
                    Marshal.WriteInt16(dataPointer, i * 2, 0);
                }

                Marshal.FreeHGlobal(dataPointer);
            }

            if (dataStruct != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(dataStruct);
            }

            Marshal.FreeHGlobal(keyName.Buffer);
            LsaClose(policyHandle);
        }
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}

<#
.SYNOPSIS
    Enables automatic logon for a user.

.DESCRIPTION
    Writes the Winlogon identity values and stores the password as an LSA
    secret. The clear text DefaultPassword value is actively removed, in case
    a previous tool left one behind.

.PARAMETER UserName
    Account to sign in, without the domain part.

.PARAMETER Password
    Account password, as a SecureString.

.PARAMETER Domain
    Domain or computer name. Defaults to the current computer.

.PARAMETER LogonCount
    Number of automatic logons before Windows stops. 0 means unlimited.

.OUTPUTS
    System.Boolean
#>
function Enable-TkAutoLogon {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(Mandatory)]
        [securestring] $Password,

        [Parameter()]
        [string] $Domain = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateRange(0, 9999)]
        [int] $LogonCount = 0
    )

    if (-not (Assert-TkElevated -Operation 'Configure automatic logon')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess(('{0}\{1}' -f $Domain, $UserName), 'Enable automatic logon')) {
        return $false
    }

    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $plain    = $null
    $bstr     = [IntPtr]::Zero

    try {
        Initialize-TkLsaInterop

        # The password only exists in clear text inside this try block and is
        # zeroed in the finally block below.
        $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        [TkLsaSecret]::Store('DefaultPassword', $plain)

        Set-TkRegistryValue -Path $winlogon -Name 'AutoAdminLogon'    -Value '1'       -Type String -Confirm:$false | Out-Null
        Set-TkRegistryValue -Path $winlogon -Name 'DefaultUserName'   -Value $UserName -Type String -Confirm:$false | Out-Null
        Set-TkRegistryValue -Path $winlogon -Name 'DefaultDomainName' -Value $Domain   -Type String -Confirm:$false | Out-Null

        # Never leave a clear text password behind, whoever wrote it.
        Remove-TkRegistryValue -Path $winlogon -Name 'DefaultPassword' -Confirm:$false | Out-Null

        if ($LogonCount -gt 0) {
            Set-TkRegistryValue -Path $winlogon -Name 'AutoLogonCount' -Value $LogonCount -Type DWord -Confirm:$false | Out-Null
        }
        else {
            Remove-TkRegistryValue -Path $winlogon -Name 'AutoLogonCount' -Confirm:$false | Out-Null
        }

        Write-TkLog -Level Warning -Category 'AutoLogon' -Message (
            'Automatic logon enabled for {0}\{1}. Anyone with physical access now has this session.' -f $Domain, $UserName
        )

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'AutoLogon' -Message (
            'Could not enable automatic logon: {0}' -f $_.Exception.Message
        )

        return $false
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        $plain = $null
        [System.GC]::Collect()
    }
}

<#
.SYNOPSIS
    Disables automatic logon and removes the stored secret.

.OUTPUTS
    System.Boolean
#>
function Disable-TkAutoLogon {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()

    if (-not (Assert-TkElevated -Operation 'Disable automatic logon')) {
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable automatic logon')) {
        return $false
    }

    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

    try {
        Set-TkRegistryValue -Path $winlogon -Name 'AutoAdminLogon' -Value '0' -Type String -Confirm:$false | Out-Null

        Remove-TkRegistryValue -Path $winlogon -Name 'DefaultPassword' -Confirm:$false | Out-Null
        Remove-TkRegistryValue -Path $winlogon -Name 'AutoLogonCount'  -Confirm:$false | Out-Null

        # Clear the LSA secret as well: leaving it behind would let a later
        # AutoAdminLogon flip re-enable a logon with a forgotten password.
        Initialize-TkLsaInterop
        [TkLsaSecret]::Store('DefaultPassword', $null)

        Write-TkLog -Level Information -Category 'AutoLogon' -Message 'Automatic logon disabled and the stored secret removed.'

        return $true
    }
    catch {
        Write-TkLog -Level Error -Category 'AutoLogon' -Message (
            'Could not fully disable automatic logon: {0}' -f $_.Exception.Message
        )

        return $false
    }
}

<#
.SYNOPSIS
    Reports the current automatic logon configuration.

.OUTPUTS
    PSCustomObject
#>
function Get-TkAutoLogonStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

    $enabled   = (Get-TkRegistryValue -Path $winlogon -Name 'AutoAdminLogon') -eq '1'
    $clearText = $null -ne (Get-TkRegistryValue -Path $winlogon -Name 'DefaultPassword')

    return [pscustomobject]@{
        Enabled            = $enabled
        UserName           = Format-TkValue (Get-TkRegistryValue -Path $winlogon -Name 'DefaultUserName')
        Domain             = Format-TkValue (Get-TkRegistryValue -Path $winlogon -Name 'DefaultDomainName')
        LogonCount         = Get-TkRegistryValue -Path $winlogon -Name 'AutoLogonCount'
        ClearTextPassword  = $clearText
        Warning            = if ($clearText) {
                                 'A clear text password is present in the registry. Disable and re-enable automatic logon to move it into the LSA store.'
                             }
                             else { '' }
    }
}
