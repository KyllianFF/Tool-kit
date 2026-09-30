# Organisation policy

The audit applies the toolkit's own controls, the same on every machine. An
organisation policy is what one organisation expects on top of them:

- the controls it does not require;
- the programs a machine must run, or must not;
- the administrators that belong in the local Administrators group;
- the least Windows build, and the oldest update it tolerates;
- its exceptions, each with a reason, an owner and the day it ends.

The audit then gives a verdict against the policy: **compliant**,
**compliant with exceptions until** a date, or **not compliant**, with what
blocks. The policy changes nothing on the machine, and nothing in the audit's
results or its score. The score measures the machine against the toolkit's
controls, and the verdict judges it against the policy.

## Where it is set

- **In the window.** Go to Settings, then Organisation policy. Give the
  policy file (a path, a share or an `https://` address) and what makes it
  trusted, then click **Check the policy**. The check says what the policy
  asks for, or why it is not applied. Each audit reads and verifies the
  policy again before applying it, so a policy published since is the one
  used.
- **Without a window.** Pass `-Policy` and `-PolicyTrust` with `-Report`.
  Without them, the policy set in Settings for the account running the report
  applies.

```powershell
$toolkit = [scriptblock]::Create((irm https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1))
& $toolkit -Report Audit -AuditLevel Full -Policy '\\server\policy$\workstations.psd1' `
           -PolicyTrust 'A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2' -OutFile "\\server\fleet$\$env:COMPUTERNAME.json"
```

The Audit report of the document then carries `Compliance`, which is
described in [REPORT-FORMAT.md](REPORT-FORMAT.md). The Fleet page counts the
verdicts across the machines.

## Trust

A policy is a data file. It is applied only when it is trusted, in one of two
ways:

| Trusted by | What to pin | What it takes |
|---|---|---|
| Its signature | The thumbprint of the certificate that signs it (40 hexadecimal characters). | An Authenticode signature that Windows reports **Valid**. The content must be unchanged since it was signed, and the certificate chain must be trusted by Windows. A self-signed certificate counts only once it is installed in Trusted Root and Trusted Publishers on the machine. |
| Its hash | The SHA-256 of the file (64 hexadecimal characters). | Nothing more. It trusts exactly one version of the file, so every change to the policy needs the new hash. |

Several values can be pinned together, separated by commas. For example, the
current certificate and its successor.

When the policy cannot be read, is not trusted, or is not a policy this
toolkit can apply, **it is not applied at all**, not even in part. The audit
is then the generic one, and its verdict is `PolicyRefused`, with the
reason. The reason names the file's SHA-256 and its signer, so that the right
value can be pinned.

How the file is read:

- A file larger than 1 MB is refused.
- An address must be `https://`.
- The bytes are read once. The data is parsed from those bytes, and the
  signature is checked on a private copy of the same bytes, which is locked
  against writing. The file cannot change between the check and the parse.
- The text is **parsed, never run**. It must be one hashtable and nothing
  else, and its values may only be constants, `@( )` arrays, `@{ }`
  hashtables, and `$true`, `$false` or `$null`. A command, a variable or an
  expression anywhere refuses the whole file. This is the same safe
  evaluation that `Import-PowerShellDataFile` uses.
- Every application is written to the intervention journal: the policy's
  name, its version, the file's SHA-256 and what trusted it. Every refusal
  is written too, with its reason.

In a fleet, the trust is whatever the command line pins. That is the RMM or
Intune script, not the machine. A machine still writes its own report, so the
fleet view says what the machines declare.

## Signing

```powershell
# With the organisation's code signing certificate:
$certificate = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Thumbprint -eq 'A1B2...'
Set-AuthenticodeSignature -FilePath .\workstations.psd1 -Certificate $certificate -TimestampServer http://timestamp.digicert.com

# Or pin the file's hash instead:
(Get-FileHash .\workstations.psd1 -Algorithm SHA256).Hash
```

`build\Sign-Toolkit.ps1` signs a policy file the same way it signs the
toolkit. Save the policy as UTF-8 with a byte order mark: **Save a starting
policy** does. Windows PowerShell 5.1 and `Set-AuthenticodeSignature` then
read it without guessing.

## The file

**Save a starting policy** in Settings writes this, with comments:

```powershell
@{
    Schema        = 'toolkit-policy'
    SchemaVersion = '1.0'
    Name          = 'Contoso workstations'
    Version       = '2026.09.1'
    Owner         = 'Contoso security team'

    Audit = @{
        Level         = 'Full'              # Essential or Full: the least the audit runs at
        NotRequired   = @('PRN-001')        # controls this organisation does not require
        WarningsBlock = $false              # $true: a warning blocks as a failure does
    }

    Administrators = @('CONTOSO\Workstation Admins')

    Windows = @{
        MinimumBuild    = 22631
        MaxPatchAgeDays = 30
    }

    Software = @{
        Required  = @(
            @{ Id = 'ORG-EDR'; Name = 'CrowdStrike Falcon sensor'; Service = 'CSAgent'; Why = 'Every workstation runs the EDR.' }
        )
        Forbidden = @(
            @{ Id = 'ORG-REMOTE'; Name = 'AnyDesk'; Package = 'AnyDesk*'; Why = 'Remote access goes through the approved tool.' }
        )
    }

    Exceptions = @(
        @{ Control = 'RDP-001'; Computers = @('LAB-*'); Reason = 'Lab machines are administered over RDP.'
           Owner = 'J. Martin'; Expires = '2026-12-31'; Ticket = 'CHG-1234' }
    )
}
```

| Key | Meaning |
|---|---|
| `Schema`, `SchemaVersion` | Always `toolkit-policy`, and `major.minor`, currently **1.0**. A later major version is refused rather than misread. |
| `Name`, `Version` | Required: they are what the journal and the reports name. `Owner`, `Published` and `Description` are optional. |
| `Audit.Level` | The audit runs at least at this level under the policy. |
| `Audit.NotRequired` | Control identifiers, as the audit shows them (`PRN-001`). Their results are still shown, but they block nothing. |
| `Audit.WarningsBlock` | By default only a failure blocks. With `$true`, a warning blocks too. |
| `Administrators` | Left out of the account controls, next to the accounts the operator excluded. |
| `Windows.MinimumBuild` | The rule `POL-WIN-BUILD`. |
| `Windows.MaxPatchAgeDays` | The rule `POL-PATCH-AGE`: days since the last update was installed, from 1 to 365. |
| `Software.Required` | Each entry has `Package`, a wildcard on an installed program's name, or `Service`, a service that must be running, or both. `Id` names the rule in reports (by default `POL-REQ-1`, and so on). `Name` and `Why` are shown with it. |
| `Software.Forbidden` | The same, and the rule fails when the program is installed or the service exists. |
| `Exceptions` | `Control` is a control or rule identifier. `Computers` holds wildcards on the computer name, and every machine is covered when it is left out. `Reason`, `Owner` and `Expires` (`yyyy-MM-dd`) are required. `Ticket` is optional. |

An entry the toolkit cannot use is left out, and the check names it. That
covers an unknown key, a rule that names nothing, and an exception without an
owner or an end. The rest of the policy still applies. An exception without
an end date is never accepted.

## The verdict

Each finding, and each of the policy's own rules, gets one of these states:

| State | Meaning |
|---|---|
| Blocking | A failure, or a warning when `WarningsBlock` is set. It makes the machine non compliant. |
| Accepted | The same, covered by an exception for this machine that has not ended. An exception holds through the day of its `Expires` date. |
| Expired | The same, covered only by exceptions that have ended. It blocks again, on its own, the day after. |
| NotRequired | A control the policy does not require. |
| Tolerated | A warning the policy lets pass. |
| NotAssessed | Not readable, for example without elevation. It blocks nothing, and is counted apart. |
| Met | The rest. |

The machine is **NonCompliant** when anything is Blocking or Expired. It is
**CompliantWithExceptions** when something is Accepted, until the first of
those exceptions ends. Otherwise it is **Compliant**. An exception for this
machine that covers nothing on it is listed, so that it can be withdrawn.
