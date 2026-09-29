# Report format

The JSON document a headless run writes (`-Report`, `-CompareWith`), which is
also what the Intervention page keeps as a snapshot. It is meant to be read by
something else: a script, an RMM agent, a monitoring rule, a fleet view. This
page is the contract between the toolkit and that reader.
[report.schema.json](report.schema.json) says the same to a JSON Schema
validator (draft-07).

## Versions

- `Schema` is always `toolkit-report`, and `SchemaVersion` is `major.minor`,
  currently **1.0**.
- A **minor** version only adds fields. A reader ignores the fields it does
  not know, and a document of any 1.x version reads the same way.
- A **major** version removes or renames a field of the envelope, or changes
  its type or meaning.
- Each report also carries its own `Version`, a whole number. It rises when a
  field of that report's `Data` is removed or renamed, or changes type or
  meaning. A field can be added without it rising.
- The toolkit compares with a document of its own major version or an earlier
  one. It refuses a later major version, written by a newer toolkit, rather
  than misread it.
- A document without `Schema` was written by toolkit 1.0.0 or earlier: the
  same envelope without `Schema`, `SchemaVersion`, `MachineId`, `Privacy` and
  the reports' `Version`. It is still read and compared.

## The document

```json
{
  "Schema": "toolkit-report",
  "SchemaVersion": "1.0",
  "Computer": "DESKTOP-4F2A",
  "MachineId": "5d8c1f0e9b7a4c2d8e6f1a3b5c7d9e0f",
  "User": "CONTOSO\\jdupont",
  "GeneratedAt": "2026-09-28T21:06:29.6988123+02:00",
  "Toolkit": { "Version": "1.0.0", "Commit": "5631fda" },
  "Elevated": false,
  "Privacy": "None",
  "Summary": { "Worst": "Warning", "Reports": { "Reboot": "Warning", "Storage": "Pass" } },
  "Reports": {
    "Reboot": { "Version": 1, "Status": "Ok", "Reason": "", "DurationMs": 213, "Worst": "Warning", "Data": { "Pending": true, "Reasons": [ "..." ], "Uptime": "3d 4h 12m" } },
    "Storage": { "Version": 1, "Status": "Ok", "Reason": "", "DurationMs": 950, "Worst": "Pass", "Data": [ { "...": "..." } ] },
    "Audit": { "Version": 1, "Status": "Skipped", "Reason": "Needs administrator rights: run the command from an elevated PowerShell.", "DurationMs": 0, "Worst": "", "Data": null }
  }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `Schema` | text | Always `toolkit-report`. |
| `SchemaVersion` | text | `major.minor`. |
| `Computer` | text | The computer name, or `PC-1` when the document is pseudonymised. |
| `MachineId` | text | 32 hexadecimal characters: a salted SHA-256 of the Windows MachineGuid. The same with or without `-Redact` and after the computer is renamed, so it tells machines apart in a fleet, pseudonymised or not; it names nothing and cannot be turned back into the MachineGuid. Empty when the MachineGuid cannot be read. Machines cloned without sysprep share it. |
| `User` | text | The account that ran the collection, `DOMAIN\user`. |
| `GeneratedAt` | text | When the document was made, ISO 8601 with the offset. |
| `Toolkit` | object | `Version` and `Commit` of the build that wrote it. |
| `Elevated` | boolean | Whether the run had administrator rights. A report that needs them is `Skipped` otherwise, never elevated behind your back. |
| `Privacy` | text | `None`, `Personal` or `Strict`: the `-Redact` level. |
| `Summary.Worst` | text | The worst judgement of all the reports: `Fail`, `Warning`, `Pass`, or empty when nothing is judged. |
| `Summary.Reports` | object | The worst judgement of each report that has one. |
| `Reports` | object | One entry per report collected, by name, in the order asked. |
| `Comparison` | object | Only with `-CompareWith`: what changed since the document given. |

Each entry of `Reports`:

| Field | Type | Meaning |
| --- | --- | --- |
| `Version` | whole number | The version of this report's `Data`. |
| `Status` | text | `Ok`, `Skipped` or `Failed`. |
| `Reason` | text | Why it was skipped, or the error it failed with; empty when `Ok`. |
| `DurationMs` | whole number | How long the collection took. |
| `Worst` | text | The worst `Severity` or `Status` of `Fail`, `Warning`, `Pass` or `Info` anywhere in its `Data` (`Info` counts as `Pass`), or empty. |
| `Data` | any | The report as the interface shows it; `null` when it is not `Ok`. |

## Values

- The file is UTF-8 without a byte order mark. Windows PowerShell 5.1 reads it
  with `Get-Content -Raw -Encoding UTF8`.
- Dates are ISO 8601 text. `GeneratedAt` carries its offset; a date inside
  `Data` carries one when Windows gave it (a local time does, a time Windows
  left unspecified does not).
- Durations are `[d.]hh:mm:ss[.fffffff]`.
- Whole numbers are written as integers (`12`, never `12.0`); a number that
  is not finite is `null`.
- Enumerations are written as their names, GUIDs and versions as text, byte
  arrays as Base64.
- A list stays a list, even with a single row.
- Windows PowerShell 5.1 and PowerShell 7 write the same data. The indentation
  differs, and 5.1 escapes a few characters (`<` as `<`), which a JSON
  reader does not see.

## The reports

| Report | Version | Administrator | `Data` |
| --- | --- | --- | --- |
| Dashboard | 1 | no | An object: `Identity`, `OS`, `Adapter`, `Adapters`, `Reboot`, `LastHotFix`, `Volumes`, `Disks`, `Battery`, `Devices`, `Crashes`, `SignIn`, as the Dashboard shows them. |
| Inventory | 1 | no | An object: `Identity`, `System`, `Hardware`, `Volumes`, `Security`, `Activation`. |
| Network | 1 | no | A list of the network adapters, connected or not. |
| Reboot | 1 | no | An object: `Pending`, `Reasons`, `Uptime`. |
| Storage | 1 | no | A list of disks and volumes, each judged. |
| Performance | 1 | no | An object: `Findings`, `Snapshot`, `Startup`, `Boot`. |
| Devices | 1 | no | A list of the devices Device Manager flags. |
| Crashes | 1 | no | An object: `Crashes` (30 days), `Stability` (14 days). |
| Duplicates | 1 | no | An object: `Folders`, `Scanned`, `Skipped`, `Truncated`, `Groups`, `Sets`, `Wasted`. |
| Path | 1 | no | An object: `Machine`, `User`, `Entries`, `SetxCopies`, `Shadowed`, `Failures`, `Missing`, `Duplicates`, `Empty`. |
| Restarts | 1 | no | An object: `Days`, `Current`, `Timeline`, `Summary`, `Wakes`. |
| Wifi | 1 | no | An object: `Findings`, `Status`. |
| Proxy | 1 | no | An object: `Findings`, `Setting`, `Probe`. |
| Identity | 1 | no | A list of sign-in and management checks. |
| Updates | 1 | no | A list of the last 30 updates. |
| Printing | 1 | no | A list of spooler, printer, port, driver and queue rows. |
| Profiles | 1 | no | A list of profile, mapped drive and logon rows. |
| Lifecycle | 1 | no | An object: `Reviewed`, `Windows`, `Programs`, `InstalledCount`. |
| Journal | 1 | no | An object: `Severity`, `Valid`, `Entries`, `Chained`, `Unchained`, `Trimmed`, `Head`, `First`, `Last`, `Breaks` (each with `File`, `Line`, `Time`, `Name`, `Problem`). |
| Audit | 1 | yes | An object: `Level`, `ExcludedAccount`, `Score`, `Findings`. |

`-Report List` writes an array of `Name`, `Version`, `Elevated` and
`Description`, one per report.

## Pseudonymised documents

With `-Redact Personal` or `-Redact Strict`, the text of the document is
pseudonymised once it is collected (see the README, "Before sending it
away"), and `Privacy` says at which level. `Schema`, `SchemaVersion`,
`MachineId`, the judgements and the structure are kept, so a pseudonymised
document validates and reads like any other. It cannot be the reference of
`-CompareWith`: its names and addresses are aliases, and each one would read
as a change.
