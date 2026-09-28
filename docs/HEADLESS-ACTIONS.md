# Headless actions

The fixes, tweaks and audit corrections of the interface, taken without a
window: from an RMM agent, a remote session or a deployment script. The run is
a **plan** until `-Execute` is added, and it ends with a JSON result and an exit
code a script can act on. [actions.schema.json](actions.schema.json) describes
the result for a JSON Schema validator (draft-07).

```powershell
$toolkit = [scriptblock]::Create((irm https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1))

& $toolkit -Fix List                                          # what can be asked for, and what is refused
& $toolkit -Fix flush-dns, reset-print-spooler                # the plan: nothing changes
& $toolkit -Fix flush-dns, reset-print-spooler -Execute       # takes them
& $toolkit -Tweak disable-telemetry -Execute -OutFile C:\Temp\tweak.json
& $toolkit -Tweak disable-telemetry -Revert -Execute          # undoes it
& $toolkit -Remediate enable-firewall, disable-smbv1 -Execute
exit $LASTEXITCODE
```

The same parameters work on `toolkit.ps1` from a clone and on
`dist\toolkit.ps1`. Pin a release with the verified launch command (see the
README) to run the build you checked on every machine.

## Rules

- **The interface's allow lists.** A fix is an id of the fixes catalog, run
  through the same dispatch table as the Fixes page; a tweak an id of the
  tweaks catalog, applied or reverted by the same engine as the Tweaks page; a
  correction an id of the audit corrections. What is typed only ever selects
  an entry, it never reaches a command line.
- **Nothing changes without `-Execute`.** Without it the run says what would be
  taken and what would be refused, with the exit code the real run would have.
- **The whole request is checked first.** One refused action refuses the run,
  and nothing is taken: a typo never leaves a machine half changed. An action
  is refused when
  - its id is unknown;
  - it needs administrator rights and the session has none (the toolkit never
    elevates by itself; an RMM agent already runs as SYSTEM or elevated);
  - it works on the signed-in account's own profile or session and the run is
    SYSTEM, where it would reach SYSTEM's profile instead: the Teams, icon and
    Store caches, OneDrive, the Office accounts, the application proxy, the
    Windows Hello PIN, the Windows Security app, Explorer and the Start menu,
    and every tweak that writes HKEY_CURRENT_USER. Run those in the user's
    session;
  - it is a correction that opens a page for a person, or one that needs a
    person at the machine (a restart into the firmware setup).
- **As in the interface.** A restore point is taken before tweaks, each action
  is written to the intervention journal and the log, and an action runs even
  when one before it failed.

`-Fix List`, `-Tweak List` and `-Remediate List` give each entry's `Id`,
`Name`, whether it needs administrator rights (`Elevated`), `RequiresRestart`,
`Risk`, whether it is refused as SYSTEM (`UserScoped`), and `Refused` with the
reason an entry is never taken without a window.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The plan would run, or every action succeeded. |
| 3010 | Every action succeeded, and a restart is needed for one of them to take effect (the Windows Installer convention). |
| 1 | An action failed. The others ran; the result says which. |
| 2 | The request was refused: nothing was taken. |

Run as a file (`powershell -File toolkit.ps1 ...`), the code is the process
exit code. Run as a script block, as above, it is left in `$LASTEXITCODE`, and
the script ends with `exit $LASTEXITCODE`: an exit from inside the toolkit
would close the console of someone who ran it by hand.

## The result

```json
{
  "Schema": "toolkit-actions",
  "SchemaVersion": "1.0",
  "Computer": "DESKTOP-4F2A",
  "MachineId": "5d8c1f0e9b7a4c2d8e6f1a3b5c7d9e0f",
  "User": "CONTOSO\\DESKTOP-4F2A$",
  "GeneratedAt": "2026-09-28T22:10:04.1234567+02:00",
  "Toolkit": { "Version": "1.0.0", "Commit": "9efcdc7" },
  "Elevated": true,
  "System": true,
  "Privacy": "None",
  "Mode": "Execute",
  "Summary": {
    "Outcome": "Done",
    "ExitCode": 3010,
    "RestartRequired": true,
    "Counts": { "Planned": 0, "Refused": 0, "NotRun": 0, "Succeeded": 2, "Failed": 0 }
  },
  "Actions": [
    { "Kind": "Fix", "Id": "reset-print-spooler", "Name": "Reset the print spooler", "Operation": "Run", "Elevated": true, "RequiresRestart": false, "Status": "Succeeded", "Reason": "", "DurationMs": 3120, "Messages": [] },
    { "Kind": "Remediation", "Id": "disable-smbv1", "Name": "Remove SMBv1", "Operation": "Run", "Elevated": true, "RequiresRestart": true, "Status": "Succeeded", "Reason": "", "DurationMs": 8410, "Messages": [] }
  ]
}
```

The envelope is the one of a report document (docs/REPORT-FORMAT.md): the same
`Computer`, `MachineId`, `User`, `GeneratedAt`, `Toolkit`, `Elevated` and
`Privacy`, with the same versioning rules. Then:

| Field | Meaning |
| --- | --- |
| `System` | Whether the run was the SYSTEM account. |
| `Mode` | `Plan` or `Execute`. |
| `Summary.Outcome` | `Planned`, `Refused`, `Done` or `Failed`. |
| `Summary.ExitCode` | The exit code of the run. |
| `Summary.RestartRequired` | Whether an action that succeeded needs a restart. |
| `Summary.Counts` | How many actions are in each status. |
| `Actions` | One per action, fixes first, then tweaks, then corrections, each in the order asked. |

Each action has its `Kind` (`Fix`, `Tweak` or `Remediation`), `Id`, `Name`,
`Operation` (`Run`, `Apply` or `Revert`), whether it needs administrator rights
(`Elevated`), `RequiresRestart`, a `Status` (`Planned`, `Refused`, `NotRun`
when another action was refused, `Succeeded` or `Failed`), the `Reason` of a
refusal or a failure (a failure names the toolkit log, which says why), its
`DurationMs`, and the `Messages` a tweak gives about each of its steps.

`-Redact Personal` or `-Redact Strict` pseudonymises the result as it does a
report.
