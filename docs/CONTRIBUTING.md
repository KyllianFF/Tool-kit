# Contributing

## Before you start

```powershell
git clone https://github.com/KyllianFF/Tool-kit.git
cd Tool-kit

Install-Module Pester           -Scope CurrentUser -MinimumVersion 5.0.0
Install-Module PSScriptAnalyzer -Scope CurrentUser

.\toolkit.ps1                   # run from source
Invoke-Pester -Path .\tests     # must be green before you push
.\build\Build-Toolkit.ps1       # must report 0 errors
```

## Branches

Work on a branch, never on `main`.

```
feature/<short-name>     new capability
fix/<short-name>         bug fix
data/<short-name>        catalog additions only
docs/<short-name>        documentation only
```

## Code style

The rules the existing code follows, so a diff reads like the rest of the file.

- **Comments in English.** No accented or special characters anywhere in the
  source, so the files behave identically whatever the console code page.
- **Comment-based help on every function**: `.SYNOPSIS`, `.DESCRIPTION` when
  the behaviour is not obvious from the name, `.PARAMETER` for each parameter,
  `.OUTPUTS`, and `.EXAMPLE` where a caller would benefit.
- **Explain the why, not the what.** `# increment the counter` is noise.
  `# Read both pipes asynchronously: reading them in sequence deadlocks as
  soon as a child fills the pipe we are not reading` is the comment that saves
  the next person an afternoon.
- **Space the code.** A blank line after `param()`, around logical blocks, and
  between the sections of a long function. Section banners such as
  `# --- Registry ---` in functions with distinct phases.
- **Verb-Noun with the `Tk` prefix**, using an approved verb.
  `Get-TkSubnetInfo`, not `SubnetInfo` or `Calculate-Subnet`.
- **`[CmdletBinding()]` and `[OutputType()]` on every function.**
- **`SupportsShouldProcess` on anything that changes the system**, and call
  `$PSCmdlet.ShouldProcess` before making the change.
- **Return objects, not text.** Formatting is the interface's job.
- **Guard privilege at the top** with `Assert-TkElevated`.
- **Use `ConvertTo-TkArray` for optional catalog collections.** `@($null)` is
  an array containing one null, and that has already caused one bug here.

## Adding data

Most contributions are catalog entries and need no code. See the tables in
[ARCHITECTURE.md](ARCHITECTURE.md#8-extending-it).

A tweak without a revert path fails the test suite. That is intentional.

## Adding a fix

Two changes, in this order:

1. A function in `src/Features/Fixes/SystemFixes.ps1` with
   `SupportsShouldProcess`, an elevation guard, and a `[bool]` return.
2. An entry in `Get-TkFixDispatchTable` mapping the catalog action name to
   that function.

The allow list is what stops an edited JSON file from executing arbitrary
commands. Do not replace it with a dynamic lookup.

## Tests

Add tests for anything deterministic: parsing, arithmetic, validation,
formatting, catalog shape. Do not add tests that need particular hardware or
that change the machine.

## Pull requests

- One concern per pull request.
- `Invoke-Pester` green and `Build-Toolkit.ps1` reporting 0 errors.
- Say what changed and why. If it changes behaviour on someone else's machine,
  say what they will notice.
- Rebuild `dist/toolkit.ps1` only when a release is being cut, not in every
  feature branch: it produces a large, unreviewable diff.
