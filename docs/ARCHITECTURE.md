# Architecture

How the toolkit is put together, and why each decision was made that way.

---

## 1. The constraint that shapes everything

The requirement is a tool that starts from `irm ... | iex`. A script piped
into `Invoke-Expression` has no `$PSScriptRoot`, no reliable working
directory, and no second file it can load. Everything it needs must be inside
the one stream of text it receives.

That rules out a PowerShell module, and it rules out loading XAML or JSON from
disk at run time.

It does **not** rule out writing the project as a module-shaped code base.
The resolution is a build step:

```
src/**.ps1  +  src/UI/MainWindow.xaml  +  data/*.json
        |
        v  build/Build-Toolkit.ps1
        |
   dist/toolkit.ps1        one file, no dependencies
```

Development runs `toolkit.ps1`, which dot-sources the same files in the same
order. Both paths produce identical function definitions in identical scope,
so what is tested is what ships.

`build/source-order.txt` is the single declaration of that order, read by
both the launcher and the build script. There is no second list to forget to
update.

---

## 2. Layers

```
                    Start-Toolkit.ps1
                           |
        +------------------+------------------+
        |                                     |
      src/UI                             src/Features
   shell + one file per page        System / Software / Tweaks /
   knows about controls             Fixes / Network / Security
   knows about features             knows about Windows
        |                                     |
        +------------------+------------------+
                           |
                        src/Core
        context, logging, elevation, process, threading, data
                    knows about nothing
```

The dependency direction is strictly downwards. Core never calls a feature,
and a feature never calls the UI. That is what lets every feature function be
used from a plain console session with `.\toolkit.ps1 -NoGui`, and what lets
the test suite exercise them with no window.

### Core

| File | Responsibility |
| --- | --- |
| `Config.ps1` | The single mutable context. Nothing else creates global state. |
| `Logging.ps1` | File sink, console sink, UI sink. Operation timing. |
| `Environment.ps1` | Pre-flight checks: OS, PowerShell version, TLS, STA, assemblies. |
| `Elevation.ps1` | Privilege detection, consent-driven restart, the `Assert-TkElevated` guard. |
| `Utilities.ps1` | Process execution, registry access, null-safe arrays, formatting. |
| `Threading.ps1` | Runspace pool and the dispatcher-driven completion pump. |
| `DataLoader.ps1` | Catalog loading, embedded first, then disk. |

### Features

One folder per area. Every function is independently callable, returns
objects rather than printing, and guards its own privilege requirements.

### UI

`Window.ps1` owns the shell: XAML loading, control registration, navigation,
status bar and the background-action helper. One file per page owns that
page's wiring and nothing else.

---

## 3. State

There is exactly one mutable object, `$script:TkContext`, built by
`Initialize-TkContext`. It holds paths, runtime facts, loaded catalogs, user
settings, the window, a name-to-control map, and the background task list.

The reasons for a single context rather than scattered script variables:

- A test can reset the entire application state with one call.
- The compiled build and the modular run resolve `$script:` to the same scope,
  so behaviour is identical.
- There is one place to look when asking "what does this instance know".

Controls are registered once, at window creation, by scanning the XAML for
`x:Name` and calling `FindName` for each. Page code then says
`Get-TkControl -Name 'BtnRefresh'` and gets `$null` rather than an exception
when a control was removed from the markup.

---

## 4. Threading

A PowerShell GUI freezes the moment slow work runs on the dispatcher thread.
winget installs, port checks and CIM queries are all slow.

The model:

1. `Start-TkTask` queues a script block into a runspace pool. The pool is
   seeded with the toolkit's own function definitions, so background code can
   call `Write-TkLog` and `Invoke-TkProcess` without loading a module from
   disk, which matters because there may be no files on disk at all.
2. Work receives **plain values only**. WPF objects and the context never
   cross the boundary.
3. A `DispatcherTimer` polls for completed tasks and runs their callbacks
   **on the UI thread**, which is where WPF expects controls to be touched.

The result is a one-way flow that needs no locks in feature code:

```
UI thread                     background runspace
   |                                  |
   | Start-TkTask  ---------------->  | does the work
   | (returns immediately)            | returns plain data
   |                                  |
   | DispatcherTimer tick  <----------+
   | runs OnComplete, touches controls
```

`Invoke-TkBackgroundAction` wraps this with the busy indicator so a page never
has to manage the status bar by hand.

---

## 5. Data-driven by default

Applications, tweaks, fixes, network topics, vendor commands and vendor
support pages are all JSON. Adding an application or a tweak is a data change,
reviewable as a diff, needing no new code and no new tests of the engine.

Two consequences follow, and both are handled explicitly:

**Data can be edited, so data is not trusted.** Package identifiers are
validated against a strict pattern before they reach a command line. Fix
actions name a key in an allow list declared in code, never a command. Vendor
URLs are checked for scheme and encoded before substitution.

**Data can be wrong, so data is tested.** The Pester suite asserts that every
application identifier is valid, that categories resolve, that identifiers are
unique, that every tweak declares a revert path, that every fix action is
registered *and* that every registered action points at a function that
exists. The build fails on a catalog that is not valid JSON.

### The tweak object

```json
{
  "id": "...", "name": "...", "category": "...",
  "impact": "Low | Medium | High",
  "requiresElevation": true, "requiresRestart": false,
  "description": "...",
  "registry":       [ { "path", "name", "type", "value", "default", "defaultAction" } ],
  "registryKeys":   [ { "path", "applyAction", "revertAction", "defaultValue" } ],
  "services":       [ { "name", "startup", "default" } ],
  "scheduledTasks": [ "\\Microsoft\\Windows\\..." ]
}
```

Applied state is **read back** from the registry rather than remembered, so
the interface stays correct when a tweak was applied by group policy or by
another tool. `registryKeys` exists because some shell behaviours depend on a
key existing rather than on a value: removing only the value would leave the
tweak silently in place.

---

## 6. Privilege model

Least privilege applied to a tool run on machines that are not yours.

- The process starts with the rights it was given.
- Read-only features work as a standard user.
- `Assert-TkElevated` guards every function that writes to HKLM, changes a
  service, installs software or edits policy. It logs and returns `$false`
  rather than throwing an access denied from deep inside the work.
- Elevation is a deliberate action: the header badge states the current level
  and offers the restart.
- A restart with no script on disk replays the HTTPS source URL the operator
  originally typed. A non-HTTPS source is refused, because an on-path attacker
  would otherwise choose the code that runs as Administrator.

---

## 7. The build

`build/Build-Toolkit.ps1`:

1. Resolves the version from `Config.ps1` and the commit from git.
2. Reads the sources in the declared order.
3. Runs PSScriptAnalyzer and **fails on any error**.
4. Validates every catalog as JSON and embeds it as base64.
5. Embeds the XAML as base64.
6. Concatenates everything with a header, the build metadata and the entry
   point.
7. Writes UTF-8 **without a BOM**, because a BOM mid-download is parsed as
   content and breaks the one liner.
8. Re-parses the generated file with the PowerShell parser and fails if it
   does not parse.
9. Emits the SHA256 next to the build so a release can publish it.

Base64 rather than here-strings: a here-string breaks the moment content
contains its own terminator, and catalogs are edited by people.

---

## 8. Extending it

| You want to add | You change |
| --- | --- |
| An application | `data/applications.json` |
| A tweak | `data/tweaks.json` |
| A network topic or vendor command | `data/network-knowledge.json`, `data/vendor-commands.json` |
| A vendor support profile | `data/vendor-support.json` |
| A fix | A function in `SystemFixes.ps1` **and** an entry in `Get-TkFixDispatchTable` |
| A whole feature area | A file under `src/Features/`, a page under `src/UI/Pages/`, a panel in `MainWindow.xaml`, an entry in `source-order.txt`, and a nav button |

Adding a page is intentionally the only change that touches several files:
navigation, markup and wiring genuinely are three different concerns.
