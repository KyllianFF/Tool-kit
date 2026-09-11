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
| A table anywhere | `Set-TkObjectTable`, or `Show-TkTableWindow` for one in its own window |
| A hardware check | A function in `HardwareTests.ps1`, a panel in the Hardware page, and an entry in its chooser |
| A section in the support bundle | A `Get-TkBundleSection` block in `New-TkSupportBundle` |
| Work on a page's first open | `Register-TkFirstShow -PageName <page> -Action { ... }` |
| A whole feature area | A file under `src/Features/`, a page under `src/UI/Pages/`, a panel in `MainWindow.xaml`, an entry in `source-order.txt`, and a nav button |

Adding a page is intentionally the only change that touches several files:
navigation, markup and wiring genuinely are three different concerns.

---

## 9. Two interface rules worth knowing before you change the UI

**There is one table renderer.** `Add-TkTable` builds a `Grid` inside a
`BlockUIContainer`, and `Set-TkObjectTable` is the call a page makes. It gives
selectable cells, banded rows, draggable column edges and live theme
following. The application used to have a second mechanism, `GridView` inside
a `ListView`, and every one of those four behaviours had to be implemented
twice; the column resize handle went missing from one of them for exactly that
reason. There is no `ListView` left, and adding one back means reimplementing
all four.

**Never clear a control's `Template` to remove its chrome.** A `TextBox` with
`Template = $null` has no visual tree: it measures correctly and draws
nothing. That emptied every table and every finding card at once, and it looks
like missing data rather than a rendering fault, which is what made it
expensive to find. Remove chrome with a style carrying a minimal template, as
`SelectableText` does, and keep the `PART_ContentHost` the control renders
into. `tests/Toolkit.Tests.ps1` asserts the rendered visual tree is not empty
so this cannot come back quietly.

Icons come from two places. Interface icons are code points from **Segoe Fluent
Icons**, falling back to **Segoe MDL2 Assets**. Both ship with Windows, so they
add nothing to the build and take the foreground colour of whatever draws them.
A code point the font does not carry draws an empty box and is invisible to
every other kind of check, so the test suite verifies each one against the
installed font.

Publisher icons for the software list live in `data/app-icons.json` as single
SVG outlines, about ninety kilobytes for the set. Vectors rather than bitmaps:
sharp at any scale, a fraction of the size, and one colour so they read on both
themes. The file is deliberately incomplete — there is no icon for most Windows
utilities — and an application without one falls back to the icon for its
category, so `Get-TkAppIconGeometry` returns nothing rather than a placeholder.

Both sets were checked by rendering them and looking at the result, which is
the only way to catch the failure that matters here: an icon that is present,
sharp, and wrong. Two of the automatic matches were a different product with a
similar name, and no amount of type checking would have found them.

**The window can be photographed.** `Render-Window.ps1` in the scratchpad shows
the pattern: load the sources, build the window, fill the pages with
representative data, `Show()` it at negative coordinates and capture it with
`RenderTargetBitmap`. It is how the interface work gets checked without a
person looking at a screen, and it is worth rebuilding whenever the UI changes
substantially.

---

## 10. The keyboard test, and why it does NOT use a hook

The obvious way to build a keyboard test is a low level `WH_KEYBOARD_LL`
hook: it sees every key before the shell does, and returning a non-zero value
from the callback consumes it, so the Windows key would not open the Start
menu and Alt+Tab would not switch away mid-test. The first version did exactly
that.

**It was removed, on purpose.** A global hook that records and swallows every
keystroke is, at the level of the Windows API, indistinguishable from a
keylogger, and antivirus software is right to treat it as one. ESET blocked
the tool outright, and a diagnostic that trips the antivirus on the machines
it is meant to help is not a diagnostic. No amount of obfuscation should be
used to get such code past an antivirus — hiding a keylogging technique from
detection is the technique's most dangerous property, not a bug to route
around.

So the test reads keys the way a local application should: a `PreviewKeyDown`
handler on its own window (`Start-TkKeyboardTest` in `HardwarePage.ps1`),
added with `handledEventsToo` so it still sees a key a focused control already
marked handled. It sees keys only while its window has focus, captures
nothing system wide, and installs no hook. Each key is marked handled so Tab
does not move the focus and Space does not press a button, which keeps the
test from being disrupted by the very keys it is checking.

The cost is real and worth stating: the shell claims the Windows key, Alt+Tab
and Ctrl+Alt+Delete before any application sees them, so those cannot be
ticked off and the result note says so. That inability is not a shortcoming to
engineer around — it is the same boundary that stops a keylogger, and being on
the right side of it is what lets the tool run on any machine.

The one native call that remains is `MapVirtualKey`, in
`src/Core/KeyboardLayout.ps1`. It is a stateless lookup that answers "what
character is on this key" and is what on screen keyboards have always used; it
sees and records nothing. It is what draws an AZERTY board as AZERTY: the map
is labelled by asking Windows what each key produces under the current layout,
so the French key that sends `VK_A` is drawn where it physically sits. Identity
is the **WPF Key** value, which already tells the numeric keypad apart from the
navigation cluster (NumPad7 is not Home); the test suite asserts every key on
the map casts to a real `Key` and that no key is drawn twice.

