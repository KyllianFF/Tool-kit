# Toolkit

A single PowerShell application for the work an IT technician, systems
engineer or network engineer actually does in a day: identify a machine,
install software, apply and revert tweaks, run repairs, do subnet maths,
and check the security posture of what is in front of you.

It runs from one command, needs nothing installed, and can be read before it
is trusted.

```powershell
irm https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1 | iex
```

> Read [On `irm | iex`](#on-irm--iex) before running that on a machine that
> matters. Piping a download into `iex` executes whatever the server returns,
> and the alternatives are one line longer.

---

## What it does

| Area | What is in it |
| --- | --- |
| **System** | Manufacturer, model, serial number, asset tag, chassis, motherboard, BIOS version and age, OS build and activation, CPU, memory, disks, volumes, graphics, Secure Boot, TPM, BitLocker and firewall. One click to the vendor driver and warranty pages **with the serial number already in the URL**, one click to install the vendor firmware utility, and an export to JSON or text for a ticket. |
| **Software** | 146 applications across 12 categories, installed through winget with a search box and a category filter. Multi-select, batch install, uninstall, upgrade everything, and an installed-state indicator. |
| **Tweaks** | 35 declarative tweaks over privacy, interface, performance, gaming, hardening and advanced settings. Every one of them is reversible, the current state is read from the registry rather than remembered, and a restore point is taken before a batch is applied. |
| **Fixes** | 12 repair actions with the symptom each one addresses: network stack reset, Windows Update rebuild, sfc and DISM, spooler, search index, icon cache, temporary files. Plus automatic logon, configured properly (see below). |
| **Network** | IPv4 **and IPv6** subnet calculator (CIDR, VLSM splitting, "what prefix fits 300 hosts", IPv6 scope and interface identifier, EUI-64), adapter inventory, connectivity chain test, port checks, subnet sweep, DNS lookups, listening sockets, a 16 topic knowledge base and a cross-vendor command reference for Cisco, Aruba, Fortinet, Ubiquiti, MikroTik, Juniper, Windows and Linux. |
| **Network admin tools** | Path MTU discovery, link quality with loss and jitter, traceroute with per hop timing, TLS certificate inspection with expiry, Wake-on-LAN, and the neighbour cache with MAC vendor names. |
| **Network configuration** | Named adapter IP profiles you can capture, save and apply per site, the routing table with persistent route management, and port forwarding through the built in Windows proxy. |
| **Security** | SSH key generation, file hashing and signature inspection, VirusTotal lookups by hash, a cryptographic password and passphrase generator, a breach check using k-anonymity, and a 15 point local security audit with an exportable report. |
| **Threat hunting** | Four read only investigations: event log triage (failed logons grouped by account, lockouts, services installed, logs cleared, privileged group changes), autostart and persistence with signature checking, network exposure joining listening sockets to the firewall policy, and a certificate inventory with batch endpoint expiry checking. |

---

## Security design

A tool that runs elevated on other people's machines has to be defensible.
These are the decisions, and the reasons for them.

**It does not elevate on sight.** The toolkit starts with the rights it was
given. Inventory, subnet maths, hashing, DNS and the knowledge base all work
as a standard user. Privileged features are visibly disabled with the reason
shown, not silently missing, and elevation happens only when you ask for it.

**Automatic logon does not store a clear text password.** The usual
implementation writes `DefaultPassword` under `Winlogon`, where any local
user can read it. This one writes the password to the LSA private data store
through `LsaStorePrivateData`, which is the same mechanism the Sysinternals
Autologon tool uses, and actively deletes any clear text value it finds.

**Package identifiers are validated before they reach a command line.** The
application catalog is data, and data can be edited. Every identifier is
checked against a strict pattern first, and arguments are passed as an array
rather than concatenated into a string, so a modified catalog cannot turn an
install into arbitrary command execution.

**Fix actions are dispatched through an allow list.** The fixes catalog names
an action, not a command. That name is resolved through a table declared in
code, so an edited JSON file cannot invoke anything the developer did not
register.

**The VirusTotal check sends a hash, not the file.** Uploading a file
publishes it to a service other researchers can download from, which is not
acceptable for an internal installer or a company document. The default path
computes the SHA256 locally and looks that up. The API key is stored with
DPAPI, encrypted for the current Windows account.

**The breach check never sends the password.** It uses the Have I Been Pwned
k-anonymity range API: the SHA1 is computed locally, the first five hex
characters are sent, and the comparison happens on this machine.

**Passwords come from the cryptographic RNG.** `Get-Random` is documented as
unsuitable for security purposes. The generator uses
`RandomNumberGenerator` with rejection sampling, so no character is more
likely than another.

**Tweaks are reversible by construction.** Each one declares both the applied
value and the value to restore in the same object. There is no one-way path.

**Every privileged operation is logged**, to `%LOCALAPPDATA%\Toolkit\logs`,
with the operation, the outcome and the duration.

### On `irm | iex`

Piping a downloaded script into `iex` executes whatever the server returns.
That is a real risk and it does not go away because the project is
well-intentioned. Mitigations that are actually available to you:

1. Read `dist/toolkit.ps1` before running it. It is generated from the
   sources in `src/`, which are small, commented and reviewable.
2. Verify the published SHA256 (`dist/toolkit.ps1.sha256`) after downloading
   and before executing.
3. Clone the repository and run `.\toolkit.ps1` instead, which removes the
   network from the trust path entirely.

Download, verify, then run:

```powershell
$url = 'https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1'
$out = "$env:TEMP\toolkit.ps1"

Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing

# Compare against the SHA256 published with the release before continuing.
(Get-FileHash -Path $out -Algorithm SHA256).Hash

powershell -NoProfile -ExecutionPolicy Bypass -STA -File $out
```

---

## Running it from a clone

Removes the network from the trust path entirely, which is the right choice
for a machine you care about.

**Clone and run**

```powershell
git clone https://github.com/KyllianFF/Tool-kit.git
cd Tool-kit
.\toolkit.ps1
```

**Run the compiled build directly**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -STA -File .\dist\toolkit.ps1
```

Add `-Elevated` to `toolkit.ps1` to raise a consent prompt before loading.

---

## Requirements

- Windows 10 1809 or later, or Windows 11, or Server 2016 or later
- Windows PowerShell 5.1 (present on every supported Windows) or PowerShell 7
- An STA thread, which is the default for both. Add `-STA` if you started a
  console with `-MTA`.
- winget for the Software page, ssh-keygen for the SSH page. Both ship with
  current Windows; the toolkit tells you when one is missing instead of
  failing silently.

Administrator rights are needed only for the features that change the system.

---

## Repository layout

```
Tool-kit/
  toolkit.ps1              Development launcher: loads src/ and starts the app
  build/
    Build-Toolkit.ps1      Compiles src/ + data/ + XAML into one file
    source-order.txt       Load order, shared by the launcher and the build
  src/
    Core/                  Context, logging, elevation, process, threading, data
    Features/              System, Software, Tweaks, Fixes, Network, Security
    UI/                    MainWindow.xaml, shell wiring, one file per page
    Start-Toolkit.ps1      Entry point
  data/                    JSON catalogs: applications, tweaks, fixes, network
                           knowledge, vendor commands, vendor support
  dist/                    Build output (toolkit.ps1 and its SHA256)
  tests/                   Pester 5 suite
  docs/                    Architecture, security policy, contributing
```

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit
together and why the build step exists.

---

## Adding to it

The catalogs are data. Most additions need no code at all.

**A new application** — one entry in `data/applications.json`:

```json
{
  "id": "example",
  "name": "Example",
  "category": "utilities",
  "packageId": "Publisher.Example",
  "description": "One line the technician reads before ticking the box."
}
```

**A new tweak** — one entry in `data/tweaks.json`. It must declare what to
restore, or the test suite fails the build:

```json
{
  "id": "example-tweak",
  "name": "Do the thing",
  "category": "privacy",
  "impact": "Low",
  "requiresElevation": true,
  "requiresRestart": false,
  "description": "What it changes and what the user loses by applying it.",
  "registry": [
    {
      "path": "HKLM:\\SOFTWARE\\Example",
      "name": "Value",
      "type": "DWord",
      "value": 1,
      "default": 0,
      "defaultAction": "delete"
    }
  ]
}
```

`defaultAction: "delete"` means the value did not exist before the tweak, so
the honest revert is removal rather than writing a guessed default.

**A new fix** needs both a function and an entry in the dispatch table in
`src/Features/Fixes/SystemFixes.ps1`. That is deliberate: it is the boundary
that stops catalog data from becoming executable.

---

## Development

```powershell
.\toolkit.ps1                        # run from source
.\toolkit.ps1 -NoGui                 # load every function into the session
Invoke-Pester -Path .\tests          # 113 tests
.\build\Build-Toolkit.ps1            # analyse, compile, verify, hash
```

The build runs PSScriptAnalyzer, embeds the XAML and catalogs as base64,
re-parses the generated file, and refuses to produce a build that does not
parse or whose catalogs are not valid JSON.

---

## Licence

MIT. See [LICENSE](LICENSE).
