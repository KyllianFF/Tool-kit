# Toolkit

A single PowerShell application for the work an IT technician, systems
engineer or network engineer actually does in a day: identify a machine,
diagnose it, install software, apply and revert tweaks, run repairs, do subnet
maths, and check the security posture of what is in front of you.

It runs from one command, needs nothing installed, and can be read before it
is trusted.

```powershell
irm https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1 | iex
```

> Read [On `irm | iex`](#on-irm--iex) before running that on a machine that
> matters. Piping a download into `iex` executes whatever the server returns,
> and the alternatives are one line longer.

The toolkit starts with the rights of the console it was launched from. When a
feature needs administrator rights, **Restart as administrator** in the header
opens an elevated instance, downloaded again from the same address: no file is
left on disk to re-run.

---

## Navigation

The pages are grouped by the kind of work, the way a support call unfolds.

| Group | Pages |
| --- | --- |
| **Workstation** | Dashboard, System, Software, Tweaks, Fixes |
| **Troubleshooting** | Diagnostics (Reports, Hardware tests), Network |
| **Security** | Audit (Security audit, Threat hunting), Tools (SSH keys, File integrity, Credentials) |
| **Reference** | Knowledge base, Vendor commands |
| | Settings, pinned below the groups |

Light and dark themes are switched from the header and remembered.

---

## What it does

### Workstation

| Page | What is in it |
| --- | --- |
| **Dashboard** | The page the toolkit opens on. Computer name, model, Windows edition and build, uptime and user; the adapter that actually carries traffic, chosen by default route metric among Ethernet, Wi-Fi, VPN and virtual adapters, with its address, gateway and DNS; the public IP only when you ask. Health tiles for a pending restart, patch age, system drive space, disk health, devices with a problem, blue screens in the last 30 days and battery, each opening the report or test that deals with it. Quick actions that go to the right page and start the work: run the security audit, run the full diagnostic, collect a support bundle, open Windows Update. |
| **System** | Manufacturer, model, serial number, asset tag, chassis, motherboard, BIOS version and age, OS build and activation, CPU, memory, graphics, and a fill bar for every volume. Platform security: antivirus or EDR, Secure Boot, TPM, BitLocker on every drive and firewall. Each action sits beside the value it uses: copy the serial, open the vendor driver and warranty pages **with the serial number already in the URL**, install the vendor firmware utility. Export to JSON or text for a ticket. |
| **Software** | 142 applications across 12 categories, installed through winget with a search box and a category filter. Multi-select, batch install, uninstall, upgrade everything, and an installed-state indicator. |
| **Tweaks** | 35 declarative tweaks across 6 categories: privacy, interface, performance, gaming, hardening and advanced settings. Every one of them is reversible, the current state is read from the registry rather than remembered, and a restore point is taken before a batch is applied. |
| **Fixes** | 12 repair actions with the symptom each one addresses: TCP/IP and Winsock reset, DNS cache, firewall defaults, Windows Update rebuild, sfc and DISM, temporary files, icon cache, Explorer, print spooler, Microsoft Store cache and search index. Plus automatic logon, configured properly (see below). |

### Troubleshooting

| Page | What is in it |
| --- | --- |
| **Diagnostics — Reports** | Read only reports, in the order a support call needs them: pending reboot (all six places Windows records one), storage health (reliability counters, free space, SSD wear), **devices** (every device Device Manager flags, with its problem code explained, what to try, and the hardware identifier to search for), **crashes** (each blue screen with its stop code named and explained from Microsoft's reference of 379 codes, the kernel drivers registered in the days before it and those found before several crashes, hard resets, and repeated application faults), update history (drivers and feature updates included), printing (spooler, printers, ports, drivers, queues), profiles and policy (profile sizes, mapped drives, domain secure channel, logon timing), or all of them as one full check. Export the last report, or collect a **support bundle**: system, network, diagnostics, security posture and log in one timestamped ZIP. Nothing leaves the machine until you send it. |
| **Diagnostics — Hardware tests** | The checks a report cannot make. **Keyboard**: a 105 key ISO board in three blocks with French AZERTY, US QWERTY, UK QWERTY and German QWERTZ legends. Keys are matched by physical scan code, so the keypad Enter is told from the main one and the layout you draw does not change the result. A held key turns orange and sinks, a tested key turns green, and the keys never seen are listed. The test runs while its panel is open and hands the keyboard back when you leave. **Display**: full screen solid colours, gradient and geometry grid, and the panels attached. **Sound**: a tone in the left, right or both channels, a frequency sweep, and the audio devices. **Battery**: health against design capacity, and the Windows battery report. **Memory**: modules slot by slot, and the Windows Memory Diagnostic. |
| **Network** | **Subnet calculator** for IPv4 **and IPv6**: CIDR, VLSM splitting, "what prefix fits 300 hosts", IPv6 scope, interface identifier and EUI-64. **Adapters**: inventory with the primary adapter identified. **Diagnostics**: connectivity chain, port checks, subnet sweep, DNS lookups, listening sockets. **Admin tools**: path MTU discovery, link quality with loss and jitter, traceroute with per hop timing, TLS certificate inspection with expiry, Wake-on-LAN, and the neighbour cache with MAC vendor names. **Configuration**: named adapter IP profiles you can capture, save and apply per site, the routing table with persistent route management, and port forwarding through the built in Windows proxy. |

### Security

| Page | What is in it |
| --- | --- |
| **Audit — Security audit** | 32 controls drawn from the CIS and ANSSI workstation baselines, run as an Essential pass (21 controls) or a Full one. A score out of 100 weighted by risk, with controls that cannot be assessed left out of the score rather than counted as failures. The antivirus or EDR actually protecting the machine is named, rather than Defender assumed. BitLocker is checked on every drive, with how each one unlocks. Expected administrator accounts can be excluded, and are named in the report. Every warning carries an action: a correction when a single step is safe, otherwise the Windows settings page where the change is made, always after a confirmation that says what will happen. It runs elevated only, because half of what it reads is invisible to a standard user. |
| **Audit — Threat hunting** | Four read only investigations: event log triage (failed logons grouped by account, lockouts, services installed, logs cleared, privileged group changes), autostart and persistence with signature checking, network exposure joining listening sockets to the firewall policy, and a certificate inventory with batch endpoint expiry checking. |
| **Tools** | **SSH keys**: generation, listing and copying the public key. **File integrity**: hashing, comparison with the hash a vendor publishes, signature inspection, and VirusTotal lookups by hash. **Credentials**: a cryptographic password and passphrase generator, and a breach check using k-anonymity. |

### Reference and settings

| Page | What is in it |
| --- | --- |
| **Knowledge base** | 26 topics across 8 categories: fundamentals, switching and VLANs, routing and addressing, network services, network security, wireless, physical layer, method and tooling. |
| **Vendor commands** | 272 commands across 16 platforms, grouped by task and searchable across every vendor at once: Cisco, Cisco Meraki, Aruba AOS-CX and AOS-S, Fortinet, Palo Alto, Stormshield, pfSense and OPNsense, Juniper, Extreme, HPE Comware, MikroTik, Ubiquiti, Windows, Linux and Linux firewalling. |
| **Settings** | The VirusTotal API key, stored encrypted for this Windows account, and the folder where the toolkit keeps its data and logs. |

---

## Security design

A tool that runs elevated on other people's machines has to be defensible.
These are the decisions, and the reasons for them.

**It does not elevate on sight.** The toolkit starts with the rights it was
given. Inventory, diagnostics, subnet maths, hashing, DNS and the reference
pages all work as a standard user. Privileged features are visibly disabled
with the reason shown, not silently missing, and elevation happens only when
you ask for it.

**Restarting elevated never trusts downloaded content.** A launch through
`irm | iex` leaves no script file to re-run, so the elevated instance downloads
the published build again. That address is part of the code, not something
read from a response, and only HTTPS is ever replayed: a plain HTTP source
would let an attacker on the network choose the code that runs as
Administrator.

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

**Fix and remediation actions are dispatched through allow lists.** The fixes
catalog names an action, not a command, and every audit remediation is an
entry in a table declared in code. An edited JSON file cannot invoke anything
the developer did not register.

**The keyboard test is not a keylogger.** It reads keys only from its own
window, only while its panel is on screen and the window has the focus. A
system wide keyboard hook would see more, including the Windows key, and is
exactly what antivirus software rightly blocks.

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

**Nothing leaves the machine unless you ask.** The public IP lookup, the
VirusTotal and breach checks, and a support bundle each wait for an explicit
click.

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
- A single threaded (STA) console, which is the default for both. Only a
  console started with `-MTA` cannot show the window.
- winget for the Software page, ssh-keygen for the SSH keys tab. Both ship
  with current Windows; the toolkit tells you when one is missing instead of
  failing silently.

Administrator rights are needed only for the features that change the system,
and for the security audit.

---

## Repository layout

```
Tool-kit/
  toolkit.ps1              Development launcher: loads src/ and starts the app
  build/
    Build-Toolkit.ps1      Compiles src/ + data/ + XAML into one file
    Invoke-Tests.ps1       Runs the Pester suite
    source-order.txt       Load order, shared by the launcher and the build
  src/
    Core/                  Context, logging, elevation, process, threading, data
    Features/              System, Software, Tweaks, Fixes, Network, Security,
                           Diagnostics and hardware tests
    UI/                    MainWindow.xaml, shell wiring, one file per page
    Start-Toolkit.ps1      Entry point
  data/                    JSON catalogs: applications, application icons,
                           tweaks, fixes, network knowledge, vendor commands,
                           vendor support
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

**A new page** is one name in `Get-TkPageName` (`src/UI/Window.ps1`), a
navigation button `Nav<Name>` and a panel `Page<Name>` in the markup, and a
page script. The test suite checks that the three agree.

---

## Development

```powershell
.\toolkit.ps1                                               # run from source
.\toolkit.ps1 -NoGui                                        # load every function into the session
powershell -STA -NoProfile -File .\build\Invoke-Tests.ps1   # the Pester suite
.\build\Build-Toolkit.ps1                                   # analyse, compile, verify, hash
```

The build runs PSScriptAnalyzer and refuses any finding, embeds the XAML and
catalogs as base64, re-parses the generated file, and refuses to produce a
build that does not parse or whose catalogs are not valid JSON. Continuous
integration runs the analysis and build, and the test suite on both Windows
PowerShell 5.1 and PowerShell 7.

---

## Licence

MIT. See [LICENSE](LICENSE).

### Third party content

`data/app-icons.json` carries publisher icons from
[Simple Icons](https://simpleicons.org), released under CC0 1.0. Each one is a
single vector outline used to identify the application it belongs to. The
marks themselves remain the property of their owners; they are used here to
name the product being installed, not to claim any association with it.

Interface icons are code points from the Segoe Fluent Icons and Segoe MDL2
Assets fonts that ship with Windows. Nothing is redistributed: the toolkit
refers to the fonts already on the machine.
