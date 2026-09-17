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

**Without a window.** For a script, a remote session or an RMM agent, the same
reports come out as JSON. `irm | iex` cannot take a parameter; running the
download as a script block can, and still writes nothing to disk but the
report you ask for:

```powershell
$toolkit = [scriptblock]::Create((irm https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1))

& $toolkit -Report List                                   # the reports, and which need administrator rights
& $toolkit -Report Storage, Reboot, Wifi                  # JSON on the output
& $toolkit -Report All -AuditLevel Full -OutFile "C:\Temp\$env:COMPUTERNAME.json"
```

The reports are Dashboard, Inventory, Network, Reboot, Storage, Performance,
Devices, Crashes, Wifi, Proxy, Identity, Updates, Printing, Profiles, Lifecycle
and Audit.
Each one carries a status (`Ok`, `Skipped` with the reason, or `Failed` with
the error), its duration and the worst judgement found in it, and
`Summary.Worst` is the worst of all for a monitoring rule to read. Audit needs
an elevated console and is skipped otherwise, never elevated behind your back.
Dates are ISO 8601, and Windows PowerShell 5.1 and PowerShell 7 write the same
data; only the indentation differs. The file is UTF-8 without a byte order
mark, as JSON asks: read it back in Windows PowerShell 5.1 with
`Get-Content -Raw -Encoding UTF8`, which otherwise assumes the ANSI code page
and garbles accented names. The same parameters work on `toolkit.ps1` from a clone and on
`dist\toolkit.ps1`.

**Before and after.** `-CompareWith` collects the reports of an earlier
document again and adds what changed: judgements that got worse or better,
devices, drives and findings that appeared or went, crashes and updates that
are new, and facts such as the Windows build, the BIOS version or the audit
score. Values that move on their own, such as free space or processor use, are
left out.

```powershell
& $toolkit -Report All -OutFile .\before.json
# ... the intervention ...
& $toolkit -CompareWith .\before.json -OutFile .\after.json
```

On the Intervention page, **Snapshot** and **Compare** do the same without a
command line, with the snapshots kept beside the journal.

---

## Navigation

The pages are grouped by the kind of work, the way a support call unfolds.

| Group | Pages |
| --- | --- |
| **Workstation** | Dashboard, System, Software, Tweaks, Fixes |
| **Troubleshooting** | Diagnostics (Reports, Hardware tests), Network |
| **Security** | Audit (Security audit, Threat hunting), Tools (Security, Generators, Text and data, Linux and DevOps) |
| **Reference** | Knowledge base, Commands |
| | Settings, pinned below the groups |

Light and dark themes are switched from the header and remembered.

**Search** everything with **Ctrl+K**, or the Search button in the header: pages, tabs, reports, hardware tests, investigations, quick actions, fixes, tweaks, applications, knowledge base topics and vendor commands. Every word typed has to match, in any order. Up and down choose, Enter opens: the page, the tab and the entry, or the page's own search box filled in. With nothing typed, the palette lists the pages, so the whole toolkit can be driven from the keyboard.

---

## What it does

### Workstation

| Page | What is in it |
| --- | --- |
| **Dashboard** | The page the toolkit opens on. Computer name, model, Windows edition and build, uptime and user; the adapter that actually carries traffic, chosen by default route metric among Ethernet, Wi-Fi, VPN and virtual adapters, with its address, gateway and DNS; the public IP only when you ask. Health tiles for a pending restart, patch age, system drive space, disk health, devices with a problem, blue screens in the last 30 days, sign-in and management, and battery, each opening the report or test that deals with it. Quick actions that go to the right page and start the work: run the security audit, run the full diagnostic, collect a support bundle, open Windows Update. |
| **System** | Manufacturer, model, serial number, asset tag, chassis, motherboard, BIOS version and age, OS build and activation, CPU, memory, graphics, and a fill bar for every volume. Platform security: antivirus or EDR, Secure Boot, TPM, BitLocker on every drive and firewall. Each action sits beside the value it uses: copy the serial, open the vendor driver and warranty pages **with the serial number already in the URL**, install the vendor firmware utility. Export to JSON or text for a ticket. |
| **Software** | Two tabs. **Applications**: 142 applications across 12 categories, installed through winget with a search box and a category filter; multi-select, batch install, uninstall, upgrade everything, and an installed-state indicator. **Windows Update**: what Windows Update has for this machine, read through the Windows Update Agent COM API (checking reads only), each update with its severity, size and whether it restarts; ticked updates are downloaded and installed after a confirmation, elevated. |
| **Tweaks** | 66 declarative tweaks across 6 categories: privacy, interface, performance, gaming, hardening and advanced settings. Beyond registry values, services and scheduled tasks, a tweak can turn optional Windows features on or off (Windows Sandbox, WSL, the telnet client, SMBv1, PowerShell 2.0), install a capability such as the OpenSSH server, or set an audit subcategory, as process creation auditing with command lines does. Every one of them is reversible, the current state is read back from Windows rather than remembered, and a restore point is taken before a batch is applied. |
| **Fixes** | 23 repair actions with the symptom each one addresses: TCP/IP and Winsock reset, DNS cache, firewall defaults, proxy settings, Kerberos tickets and Group Policy, the clock, the secure channel with the domain, Windows Update rebuild, sfc and DISM, the WMI repository, Defender signatures, temporary files, icon cache, Explorer, the Start menu and search, print spooler, Microsoft Store cache, search index, OneDrive, the Teams cache, and the audio and Bluetooth services. Plus automatic logon, configured properly (see below). |
| **Intervention** | A journal written as the work happens: every fix, tweak, installation, audit correction, network profile, SSH key, audit, investigation, report and support bundle run through the toolkit, with its outcome, for this session, today or the last 7 days. Add the ticket reference, the technician and notes, then create the **intervention report**: one HTML file with the machine, its health, the latest audit, what was done and the notes, to attach to a ticket or send to a customer. The journal is kept per day under `%LOCALAPPDATA%\Toolkit\journal`. |

### Troubleshooting

| Page | What is in it |
| --- | --- |
| **Diagnostics — Reports** | Read only reports, in the order a support call needs them: pending reboot (all six places Windows records one), storage health (reliability counters, free space, SSD wear), **disk space** (where the space went, without a third-party tool: how full each fixed drive is, the biggest folders and files on the system drive from one safe scan that follows no junctions and skips what it is refused, and the caches Windows treats as disposable with the size of each, so it reports what could be freed without deleting anything), **performance** (what uses the processor, memory and disks right now, grouped by application; the programs that start with Windows and whether each one really runs; how long start up takes to the desktop and the applications, drivers, services and devices Windows measured slowing it, the last part elevated only), **devices** (every device Device Manager flags, with its problem code explained, what to try, and the hardware identifier to search for), **crashes** (each blue screen with its stop code named and explained from Microsoft's reference of 379 codes, the kernel drivers registered in the days before it and those found before several crashes, hard resets, and repeated application faults), **Wi-Fi** (signal in dBm, band and channel, link rate, standard and security of the network, how crowded the channel is, and the drops and failed connections of the last week, read from the Wi-Fi API so the display language does not matter; since Windows 11 24H2 Windows needs location access for desktop apps to give these, and the report says so), **proxy** (the three settings Windows keeps: the one applications read, the one Windows Update and the agents read, and the environment variables of command line tools; whether each proxy and configuration script answers, a proxy running on the machine itself, and what automatic detection finds), update history (drivers and feature updates included), **software support** (whether this Windows release still receives security updates, judged from its edition and build rather than its translated name, so Home and Pro, Enterprise and Education, LTSC and Server each get their own calendar; and the installed programs against the end of support dates their vendors publish, from Office, Acrobat, Java, .NET, Python, Node.js and PowerShell to SQL Server, Exchange, MySQL and PostgreSQL, the plugins nobody should still have such as Flash, and the Visual C++ runtimes old programs load; each one judged by its risk, with what to move to, and a version the catalog does not list reported as such rather than guessed), printing (spooler, printers, ports, drivers, queues), **sign-in and management** (the join type from dsregcmd: workgroup, domain, Microsoft Entra, hybrid or registered; whether Entra ID still knows the device; the single sign-on token and why the last attempt failed; a stalled hybrid join; the domain controller reached, the secure channel and the clock against Kerberos; Windows Hello; Intune or another MDM enrollment and its recent errors), profiles and policy (profile sizes, mapped drives, logon timing), **local accounts** (the local users and groups: who can sign in, whose password never expires or is not required, the built-in Administrator and Guest told from the end of their SID rather than a renameable name, and who is a local administrator), **Group Policy** (which Group Policy objects applied to this machine and user and which were filtered out and why, from gpresult, with the security groups the token carries; the computer side needs administrator rights), or all of them as one full check. Export the last report, or collect a **support bundle**: system, network, diagnostics, security posture and log in one timestamped ZIP. Nothing leaves the machine until you send it. |
| **Diagnostics — Hardware tests** | The checks a report cannot make. **Keyboard**: a 105 key ISO board in three blocks with French AZERTY, US QWERTY, UK QWERTY and German QWERTZ legends. Keys are matched by physical scan code, so the keypad Enter is told from the main one and the layout you draw does not change the result. A held key turns orange and sinks, a tested key turns green, and the keys never seen are listed. The test runs while its panel is open and hands the keyboard back when you leave. **Display**: full screen solid colours, gradient and geometry grid, and the panels attached. **Sound**: a tone in the left, right or both channels, a frequency sweep, and the audio devices. **Battery**: health against design capacity, and the Windows battery report. **Memory**: modules slot by slot, and the Windows Memory Diagnostic. |
| **Network** | **Subnet calculator** for IPv4 **and IPv6**: CIDR, VLSM splitting, "what prefix fits 300 hosts", IPv6 scope, interface identifier and EUI-64, and a unique local IPv6 prefix generator (a random /48 in fd00::/8 with its first /64s, as RFC 4193 asks). **Adapters**: inventory with the primary adapter identified. **Diagnostics**: connectivity chain, port checks, subnet sweep, DNS lookups, listening sockets. **Admin tools**: path MTU discovery, link quality with loss and jitter, traceroute with per hop timing, TLS certificate inspection with expiry, Wake-on-LAN, a **MAC address lookup** and the neighbour cache, with vendors from the IEEE MA-L, MA-M and MA-S registries built into the toolkit (about 54,000 blocks, compressed, looked up offline; rebuilt with `build/Update-MacVendorRegistry.ps1`) and the kind of address named: burned in, randomised by a phone or a virtual machine, multicast, or a VRRP or HSRP gateway, and **which switch port this machine is on**: about a minute of listening with Packet Monitor, filtered on the LLDP and CDP announcements a switch sends to its port, gives the switch name, the port and its description, the VLAN and voice VLAN, the platform and the management address (administrator rights, capture file deleted once read). **Configuration**: named adapter IP profiles you can capture, save and apply per site, the routing table with persistent route management, and port forwarding through the built in Windows proxy. |

### Security

| Page | What is in it |
| --- | --- |
| **Audit — Security audit** | 39 controls drawn from the CIS and ANSSI workstation baselines, run as an Essential pass (25 controls) or a Full one. A fully patched machine on a Windows release past its end of support is still failed, because no update is waiting to show it. Beyond the basics it looks at what an attacker already on the machine reaches next: the vulnerable driver blocklist and memory integrity, Defender exclusions wide enough to hide a payload in (a drive, a download or temporary folder, a script host, a file type that runs code), a print spooler running for no real printer, NTLM session security and the LAN Manager level as Windows really applies it, and cached domain sign-ins. A score out of 100 weighted by risk, with controls that cannot be assessed left out of the score rather than counted as failures. The antivirus or EDR actually protecting the machine is named, rather than Defender assumed. BitLocker is checked on every drive, with how each one unlocks. Expected administrator accounts can be excluded, and are named in the report. Every warning carries an action: a correction when a single step is safe, otherwise the Windows settings page where the change is made, always after a confirmation that says what will happen. It runs elevated only, because half of what it reads is invisible to a standard user. |
| **Audit — Threat hunting** | Eight read only investigations: event log triage (failed logons grouped by account, lockouts, services installed, logs cleared, privileged group changes), autostart and persistence with signature checking, network exposure joining listening sockets to the firewall policy, a certificate inventory with batch endpoint expiry checking, **USB storage history** (every USB drive ever connected, from the record Windows keeps, with its serial and, when elevated, when it was last plugged in), **Remote Desktop history** (who connected in and from which address, read from the Terminal Services log, and the servers this account connected out to, read from its own registry), **browser extensions** (what is installed in Chrome, Edge, Brave and Firefox, with the permissions that reach the most — read every page, watch traffic, talk to the machine, read cookies or history — flagged first), and **Defender detections** (what Windows Defender has caught in the last 90 days, each threat named and rated with what was done about it). |
| **Tools** | Listed by category, Security, Generators, Text and data, Linux and DevOps, Windows and AD, and each one found from Ctrl+K. **Passwords**: a cryptographic password and passphrase generator; a strength analysis that gives the time to crack a password by brute force, every combination of its length and character types, and by the guessing cracking tools really start with, for a throttled and an unthrottled login, a slow hash such as bcrypt and a stolen NTLM hash on one GPU, naming the weaknesses found (common passwords, even with capitals, symbols for letters or written backwards, keyboard runs on QWERTY, AZERTY and QWERTZ, sequences, repeats, years and dates), live as the password is typed and never shown; and a breach check using k-anonymity. **SSH keys**: generation, listing and copying the public key. **File integrity**: hashing, comparison with the hash a vendor publishes, signature inspection, and VirusTotal lookups by hash. **Ports**: random ports from the dynamic, registered or a custom range, drawn with the cryptographic generator, leaving out the ports listening or bound on this machine, the ranges Windows reserves for Hyper-V, WSL or Docker, and the ports of known services. **chmod**: Unix permissions as check boxes, octal (755, 4755) and symbolic (rwxr-xr-x, rwsr-xr-x) forms that follow each other as you type, with setuid, setgid and sticky, and both chmod commands. **Regex**: a regular expression tester with the .NET flavour PowerShell uses, every match with its line, named groups and a replacement preview, and a time limit so a pattern that backtracks without end cannot freeze the window; beside it a cheat sheet of characters, anchors, repeats, groups, lookaround, inline options and replacement tokens, and ready-made patterns for IPv4 and MAC addresses, e-mail, host names, URLs, dates, GUIDs, SIDs, Windows paths and log severities, each inserted at the caret with a double-click. **Timestamps**: Unix seconds, milliseconds, microseconds or nanoseconds, Windows FILETIME and the Active Directory timestamps (lastLogonTimestamp, pwdLastSet, accountExpires and their never values), or a date, in every form and relative to now. **Encoding**: Base64 (URL safe included), URL, HTML and hexadecimal both ways, and a JWT decoder that shows the header, the payload and when it expires, and says the signature is not checked. **JSON and YAML**: format, minify or validate a JSON text without re-reading it, so numbers and dates stay exactly as written, and turn it into YAML or, for an array of flat objects, CSV. **Number bases**: a number read from decimal or a 0x, 0b or 0o prefix and shown in binary, octal, decimal and hexadecimal, with the bits it sets listed one by one, to read a userAccountControl or an SDDL mask. **Data size and rate**: a size read in decimal (KB) or binary (KiB) units and bits told from bytes, converted both ways, and the time a transfer takes at a given link speed, at the full rate and at ninety percent. **Safe Links**: paste a link rewritten by Microsoft Defender for Office 365, or a whole e-mail, and read where every link really goes, the site it points at and the mailbox it was sent to, unwrapped to the end when a message was forwarded, without opening anything. **E-mail headers**: paste the headers of a suspicious message and read its route oldest hop first with the delay each server added, where it was really sent from, the verdict of SPF, DKIM and DMARC on arrival, and what phishing looks like: replies sent to another domain, a display name showing an address that is not the sender's, an unrelated envelope sender. **Mail DNS records**: the MX, SPF, DKIM and DMARC records of a domain, with the SPF includes followed to count the 10 DNS lookups receivers allow, the DMARC policy explained, DKIM keys found under the usual selectors with their size, and a verdict for each; queried only when asked. **Certificates**: paste or open a certificate, a chain, a .p7b or a certificate request and read its names, validity, key, purposes and SHA-1 and SHA-256 fingerprints, or what a CSR asks for, decoded on the machine; a private key pasted by mistake is recognised and never decoded. **UUIDs**: random version 4 and time ordered version 7 UUIDs in the standard, upper case, braces, compact and URN forms, and a decoder that reads the version, the variant, and the creation time of a version 1, 6 or 7 UUID. **Text diff**: two texts compared line by line with Myers' algorithm, the one diff and git use, ignoring case or spaces on request, with the removed and added lines coloured and three unchanged lines kept around each change. **URL parser**: a link taken apart as you type, host as DNS resolves it, port, path and every query parameter decoded, with the tricks phishing links use named: a user name before @ that looks like the site, look-alike letters, an IP address, a password in clear. **NATO alphabet**: a serial number, licence key or password spelled out for the phone, with capitals, digits, symbols and accents. **Phone numbers**: a number written in any form read and written as E.164, international, national and a tel: link, with the grouping of 25 countries and the kind of a French number. **HTML editor**: formatted text on one side and clean HTML on the other, headings, paragraphs, lists, bold, italic, underline and links and nothing else, for a signature, a ticket or a wiki; HTML pasted in loads back without its scripts, styles, attributes and javascript: links. **Crontab**: a schedule picked from presets or typed, read back in words with its next five runs, including the rule that makes cron run on either day when both the day of the month and the day of the week are set, and the line for crontab -e. **Docker Compose**: a docker run command, on one line or continued with \ or a backtick, turned into its Compose service, ports, volumes, environment, networks, restart policy, health check, limits and a hundred other options, with named volumes and networks declared and the options Compose has no place for listed as comments. **QR code**: a link or a text encoded as you type by an encoder written into the toolkit, byte mode in UTF-8, versions 1 to 40 and the four error correction levels, saved as a PNG or copied as a picture, so a client's link or password is never pasted into a generator online. **Wi-Fi QR code**: the network name, security and password as the code a phone camera joins with, for guests or a meeting room, with the name and security of the connected network filled in on request and a key the network would not accept refused before a code is drawn. **SDDL**: a security descriptor string (from `Get-Acl`, `sc.exe sdshow` or an AD attribute) read into its owner, group and each access control entry, with the SID of every trustee named, the inheritance and audit flags spelled out, and the access mask decoded for the kind of object it protects, a file, a registry key, a directory object or a service. **AD account flags**: a userAccountControl, groupType or msDS-SupportedEncryptionTypes value broken into the bits it sets, with a note for what matters (an account disabled, a password that never expires, pre-authentication off, RC4 still allowed). **Robocopy**: a robocopy command built from its options, each explained on hover (what backup mode, all attributes, restartable and the rest actually do), with mirror winning over a plain subfolder copy, files and folders to exclude, a log file, and paths quoted, and a reading of what a robocopy exit code means, as the bitmask it is rather than a rank. **Scheduled task**: a schtasks /create command line built from a schedule and a program, adding only the fields the schedule uses. **dsacls delegation**: a dsacls command that delegates control on an OU, the same as the Delegation of Control wizard, from a task (full control, create and delete objects, reset passwords, read or write properties, manage group membership, or a custom rights string), the object type it applies to, and how far it reaches, with grant or deny. |

### Reference and settings

| Page | What is in it |
| --- | --- |
| **Knowledge base** | **Topics**: 38 topics across 12 categories: fundamentals, switching and VLANs, routing and addressing, network services, network security, wireless, physical layer, method and tooling, Windows administration (start-up and recovery with BitLocker, Windows Update servicing with WSUS and Windows Update for Business), identity and access (Group Policy, Kerberos and NTLM, Microsoft Entra join and Intune enrolment, passwords and MFA), security operations (backups that survive ransomware, the first hour of an incident), SPF, DKIM and DMARC, and reference tables: well-known SIDs and RIDs, HTTP status codes, SMTP reply and Exchange Online status codes. **Windows codes**: type an error code in any form (0x80070005, 80070005, -2147024891 as the update history returns it, or a Win32 number), an event ID or words, and read what it means and what to try. Written from Microsoft's references: every Windows Update error, the servicing (CBS), setup and upgrade, network and sign-in failure codes a call meets, Intune enrolment errors, KMS and MAK activation errors, the NTSTATUS and exception codes of application crashes, and about a hundred event IDs with their source, from Kernel-Power 41 to the Secure Boot certificate update events. A code not in the reference is still decoded into its facility and code, with the Windows message for a Win32 error. Codes and events are also found from Ctrl+K, a failed update names its error in Update history, and the security event triage says why sign-ins failed. |
| **Commands** | 691 commands, grouped by task and searchable all at once. **Administration cheat sheets**: **Active Directory** (users, groups, computers, replication, Group Policy, recycle bin), the **Windows command line** (robocopy, icacls, sc, schtasks, diskpart, bcdedit, wevtutil, certutil), **Intune and Entra device management** (dsregcmd, enrolment events, check-in, Intune Management Extension logs, Autopilot, BitLocker keys), **Microsoft Graph and Exchange Online PowerShell**, **OpenSSL and certificates**, **tcpdump, Wireshark filters and Nmap**, **Docker and Compose**, **Kubernetes**, and **Hyper-V, ESXi and Proxmox VE**. **Scripting cheat sheets**: **Git** from the first commit to recovering one that seemed lost; **PowerShell** with the verbs and what each promises, what can follow a \| (Where-Object, Sort-Object, Select-Object with computed properties, Group-Object, Measure-Object, ForEach-Object, Export-Csv, ConvertTo-Json, Out-GridView), the operators, variables, types, hashtables, objects and classes, parameters, error handling and remoting, and the everyday administration commands; **Bash** with quoting, parameter expansion, conditions and loops, functions and exit codes, redirections, arrays and globbing; **Linux system administration** with files, permissions and users, processes and systemd services, packages on Debian and Red Hat, disks, SSH and cron. **Network platforms**: Cisco, Cisco Meraki, Aruba AOS-CX and AOS-S, Fortinet, Palo Alto, Stormshield, pfSense and OPNsense, Juniper, Extreme, HPE Comware, MikroTik, Ubiquiti, Windows, Linux and Linux firewalling. |
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
