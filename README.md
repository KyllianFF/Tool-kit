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
> and the alternatives are one line longer: the [verified launch](#verified-launch-pinned-to-a-release)
> of a release runs that release only if its SHA-256 matches.

The toolkit starts with the rights of the console it was launched from. When a
feature needs administrator rights, **Restart as administrator** in the header
opens an elevated instance, downloaded again from the same address: no file is
left on disk to re-run. Started with the verified launch command of a release,
it downloads that release again and runs it only if its SHA-256 still matches,
so the elevated process is always the build that was checked.

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
Devices, Crashes, Restarts, Timeline, Wifi, Proxy, Identity, Updates, Printing, Profiles,
Path, Duplicates, Lifecycle, Readiness, Journal and Audit.
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

The document follows a versioned format, described in
[docs/REPORT-FORMAT.md](docs/REPORT-FORMAT.md) with a
[JSON Schema](docs/report.schema.json) beside it, so a script or a fleet view
can rely on it: `Schema` and `SchemaVersion` say what it is (a minor version
only adds fields), each report carries the `Version` of its data, and
`MachineId`, derived from the Windows MachineGuid without revealing it, tells
machines apart after a rename or once pseudonymised.

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

**Before sending it away.** `-Redact Personal` pseudonymises the document once
it is collected: the names of this computer and of its accounts, profile
folders, e-mail addresses, the machine or domain part of account SIDs and the
serial numbers become stable aliases (PC-1, USER-1, SERIAL-1), the same
everywhere in the document so it still reads. `-Redact Strict` also replaces
the IP and MAC addresses (the maker's part of a MAC is kept), the saved Wi-Fi
networks and the domain names. A comparison is made on the real values, before
they are replaced. The table back to the real values stays on the machine,
encrypted for the Windows account that ran it, and **Settings, Privacy of
exports** finds what an alias stood for. The document says its level in
`Privacy`, and a pseudonymised document cannot be the reference of
`-CompareWith`: its aliases would each read as a change.

```powershell
& $toolkit -Report All -Redact Strict -OutFile .\for-the-vendor.json
```

**Fixes, tweaks and corrections.** The same script block takes the fixes,
tweaks and audit corrections of the interface, through the same allow lists.
Without `-Execute` the run is a plan: it says what would be taken and what
would be refused, and changes nothing. The whole request is checked before
anything runs, so an unknown id, an action that needs administrator rights in
a standard session, or one that works on the signed-in account's profile when
the run is SYSTEM (as an RMM agent's is), refuses the run rather than leaving
the machine half changed. The result is JSON, and the exit code is 0, 3010
when a restart is needed, 1 when an action failed and 2 when the request was
refused. [docs/HEADLESS-ACTIONS.md](docs/HEADLESS-ACTIONS.md) has the rules,
the codes and the result format.

```powershell
& $toolkit -Fix List                                              # every fix, and what is refused without a window
& $toolkit -Fix reset-print-spooler -Remediate disable-smbv1       # the plan
& $toolkit -Fix reset-print-spooler -Remediate disable-smbv1 -Execute -OutFile C:\Temp\actions.json
exit $LASTEXITCODE
```

---

## Navigation

The pages are grouped by the kind of work, the way a support call unfolds.

| Group | Pages |
| --- | --- |
| **Workstation** | Dashboard, System, Software, Tweaks, Migration |
| **Troubleshooting** | Playbooks, Diagnostics (Reports, Event logs, Hardware tests), Fixes, Network, Microsoft 365, Intervention |
| **Security** | Audit (Security audit, Threat hunting) |
| **Toolbox** | Tools (Credentials, E-mail, Web and certificates, Analysis, Generators, Text, Data formats, Linux and DevOps, Active Directory, Windows commands) |
| **Reference** | Knowledge base, Commands |
| | Settings, pinned below the groups |

Light and dark themes are toggled with the switch under Settings, in the navigation, and remembered. Both share one soft style: a violet accent, rounded cards, pill-shaped buttons and navigation, and Segoe UI Variable on Windows 11 (Segoe UI on Windows 10).

**Search** everything with **Ctrl+K**, or the Search button in the header: pages, tabs, reports, hardware tests, investigations, quick actions, fixes, tweaks, applications, knowledge base topics and vendor commands. Every word typed has to match, in any order. Up and down choose, Enter opens: the page, the tab and the entry, or the page's own search box filled in. With nothing typed, the palette opens on your **favourites** (starred with Ctrl+D or a right-click on a result), then the **recent** reports, tools, hardware tests and investigations you opened, from the palette or from their own list, then the pages, so the whole toolkit can be driven from the keyboard. Both are kept in the settings file, the eight most recent at most.

---

## What it does

### Workstation

| Page | What is in it |
| --- | --- |
| **Dashboard** | The page the toolkit opens on. Computer name, model, Windows edition and build, uptime and user; the adapter that actually carries traffic, chosen by default route metric among Ethernet, Wi-Fi, VPN and virtual adapters, with its address, gateway and DNS; the public IP only when you ask. Health tiles for a pending restart, patch age, system drive space, disk health, devices with a problem, blue screens in the last 30 days, sign-in and management, and battery, each opening the report or test that deals with it. Quick actions that go to the right page and start the work: run the security audit, run the full diagnostic, collect a support bundle, open Windows Update. |
| **System** | Manufacturer, model, serial number, asset tag, chassis, motherboard, BIOS version and age, OS build and activation, CPU, memory, graphics, and a fill bar for every volume. Platform security: antivirus or EDR, Secure Boot, TPM, BitLocker on every drive and firewall. Each action sits beside the value it uses: copy the serial, open the vendor driver and warranty pages **with the serial number already in the URL**, install the vendor firmware utility. Export to JSON or text for a ticket. **Windows Update**: what Windows Update has for this machine, read through the Windows Update Agent COM API (checking reads only), each update with its severity, size and whether it restarts; ticked updates are downloaded and installed after a confirmation, elevated. |
| **Software** | Two tabs. **Install Apps**: 142 applications across 12 categories, installed through winget with a search box and a category filter; multi-select, batch install, uninstall, upgrade everything, and an installed-state indicator. **Installed Apps**: every application installed on the machine, as UniGetUI lists them, in columns (name, package id, version, the update available, source): winget and the Microsoft Store, the programs of the uninstall keys (Local PC), the games of Steam, Epic Games, Battle.net, Rockstar Games, Ubisoft Connect, EA app and GOG, and the packages of pip, npm, Chocolatey, Scoop, the PowerShell Gallery (PowerShell 5 and 7), .NET tools and Cargo, each read only if its manager is installed; winget's list is the base, read in the display language (the update column is Disponible in French), and each ARP entry is matched to its uninstall key to find the games of a launcher. A search box, a filter by source (with the count of each), Updates available and Preinstalled Windows apps, sorting by any column, and a tick-all box. The ticked rows are updated or uninstalled one after the other, **Automatic** (silent, the default) or **Manual** (the installer's or the command's own window), each in a task of its own: every row shows whether it is waiting, running, done, failed or handed to a launcher, a progress panel says which one runs, for how long and what is left, and **Stop after this one** ends the batch between two applications. An uninstaller is waited for with the programs it starts (Inno Setup exits at once and leaves a copy running), up to 30 minutes; through winget for what winget lists, the package manager for a package, msiexec or the registered (quiet) uninstall string without winget; a game is handed to its launcher, which opens its own uninstall and updates its games itself, and is never waited for (a launcher does not exit). What needs administrator rights (Chocolatey, modules installed for every account, and the preinstalled Store apps, still removed for every account and from the Windows image from the fixed list, with codecs, language packs, frameworks and the apps Windows needs never touched) runs after the others through one UAC prompt, every name checked again in the elevated process. Each row shows its result, and every batch is journaled. |
| **Tweaks** | 66 declarative tweaks across 6 categories: privacy, interface, performance, gaming, hardening and advanced settings. Beyond registry values, services and scheduled tasks, a tweak can turn optional Windows features on or off (Windows Sandbox, WSL, the telnet client, SMBv1, PowerShell 2.0), install a capability such as the OpenSSH server, or set an audit subcategory, as process creation auditing with command lines does. Every one of them is reversible, the current state is read back from Windows rather than remembered, and a restore point is taken before a batch is applied. **Configuration profiles**: the applications ticked on Software and the tweaks ticked on Tweaks saved to a small JSON file with Save profile, at the top of either page, and ticked again on another machine with Load profile. A profile holds catalogue identifiers and nothing else, each one looked up again in the catalogues of the toolkit that reads it; what it does not know is named and left out. Loading only ticks: installing and applying stay on their own buttons, with their confirmation and their elevation. **Export for the fleet**: the ticked tweaks written, without applying anything here, as what fleet tools take: an Intune remediation pair (a detection script that exits 1 when a step is not in the applied state, and the remediation), a standalone script with -Check and -Revert for a GPO startup or logon script or an RMM, and .reg files to apply and to revert the registry part. Every tweak declares its applied value and its value to restore, so detection, remediation and revert agree by construction; the machine part (HKLM, services, tasks, optional features, capabilities, the audit policy by subcategory GUID) and the account part (HKCU, run with the user's credentials) are written apart. Each catalog value is checked against a strict form and written as a quoted literal, so an edited catalog cannot turn an export into a command, and each script names in its header the toolkit, the date, the tweaks and the SHA-256 of its body. |
| **Migration** | Before a reinstall or a new PC. **What to carry over**: the personal folders with their size and whether OneDrive already keeps them, the network drives with the net use command that maps each again, the printers and how each comes back (a shared one by its \\server\name, a TCP/IP one by its address, a discovered one by itself; PDF, XPS, OneNote and fax left out), Outlook PST files, Outlook signatures and the browser profiles holding bookmarks, and **every application** of the machine, not only the catalogue ones: the programs of the uninstall keys, the Store apps the Start menu shows and the packages winget installed, each with how it comes back (winget, the Microsoft Store, Windows itself, or by hand with its installer and licence, listed so they can be gathered before the old disk is wiped). winget list does not always connect a per-user install to its source, so a program it leaves unconnected is matched to the toolkit catalogue by name. **Before a reinstall**: whether Windows reactivates by itself (a firmware key or digital licence, a retail key to keep, or an organisation licence), and every drive BitLocker encrypts, read without administrator rights, with a warning only for a protected data drive, the one that stays locked after a reinstall without its recovery key; the keys themselves are never read out. **Save installed apps as a profile** turns the catalogue applications installed here into a configuration profile for Software, Load profile on the new machine. **Export drivers** copies the third-party drivers with pnputil through a single UAC prompt. **Copy the personal folders** to another drive with robocopy, into a dated folder with a log per folder, after a confirmation that shows the sizes and the free space; folders OneDrive keeps are skipped and files kept online only are not downloaded, and nothing is deleted; each folder is stored under its Windows name (Desktop, Documents, Pictures...) with a migration.json manifest, and the export can add the applications: the whole list as apps\applications.csv and a winget export as apps\winget.json, completed with the catalogue matches. On import, **Reinstall the applications winget knows** runs winget import with it, as the signed-in user, skipping what is no longer available and installing the latest versions; the report lists the applications to reinstall by hand. **Import** reads such a package (or an older one by its folder names) and maps each folder to a real path on the new machine: by default the same Windows folder of this account, which already follows OneDrive folder backup, or the same folders inside a cloud folder found on the machine (OneDrive, iCloud Drive, Google Drive, Dropbox), or any folder picked by hand, or none. Nothing on the new machine is ever overwritten: the files are compared first (size and time, as robocopy does), only missing ones are copied (robocopy /XC /XN /XO), and a file already there with other content is kept and listed as a conflict. A folder name in the manifest that would lead out of the package is ignored. **Pins**: the export can carry the folders pinned to Quick Access and the jump lists of each application (the AutomaticDestinations and CustomDestinations files), the taskbar shortcuts with their order (the Taskband key) and the Start menu pins (start2.bin); on import the pins already there are saved first to a dated folder of the toolkit data folder, Explorer and the Start menu are restarted around the copy, taskbar shortcuts already there are kept, and the taskbar .reg file is imported only if it writes that key and nothing else. **Browser bookmarks**: the bookmark files of Edge, Chrome, Brave and Firefox (every profile; Firefox must be closed) and one bookmarks.html in the format every browser imports, DuckDuckGo included, whose own store is not a documented file and is not copied (its Sync and Backup carries its bookmarks; it imports the HTML file of the others). On import, Chromium bookmarks are merged into the same browser in a folder named after the old PC, after a backup of the file there, and never while the browser is open; a Firefox that already has its bookmarks keeps them and gets the HTML file, which is put on the desktop without replacing anything. Some security products (ESET among them) refuse every read of browser data by another program; the toolkit does not try to get around it, it names the product and points at the browser's own export or sync. **Another profile** copies the personal folders from one user profile of the machine to another (a new account, a domain change, a local account moved to Entra ID), through a single UAC prompt; the profiles and every path are checked again in the elevated process, each folder must come from inside the source profile and go inside the destination profile, and a source and a destination may not overlap. robocopy copies only the missing files (/XC /XN /XO, never overwriting) without their permissions (/COPY:DAT) in backup mode, so each file takes the permissions of the folder it lands in; the owner of what the copy created (and only that) is then set to the destination account with icacls /setowner, and the report says whether that account has Modify on each folder. The **Move** option deletes a source file only once its copy has been read back and its SHA-256 matches; a conflict, a file that failed, a file kept online only by OneDrive and any file that cannot be verified stay at the source, and nothing is deleted from a folder whose copy reported errors. The same tab can carry the **pins** (Quick Access, jump lists, taskbar and Start) and the **browser bookmarks** of the source account: the destination account must be signed out for its pins, which are saved first; the taskbar order is read from the source account's registry and written to the destination's, each hive loaded with reg load only when its account is signed out and unloaded right after (the report says so, loudly, if one stays loaded), and the .reg text is checked to write the taskbar key alone; the bookmarks are merged into a folder of the destination account's browsers with the HTML file on its desktop, the temporary export removed at once, and every file written there is given to that account. Pins and bookmarks are always copied, never moved. |

### Troubleshooting

| Page | What is in it |
| --- | --- |
| **Playbooks** | Guided sequences for the problems a support call is about — slow machine, no network, cannot sign in, disk full, suspected malware, blue screens, printing, a stuck Windows Update. A playbook does nothing new: it puts the reports, checks and fixes the toolkit already has into the order to work through them, so a call has a first step rather than a blank page. Each step names where it happens and takes you there — a read-only report runs when you arrive, a fix or a page leaves you there to act — and you come back for the next one. |
| **Diagnostics — Reports** | Read only reports, grouped under Overview, Stability and performance, Hardware and devices, Storage, Network, Accounts and policy, and Software and updates: pending reboot (all six places Windows records one), storage health (reliability counters, free space, SSD wear), **disk space** (where the space went, without a third-party tool: how full each fixed drive is, the biggest folders and files on the system drive from one safe scan that follows no junctions and skips what it is refused, and the caches Windows treats as disposable with the size of each, so it reports what could be freed without deleting anything), **performance** (what uses the processor, memory and disks right now, grouped by application; the programs that start with Windows and whether each one really runs; how long start up takes to the desktop and the applications, drivers, services and devices Windows measured slowing it, the last part elevated only), **performance trace** (what the processor, disks, files, network or power did for 15 seconds to 2 minutes, recorded with Windows Performance Recorder, built into Windows, into an ETL file Windows Performance Analyzer opens and a vendor's support asks for; the profiles are a closed list checked again in the elevated process, and the recording starts and stops in one elevated call that cancels the trace whatever happens, so closing the toolkit never leaves one running; a trace left by another tool can be cancelled from the same view), **Windows 11 and renewal** (whether the processor, memory, system disk, firmware, Secure Boot and TPM meet Windows 11, read without administrator rights, the processor judged by its CPUID family, model and stepping with the rules of Microsoft's own readiness check kept in a catalog; what a firmware setting or a part would change told apart from what only new hardware can, so a TPM switched off or a legacy BIOS boot is a setting and an unsupported processor a replacement; and whether to keep, upgrade or replace the machine, from the age its firmware gives as a lower bound, the system disk type, health and wear, the memory and the battery), **devices** (every device Device Manager flags, with its problem code explained, what to try, and the hardware identifier to search for), **crashes** (each blue screen with its stop code named and explained from Microsoft's reference of 379 codes, the kernel drivers registered in the days before it and those found before several crashes, hard resets, and repeated application faults), **restarts and shutdowns** (every start of the last 30 days and how the session before it ended, a restart, a shutdown, a power loss or a blue screen; which program asked, named for what it is, such as Windows Update, the Start menu or an installer; how long each session ran and how long the machine stayed off; and whether a start was a Fast Startup resume, which is why the uptime keeps counting across a night off; read from structured event fields, so a French or an English log reads the same), **Wi-Fi** (signal in dBm, band and channel, link rate, standard and security of the network, how crowded the channel is, and the drops and failed connections of the last week, read from the Wi-Fi API so the display language does not matter; since Windows 11 24H2 Windows needs location access for desktop apps to give these, and the report says so), **proxy** (the three settings Windows keeps: the one applications read, the one Windows Update and the agents read, and the environment variables of command line tools; whether each proxy and configuration script answers, a proxy running on the machine itself, and what automatic detection finds), update history (drivers and feature updates included), **duplicate files** (files of 1 MB and more that exist more than once in the account's own folders, Desktop, Documents, Downloads, Pictures, Videos and Music, compared by content in stages so it stays quick: the same size, then the same first bytes, then the same whole content; summed up by the folders that hold the same files and listed biggest first, with the space the copies take; the inner folders of tools such as .git and node_modules are left out, OneDrive files kept online only are not read so nothing is downloaded, and nothing is deleted, since a copy may be a backup kept on purpose), **command path** (the system and user PATH entry by entry: a system PATH folder a standard account can write, or a missing one it can create, flagged as a failure since services running as SYSTEM search it too; folders of one user's profile and profile variables in the system PATH; the copies setx PATH %PATH% leaves in the user PATH; a value long enough for an edit to cut it; folders that no longer exist, repeats and empty entries; and the commands found in more than one folder with the one that wins, a Store alias shadowing an installed Python included), **software support** (whether this Windows release still receives security updates, judged from its edition and build rather than its translated name, so Home and Pro, Enterprise and Education, LTSC and Server each get their own calendar; and the installed programs against the end of support dates their vendors publish, from Office, Acrobat, Java, .NET, Python, Node.js and PowerShell to SQL Server, Exchange, MySQL and PostgreSQL, the plugins nobody should still have such as Flash, and the Visual C++ runtimes old programs load; each one judged by its risk, with what to move to, and a version the catalog does not list reported as such rather than guessed), printing (spooler, printers, ports, drivers, queues), **sign-in and management** (the join type from dsregcmd: workgroup, domain, Microsoft Entra, hybrid or registered; whether Entra ID still knows the device; the single sign-on token and why the last attempt failed; a stalled hybrid join; the domain controller reached, the secure channel and the clock against Kerberos; Windows Hello; Intune or another MDM enrollment and its recent errors), profiles and policy (profile sizes, mapped drives, logon timing), **local accounts** (the local users and groups: who can sign in, whose password never expires or is not required, the built-in Administrator and Guest told from the end of their SID rather than a renameable name, and who is a local administrator), **Group Policy** (which Group Policy objects applied to this machine and user and which were filtered out and why, from gpresult, with the security groups the token carries; the computer side needs administrator rights), **services** (an operational view: how each service starts, the account it runs as, and the automatic services that failed to start or run as a named account whose password can expire), **drivers** (the third-party and unsigned drivers, with their provider, version, date and signature, the built-in Windows drivers left out), or all of them as one full check. Export the last report, or collect a **support bundle**: system, network, diagnostics, security posture and log in one timestamped ZIP. Nothing leaves the machine until you send it. |
| **Diagnostics — Timeline** | What changed on the machine, newest first, over the last day to the last 30: programs installed and removed (Windows Installer, and the day the uninstall entries record for the others), Windows updates installed or failed, drivers, services installed (one running from a folder a user can write to flagged) and scheduled tasks, starts, stops without a shutdown and blue screens, application crashes, threats Microsoft Defender caught, local groups changed (administrator rights) and firewall rules added, changed or deleted (the Windows 10 and the Windows 11 identifiers), with what was done through the toolkit beside them. Every event is read by its fields, never by the message Windows translates, so a French and an English machine give the same lines; a log turned off or out of reach is named, never passed over. Repeats of the same change within the hour are one line with their count, filters by kind and text work on what was read, and the last column names the report that deals with a line. Export CSV follows the privacy of exports, and `-Report Timeline` gives the last 14 days as JSON. |
| **Diagnostics — Event logs** | Search an event log, read only, and read what it finds in a table, newest first: a log picked from the common ones or typed by name, a period, a level, event ids and ranges, a provider, and text the message must contain. The search is handed to Windows as a FilterHashtable, never as query text, so nothing typed can change what it does; a log that needs administrator rights, one that does not exist and a provider that is not installed are each said plainly. Export CSV keeps the whole message of every event. The query written in Tools, Event log query, runs here with **Run this search**. |
| **Diagnostics — Hardware tests** | The checks a report cannot make. **Keyboard**: a 105 key ISO board in three blocks with French AZERTY, US QWERTY, UK QWERTY and German QWERTZ legends. Keys are matched by physical scan code, so the keypad Enter is told from the main one and the layout you draw does not change the result. A held key turns orange and sinks, a tested key turns green, and the keys never seen are listed. The test runs while its panel is open and hands the keyboard back when you leave. **Display**: full screen solid colours, gradient and geometry grid, and the panels attached. **Sound**: a tone in the left, right or both channels, a frequency sweep, and the audio devices. **Battery**: health against design capacity, and the Windows battery report. **Memory**: modules slot by slot, and the Windows Memory Diagnostic. |
| **Fixes** | 27 repair actions with the symptom each one addresses: TCP/IP and Winsock reset, DNS cache, firewall defaults, proxy settings, Kerberos tickets and Group Policy, the clock, the secure channel with the domain, Windows Update rebuild, sfc and DISM, the WMI repository, Defender signatures, temporary files, icon cache, Explorer, the Start menu and search, print spooler, Microsoft Store cache, search index, OneDrive, the Teams cache, the audio and Bluetooth services, the Windows Hello PIN (the account's Hello container deleted with certutil, so a new PIN is set at the next sign-in), the Windows Security app (its package reset when it opens blank), the Office activation and cached accounts (the per-user part of Microsoft's reset: license files, Licensing and Identity keys, Office credentials; refused while Office is open), and the main network marked Private when Windows filed it as Public (only the physical connection that carries the default route, never a VPN or a virtual switch). Plus automatic logon, configured properly (see below). |
| **Network** | **Subnet calculator** for IPv4 **and IPv6**: CIDR, VLSM splitting, "what prefix fits 300 hosts", IPv6 scope, interface identifier and EUI-64, and a unique local IPv6 prefix generator (a random /48 in fd00::/8 with its first /64s, as RFC 4193 asks). **Adapters**: inventory with the primary adapter identified. **Diagnostics**: connectivity chain, port checks, subnet sweep, DNS lookups, listening sockets. **Admin tools**: path MTU discovery, link quality with loss and jitter, traceroute with per hop timing, TLS certificate inspection with expiry, Wake-on-LAN, a **MAC address lookup** and the neighbour cache, with vendors from the IEEE MA-L, MA-M and MA-S registries built into the toolkit (about 54,000 blocks, compressed, looked up offline; rebuilt with `build/Update-MacVendorRegistry.ps1`) and the kind of address named: burned in, randomised by a phone or a virtual machine, multicast, or a VRRP or HSRP gateway, and **which switch port this machine is on**: about a minute of listening with Packet Monitor, filtered on the LLDP and CDP announcements a switch sends to its port, gives the switch name, the port and its description, the VLAN and voice VLAN, the platform and the management address (administrator rights, capture file deleted once read), and a **LAN throughput test** between two machines running the toolkit, in the spirit of iperf: one listens, the other sends to it then receives from it for a few seconds, memory to memory so the disks are left out, and both rates come back in Mbps next to the link speed of the adapter, with what the ratio means (Wi-Fi is judged against half its rate); the listener waits two minutes at most on TCP 5201, serves one test, answers only local network addresses and a well formed request, and can add a temporary firewall rule (one port, local subnet, private and domain networks) through a UAC prompt, removed by a second one when it stops. **Configuration**: named adapter IP profiles you can capture, save and apply per site, the routing table with persistent route management, and port forwarding through the built in Windows proxy. |
| **Microsoft 365** | **Test the connection**: every endpoint Microsoft publishes for sign-in (Entra ID), Exchange Online, SharePoint and OneDrive (with the tenant name, remembered), Teams, Office activation and updates, and Intune, resolved and opened on its port from this machine, judged per workload with the likely cause of a failure (DNS, a firewall or web filter, a proxy); **TLS inspection** detected when the sign-in certificate does not chain to Microsoft's roots, naming the product that re-signed it; and one STUN request to a Teams relay to say whether calls can use UDP 3478. **Read the apps and accounts**: the Microsoft 365 apps version and update channel, updates turned off, the accounts Office knows (several work accounts flagged), OneDrive signed in and running and whether Desktop, Documents and Pictures are backed up, new or classic Teams (classic flagged), new and classic Outlook. The Office activation reset, the Teams cache and OneDrive reset, and the Sign-in and management report are one click away. Everything but those fixes is read only. |
| **Intervention** | A journal written as the work happens: every fix, tweak, installation, audit correction, network profile, SSH key, audit, investigation, report and support bundle run through the toolkit, with its outcome, for this session, today or the last 7 days. Add the ticket reference, the technician and notes, then create the **intervention report**: one HTML file with the machine, its health, the latest audit, what was done and the notes, to attach to a ticket or send to a customer. The journal is kept per day under `%LOCALAPPDATA%\Toolkit\journal`, and each line records the SHA-256 of the line before it, across the days: **Verify** says whether a line was changed, removed or added since it was written (and where), the intervention report records the head of the chain, and **Export** writes the period as JSON Lines, with the links so the chain can be checked elsewhere, or as CEF for a SIEM. The Journal report does the same check without a window, judged Pass or Fail for a monitoring rule. |

### Security

| Page | What is in it |
| --- | --- |
| **Audit — Security audit** | 39 controls drawn from the CIS and ANSSI workstation baselines, run as an Essential pass (25 controls) or a Full one. A fully patched machine on a Windows release past its end of support is still failed, because no update is waiting to show it. Beyond the basics it looks at what an attacker already on the machine reaches next: the vulnerable driver blocklist and memory integrity, Defender exclusions wide enough to hide a payload in (a drive, a download or temporary folder, a script host, a file type that runs code), a print spooler running for no real printer, NTLM session security and the LAN Manager level as Windows really applies it, and cached domain sign-ins. A score out of 100 weighted by risk, with controls that cannot be assessed left out of the score rather than counted as failures. The antivirus or EDR actually protecting the machine is named, rather than Defender assumed. BitLocker is checked on every drive, with how each one unlocks. Expected administrator accounts can be excluded, and are named in the report. Every warning carries an action: a correction when a single step is safe, otherwise the Windows settings page where the change is made, always after a confirmation that says what will happen. It runs elevated only, because half of what it reads is invisible to a standard user. Export it as a printable, self-contained HTML page to attach to a ticket, or as JSON for another tool. |
| **Audit — Threat hunting** | Eleven read only investigations, grouped under Logs and history, Persistence and privilege, and Exposure: event log triage (failed logons grouped by account, lockouts, services installed, logs cleared, privileged group changes), autostart and persistence with signature checking, network exposure joining listening sockets to the firewall policy, a certificate inventory with batch endpoint expiry checking, **USB storage history** (every USB drive ever connected, from the record Windows keeps, with its serial and, when elevated, when it was last plugged in), **Remote Desktop history** (who connected in and from which address, read from the Terminal Services log, and the servers this account connected out to, read from its own registry), **browser extensions** (what is installed in Chrome, Edge, Brave and Firefox, with the permissions that reach the most — read every page, watch traffic, talk to the machine, read cookies or history — flagged first), **Defender detections** (what Windows Defender has caught in the last 90 days, each threat named and rated with what was done about it), and **privilege escalation** (the local misconfigurations that let a standard user become SYSTEM: unquoted service paths, AlwaysInstallElevated set in both hives, a clear-text autologon password, Image File Execution Options debuggers, and the credentials stored on the machine, domain ones flagged), and **shared folders** (what the PC shares on the network and who can reach it: the share permissions and the NTFS permissions of the folder judged together, a broad group such as Everyone or Authenticated Users able to write through both flagged as a failure and through one as a warning, hidden shares of your own making, and the default administrative shares set apart; read by security identifier, so a French and an English Windows are judged the same), and **saved Wi-Fi networks** (every network the PC remembers, read from the Wi-Fi API as structured profiles: an open network it joins by itself flagged as a failure, since a look-alike hotspot is joined too, WEP as a failure, the retired WPA and TKIP, and hidden networks the PC calls out for wherever it goes; the keys are never read, Windows returns them encrypted). |

### Toolbox

| Page | What is in it |
| --- | --- |
| **Tools** | Listed by category, Credentials, E-mail, Web and certificates, Analysis, Generators, Text, Data formats, Linux and DevOps, Active Directory and Windows commands, and each one found from Ctrl+K. **Passwords**: a cryptographic password and passphrase generator; a strength analysis that gives the time to crack a password by brute force, every combination of its length and character types, and by the guessing cracking tools really start with, for a throttled and an unthrottled login, a slow hash such as bcrypt and a stolen NTLM hash on one GPU, naming the weaknesses found (common passwords, even with capitals, symbols for letters or written backwards, keyboard runs on QWERTY, AZERTY and QWERTZ, sequences, repeats, years and dates), live as the password is typed and never shown; and a breach check using k-anonymity. **SSH keys**: generation, listing and copying the public key. **File integrity**: hashing, comparison with the hash a vendor publishes, signature inspection, and VirusTotal lookups by hash. **Hash identifier**: paste a hash and read its likely kinds from its length and shape, on the machine — the same 32 hex characters are an MD5, an NTLM from a Windows dump, or an LM, so the candidates are listed rather than guessed at one; bcrypt, Argon2, the /etc/shadow formats, MySQL and an LM:NTLM pwdump pair are recognised by their marks. **Indicators (IOC)**: paste an e-mail, a report or a log and pull the indicators out of the prose around them — IP addresses, domains, URLs, e-mail addresses, file hashes and CVE numbers — refanging the defanged ones first so `hxxp://1.2.3[.]4` is found; and defang a text the other way, so a live link is not left clickable where a colleague opens it by reflex, or refang one back. Read on the machine; nothing is fetched. **Secret scanner**: paste a config, a script or a log and flag what looks like a secret left in it — the cloud and service tokens that announce themselves with a prefix (AWS, GitHub, Slack, Stripe, Google, npm), a private key block, a JSON Web Token, and a password or secret on an assignment or in a connection string — each named and masked, so the report does not carry the secret on; obvious placeholders are left out, and it matches shape, so it can miss a secret with no form. Read on the machine. **Ports**: random ports from the dynamic, registered or a custom range, drawn with the cryptographic generator, leaving out the ports listening or bound on this machine, the ranges Windows reserves for Hyper-V, WSL or Docker, and the ports of known services. **chmod**: Unix permissions as check boxes, octal (755, 4755) and symbolic (rwxr-xr-x, rwsr-xr-x) forms that follow each other as you type, with setuid, setgid and sticky, and both chmod commands. **Regex**: a regular expression tester with the .NET flavour PowerShell uses, every match with its line, named groups and a replacement preview, and a time limit so a pattern that backtracks without end cannot freeze the window; beside it a cheat sheet of characters, anchors, repeats, groups, lookaround, inline options and replacement tokens, and ready-made patterns for IPv4 and MAC addresses, e-mail, host names, URLs, dates, GUIDs, SIDs, Windows paths and log severities, each inserted at the caret with a double-click. **Timestamps**: Unix seconds, milliseconds, microseconds or nanoseconds, Windows FILETIME and the Active Directory timestamps (lastLogonTimestamp, pwdLastSet, accountExpires and their never values), or a date, in every form and relative to now. **Encoding**: Base64 (URL safe included), URL, HTML and hexadecimal both ways, and a JWT decoder that shows the header, the payload and when it expires, and verifies an HS256, HS384 or HS512 signature against a secret you paste (an RS, ES or PS token is signed with a private key and needs the public key, which is not taken here). **JSON and YAML**: format, minify or validate a JSON text without re-reading it, so numbers and dates stay exactly as written, and turn it into YAML or, for an array of flat objects, CSV. **Number bases**: a number read from decimal or a 0x, 0b or 0o prefix and shown in binary, octal, decimal and hexadecimal, with the bits it sets listed one by one, to read a userAccountControl or an SDDL mask. **Data size and rate**: a size read in decimal (KB) or binary (KiB) units and bits told from bytes, converted both ways, and the time a transfer takes at a given link speed, at the full rate and at ninety percent. **Safe Links**: paste a link rewritten by Microsoft Defender for Office 365, or a whole e-mail, and read where every link really goes, the site it points at and the mailbox it was sent to, unwrapped to the end when a message was forwarded, without opening anything. **E-mail headers**: paste the headers of a suspicious message and read its route oldest hop first with the delay each server added, where it was really sent from, the verdict of SPF, DKIM and DMARC on arrival, and what phishing looks like: replies sent to another domain, a display name showing an address that is not the sender's, an unrelated envelope sender. **Mail DNS records**: the MX, SPF, DKIM and DMARC records of a domain, with the SPF includes followed to count the 10 DNS lookups receivers allow, the DMARC policy explained, DKIM keys found under the usual selectors with their size, and a verdict for each; queried only when asked. **SPF record** and **DMARC record**: the builders that go with it. SPF from the domain's own servers, addresses and ranges, and the mail services it uses (Microsoft 365, Google Workspace, SendGrid and seven others add their include), with what happens to everyone else; it refuses a record that needs more than 10 DNS lookups by itself, warns about ?all and very wide ranges, and counts the real total through the includes on request. DMARC from the policy, the subdomain policy, the share it applies to, the aggregate and failure report addresses and the alignment, with the rollout explained (none with reports, then quarantine, then reject), a warning where it goes wrong (p=none or p=reject with no report address, subdomains left open), and the record an outside report address must publish. Both records are read back with the parsers the Mail DNS tool uses; nothing is published. **HTTP headers**: paste a site's response headers (nothing is fetched) and grade its security headers — HSTS, the content security policy and its weaknesses, framing, MIME sniffing, referrer and permissions policy, information disclosure, and the Secure, HttpOnly and SameSite flags on each cookie. **Invisible characters**: paste a link, a file name, a command or any text and reveal the characters that do not show what they are — zero-width and formatting characters, the direction overrides behind a "gpj.exe" that runs as an executable, unusual spaces, C0 and C1 controls, and letters from other scripts that impersonate an ASCII one (a Cyrillic a in paypal.com) — each named and located, with the text redrawn so every one is marked in place; ordinary text, accents included, raises nothing. **Event log query**: build a query from a log, event ids, level, provider, time window and a text search, as a Get-WinEvent FilterHashtable, an XPath filter for -FilterXPath and Event Viewer, and a wevtutil command. **Certificates**: paste or open a certificate, a chain, a .p7b or a certificate request and read its names, validity, key, purposes and SHA-1 and SHA-256 fingerprints, or what a CSR asks for, decoded on the machine; and convert the public certificate between PEM and one-line Base64 DER, split a chain into its certificates, or extract the public key as a PEM SubjectPublicKeyInfo; a private key pasted by mistake is recognised and never decoded, and a .pfx, which carries one, is out of scope for this reason. **UUIDs**: random version 4 and time ordered version 7 UUIDs in the standard, upper case, braces, compact and URN forms, and a decoder that reads the version, the variant, and the creation time of a version 1, 6 or 7 UUID. **Text diff**: two texts compared line by line with Myers' algorithm, the one diff and git use, ignoring case or spaces on request, with the removed and added lines coloured and three unchanged lines kept around each change. **URL parser**: a link taken apart as you type, host as DNS resolves it, port, path and every query parameter decoded, with the tricks phishing links use named: a user name before @ that looks like the site, look-alike letters, an IP address, a password in clear. **Connection string**: paste a database connection string and read it apart on the machine — the driver it is for (SQL Server, PostgreSQL, MySQL, ODBC, OLE DB), the server, database and user, and every parameter with the password masked; and what it exposes: a password kept in clear, a connection left unencrypted, and a server certificate trusted without being checked (TrustServerCertificate, SSL Mode). **User-Agent**: paste a User-Agent line and read it apart on the machine into the browser and its version, the layout engine, the operating system, and whether it is a desktop, a phone, a tablet, a bot or a command line tool; read by known patterns most specific first, since an Edge line also says Chrome and a Chrome line also says Safari. **Text normalizer**: rewrite a pasted text to one set of choices, on the machine, with a note of what changed — the line endings (LF, CRLF or CR), tabs turned to spaces or leading spaces to tabs at a chosen width, the spaces and tabs left at the end of a line, and a byte order mark at the front; the invisible differences that make a config behave differently on two machines, or a diff show a change that is not one. **XML**: the XML counterpart of the JSON tool, worked out on the machine — format a document so it can be read, minify it, say whether it is well formed and where it is not, or run an XPath query over it (an element comes back as its markup, an attribute as its value); the configs, GPO backups and event records an administrator meets are XML. **INI and .env**: read an INI or a .env file on the machine, laid out section by section or as JSON, with the values whose key names a secret (password, token, key, connection string) masked so the readout does not carry one on; it flags a key repeated in a section, a key sitting above the first section, and a line that is neither a comment nor a key = value, and reads both = and : as INI separators, an export prefix, quotes and inline comments. **CSV cleaner**: paste a CSV and read it as an aligned table on the machine — the delimiter worked out (comma, semicolon, tab or pipe), the quoting parsed properly so a field can hold the delimiter, a quote or a newline of its own, and the rows laid out in columns; trim the cells, drop the blank rows and the exact duplicates, and read the result back as a table, as JSON, or as clean CSV. **NATO alphabet**: a serial number, licence key or password spelled out for the phone, with capitals, digits, symbols and accents. **Phone numbers**: a number written in any form read and written as E.164, international, national and a tel: link, with the grouping of 25 countries and the kind of a French number. **HTML editor**: formatted text on one side and clean HTML on the other, headings, paragraphs, lists, bold, italic, underline and links and nothing else, for a signature, a ticket or a wiki; HTML pasted in loads back without its scripts, styles, attributes and javascript: links. **Crontab**: a schedule picked from presets or typed, read back in words with its next five runs, including the rule that makes cron run on either day when both the day of the month and the day of the week are set, and the line for crontab -e. **Docker Compose**: a docker run command, on one line or continued with \ or a backtick, turned into its Compose service, ports, volumes, environment, networks, restart policy, health check, limits and a hundred other options, with named volumes and networks declared and the options Compose has no place for listed as comments. **QR code**: a link or a text encoded as you type by an encoder written into the toolkit, byte mode in UTF-8, versions 1 to 40 and the four error correction levels, saved as a PNG or copied as a picture, so a client's link or password is never pasted into a generator online. **Wi-Fi QR code**: the network name, security and password as the code a phone camera joins with, for guests or a meeting room, with the name and security of the connected network filled in on request and a key the network would not accept refused before a code is drawn. **TOTP code**: the six-digit authenticator code (RFC 6238) computed on the machine from a Base32 secret or an otpauth:// URI and refreshed every second, with the seconds left in the window and the previous and next codes for clock skew, to test a service account's second factor or check a seed was enrolled without reaching for a phone; the secret is read, never sent anywhere and never shown, only its length. **SDDL**: a security descriptor string (from `Get-Acl`, `sc.exe sdshow` or an AD attribute) read into its owner, group and each access control entry, with the SID of every trustee named, the inheritance and audit flags spelled out, and the access mask decoded for the kind of object it protects, a file, a registry key, a directory object or a service. **AD account flags**: a userAccountControl, groupType or msDS-SupportedEncryptionTypes value broken into the bits it sets, with a note for what matters (an account disabled, a password that never expires, pre-authentication off, RC4 still allowed). **Robocopy**: a robocopy command built from its options, each explained on hover (what backup mode, all attributes, restartable and the rest actually do), with mirror winning over a plain subfolder copy, files and folders to exclude, a log file, and paths quoted, and a reading of what a robocopy exit code means, as the bitmask it is rather than a rank. **Scheduled task**: a schtasks /create command line built from a schedule and a program, adding only the fields the schedule uses. **dsacls delegation**: a dsacls command that delegates control on an OU, the same as the Delegation of Control wizard. Pick a task, or double-click one on the cheat sheet of common jobs (reset passwords, unlock or enable accounts, edit contact info, manage group membership, link GPOs, create and delete objects, join computers to the domain), which fill in the minimum rights; or tick **specific properties** — the attributes and property sets offered change with the object type (user, group, computer, OU, contact, printer, shared folder) — with read, write or both; or **move an object**, which builds the two commands, delete in the source OU and create in the target. With how far it reaches, grant or deny, or a custom rights string. **icacls (NTFS)**: an icacls command for the permissions of a file or folder — grant or deny from permissions that combine as check boxes (full control, modify, read and execute, read, write, delete, a higher one greying out the rights it already includes), remove a trustee, reset to inherited, set the owner, turn the object's own inheritance on, off or clear, and save or restore the ACLs to a file; with the inheritance a folder's entry applies with (this folder, its subfolders and its files, and the rest), and whether to apply it through the existing tree, carry on past errors, stay quiet and act on a symbolic link itself. **SID resolver**: a security identifier read both ways on the machine — a SID named and taken apart into its authority, its domain and its RID, and an account name turned back into its SID; the well-known SIDs and the domain RIDs are named offline, the English well-known names (Everyone, SYSTEM, Administrators) resolve whatever the language of Windows, and a local or reachable-domain account is translated by Windows. **LDAP filter**: compose an Active Directory search filter on the machine — pick the kind of object, write the conditions one per line as attribute operator value (=, !=, <=, >=, ~=, and * for a wildcard or a set attribute), and choose whether all or any must hold; the filter is built and escaped, with the Get-ADObject, the object-specific cmdlet and the dsquery command that use it. Presets drop a ready condition in (disabled accounts, password never expires, locked out, never signed in, member of a group), the matching-rule OID a userAccountControl bit test needs already filled in. **WMI query**: build a WMI query on the machine from a class (a list of common ones to pick from, or type your own), the properties and the conditions written one per line as property operator value (=, != or <>, <, >, <=, >=, and LIKE with % as the wildcard), all or any of them; it composes the WQL and the three ways to run it, Get-CimInstance with a filter, Get-CimInstance with a query, and the old wmic command, quoting the strings and leaving the numbers bare, and keeping a namespace other than root\cimv2 in every form. Nothing is queried; it only writes the commands. **Firewall rule**: build a Windows Firewall rule from its direction, action, protocol (ping included, as an ICMP echo request), local and remote ports and ranges, remote addresses (LocalSubnet and the other keywords, addresses, subnets, ranges), program and profiles, or start from a ready-made one (ping or SMB from the local subnet, Remote Desktop or WinRM from an admin host, block an application); it writes the rule as New-NetFirewallRule and as netsh advfirewall, with the commands that check and remove it, and warns when a rule is wider than it looks: open to any address on the Public profile, a remote administration or file sharing port (RDP, SMB, WinRM, SSH, SQL...) reachable from anywhere, ranges included, or every port let in. Nothing is applied. **.reg and PowerShell**: a .reg file, pasted or opened (regedit's UTF-16 included), turned into PowerShell and into reg.exe commands for a batch file, a GPO or an Intune script, and PowerShell registry commands turned back into a .reg file to save; every value type a .reg file carries (strings, dword, qword, binary, expandable and multi-strings), deleted keys and values, and lines continued with \. A key is created only when it is missing, since New-Item -Force on an existing key would empty it; PowerShell is read with the parser and never run, so only literal values are taken and anything computed is named instead. Nothing is written to the registry. |

### Reference and settings

| Page | What is in it |
| --- | --- |
| **Knowledge base** | **Topics**: 38 topics across 12 categories: fundamentals, switching and VLANs, routing and addressing, network services, network security, wireless, physical layer, method and tooling, Windows administration (start-up and recovery with BitLocker, Windows Update servicing with WSUS and Windows Update for Business), identity and access (Group Policy, Kerberos and NTLM, Microsoft Entra join and Intune enrolment, passwords and MFA), security operations (backups that survive ransomware, the first hour of an incident), SPF, DKIM and DMARC, and reference tables: well-known SIDs and RIDs, HTTP status codes, SMTP reply and Exchange Online status codes. **Windows codes**: type an error code in any form (0x80070005, 80070005, -2147024891 as the update history returns it, or a Win32 number), an event ID or words, and read what it means and what to try. Written from Microsoft's references: every Windows Update error, the servicing (CBS), setup and upgrade, network and sign-in failure codes a call meets, Intune enrolment errors, KMS and MAK activation errors, the NTSTATUS and exception codes of application crashes, and about a hundred event IDs with their source, from Kernel-Power 41 to the Secure Boot certificate update events. A code not in the reference is still decoded into its facility and code, with the Windows message for a Win32 error. Codes and events are also found from Ctrl+K, a failed update names its error in Update history, and the security event triage says why sign-ins failed. |
| **Commands** | 691 commands, grouped by task and searchable all at once. **Administration cheat sheets**: **Active Directory** (users, groups, computers, replication, Group Policy, recycle bin), the **Windows command line** (robocopy, icacls, sc, schtasks, diskpart, bcdedit, wevtutil, certutil), **Intune and Entra device management** (dsregcmd, enrolment events, check-in, Intune Management Extension logs, Autopilot, BitLocker keys), **Microsoft Graph and Exchange Online PowerShell**, **OpenSSL and certificates**, **tcpdump, Wireshark filters and Nmap**, **Docker and Compose**, **Kubernetes**, and **Hyper-V, ESXi and Proxmox VE**. **Scripting cheat sheets**: **Git** from the first commit to recovering one that seemed lost; **PowerShell** with the verbs and what each promises, what can follow a \| (Where-Object, Sort-Object, Select-Object with computed properties, Group-Object, Measure-Object, ForEach-Object, Export-Csv, ConvertTo-Json, Out-GridView), the operators, variables, types, hashtables, objects and classes, parameters, error handling and remoting, and the everyday administration commands; **Bash** with quoting, parameter expansion, conditions and loops, functions and exit codes, redirections, arrays and globbing; **Linux system administration** with files, permissions and users, processes and systemd services, packages on Debian and Red Hat, disks, SSH and cron. **Network platforms**: Cisco, Cisco Meraki, Aruba AOS-CX and AOS-S, Fortinet, Palo Alto, Stormshield, pfSense and OPNsense, Juniper, Extreme, HPE Comware, MikroTik, Ubiquiti, Windows, Linux and Linux firewalling. |
| **Settings** | The VirusTotal API key, stored encrypted for this Windows account, and the folder where the toolkit keeps its data and logs. **Privacy of exports**: whether what is exported from the window (the diagnostic, audit, system and threat hunting reports, the event CSV, the support bundle and the intervention report) is pseudonymised, and at which level, Personal or Strict; what that replaces on this PC, and what an alias such as PC-1 or USER-2 stood for, read back from the tables kept on it. |

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
the published build again. That address is part of the code or of the command
the operator typed, never something read from a response, and only a plain
HTTPS address is ever replayed: a plain HTTP source would let an attacker on
the network choose the code that runs as Administrator. Started with the
verified launch command, the elevated instance checks the same SHA-256 before
it runs, and runs nothing when the hash differs. The address and the hash are
checked against a strict form before they are written into that command.

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
the developer did not register. The same tables are the only way in without a
window: a command line selects an entry by its id, never a command, and a run
without `-Execute` changes nothing.

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

**What leaves can be pseudonymised, and says how far.** Reports and support
bundles are made to be sent. With Privacy of exports, or `-Redact` without a
window, what names a person, the machine or where it sits is replaced in the
final text of the export by stable aliases, and the table back to the real
values is kept on the machine, encrypted with DPAPI for the Windows account.
Built-in and generic account names (Administrator, Public, admin, test) and
addresses that name nobody (loopback, APIPA, multicast, masks, network
addresses) are kept: they carry diagnostic meaning. The replacement works from
the values the machine is known by and from patterns, so a name typed in a
note or buried in another program's message can still be there: the toolkit
says the export is reduced, never that it is anonymous.

**Every privileged operation is logged**, to `%LOCALAPPDATA%\Toolkit\logs`,
with the operation, the outcome and the duration.

**The journal is tamper-evident, not tamper-proof.** Each line records the
SHA-256 of the one before it, so a line changed, removed or slipped in later,
or a missing day, shows when the journal is verified. Anyone who can write the
files can still rewrite the whole chain with new hashes, and no key kept on the
same machine would stop an administrator. What exposes that is outside the
machine: the head of the chain is written into every intervention report, and
a journal rewritten afterwards no longer leads to it. The export keeps the
lines as they are, links included, and is not pseudonymised: it is the record
itself.

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

### Verified launch, pinned to a release

Each release is tagged (`v1.0.0`, ...), and its page on GitHub gives the
SHA-256 of `dist/toolkit.ps1` at that tag with the command below, filled in.
The command downloads the build of the release, checks its SHA-256 and runs it
only if it matches, all in memory: nothing is written to disk.

```powershell
$u = 'https://raw.githubusercontent.com/KyllianFF/Tool-kit/<tag>/dist/toolkit.ps1'; $h = '<SHA-256 from the release page>'; $b = (Invoke-WebRequest -Uri $u -UseBasicParsing).RawContentStream.ToArray(); if (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)) -replace '-') -ne $h) { throw 'SHA-256 mismatch: this is not the expected build, and nothing was run.' }; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) -SourceUri $u -ExpectedSha256 $h
```

Why it is worth the longer line:

- **A build that does not move.** `main` serves the latest build, which can
  change between two launches. A tag serves the same bytes every time.
- **Checked before it runs.** A download that is not the expected build is
  refused before a single line of it executes.
- **The same build when elevated.** `-SourceUri` and `-ExpectedSha256` go on
  to the toolkit, so **Restart as administrator** and every per-action UAC
  prompt download the same address again and run it only if the hash still
  matches.

Take the hash from the release page, a channel distinct from the download
itself. **Settings, Updates, This copy** says where the running instance came
from and what was checked, and copies its verified command for a colleague.

### Download, verify, then run

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

## Portable, offline edition

For a machine with no network, or one where a single file full of base64 makes
an antivirus nervous, `build/New-PortablePackage.ps1` produces an offline build
that is deliberately unremarkable: a readable script with the catalogs and the
interface left in plain files beside it, rather than embedded as blobs.

```powershell
.\build\New-PortablePackage.ps1
```

This writes to `dist/`:

- `Toolkit-Portable-<version>/` and its `.zip` — the de-blobbed folder:
  `Toolkit.ps1`, `MainWindow.xaml`, `data/`, a `Start-Toolkit.cmd` launcher,
  a `README.txt` with offline-run and allowlisting guidance, and a
  `SHA256SUMS.txt` for the whole set.
- `Toolkit-<version>.ps1` — the same self-contained single file the one-liner
  serves, under a versioned name so it can be signed and shipped on its own.

Run it by double-clicking `Start-Toolkit.cmd`, or:

```powershell
powershell.exe -ExecutionPolicy Bypass -Sta -File .\Toolkit.ps1
```

**Signing.** Code signing is the honest way to get an administration tool past
an endpoint product: sign it, then let the security team allow it by publisher.
Create a certificate, then build again with it:

```powershell
.\build\New-CodeSigningCertificate.ps1 -Install         # self-signed, for a lab or an internal fleet
.\build\New-PortablePackage.ps1 -Thumbprint <thumbprint> # signs both editions, timestamped
```

The build makes no attempt to hide from or disable any security product. If an
endpoint sensor still flags a signed build, the answer is a scoped exception
the security team owns — the package `README.txt` has the specifics for
Microsoft Defender, CrowdStrike Falcon and ESET.

**Staying current.** A portable or saved copy grows old without saying so. In
Settings, **Updates** turns on an opt-in check at start-up (off by default), or
runs one with **Check now**. It reads a single small file,
`dist/toolkit.ps1.version.json`, which the build writes beside the script:
the version, commit, SHA256 and date of the published build. When a newer build
is published, an **Update available** button appears in the header. Nothing is
downloaded or replaced: a signed copy would lose its signature, and a tool that
rewrites itself from the network is what a security product is right to
distrust. You fetch the published build, check its SHA256 against the one
shown, and rebuild the portable package if that is the edition you use.

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
    New-PortablePackage.ps1 Builds the offline, de-blobbed editions
    Sign-Toolkit.ps1       Authenticode-signs a build, timestamped
    New-CodeSigningCertificate.ps1 Creates a self-signed signing certificate
    New-ReleaseNotes.ps1   Writes a release's SHA-256 and verified launch command
    portable/              Launcher and readme templates for the portable build
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
  docs/                    Architecture, security policy, contributing,
                           the report format, the headless actions and
                           their JSON Schemas
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

**A release.** Once the build of the version in `src/Core/Config.ps1` is
merged, tag that commit and publish its notes, which carry the SHA-256 and the
verified launch command:

```powershell
git tag v1.0.0; git push origin v1.0.0
.\build\New-ReleaseNotes.ps1 -Tag v1.0.0 -OutFile notes.md    # refuses a tag that is not the build's version
gh release create v1.0.0 --title "Toolkit 1.0.0" --notes-file notes.md
```

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
