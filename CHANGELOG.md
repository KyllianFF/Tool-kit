# Changelog

All notable changes to this project are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **Threat hunting**, a new tab on the Security page. Four read only
  investigations, so they are safe to run first on a machine whose state you
  do not want to disturb:
  - **Event log triage**: failed logons grouped by account, so brute force is
    distinguished from password spraying; lockouts; services installed, which
    is how most remote execution frameworks obtain SYSTEM; Security log
    cleared; remote desktop logons; privileged group additions; local accounts
    created. Summarised rather than dumped, because ten thousand raw records
    say nothing.
  - **Autostart and persistence**: Run keys, start-up folders, services whose
    binary sits outside the Windows directory, scheduled tasks outside the
    Microsoft namespace, and WMI permanent event consumers. Each entry is
    signature checked and flagged when it is unsigned, missing, running from a
    user writable folder, or carrying encoding or download markers on its
    command line. What ships with Windows is separated from what does not.
  - **Network exposure**: listening sockets joined to the enabled inbound
    allow rules, so the report says what a packet from the network can
    actually reach rather than what merely listens. Loopback only sockets are
    called out as unreachable.
  - **Certificate inventory**: the machine and user stores, with expiry,
    SHA-1 signatures and RSA keys below 2048 bits flagged; plus a batch expiry
    check against a list of endpoints.
- Reports from any of the four export to JSON.
- **Knowledge base rendered as a document** instead of a block of text:
  headings, prose, bullets and real tables. The port reference is now five
  grouped tables of 46 rows rather than a paragraph, and the OSI model and the
  IPv4 reserved ranges are tables too.
- **Search highlighting** across the knowledge base and the vendor reference,
  in the body and inside command blocks, not only in the topic list.
- **Input hints**: every field whose content is not obvious now shows an
  example while it is empty.

### Fixed

- **Piping a function that returns a collection returned the collection
  itself.** Wrapping returns with the comma operator, added to guarantee an
  array on assignment, broke enumeration: `Get-TkFix | Where-Object` handed
  the whole array to the filter, so a fix ran with an array where it expected
  one object and the interface crashed on `Cannot convert value to type
  System.String`. The comma is kept only on `ConvertTo-TkArray`, whose
  contract is explicitly to return an array object.
- **Tables rendered empty.** The custom `ListViewItem` template did not bind
  `Content`, and a `GridViewRowPresenter` is not a `ContentPresenter`: it does
  not inherit it. The local audit and the adapter list showed rows of the
  right height with nothing in them.
- **The VirusTotal key never decrypted.** `Set-Content` appends a newline and
  `ConvertTo-SecureString` rejects it, so the key failed to read back
  immediately after it was saved.
- **Store applications could not be installed.** Every install was pinned to
  the winget source, and a Microsoft Store product identifier only exists in
  msstore. The source is now chosen from the shape of the identifier, and the
  common winget exit codes are translated instead of being printed raw.
- **Adapter enumeration filled the output panel with errors.**
  `Get-NetIPConfiguration` writes a record for every adapter with no
  connection profile, and `SilentlyContinue` only hides the display: the
  record still reaches the runspace error stream. Switched to `Ignore`.
- **Background work never reached the output panel.** `Write-TkLog` uses
  `Write-Host`, which lands in the information stream of the worker runspace
  where there is no window. Those lines are now replayed on the UI thread.
- **The widgets tweak always failed.** `TaskbarDa` is protected by Windows 11
  and returns "unauthorized operation" even for the owning user, so it was
  removed from the tweak rather than left to fail every time.

### Added, earlier

- **Network administration tools**, a new tab on the Network page:
  - **Path MTU discovery** by binary search with the do-not-fragment bit,
    which is the measurement that explains a VPN that connects but stalls on
    large transfers. Reports the MSS to clamp to.
  - **Link quality**: loss, minimum, average and maximum latency, and jitter
    as the mean deviation between consecutive round trips, which is the
    figure voice and video actually depend on and the one an average hides.
  - **Traceroute** with per hop timing and reverse resolution, several probes
    per hop so a slow hop is distinguished from a hop that deprioritises the
    ICMP it has to generate.
  - **TLS certificate inspection**: subject, issuer, alternative names,
    expiry with a countdown, protocol, key size, and a separately evaluated
    chain status. Subject alternative name parsing is locale independent.
  - **Wake-on-LAN** with a directed broadcast option, and the checklist of
    why a machine does not wake.
  - **Neighbour cache** with vendor names from a built in OUI table covering
    the hardware met on a corporate LAN, including hypervisors.
- **Network configuration**, a second new tab:
  - **Adapter IP profiles**: capture the live configuration of an adapter,
    save named static or DHCP profiles, and apply one per site. Validation
    happens at save time rather than on site, and a gateway outside its own
    prefix is flagged.
  - **Routing table** with persistent route creation and removal, sorted
    longest prefix first the way a router evaluates it.
  - **Port forwarding** through netsh portproxy, with a reminder that a rule
    forwards but does not open the firewall.
- **IPv6 subnet calculator**, sharing the existing input box: the family is
  detected from the address. Reports the prefix, first and last address, the
  address count as an exact integer, how many /64 links a prefix contains,
  the RFC scope and the interface identifier. Plus EUI-64 derivation from a
  MAC address.
- 33 further tests, covering IPv6 conversion and scoping, /64 counting,
  EUI-64, OUI lookup and the shape of the OUI table.

## [1.0.0] - 2026-09-08

First release.

### Added

- **Shell**: WPF interface with six feature areas, a live output console, a
  status bar with a busy indicator, and an elevation badge that states the
  current privilege level rather than hiding disabled features.
- **System**: machine identity from SMBIOS, firmware version and age,
  operating system state and activation, hardware inventory, platform security
  posture, vendor driver and warranty links with the serial number substituted
  into the URL, vendor firmware utility installation, and report export to
  JSON or text.
- **Software**: 146 applications in 12 categories installed through winget,
  with search, category filter, batch install and uninstall, upgrade all, and
  an installed-state indicator.
- **Tweaks**: 35 declarative and fully reversible tweaks across privacy,
  interface, performance, gaming, hardening and advanced settings, with state
  read back from the registry and a restore point taken before a batch.
- **Fixes**: 12 repair actions dispatched through an allow list, plus
  automatic logon configured through the LSA secret store rather than a clear
  text registry value.
- **Network**: IPv4 subnet calculator with VLSM splitting and prefix sizing,
  adapter inventory, connectivity chain test, port checks, subnet sweep, DNS
  lookups, listening sockets, a 16 topic knowledge base and a cross-vendor
  command reference covering Cisco, Aruba, Fortinet, Ubiquiti, MikroTik,
  Juniper, Windows and Linux.
- **Security**: SSH key generation with enforced passphrases and tightened
  file permissions, file hashing with Authenticode inspection, VirusTotal
  lookups by hash, a cryptographic password and passphrase generator, a
  k-anonymity breach check, and a 15 point local security audit with an
  exportable report.
- **Build**: single file compiler with static analysis, catalog validation,
  base64 embedding, a post-build parse check and SHA256 emission.
- **Tests**: 113 Pester assertions covering subnet arithmetic, winget output
  parsing, package identifier validation, catalog integrity and the credential
  tools.
