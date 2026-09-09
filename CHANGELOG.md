# Changelog

All notable changes to this project are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

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
