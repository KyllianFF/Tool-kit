# Changelog

All notable changes to this project are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

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
