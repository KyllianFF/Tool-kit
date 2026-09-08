# Security policy

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer
directly. Please do not open a public issue for a vulnerability.

Include what you did, what happened, and what you expected. A proof of concept
is welcome but not required.

## Scope

This project runs elevated on Windows machines and touches the registry, the
service control manager, the LSA secret store and third party APIs. The
following are in scope:

- Command or argument injection through a catalog file or a user input field
- A privileged operation reachable without the elevation guard
- A secret written in clear text, logged, or sent to a third party
- A tweak or fix whose revert path does not restore the original state
- The `dist/toolkit.ps1` build not matching the sources it claims to be built
  from

## Design commitments

These are properties the project intends to keep. A change that breaks one of
them is a bug.

1. **No clear text secrets.** The VirusTotal API key is stored with DPAPI for
   the current user. The automatic logon password goes to the LSA private data
   store. Neither ever appears in a log line, a command line, or an exported
   report.
2. **No file uploads without an explicit action.** The VirusTotal check sends
   a SHA256. It does not upload files.
3. **No password leaves the machine.** The breach check uses the Have I Been
   Pwned k-anonymity range API: five hex characters of the SHA1 are sent, and
   the comparison happens locally.
4. **Data is not code.** Catalog values are validated before use. Fix actions
   resolve through an allow list declared in code. Package identifiers are
   pattern-checked. Vendor URLs are scheme-checked and encoded.
5. **No implicit elevation.** The process runs with the rights it was given
   until the operator asks for more.
6. **No one-way changes.** Every tweak declares its revert path.
7. **Everything privileged is logged**, with the operation, the outcome and
   the duration, to `%LOCALAPPDATA%\Toolkit\logs`.
8. **Transport is TLS 1.2 or better**, and an elevation restart refuses a
   non-HTTPS source.

## Known and accepted risks

**Piping a download into `iex` executes what the server returns.** This is
inherent to the delivery method the project chose. It is mitigated by
publishing the sources, by publishing a SHA256 next to the build, and by
supporting a clone-and-run path that removes the network from the trust path.
It is not eliminated.

**Automatic logon is a physical security trade-off.** The stored secret is
protected at rest. Anyone sitting at the keyboard is still that user. The
interface says so before you enable it.

**Port checks and subnet sweeps are dual-use.** They are capped, sequential,
and every target is logged. They are intended for networks you administer.

**The local audit is a hygiene check, not a compliance audit.** It does not
replace a CIS or ANSSI benchmark run, and the exported report says so.
