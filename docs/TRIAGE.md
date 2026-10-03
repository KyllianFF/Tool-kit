# Incident triage

In the first hour of an incident, the state of a suspect machine has to be
kept before it changes, in a form the people who handle the incident can
trust. The triage collection does that: it takes what is most volatile first,
writes each artefact as a file, hashes every file in a manifest dated in UTC
that names the operator and the build that collected, packs the whole into
one archive and, given the responder's certificate, encrypts it for them
alone.

It runs from the **Audit** page, **Incident triage** tab, or without a window:

```powershell
$toolkit = [scriptblock]::Create((irm https://raw.githubusercontent.com/KyllianFF/Tool-kit/main/dist/toolkit.ps1))

& $toolkit -Triage List                                         # the steps
& $toolkit -Triage E:\ -TriageReference INC-0142                # every step, in clear
& $toolkit -Triage E:\ -TriageReference INC-0142 -TriageCertificate E:\soc.cer
& $toolkit -Triage E:\ -TriageStep processes, connections, event-logs -OutFile E:\triage.json
exit $LASTEXITCODE
```

Pin a release with the verified launch command (see the README): the manifest
then records the SHA-256 of the build that ran, checked before it ran.

## Before collecting

- **Isolate the machine first** (unplug it, or isolate it from the EDR
  console), and write down the time. Do not power it off, reinstall it or run
  a cleanup tool: that erases what the collection keeps.
- **Write to removable media** or a share, not to the suspect disk. The
  manifest says when the case was written to the system drive.
- **Run as administrator** when you can. Without it the collection still runs,
  but the steps marked below are partial, and say what they could not read.

## What it does not do

No memory image, no copy of LSASS, no password, hash or credential: those
belong to a forensic tool, and look exactly like what malware does. The
collection only reads, but it leaves traces of its own, which the manifest
records: Windows PowerShell and the toolkit write their own events, Prefetch
records the programs it ran (powershell, netsh, ipconfig), and the files of
the case are written to the destination.

## The steps

Most volatile first. Each writes into `artefacts/NN-key/`. A step that fails is
recorded with its error and the next one runs; a step that needs administrator
rights runs anyway and is marked **Partial**.

| # | Key | What | Files | Without administrator rights |
| --- | --- | --- | --- | --- |
| 01 | `processes` | Processes: command line, parent, owner, creation time, path, SHA-256 and Authenticode signature of each executable | `processes.csv` | Other accounts' command lines and owners are hidden |
| 02 | `connections` | TCP connections and listening ports, UDP endpoints, with the owning process | `tcp.csv`, `udp.csv` | |
| 03 | `sessions` | Logon sessions: user, logon type, authentication package, start | `sessions.csv` | Other accounts' sessions are hidden |
| 04 | `dns-cache` | The DNS client cache | `dns-cache.csv` | |
| 05 | `arp-cache` | The ARP and IPv6 neighbour cache | `arp-cache.csv` | |
| 06 | `network` | `ipconfig /all`, the WinHTTP proxy, routes, the hosts file, mapped drives, shares | `ipconfig.txt`, `winhttp-proxy.txt`, `routes.csv`, `hosts.txt`, `smb-mappings.csv`, `shares.csv` | |
| 07 | `tasks` | Scheduled tasks with their actions, triggers, account and last run | `scheduled-tasks.csv` | |
| 08 | `services` | Services and kernel drivers with their binary and account | `services.csv`, `drivers.csv` | |
| 09 | `autostarts` | Run keys, services, tasks and WMI subscriptions, signature checked (as Threat hunting reads them) | `autostarts.json` | |
| 10 | `accounts` | Local accounts, and the members of Administrators, Remote Desktop Users, Backup Operators and Remote Management Users | `local-users.csv`, `privileged-groups.csv` | |
| 11 | `firewall` | Firewall profiles and every rule | `firewall-profiles.csv`, `firewall-rules.txt` | |
| 12 | `defender` | Microsoft Defender: status, detections, threats and exclusions | `defender.json` | The exclusions are hidden |
| 13 | `extensions` | Browser extensions of Chrome, Edge, Brave and Firefox | `browser-extensions.json` | |
| 14 | `history` | USB storage and Remote Desktop history | `usb-history.json`, `rdp-history.json` | |
| 15 | `event-logs` | System, Application, Security, both PowerShell logs, Defender, Task Scheduler, the two Terminal Services logs, WMI activity, BITS and Sysmon when present, exported whole | one `.evtx` per log | The Security log is not readable |

## The case

```
<destination>\
  triage-<COMPUTER>-<yyyyMMddTHHmmssZ>\          the case folder
    artefacts\01-processes\processes.csv ...
    manifest.json
    manifest.sha256                              "<sha256>  manifest.json"
  triage-<COMPUTER>-<yyyyMMddTHHmmssZ>.zip       the case folder, packed
  triage-<COMPUTER>-<yyyyMMddTHHmmssZ>.sha256.txt
  triage-<COMPUTER>-<yyyyMMddTHHmmssZ>.zip.p7m.001, .002 ...   with a certificate
  triage-<COMPUTER>-<yyyyMMddTHHmmssZ>.zip.p7m.json            with a certificate
```

The `.sha256.txt` file lists, in the `sha256sum` format, the manifest, the
archive and each encrypted chunk. The same two hashes, manifest and archive,
go into the intervention journal (category Triage) and on screen: write them
into the incident log, they prove later that the case was not changed.

### manifest.json

| Field | Meaning |
| --- | --- |
| `Schema`, `SchemaVersion` | `toolkit-triage`, `1.0` |
| `Case` | `Id` (the folder name) and `Reference` (the incident or ticket number typed) |
| `Started`, `Ended` | UTC, ISO 8601 |
| `Machine` | `Computer`, `MachineId` (as in the report documents), `Os`, `LastBoot` (UTC), `TimeZone`, `UtcOffset` |
| `Operator` | `User` (DOMAIN\name) and `Elevated` |
| `Toolkit` | `Version`, `Commit`, `Source` (the file that ran, or the address it was downloaded from), `Sha256` of that build, and `Proof`: how that hash is known |
| `Steps` | per step: `Key`, `Label`, `Started`, `Ended`, `Status` (`Done`, `Partial`, `Failed`, `NotRun`), `Note`, `Folder` |
| `Files` | every file of the case but the manifest: `Path` (forward slashes), `Bytes`, `Sha256` |
| `Footprint`, `NotCollected`, `Destination` | what the collection changed on the machine, what it leaves out by design, and whether it wrote to the system drive |

## Encryption

With a certificate, the archive is encrypted in **CMS** (`EnvelopedCms`,
AES-256-CBC, the key wrapped with RSA for the certificate): the format openssl
and Windows both read, with no cryptography of the toolkit's own. The
certificate must hold an RSA key and be valid; it is read before anything is
collected, so a wrong one is refused at once.

One CMS message cannot hold a large archive (.NET cannot read one back past
about 64 MB), so the archive is cut into chunks of 32 MB, each its own CMS
message, each read back and checked for the certificate before the next is
written. The index, `<archive>.p7m.json`, gives:

| Field | Meaning |
| --- | --- |
| `Schema` | `toolkit-triage-archive` |
| `Archive`, `Sha256` | the clear archive's name and SHA-256 |
| `Algorithm`, `ChunkBytes` | how it was encrypted, and the size of each clear chunk |
| `Recipient` | `Subject`, `Thumbprint`, `SerialNumber`, `NotAfter` of the certificate |
| `Chunks` | in order: `File`, `ClearBytes`, `Sha256` of the encrypted chunk |

The clear archive and folder are **kept** beside the encrypted chunks unless
`-TriageRemoveClear` (or the tab's tick) asks to remove them, and only once
every chunk has been read back. If encryption fails, the clear archive stays
and the result says why: the evidence is never lost to a wrong certificate.

### Opening an encrypted archive

With openssl, the certificate (`soc.pem`) and its private key (`soc.key`), in
the order of the index:

```bash
: > archive.zip
for chunk in triage-PC-20261003T084001Z.zip.p7m.[0-9][0-9][0-9]; do
    openssl cms -decrypt -inform DER -in "$chunk" -recip soc.pem -inkey soc.key >> archive.zip
done
sha256sum archive.zip    # compare with Sha256 in the .p7m.json index
```

With the toolkit (`-NoGui` loads its functions), the key taken from the
certificate store by the thumbprint of the index, or from a `.pfx`:

```powershell
Unprotect-TkTriageArchive -Index .\triage-PC-20261003T084001Z.zip.p7m.json -OutFile .\archive.zip
Unprotect-TkTriageArchive -Index .\triage-PC-20261003T084001Z.zip.p7m.json -OutFile .\archive.zip -PfxPath .\soc.pfx -Password (Read-Host -AsSecureString)
```

It checks each chunk's SHA-256 against the index before decrypting it, and
the rebuilt archive's SHA-256 at the end.

## Without a window

`-Triage <destination>` returns JSON (or writes it to `-OutFile`):

| Field | Meaning |
| --- | --- |
| `Schema`, `SchemaVersion` | `toolkit-triage-result`, `1.0` |
| `Computer`, `MachineId`, `GeneratedAt`, `Toolkit`, `Elevated` | as in the other headless results |
| `Outcome` | `Done`, `Partial` (a step could not read everything without administrator rights) or `Failed` |
| `ExitCode` | `0`, or `1` when a step failed or the encryption asked for failed |
| `Case` | where everything went: `Folder`, `Manifest`, `ManifestSha256`, `Archive`, `ArchiveSha256`, `Encrypted`, `EncryptionError`, `Index`, `Chunks`, `ClearRemoved`, `Hashes`, `Steps`, `Failed`, `Partial` |

The exit code is left in `$LASTEXITCODE`, and is the process's own when the
script is run as a file. `-TriageReference`, `-TriageCertificate`,
`-TriageStep` and `-TriageRemoveClear` go with `-Triage`, which does not mix
with `-Report`, `-Fix` or the other modes.
