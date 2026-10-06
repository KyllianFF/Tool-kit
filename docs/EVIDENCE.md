# Framework mapping and evidence pack

An ISO 27001 audit, a NIS2 programme or a cyber insurer asks for technical
evidence, requirement by requirement. The security audit measures a machine
control by control. This mapping says which requirement each control
contributes to, and the **evidence pack** puts the two together: for each
requirement, the controls measured, their value and how it was read, when, on
which machine, by whom and with which build of the toolkit, then the SHA-256
of the pack and, optionally, its signature.

> **The pack never says a requirement is met.** A requirement is met by an
> organisation's measures as a whole: policies, people, processes, the rest
> of the estate. One workstation's settings never show that. The pack
> contributes evidence; an auditor judges. Its wording says so, and a test
> keeps the word "compliant" out of it.

## The frameworks

| Id | Framework | What is cited |
| --- | --- | --- |
| `ISO27001` | ISO/IEC 27001:2022, Annex A | The controls the audit's checks contribute to, mostly technological (8.x), plus 5.15–5.18, 7.7 and 7.10 |
| `NIS2` | NIS2 Directive (EU) 2022/2555, Article 21(2) | The measures (b), (e), (g), (h) and (i). **Indicative**: the article lists risk-management measures, not settings |
| `CIS` | CIS Critical Security Controls v8 | Safeguards. The Windows *Benchmark*'s section numbers change with every release, so they are not cited |
| `ANSSI` | ANSSI, *Guide d'hygiène informatique* (42 measures, 2017) | The measures, by number, with their titles translated |

Every one of the 39 audit controls is mapped (`data/frameworks.json`). Each
control also carries its **method**, which says what it reads and how: a
registry value, a cmdlet, a WMI class. A test keeps the mapping in step with
the audit's control table. Every requirement listed is used by at least one
control, and every requirement cited exists.

The mapping is the toolkit's reading, version-dated in the catalog. Review it
against the editions your organisation follows. A mapping that could not be
argued is left empty rather than stretched: no CIS safeguard is cited for
ACC-005 (local accounts whose password never expires).

The audit page and its HTML report show, under each control, what it
**contributes to**:

```
Contributes to: ISO 27001 8.1, 8.24; NIS2 21(2)(h); CIS Controls 3.6; ANSSI hygiene 31.
```

## Making a pack

- **In the window:** Audit › Security audit, run the audit, then **Evidence
  pack**. Choose a folder. When this account or the machine holds a valid
  certificate made for signing (Document Signing or Code Signing, with its
  private key), the toolkit offers to sign with it. It never signs silently.
- **Without a window**, for an RMM or a scheduled task:

```powershell
& $toolkit -Evidence List                                              # the frameworks
& $toolkit -Evidence \\server\evidence$ -AuditLevel Full               # every framework, unsigned
& $toolkit -Evidence E:\ -EvidenceFramework ISO27001, NIS2 -EvidenceCertificate 3F2A...C9
```

`-AuditLevel`, `-Policy`, `-PolicyTrust` and `-Redact` apply as with
`-Report Audit`. The run refuses an unknown framework or certificate before
the audit starts. It also refuses without administrator rights, as the audit
does: half of what it reads is invisible to a standard user. It returns a
`toolkit-evidence-result` JSON with the paths and hashes of what it wrote, and
a count of each observation.

The pack follows the export privacy set in Settings (or `-Redact`), with the
same pseudonyms in both files.

## Observations

For each requirement, the controls of the audit mapped to it give one
observation:

| Observation | Shown as | When |
| --- | --- | --- |
| `Supported` | Evidence | Every control measured for it passes (or is a fact that asks for nothing) |
| `Weakness` | Weakness | A control is only partly in place (a warning) |
| `Gap` | Gap | A control fails |
| `AcceptedRisk` | Accepted risk | The controls that fall short are under an exception of the organisation policy that has not ended; the earliest end date is given |
| `NotAssessed` | Not assessed | Its controls could not be read |
| `NotRequired` | Not required | The organisation policy does not require its controls |
| `NotCovered` | Not covered | None of its controls was in this audit; when they all belong to the Full level and the audit was Essential, it says the Full audit runs them |

The controls of a requirement that were not in the audit are named under
`NotInAudit`.

## The files

```
<folder>\
  evidence-<COMPUTER>-<yyyyMMddTHHmmssZ>.json       the pack (toolkit-evidence 1.0)
  evidence-<COMPUTER>-<yyyyMMddTHHmmssZ>.html       the same, printable
  evidence-<COMPUTER>-<yyyyMMddTHHmmssZ>.sha256     SHA-256 of the files above, sha256sum format
  evidence-<COMPUTER>-<yyyyMMddTHHmmssZ>.json.p7s   detached CMS signature of the JSON, when signed
```

The pack is journaled (category *Evidence*), with its SHA-256 and its signer.
The pack records the journal's head (its last line's hash) as it was before
that entry. The pack and the journal therefore point at each other.

### toolkit-evidence 1.0

| Field | Meaning |
| --- | --- |
| `Schema`, `SchemaVersion`, `Id`, `GeneratedAt` | `toolkit-evidence`, `1.0`, the file name, UTC |
| `Notice` | What the pack is and is not |
| `Machine` | `Computer`, `MachineId` (as in the report documents), `Os` |
| `Operator` | `User` and `Elevated` |
| `Toolkit` | `Version`, `Commit`, `Source`, `Sha256` of the build and `Proof`: how that hash is known (the file that ran, hashed; or the download, checked before it ran) |
| `Mapping` | The catalog's `Version` and the `Frameworks` included |
| `Audit` | `Level`, `AuditedAt` (UTC), `Score`, `Controls`, `ExcludedAccount`, and `Policy` (verdict, name, version, how it was trusted, SHA-256) when audited under one |
| `Journal` | `Valid`, `Entries`, `Head`: the journal's chain when the pack was made |
| `Frameworks` | Per framework: `Id`, `Name`, `Edition`, `Indicative`, and `Requirements`, each with `Id`, `Title`, `Observation`, `Label`, `Text`, `Controls` (`Id`, `Name`, `Status`, `Measured`) and `NotInAudit` |
| `Controls` | Each control of the audit: `Id`, `Name`, `Category`, `Status`, `Measured`, `Detail`, `Recommendation`, `Level`, `Weight`, `Method`, `References` (`ISO27001 8.24`…), and `Policy` (`State`, and the `Exception` with its end date, owner, ticket and reason) |

## Checking a pack

The hashes, from any shell:

```bash
sha256sum -c evidence-PC-20261006T090500Z.sha256
```

The signature, with openssl and the signer's certificate (or the CA that
issued it):

```bash
openssl cms -verify -binary -inform DER -purpose any \
    -in evidence-PC-20261006T090500Z.json.p7s -content evidence-PC-20261006T090500Z.json \
    -CAfile signer.pem -out /dev/null
# CMS Verification successful
```

With the toolkit (`-NoGui` loads its functions):

```powershell
Test-TkEvidencePack -Path .\evidence-PC-20261006T090500Z.json
```

It checks each file against the `.sha256` and names any that changed. It also
checks the signature against the JSON: `Signed`, with the signer, its
thumbprint and the signing time. `ChainTrusted` says apart whether Windows
trusts the signer's chain, since a company's own signing certificate is often
trusted only inside it.

## Changing the mapping

`data/frameworks.json`:
- `frameworks`: each with `id`, `name`, `short`, `edition`, `indicative` and
  its `requirements` (`id`, `title`);
- `controls`: each with its audit `id`, its `method`, and its `maps`, one list
  of requirement ids per framework.

A new audit control needs its row here, or the test fails. Raise the catalog's
`version` with any change: the pack records it.
