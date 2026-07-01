# LDAP Extended Controls Toolkit

Red-team and blue-team tooling built from hands-on research into Active Directory's **LDAP
extended controls**. Each capability here corresponds to a behavior that was validated in a
two-DC lab (Windows Server 2022) — see **Provenance** below.

**Status:** all 7 features (3 red + 4 blue) are fire-and-confirmed against the lab.

> ## ⚠️ Authorization
> The `red/` tool is **offensive** and is provided for **authorized security testing and research
> only** — your own labs, or engagements you have written permission to perform. It is released in
> the spirit of established AD research tooling (BloodHound, Rubeus, mimikatz). It acts only on the
> target and objects you explicitly point it at. You are responsible for using it lawfully.

## Two tools

| Folder | Tool | Language | Use it to… |
|--------|------|----------|------------|
| [`red/`](red/) | offensive CLI (`ldapctl`) | Python 3 / ldap3 | collect the directory invisibly, make a change survive remediation, and probe existence without logging |
| [`blue/`](blue/) | defensive module (`AdLdapDefense`) | PowerShell | audit what your DC actually logs, hunt replication-metadata tampering, deploy & self-test SACL canaries, and catch replication (DirSync/DCSync) abuse |

## Which do I use?

- **Red team / pentest / purple-team emulation** → `red/` (see [red/README.md](red/README.md) for the
  account and privilege each feature needs).
- **Blue team / detection engineering / hardening** → `blue/` (see [blue/README.md](blue/README.md)).

The two are complements: several `blue/` functions detect (or fail to detect, and tell you so) the
exact techniques `red/` performs.

## What each tool does

### `red/` — `ldapctl` (offensive)

Three subcommands, each operationalizing one validated extended-control technique. Full flags,
privileges, and output shapes are in [red/README.md](red/README.md).

| Subcommand | What it actually does | Control / finding | Footprint |
|------------|-----------------------|-------------------|-----------|
| `collect` | Bulk-reads objects, attributes, and group `member` lists over the replication path as an ordinary Domain User, paging on the DirSync cookie for incremental delta runs. Scopes to what the account can already read: it does **not** bypass confidential attributes and does **not** return security descriptors (that path stays empty). | OBJECT_SECURITY DirSync | None in host logs — 0× Event 1644, 0× Event 4662. Caught only by a SACL read canary. |
| `pin` | Writes a value, then inflates that attribute's per-attribute replication **version** so it wins AD conflict resolution (version beats timestamp) against a defender's later correction on another DC. Refuses linked attributes (LVR, unaffected). Needs only WriteProperty on the attribute. | FORCE_UPDATE conflict-win | Not stealthy: writes the value and bumps its version. Persistence/anti-remediation, not privesc. |
| `recon` | Tests whether a specific DN exists at base scope without reading its attributes and without appearing in Event 1644. Base-DN oracle only (AD evaluates the control as 0 under subtree scope). | EXPECTED_ENTRY_COUNT oracle | Invisible to Event 1644 — the control isn't recorded in the 1644 controls field. |

### `blue/` — `AdLdapDefense` (defensive)

A PowerShell module of five exported functions covering four detection/hardening capabilities.
Parameters and sample output are in [blue/README.md](blue/README.md). Requires PowerShell 5.1+ and
RSAT (ActiveDirectory), run from an admin workstation that can reach the DC.

| Function | What it actually does | Catches |
|----------|-----------------------|---------|
| `Invoke-LdapLoggingAudit` | Reports whether Event 1644 is *effective* — it's silently useless when the search thresholds are `0` (disabled), the common misconfig — plus which controls actually land in the 1644 controls field (with `-Probe`) and whether 4662 auditing is on. `-Fix` corrects the threshold trap. | LDAP logging blind spots |
| `Invoke-ReplMetadataHunt` | Baselines each sensitive attribute's replication **Version** plus a value hash, then on later runs flags any object where the version rose while the value did not change. That mismatch is the tamper signature, and it's the reliable catch because FORCE_UPDATE rides a modify and leaves no 1644. | FORCE_UPDATE / DCShadow-class version tampering |
| `Deploy-SaclCanary` / `Test-SaclCanary` | Plants a SACL audit ACE on a high-value object so access raises Event 4662, then self-tests that it fires. A **read** canary is the reliable catch for the OBJECT_SECURITY DirSync collection that is otherwise invisible (matched by objectGUID, not CN). | reads (incl. invisible DirSync) and writes |
| `Get-ReplicationAbuse` | Hunts Event 4662 carrying a Get-Changes replication GUID from a non-DC, non-approved-sync account, and recovers the **source IP** by joining to the matching 4624 logon on LogonId. Flags DirSync (`Get-Changes`) as well as DCSync (`Get-Changes-All`) — rules that watch only Get-Changes-All miss the lower-privileged DirSync path. | DirSync / DCSync Get-Changes abuse |

### Red technique → blue detection

| `red/` does this | `blue/` catches it with |
|------------------|-------------------------|
| `collect` (OBJECT_SECURITY DirSync) | `Deploy-SaclCanary` / `Test-SaclCanary` (read canary) — invisible to logging, so `Get-ReplicationAbuse` and 1644 do *not* see it |
| `pin` (FORCE_UPDATE) | `Invoke-ReplMetadataHunt` (version-up, value-unchanged) |
| `recon` (EXPECTED_ENTRY_COUNT) | *known blind spot* — `Invoke-LdapLoggingAudit` reports it as uncaptured by 1644 rather than detecting it |
| DirSync / DCSync Get-Changes | `Get-ReplicationAbuse` (4662 + source IP) |


## Provenance

Derived from a full audit of the MS-ADTS LDAP extended controls. Background and the detailed
findings/detections live in the companion research:

- Two disclosure writeups: **FORCE_UPDATE replication-conflict win** (anti-remediation) and
  **OBJECT_SECURITY DirSync invisible enumeration** — plus a detection blind-spots survey.
- Each toolkit feature was **fire-and-confirmed** against the lab before shipping.

## License

MIT — see [LICENSE](LICENSE) (fill in the year).
