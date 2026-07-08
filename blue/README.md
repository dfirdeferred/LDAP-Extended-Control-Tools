# AdLdapDefense — blue-team PowerShell module

Detection and hardening for the LDAP-extended-control abuses in the companion `red/` tool. Five
functions, each derived from a validated finding.

| Function | What it does | Detects |
|----------|--------------|---------|
| `Invoke-LdapLoggingAudit` | audit what a DC *actually* logs (and optionally fix Event 1644) | logging blind spots |
| `Invoke-ReplMetadataHunt` | hunt version-up-with-no-value-change | FORCE_UPDATE / DCShadow |
| `Deploy-SaclCanary` / `Test-SaclCanary` | deploy audit-ACE canaries and verify they fire | reads (incl. OBJECT_SECURITY DirSync) + writes |
| `Get-ReplicationAbuse` | 4662 Get-Changes from non-DC/non-sync accounts, with source IP | DirSync / DCSync |

## Install

```powershell
Import-Module .\AdLdapDefense.psd1 -DisableNameChecking
```
Requires PowerShell 5.1+ and the **ActiveDirectory** module (RSAT). Run from an **elevated** admin
workstation that can reach the DC (functions use `Invoke-Command`/`Get-WinEvent -ComputerName`, and
the SACL-canary functions need `SeSecurityPrivilege`). `-DisableNameChecking` suppresses the
harmless "unapproved verb" warning from `Deploy-SaclCanary`.

## How to run

```powershell
cd blue
.\Import-AdLdapDefense.ps1                       # loads the module and lists the 5 functions
```

Then call any function, e.g.:

```powershell
Invoke-LdapLoggingAudit -Dc dc01.cloud.lab                                   # what the DC actually logs
Deploy-SaclCanary -Target 'CN=AdminSDHolder,CN=System,DC=cloud,DC=lab' -Audit All
Test-SaclCanary   -Target 'CN=AdminSDHolder,CN=System,DC=cloud,DC=lab' -Dc dc01.cloud.lab -Audit Read
Get-ReplicationAbuse -Dc dc01.cloud.lab -Since (Get-Date).AddHours(-6)
```

State-changing functions (`Invoke-LdapLoggingAudit -Fix`, `Deploy-SaclCanary`, `Test-SaclCanary`)
support `-WhatIf`. See each function's section below for full parameters.

---

## `Invoke-LdapLoggingAudit`

Reports the DC's real LDAP logging coverage: whether Event 1644 is *effective* (it is silently
useless when the thresholds are `0` = disabled), which controls actually appear in the 1644 "Server
controls" field (with `-Probe`), whether Event 4662 auditing is on, and the known blind spots.

**Account / privilege:** **local admin / Domain Admin on the DC** (reads NTDS registry; `-Fix`
writes it; reads the Security log).

| Parameter | Meaning |
|-----------|---------|
| `-Dc` | target DC *(required)* |
| `-Probe` | fire benign control searches and report which are captured |
| `-Fix` | set `15 Field Engineering`=5 and all three thresholds=1 (log every search) |

```powershell
Invoke-LdapLoggingAudit -Dc dc01.cloud.lab -Probe
Invoke-LdapLoggingAudit -Dc dc01.cloud.lab -Fix        # corrects the thresholds=0 trap
```
Returns a report object (`Event1644Effective`, `ThresholdTrap`, `ControlsCaptured`,
`Event4662Auditing`, `BlindSpots`). **Changes state only with `-Fix`** (registry; supports `-WhatIf`).

---

## `Invoke-ReplMetadataHunt`

Baselines per-attribute replication **Version** + value hash for sensitive attributes; on later runs
alerts on **version increased while value unchanged** (the FORCE_UPDATE / DCShadow signature).
FORCE_UPDATE leaves no Event 1644, so this metadata hunt is the reliable detection.

**Account / privilege:** an account that can **read the attributes and their replication metadata**
(Domain Admin, or delegated read of `msDS-replAttributeMetaData`).

| Parameter | Meaning | Default |
|-----------|---------|---------|
| `-Server` | DC to read from *(required)* | |
| `-SearchBase` | base DN to scan | domain root |
| `-Attributes` | sensitive attributes to watch | description, scriptPath, SPN, gPLink, RBCD attr |
| `-BaselinePath` | baseline JSON (seed on first run, diff after) *(required)* | |

```powershell
# first run seeds the baseline
Invoke-ReplMetadataHunt -Server dc01.cloud.lab -SearchBase 'OU=Tier0,DC=cloud,DC=lab' -BaselinePath .\t0.json
# later runs emit anomalies (schedule this)
Invoke-ReplMetadataHunt -Server dc01.cloud.lab -SearchBase 'OU=Tier0,DC=cloud,DC=lab' -BaselinePath .\t0.json
```
Read-only (rewrites the baseline file each run).

---

## `Deploy-SaclCanary` / `Test-SaclCanary`

Deploys a SACL audit-ACE "canary" on a high-value object so access raises **Event 4662** — and
self-tests that it fires. **Both write and read canaries fire (validated), and a read canary also
catches OBJECT_SECURITY DirSync collection** (which is otherwise invisible). This is the reliable
catch for the stealthy DirSync read.

**Account / privilege:** **admin with SeSecurityPrivilege** (to edit SACLs); "Audit Directory
Service Access" (Success) enabled; reads the Security log.

| `Deploy-SaclCanary` | Meaning | Default |
|----------|---------|---------|
| `-Target` | object DN to canary *(required)* | |
| `-Audit` | `Read`, `Write`, or `All` | `Write` |
| `-Principal` | audited principal (SID/name) | Everyone |

| `Test-SaclCanary` | Meaning | Default |
|----------|---------|---------|
| `-Target` | object DN *(required)* | |
| `-Dc` | DC whose Security log to check | discovered |
| `-Audit` | `Read` or `Write` (which access to trigger) | `Write` |
| `-Remove` | revoke the canary for `-Principal` | off |

```powershell
Deploy-SaclCanary -Target 'CN=AdminSDHolder,CN=System,DC=cloud,DC=lab' -Audit All
Test-SaclCanary   -Target 'CN=AdminSDHolder,CN=System,DC=cloud,DC=lab' -Dc dc01.cloud.lab -Audit Read
# -> Fired4662 : True   (a read canary also catches OBJECT_SECURITY DirSync)
Test-SaclCanary   -Target 'CN=AdminSDHolder,CN=System,DC=cloud,DC=lab' -Dc dc01.cloud.lab -Remove
```
**Changes state:** `Deploy-SaclCanary` adds a SACL ACE; `Test-SaclCanary -Remove` reverts it. Both
support `-WhatIf`.

---

## `Get-ReplicationAbuse`

Hunts **Event 4662** carrying a Get-Changes replication GUID from a **non-DC, non-approved-sync**
account (catches DirSync's `Get-Changes` *and* DCSync's `Get-Changes-All` — DCSync-only rules miss
DirSync). Recovers the **source IP** by joining to the 4624 logon on LogonId.

**Account / privilege:** read the DC **Security log** (admin / Event Log Readers).

| Parameter | Meaning | Default |
|-----------|---------|---------|
| `-Dc` | DC whose Security log to read *(required)* | |
| `-Since` | look-back start | 24h ago |
| `-ApprovedSyncAccounts` | allowlisted sync accounts (wildcards) | `MSOL_*` |
| `-IncludeDCSyncOnly` | only flag Get-Changes-All (classic DCSync) | off |

```powershell
Get-ReplicationAbuse -Dc dc01.cloud.lab -Since (Get-Date).AddHours(-6) `
    -ApprovedSyncAccounts 'MSOL_*','svc-aadconnect'
# -> Time / Account / SourceIp / Kind(DirSync|DCSync) / Guids / Object
```
Read-only.
