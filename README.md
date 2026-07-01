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

## Provenance

Derived from a full audit of the MS-ADTS LDAP extended controls. Background and the detailed
findings/detections live in the companion research:

- Two disclosure writeups: **FORCE_UPDATE replication-conflict win** (anti-remediation) and
  **OBJECT_SECURITY DirSync invisible enumeration** — plus a detection blind-spots survey.
- Each toolkit feature was **fire-and-confirmed** against the lab before shipping.

## License

MIT — see [LICENSE](LICENSE) (fill in the year).
