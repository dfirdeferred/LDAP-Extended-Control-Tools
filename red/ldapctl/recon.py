"""Evasion-aware existence oracle via EXPECTED_ENTRY_COUNT (base scope).

Invisible to Event 1644 (validated: this control is not recorded in the 1644 'Server controls'
field). Read-only. Note: AD evaluates EXPECTED_ENTRY_COUNT as 0 under SUBTREE scope, so it is a
BASE-DN existence oracle only, not a subtree counter.
"""
from __future__ import annotations
from ldap3 import BASE
from .ber import expected_count_value, EXPECTED_COUNT_OID


def exists(conn, dn: str) -> bool:
    """[1,1] base-scope assertion on the DN: success => exactly one (exists);
    constraintViolation(19) or noSuchObject(32) => absent."""
    ctrl = (EXPECTED_COUNT_OID, True, expected_count_value(1, 1))
    ok = conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["1.1"],
                     controls=[ctrl])
    if ok:
        return True
    if conn.result["result"] in (19, 32):   # constraintViolation / noSuchObject
        return False
    raise RuntimeError(f"oracle inconclusive: {conn.result}")
