"""Invisible DirSync collector: OBJECT_SECURITY DirSync as a plain domain user.

Bulk-collects objects, attributes, and group memberships that the caller can already read, and
generates **no Event 1644** (replication path, not the search path) and **no Event 4662** (no
Get-Changes right) -- validated. A low-noise collection primitive, not new access: it scopes to
the caller's effective read access and does not bypass the confidential-attribute gate.

Scope note (validated by measurement): OBJECT_SECURITY DirSync returns `nTSecurityDescriptor`
as an EMPTY value -- it does **not** harvest ACLs/security descriptors. A plain user can read SDs,
but only via ordinary searches, which DO log to Event 1644 (when enabled). So ACL collection is
not available through this invisible path; this collector deliberately does not request the SD.

Builds the DirSync request control by hand (ldap3's dir_sync helper does not drive the
OBJECT_SECURITY path reliably).
"""
from __future__ import annotations
from datetime import datetime, timezone
from ldap3 import SUBTREE
from .ber import tlv, enc_int

DIRSYNC_OID = "1.2.840.113556.1.4.841"
FLAG_OBJECT_SECURITY = 0x1
DEFAULT_ATTRS = ["sAMAccountName", "objectSid", "memberOf", "member",
                 "servicePrincipalName", "userAccountControl", "objectClass"]


def _dirsync_control(flags: int, max_bytes: int, cookie: bytes | None):
    """DirSync request control tuple: SEQUENCE { Flags INT, MaxBytes INT, Cookie OCTET STRING }."""
    value = tlv(0x30, tlv(0x02, enc_int(flags)) + tlv(0x02, enc_int(max_bytes))
                + tlv(0x04, cookie or b""))
    return (DIRSYNC_OID, True, value)


def _read_tlv(b: bytes, i: int):
    tag = b[i]; i += 1
    ln = b[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big"); i += n
    return tag, b[i:i + ln], i + ln


def _parse_dirsync_response(conn) -> tuple[bool, bytes | None]:
    """Return (more_results, cookie) from the DirSync response control."""
    ctl = (conn.result or {}).get("controls", {}).get(DIRSYNC_OID)
    if not ctl:
        return False, None
    val = ctl.get("value")
    if isinstance(val, dict):                       # ldap3 parsed it
        return bool(val.get("more_results")), val.get("cookie")
    raw = val if isinstance(val, (bytes, bytearray)) else ctl.get("raw")
    if not raw:
        return False, None
    _, content, _ = _read_tlv(bytes(raw), 0)        # SEQUENCE { moreData INT, len INT, cookie OS }
    _, more_b, j = _read_tlv(content, 0)
    _, _, j = _read_tlv(content, j)
    _, cookie, _ = _read_tlv(content, j)
    return (int.from_bytes(more_b, "big") != 0), bytes(cookie)


def collect(conn, base: str, ldap_filter: str = "(objectClass=*)", attributes=None,
            cookie: bytes | None = None, max_bytes: int = 10 * 1024 * 1024,
            max_pages: int = 100) -> dict:
    """Bulk-collect via OBJECT_SECURITY DirSync, paging on the cookie until complete.

    Returns {"collected_utc", "count", "objects":[{dn, attributes{}}], "cookie"}; feed the cookie
    back in for an incremental (changes-only) re-run.
    """
    attributes = list(attributes or DEFAULT_ATTRS)
    objects, pages = [], 0
    while True:
        controls = [_dirsync_control(FLAG_OBJECT_SECURITY, max_bytes, cookie)]
        conn.search(base, ldap_filter, search_scope=SUBTREE, attributes=attributes,
                    controls=controls)
        for e in (conn.response or []):
            if e.get("type") != "searchResEntry":
                continue
            raw = dict(e.get("raw_attributes") or {})
            attrs = {k: [v.decode(errors="replace") for v in (vals or []) if v is not None]
                     for k, vals in raw.items()}
            objects.append({"dn": e["dn"], "attributes": attrs})
        more, cookie = _parse_dirsync_response(conn)
        pages += 1
        if not more or pages >= max_pages:
            break
    return {"collected_utc": datetime.now(timezone.utc).isoformat(),
            "count": len(objects), "objects": objects, "cookie": cookie}
