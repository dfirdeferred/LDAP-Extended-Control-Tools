"""Bind helpers and the linked-attribute guard."""
from __future__ import annotations
from ldap3 import Server, Connection, NTLM, SIMPLE, ALL

# Common linked attributes (Linked-Value Replication). FORCE_UPDATE version inflation does NOT
# work on these (validated). This is only a FALLBACK for when the schema linkID can't be read;
# `is_linked_attribute` prefers the authoritative schema linkID check.
LINKED_DENYLIST = {
    "member", "memberof", "manager", "directreports",
    "managedby", "managedobjects",
}


def connect(dc: str, user: str, password: str, auth: str = "ntlm", port: int = 389) -> Connection:
    """Bind to a DC (NTLM signed, or simple) and return the connection. Raises on failure."""
    server = Server(dc, port=port, get_info=ALL)
    authentication = NTLM if auth == "ntlm" else SIMPLE
    conn = Connection(server, user=user, password=password, authentication=authentication)
    if not conn.bind():
        raise RuntimeError(f"bind failed as {user}: {conn.result}")
    return conn


def root_dn(conn) -> str:
    """defaultNamingContext (the domain root DN) from rootDSE."""
    return conn.server.info.other["defaultNamingContext"][0]


def is_linked_attribute(conn, attr: str) -> bool:
    """True if the attribute has a schema linkID (forward or back link), i.e. uses LVR.

    Prefers the authoritative schema lookup; falls back to the static denylist if the schema
    entry can't be read.
    """
    try:
        schema_nc = conn.server.info.other["schemaNamingContext"][0]
        conn.search(schema_nc, f"(lDAPDisplayName={attr})", attributes=["linkID"])
        if conn.entries:
            link = conn.entries[0].linkID.value
            if link not in (None, "", 0):
                return True
            return attr.lower() in LINKED_DENYLIST
    except Exception:
        pass
    return attr.lower() in LINKED_DENYLIST
