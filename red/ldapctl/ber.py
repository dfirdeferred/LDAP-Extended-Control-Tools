"""Minimal BER encoders for the LDAP control values this tool sends."""
from __future__ import annotations

SD_FLAGS_OID = "1.2.840.113556.1.4.801"
EXPECTED_COUNT_OID = "1.2.840.113556.1.4.2211"


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def enc_int(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    if b[0] & 0x80:
        b.insert(0, 0)
    return bytes(b)


def sd_flags_control(flags: int = 0x7):
    """LDAP_SERVER_SD_FLAGS control tuple for ldap3: (oid, criticality, value)."""
    value = tlv(0x30, tlv(0x02, enc_int(flags)))
    return (SD_FLAGS_OID, True, value)


def expected_count_value(minimum: int, maximum: int) -> bytes:
    """SEQUENCE { minimum INTEGER, maximum INTEGER } for LDAP_SERVER_EXPECTED_ENTRY_COUNT."""
    return tlv(0x30, tlv(0x02, enc_int(minimum)) + tlv(0x02, enc_int(maximum)))
