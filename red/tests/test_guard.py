from ldapctl.ldapconn import LINKED_DENYLIST


def test_member_is_denylisted():
    assert "member" in LINKED_DENYLIST
    assert "memberof" in LINKED_DENYLIST
    assert "description" not in LINKED_DENYLIST
