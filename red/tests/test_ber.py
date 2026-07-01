from ldapctl.ber import tlv, enc_int, sd_flags_control, expected_count_value


def test_tlv_short_form():
    assert tlv(0x02, b"\x05") == b"\x02\x01\x05"


def test_enc_int_pads_high_bit():
    assert enc_int(0x80) == b"\x00\x80"      # positive int needs a leading 0
    assert enc_int(7) == b"\x07"


def test_sd_flags_control_default_0x7():
    oid, crit, val = sd_flags_control()
    assert oid == "1.2.840.113556.1.4.801" and crit is True
    # SEQUENCE { INTEGER 7 }  ->  30 03 02 01 07
    assert val == b"\x30\x03\x02\x01\x07"


def test_expected_count_value_1_1():
    # SEQUENCE { INTEGER 1, INTEGER 1 } -> 30 06 02 01 01 02 01 01
    assert expected_count_value(1, 1) == b"\x30\x06\x02\x01\x01\x02\x01\x01"
