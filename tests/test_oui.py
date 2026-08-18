"""OUI vendor lookup."""

from netpulse.oui import OUI_VENDORS, lookup_vendor


def test_known_prefix():
    assert lookup_vendor("00:00:0C:11:22:33") == "Cisco"
    assert lookup_vendor("00:00:9F:aa:bb:cc") == "Apple"


def test_lookup_is_case_insensitive():
    assert lookup_vendor("00:00:0c:aa:bb:cc") == lookup_vendor("00:00:0C:AA:BB:CC")
    assert lookup_vendor("00:00:0c:aa:bb:cc") == "Cisco"


def test_unknown_prefix_returns_unknown():
    assert lookup_vendor("de:ad:be:ef:00:00") == "Unknown"


def test_uses_only_first_three_octets():
    # Everything past the 24-bit OUI is ignored.
    a = lookup_vendor("00:00:00:00:00:01")
    b = lookup_vendor("00:00:00:ff:ff:ff")
    assert a == b == "Xerox"


def test_table_is_nonempty_and_well_formed():
    assert len(OUI_VENDORS) > 1000
    for prefix, vendor in OUI_VENDORS.items():
        assert prefix == prefix.upper()          # keys are upper-case
        assert len(prefix) == 8 and prefix.count(":") == 2
        assert vendor                            # no empty vendor names
