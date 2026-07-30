"""SPF expansion and source classification."""

import ipaddress

from dmarc_service.ingest import spf


class FakeResolver:
    """Minimal stand-in: TXT for SPF records, A/AAAA for hosts."""

    lifetime = 1.0

    def __init__(self, txt=None, addresses=None, mx=None):
        self.txt = txt or {}
        self.addresses = addresses or {}
        self.mx = mx or {}
        self.queries = []

    def resolve(self, name, rtype):
        self.queries.append((name, rtype))
        name = str(name).rstrip(".")
        if rtype == "TXT" and name in self.txt:
            return [type("R", (), {"strings": [self.txt[name].encode()]})()]
        if rtype in ("A", "AAAA"):
            return [type("R", (), {"__str__": lambda s, v=v: v})()
                    for v in self.addresses.get(name, [])
                    if (":" in v) == (rtype == "AAAA")]
        if rtype == "MX" and name in self.mx:
            return [type("R", (), {"exchange": self.mx[name]})()]
        raise LookupError(name)


def test_expands_includes_and_ip_terms():
    resolver = FakeResolver(txt={
        "example.com": "v=spf1 include:_spf.vendor.example ip4:203.0.113.0/24 a -all",
        "_spf.vendor.example": "v=spf1 ip4:198.51.100.0/22 ip6:2001:db8::/32 ~all",
    }, addresses={"example.com": ["192.0.2.10"]})

    networks = spf.expand("example.com", resolver)
    assert ipaddress.ip_network("203.0.113.0/24") in networks
    assert ipaddress.ip_network("198.51.100.0/22") in networks
    assert ipaddress.ip_network("2001:db8::/32") in networks
    assert ipaddress.ip_network("192.0.2.10/32") in networks  # from the "a" term


def test_classification():
    networks = [ipaddress.ip_network("198.51.100.0/24")]
    assert spf.classify(networks, "198.51.100.7", aligned=False) == "authorized"
    assert spf.classify(networks, "203.0.113.9", aligned=True) == "aligned"
    assert spf.classify(networks, "203.0.113.9", aligned=False) == "unknown"
    assert spf.classify(networks, "not-an-ip", aligned=False) == "unknown"


def test_ipv6_and_ipv4_do_not_cross_match():
    networks = [ipaddress.ip_network("2001:db8::/32")]
    assert spf.contains(networks, "2001:db8::1") is True
    assert spf.contains(networks, "203.0.113.1") is False


def test_lookup_budget_stops_recursive_records():
    """A record that includes itself must not spin forever."""
    resolver = FakeResolver(txt={"loop.example": "v=spf1 include:loop2.example -all",
                                 "loop2.example": "v=spf1 include:loop.example -all"})
    spf.expand("loop.example", resolver)
    assert len(resolver.queries) <= spf.MAX_DNS_TERMS + 2


def test_missing_record_yields_nothing():
    assert spf.expand("nothing.example", FakeResolver()) == []
