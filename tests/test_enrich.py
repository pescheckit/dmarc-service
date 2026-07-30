"""IP owner lookup: caching, entity preference, and graceful failure."""

from dmarc_service.ingest import enrich


def test_rdap_prefers_organisation_over_individual(monkeypatch):
    payload = {
        "name": "UK-MICROSOFT-20060601",
        "entities": [
            {
                "roles": ["administrative"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Some Person"],
                                         ["kind", {}, "text", "individual"]]],
            },
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Limited"],
                                         ["kind", {}, "text", "org"]]],
            },
        ],
    }

    class FakeResponse:
        def raise_for_status(self): pass
        def json(self): return payload

    monkeypatch.setattr(enrich.httpx, "get", lambda *a, **k: FakeResponse())
    netname, org = enrich._rdap("2a01:111:f403:c200::5")
    assert netname == "UK-MICROSOFT-20060601"
    assert org == "Microsoft Limited"


def test_lookup_failures_are_not_fatal(monkeypatch):
    monkeypatch.setattr(enrich, "_ptr", lambda ip: "")
    def boom(*a, **k):
        raise OSError("registry unreachable")
    monkeypatch.setattr(enrich.httpx, "get", boom)
    assert enrich.lookup("192.0.2.1") == {"ip": "192.0.2.1", "ptr": "", "netname": "", "org": ""}


def test_enrich_caches_and_reuses(db, monkeypatch):
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return {"ip": ip, "ptr": f"host.{ip}", "netname": "NET", "org": "Example Org"}

    monkeypatch.setattr(enrich, "lookup", fake_lookup)

    first = enrich.enrich_ips(db, ["203.0.113.5", "203.0.113.5", "198.51.100.9"])
    assert sorted(calls) == ["198.51.100.9", "203.0.113.5"]  # deduplicated
    assert enrich.describe(first["203.0.113.5"]) == "Example Org"

    enrich.enrich_ips(db, ["203.0.113.5"])
    assert len(calls) == 2  # served from the database, not looked up again


def test_describe_falls_back(db, monkeypatch):
    monkeypatch.setattr(
        enrich, "lookup",
        lambda ip: {"ip": ip, "ptr": "mail.example.net", "netname": "NETNAME", "org": ""},
    )
    intel = enrich.enrich_ips(db, ["203.0.113.7"])["203.0.113.7"]
    assert enrich.describe(intel) == "NETNAME"
    assert enrich.describe(None) == ""
