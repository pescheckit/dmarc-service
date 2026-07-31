from dmarc_service.control_plane import service as control_plane


def test_org_domain():
    assert control_plane.org_domain("dmarc.example.com") == "example.com"
    assert control_plane.org_domain("example.com") == "example.com"
    assert control_plane.org_domain("foo.bar.example.co.uk") == "example.co.uk"


def test_mint_local_part_is_unguessable():
    parts = {control_plane.mint_local_part() for _ in range(100)}
    assert len(parts) == 100
    for part in parts:
        assert len(part) >= 8
        assert "+" not in part


def test_domain_gets_address_and_dns(db):
    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "Example.COM.")

    assert domain.name == "example.com"
    addresses = control_plane.active_addresses(db, domain)
    assert len(addresses) == 1

    records = control_plane.required_dns_records(db, domain)
    by_name = {r.name: r for r in records}
    dmarc = by_name["_dmarc.example.com"]
    assert f"mailto:{addresses[0].local_part}@dmarc.reporthost.net" in dmarc.content
    tls = by_name["_smtp._tls.example.com"]
    assert "https://dmarc.reporthost.net/tlsrpt" in tls.content

    # example.com vs reports.example -> different org domains -> EDV required
    edv = by_name["example.com._report._dmarc.dmarc.reporthost.net"]
    assert edv.content == "v=DMARC1"
    assert edv.published_by == "operator"
    assert edv.zone == "reporthost.net"


def test_no_edv_for_same_org_domain(db, monkeypatch):
    from dmarc_service.config import get_settings

    monkeypatch.setenv("REPORT_HOST", "dmarc.example.com")
    get_settings.cache_clear()

    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    records = control_plane.required_dns_records(db, domain)
    assert not [r for r in records if "_report._dmarc" in r.name]


def test_rotation_keeps_two_active(db):
    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    first = control_plane.active_addresses(db, domain)[0]

    second = control_plane.mint_address(db, domain)
    active = control_plane.active_addresses(db, domain)
    assert {a.local_part for a in active} == {first.local_part, second.local_part}

    # both appear in the advised DNS record during the rollover window
    records = control_plane.required_dns_records(db, domain)
    dmarc = next(r for r in records if r.name.startswith("_dmarc."))
    assert first.local_part in dmarc.content and second.local_part in dmarc.content


def test_check_dns_flags_malformed(db, monkeypatch):
    from dmarc_service.control_plane import service as cp

    tenant = cp.create_tenant(db, "acme", "Acme")
    domain = cp.add_domain(db, tenant, "example.com")
    records = cp.required_dns_records(db, domain)

    # our address is present but the value has a stray leading quote, so
    # receivers would skip it: that must NOT read as "published"
    address = cp.active_addresses(db, domain)[0].local_part
    monkeypatch.setattr(
        cp, "_resolve_txt",
        lambda name: [f'"v=DMARC1; p=none; rua=mailto:{address}@dmarc.reporthost.net"'],
    )
    cp.clear_dns_cache()
    statuses = {r["name"]: r["status"] for r in cp.check_dns_records(records)}
    assert statuses["_dmarc.example.com"] == "malformed"


def test_recheck_is_rate_limited(db, monkeypatch):
    from dmarc_service.control_plane import service as cp

    cp.clear_dns_cache()
    monkeypatch.setattr(cp, "_resolve_txt", lambda name: ["v=DMARC1"])
    cp.check_dns_records(
        [cp.DnsRecord(zone="z", name="_dmarc.example.com", type="TXT", content="c",
                      published_by="tenant", must_contain="v=DMARC1")]
    )
    assert cp.force_dns_recheck(["_dmarc.example.com"]) is False  # too soon
    cp.clear_dns_cache()
    assert cp.force_dns_recheck(["_dmarc.example.com"]) is True   # nothing cached


def test_dns_naming_a_retired_address_is_not_published(db, monkeypatch):
    """Rotating in the UI without updating DNS must not read as healthy."""
    from dmarc_service.control_plane import service as cp

    tenant = cp.create_tenant(db, "acme", "Acme")
    domain = cp.add_domain(db, tenant, "example.com")
    old = cp.active_addresses(db, domain)[0].local_part
    new = cp.mint_address(db, domain).local_part
    for address in domain.addresses:
        if address.local_part == old:
            address.active = False
    db.flush()

    # DNS still names the retired address
    monkeypatch.setattr(
        cp, "_resolve_txt",
        lambda name: [f"v=DMARC1; p=none; rua=mailto:{old}@dmarc.reporthost.net"],
    )
    cp.clear_dns_cache()
    statuses = {r["name"]: r["status"] for r in
                cp.check_dns_records(cp.required_dns_records(db, domain))}
    assert statuses["_dmarc.example.com"] == "retired"

    # once DNS names the current address it is healthy again
    monkeypatch.setattr(
        cp, "_resolve_txt",
        lambda name: [f"v=DMARC1; p=none; rua=mailto:{new}@dmarc.reporthost.net"],
    )
    cp.clear_dns_cache()
    statuses = {r["name"]: r["status"] for r in
                cp.check_dns_records(cp.required_dns_records(db, domain))}
    assert statuses["_dmarc.example.com"] == "ok"


def test_a_single_mailbox_becomes_the_published_address(db):
    """A polled mailbox that is not a catch-all can only receive its own
    address, so every domain must publish that instead of a minted one."""
    from dmarc_service.control_plane import service as cp
    from dmarc_service.db.models import ImapAccount

    tenant = cp.create_tenant(db, "acme", "Acme")
    domain = cp.add_domain(db, tenant, "example.com")
    minted = cp.active_addresses(db, domain)[0].local_part

    records = {r.name: r.content for r in cp.required_dns_records(db, domain)}
    assert minted in records["_dmarc.example.com"]  # per-domain address by default

    db.add(ImapAccount(host="imap.example.net", port=993, use_ssl=True,
                       username="dmarc@company.example", password_encrypted="x",
                       folder="INBOX", processed_folder="", catch_all=False,
                       enabled=True))
    db.flush()

    records = {r.name: r.content for r in cp.required_dns_records(db, domain)}
    assert "mailto:dmarc@company.example" in records["_dmarc.example.com"]
    assert minted not in records["_dmarc.example.com"]
    assert "mailto:dmarc@company.example" in records["_smtp._tls.example.com"]
