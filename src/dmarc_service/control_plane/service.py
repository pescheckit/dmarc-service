"""Tenant/domain provisioning: mints report addresses and computes the DNS
records a tenant must publish (including external destination verification)."""

import secrets
from dataclasses import dataclass

import tldextract
from sqlalchemy import select
from sqlalchemy.orm import Session

from dmarc_service.config import get_settings
from dmarc_service.db.models import UNROUTED_TENANT_SLUG, Domain, ReportAddress, Tenant

# Offline extract: use the snapshot bundled with tldextract, never the network.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def org_domain(hostname: str) -> str:
    ext = _extract(hostname)
    return ext.top_domain_under_public_suffix or hostname


def mint_local_part() -> str:
    # 12 hex chars, unguessable, no dictionary words, no '+' addressing.
    # The address is a bearer token: knowing it lets you inject reports.
    return secrets.token_hex(6)


def bootstrap(session: Session) -> None:
    """Ensure built-in tenants exist. Idempotent, runs at startup."""
    settings = get_settings()
    if not session.scalar(select(Tenant).where(Tenant.slug == UNROUTED_TENANT_SLUG)):
        session.add(Tenant(slug=UNROUTED_TENANT_SLUG, name="Unrouted quarantine"))
    if settings.tenancy_mode == "single" and not session.scalar(
        select(Tenant).where(Tenant.slug == settings.default_tenant)
    ):
        session.add(Tenant(slug=settings.default_tenant, name=settings.default_tenant))
    session.flush()


def create_tenant(session: Session, slug: str, name: str) -> Tenant:
    tenant = Tenant(slug=slug, name=name)
    session.add(tenant)
    session.flush()
    return tenant


def add_domain(session: Session, tenant: Tenant, name: str) -> Domain:
    domain = Domain(tenant_id=tenant.id, name=name.lower().strip("."))
    session.add(domain)
    session.flush()
    mint_address(session, domain)
    return domain


def mint_address(session: Session, domain: Domain) -> ReportAddress:
    """Add a new active address. During rotation a domain briefly has two
    active addresses so reports keep flowing while DNS caches expire."""
    address = ReportAddress(domain_id=domain.id, local_part=mint_local_part(), active=True)
    session.add(address)
    session.flush()
    return address


def active_addresses(session: Session, domain: Domain) -> list[ReportAddress]:
    return list(
        session.scalars(
            select(ReportAddress)
            .where(ReportAddress.domain_id == domain.id, ReportAddress.active.is_(True))
            .order_by(ReportAddress.created_at)
        )
    )


def resolve_address(session: Session, local_part: str) -> ReportAddress | None:
    return session.scalar(
        select(ReportAddress).where(
            ReportAddress.local_part == local_part, ReportAddress.active.is_(True)
        )
    )


def delete_domain(session: Session, domain: Domain) -> None:
    """Remove a domain and its addresses. Historical reports are kept but
    unlinked, so past data stays queryable per tenant."""
    from dmarc_service.db.models import AggregateReport, TlsReport

    for report in session.scalars(
        select(AggregateReport).where(AggregateReport.domain_id == domain.id)
    ):
        report.domain_id = None
    for report in session.scalars(select(TlsReport).where(TlsReport.domain_id == domain.id)):
        report.domain_id = None
    for address in list(domain.addresses):
        session.delete(address)
    session.delete(domain)


def delete_tenant(session: Session, tenant: Tenant) -> bool:
    """Only empty tenants can be deleted; returns False otherwise."""
    if tenant.domains:
        return False
    session.delete(tenant)
    return True


@dataclass
class DnsRecord:
    zone: str  # which DNS zone the record belongs in
    name: str  # fully qualified record name
    type: str
    content: str
    # tenant: published by the domain owner; operator: published by whoever
    # runs this service (matters when they are different parties)
    published_by: str
    # substring whose presence in a live TXT answer counts as "published"
    # (records may legitimately carry extra rua entries during migrations)
    must_contain: str = ""
    # every valid record of this kind starts with this version tag; a live
    # answer that lacks it is malformed and receivers will ignore it
    must_start_with: str = ""


def required_dns_records(session: Session, domain: Domain) -> list[DnsRecord]:
    settings = get_settings()
    report_host = settings.report_host
    addresses = active_addresses(session, domain)
    mailtos = ",".join(f"mailto:{a.local_part}@{report_host}" for a in addresses)

    any_mailto = f"@{report_host}"
    records = [
        DnsRecord(
            zone=domain.name,
            name=f"_dmarc.{domain.name}",
            type="TXT",
            content=f"v=DMARC1; p=none; rua={mailtos}",
            published_by="tenant",
            must_contain=any_mailto,
            must_start_with="v=DMARC1",
        ),
        DnsRecord(
            zone=domain.name,
            name=f"_smtp._tls.{domain.name}",
            type="TXT",
            content=f"v=TLSRPTv1; rua={settings.external_url}/tlsrpt,{mailtos}",
            published_by="tenant",
            must_contain=any_mailto,
            must_start_with="v=TLSRPTv1",
        ),
    ]

    # RFC 7489 section 7.1: when the report address lives outside the monitored
    # domain's organizational domain, the report host must publish a
    # verification record. Receiver implementations differ on org-vs-exact
    # comparison, so we always emit it when the org domains differ.
    if org_domain(domain.name) != org_domain(report_host):
        records.append(
            DnsRecord(
                zone=org_domain(report_host),
                name=f"{domain.name}._report._dmarc.{report_host}",
                type="TXT",
                content="v=DMARC1",
                published_by="operator",
                must_contain="v=DMARC1",
                must_start_with="v=DMARC1",
            )
        )
    return records


# --- live DNS verification ---

# Passive page loads serve cached lookups; the "re-check" button forces a
# fresh lookup but no more than once per minute, so resolvers stay happy.
DNS_CACHE_TTL = 900.0
DNS_RECHECK_INTERVAL = 60.0
_dns_cache: dict[str, tuple[float, list[str] | None]] = {}


def clear_dns_cache() -> None:
    _dns_cache.clear()


def dns_checked_age(names: list[str]) -> float | None:
    """Seconds since the oldest cached lookup among names; None if uncached."""
    import time

    ages = [time.monotonic() - _dns_cache[n][0] for n in names if n in _dns_cache]
    return max(ages) if len(ages) == len(names) else None


def force_dns_recheck(names: list[str]) -> bool:
    """Drop cache entries so the next render re-resolves. Refused (False)
    when the last check is younger than DNS_RECHECK_INTERVAL."""
    age = dns_checked_age(names)
    if age is not None and age < DNS_RECHECK_INTERVAL:
        return False
    for name in names:
        _dns_cache.pop(name, None)
    return True


def _resolve_txt_cached(name: str) -> list[str] | None:
    import time

    hit = _dns_cache.get(name)
    if hit and time.monotonic() - hit[0] < DNS_CACHE_TTL:
        return hit[1]
    answers = _resolve_txt(name)
    _dns_cache[name] = (time.monotonic(), answers)
    return answers


def _authoritative_nameservers(zone: str) -> list[str]:
    """IPs of the zone's authoritative nameservers, via public resolvers."""
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = 3.0

    ips: list[str] = []
    for ns in resolver.resolve(zone, "NS"):
        host = str(ns.target).rstrip(".")
        try:
            ips.extend(str(a) for a in resolver.resolve(host, "A"))
        except Exception:  # noqa: BLE001 - skip a nameserver we cannot reach
            continue
    return ips


def _resolve_txt(name: str) -> list[str] | None:
    """Returns TXT answers, [] when the name exists without TXT data, or
    None when resolution failed (treat as unknown, not missing).

    Queries the zone's authoritative nameservers directly: a recursive
    resolver would serve stale positive *and* negative answers for up to the
    record's TTL, which makes a "live check" lie right after a DNS edit.
    """
    import dns.resolver

    try:
        nameservers = _authoritative_nameservers(org_domain(name))
    except Exception:  # noqa: BLE001 - fall back to public resolvers
        nameservers = []

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = 4.0

    try:
        answers = resolver.resolve(name, "TXT")
        return ["".join(s.decode() for s in r.strings) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:  # noqa: BLE001 - timeout/servfail: unknown, not missing
        return None


def check_dns_records(records: list[DnsRecord]) -> list[dict]:
    """Verify each expected record against live DNS.

    Status per record: ok (published), missing (nothing there), mismatch
    (TXT exists but doesn't contain ours - e.g. stale record), unknown
    (lookup failed).
    """
    results = []
    for record in records:
        answers = _resolve_txt_cached(record.name)
        if answers is None:
            status = "unknown"
        elif not answers:
            status = "missing"
        elif any(record.must_contain in answer for answer in answers):
            # ours is there; flag it when the live value is malformed anyway
            # (a stray leading quote or prefix makes receivers skip it)
            matching = [a for a in answers if record.must_contain in a]
            if record.must_start_with and not any(
                a.strip().startswith(record.must_start_with) for a in matching
            ):
                status = "malformed"
            else:
                status = "ok"
        else:
            status = "mismatch"
        results.append(
            {
                "zone": record.zone,
                "name": record.name,
                "type": record.type,
                "content": record.content,
                "published_by": record.published_by,
                "status": status,
                "found": answers or [],
            }
        )
    return results
