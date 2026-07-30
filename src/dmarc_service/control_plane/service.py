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


@dataclass
class DnsRecord:
    zone: str  # which DNS zone the record belongs in
    name: str  # fully qualified record name
    type: str
    content: str
    # tenant: published by the domain owner; operator: published by whoever
    # runs this service (matters when they are different parties)
    published_by: str


def required_dns_records(session: Session, domain: Domain) -> list[DnsRecord]:
    settings = get_settings()
    report_host = settings.report_host
    addresses = active_addresses(session, domain)
    mailtos = ",".join(f"mailto:{a.local_part}@{report_host}" for a in addresses)

    records = [
        DnsRecord(
            zone=domain.name,
            name=f"_dmarc.{domain.name}",
            type="TXT",
            content=f"v=DMARC1; p=none; rua={mailtos}",
            published_by="tenant",
        ),
        DnsRecord(
            zone=domain.name,
            name=f"_smtp._tls.{domain.name}",
            type="TXT",
            content=f"v=TLSRPTv1; rua={settings.external_url}/tlsrpt,{mailtos}",
            published_by="tenant",
        ),
    ]

    # RFC 7489 §7.1: when the report address lives outside the monitored
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
            )
        )
    return records
