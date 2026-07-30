"""Message processing: raw MIME in, parsed rows out.

Routing key is the recipient local part. A message addressed to an active
report address lands in that address's tenant/domain; anything else is kept
in the "unrouted" quarantine tenant rather than bounced or dropped — a typo'd
DNS record or a mid-rotation address should never silently lose data.
"""

import logging
from email import message_from_bytes
from email.message import Message

from sqlalchemy import select
from sqlalchemy.orm import Session

from dmarc_service.control_plane.service import resolve_address
from dmarc_service.db.models import (
    UNROUTED_TENANT_SLUG,
    AggregateRecord,
    AggregateReport,
    Domain,
    RawMessage,
    Tenant,
    TlsReport,
)
from dmarc_service.ingest import parsers

logger = logging.getLogger(__name__)


def process_message(
    session: Session,
    content: bytes,
    *,
    source_ip: str = "",
    mail_from: str = "",
    rcpt_to: str = "",
) -> RawMessage:
    raw = RawMessage(
        source_ip=source_ip,
        mail_from=mail_from,
        rcpt_to=rcpt_to,
        size=len(content),
        content=content,
    )
    session.add(raw)
    session.flush()

    local_part = rcpt_to.split("@", 1)[0].lower() if rcpt_to else ""
    address = resolve_address(session, local_part) if local_part else None

    if address is not None:
        tenant_id = address.domain.tenant_id
        domain_id = address.domain_id
        raw.status = "routed"
    else:
        unrouted = session.scalar(select(Tenant).where(Tenant.slug == UNROUTED_TENANT_SLUG))
        tenant_id = unrouted.id if unrouted else None
        domain_id = None
        raw.status = "unrouted"

    message = message_from_bytes(content)
    try:
        stored = _store_reports(session, message, raw, tenant_id, domain_id)
        if stored == 0 and raw.status == "routed":
            raw.status = "failed"
            raw.error = "no parsable report documents found"
    except Exception as exc:
        logger.exception("failed to process message %s", raw.id)
        raw.status = "failed"
        raw.error = str(exc)[:2000]

    session.flush()
    return raw


def _store_reports(
    session: Session,
    message: Message,
    raw: RawMessage,
    tenant_id: int | None,
    domain_id: int | None,
) -> int:
    stored = 0
    for document in parsers.extract_report_payloads(message):
        kind = parsers.classify(document)
        if kind == "aggregate" and _store_aggregate(
            session, parsers.parse_aggregate_xml(document), raw, tenant_id, domain_id
        ):
            stored += 1
        elif kind == "tlsrpt" and _store_tlsrpt(
            session, parsers.parse_tlsrpt_json(document), raw, tenant_id, domain_id
        ):
            stored += 1
    return stored


def _store_aggregate(
    session: Session,
    parsed: parsers.ParsedAggregateReport,
    raw: RawMessage,
    tenant_id: int | None,
    domain_id: int | None,
) -> bool:
    duplicate = session.scalar(
        select(AggregateReport).where(
            AggregateReport.org_name == parsed.org_name,
            AggregateReport.report_id == parsed.report_id,
            AggregateReport.policy_domain == parsed.policy_domain,
        )
    )
    if duplicate:
        logger.info("duplicate aggregate report %s/%s", parsed.org_name, parsed.report_id)
        return False

    # If routing didn't pin a domain (unrouted), still try to attach by the
    # published policy domain so quarantined data stays queryable.
    if domain_id is None and parsed.policy_domain:
        domain = session.scalar(select(Domain).where(Domain.name == parsed.policy_domain))
        if domain is not None:
            domain_id = domain.id

    report = AggregateReport(
        tenant_id=tenant_id,
        domain_id=domain_id,
        raw_message_id=raw.id,
        org_name=parsed.org_name,
        org_email=parsed.org_email,
        report_id=parsed.report_id,
        date_begin=parsed.date_begin,
        date_end=parsed.date_end,
        policy_domain=parsed.policy_domain,
        policy_adkim=parsed.policy_adkim,
        policy_aspf=parsed.policy_aspf,
        policy_p=parsed.policy_p,
        policy_sp=parsed.policy_sp,
        policy_pct=parsed.policy_pct,
    )
    report.records = [
        AggregateRecord(
            source_ip=r.source_ip,
            count=r.count,
            disposition=r.disposition,
            dkim_result=r.dkim_result,
            spf_result=r.spf_result,
            header_from=r.header_from,
            envelope_from=r.envelope_from,
            auth_dkim_domain=r.auth_dkim_domain,
            auth_dkim_result=r.auth_dkim_result,
            auth_spf_domain=r.auth_spf_domain,
            auth_spf_result=r.auth_spf_result,
        )
        for r in parsed.records
    ]
    session.add(report)
    return True


def _store_tlsrpt(
    session: Session,
    parsed: parsers.ParsedTlsReport,
    raw: RawMessage | None,
    tenant_id: int | None,
    domain_id: int | None,
    source: str = "smtp",
) -> bool:
    duplicate = session.scalar(
        select(TlsReport).where(
            TlsReport.organization_name == parsed.organization_name,
            TlsReport.report_id == parsed.report_id,
        )
    )
    if duplicate:
        return False

    if domain_id is None and parsed.policy_domains:
        domain = session.scalar(select(Domain).where(Domain.name == parsed.policy_domains[0]))
        if domain is not None:
            domain_id = domain.id
            if tenant_id is None:
                tenant_id = domain.tenant_id

    session.add(
        TlsReport(
            tenant_id=tenant_id,
            domain_id=domain_id,
            raw_message_id=raw.id if raw else None,
            organization_name=parsed.organization_name,
            report_id=parsed.report_id,
            date_begin=parsed.date_begin,
            date_end=parsed.date_end,
            contact_info=parsed.contact_info,
            body=parsed.body,
            source=source,
        )
    )
    return True


def process_tlsrpt_http(session: Session, document: bytes) -> bool:
    """TLS-RPT delivered via the https rua endpoint (no MIME envelope)."""
    parsed = parsers.parse_tlsrpt_json(document)
    return _store_tlsrpt(session, parsed, None, None, None, source="https")
