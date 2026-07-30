import gzip
from email import policy
from email.message import EmailMessage

from sqlalchemy import select

from dmarc_service.control_plane import service as control_plane
from dmarc_service.db.models import AggregateReport, RawMessage
from dmarc_service.ingest.pipeline import process_message


def build_report_email(aggregate_xml: bytes, rcpt: str) -> bytes:
    message = EmailMessage()
    message["From"] = "noreply-dmarc-support@google.com"
    message["To"] = rcpt
    message["Subject"] = "Report domain: example.com Submitter: google.com"
    message.set_content("This is an aggregate report from google.com")
    message.add_attachment(
        gzip.compress(aggregate_xml),
        maintype="application",
        subtype="gzip",
        filename="google.com!example.com!1753142400!1753228799.xml.gz",
    )
    # CRLF line endings, like a real SMTP client on the wire
    return message.as_bytes(policy=policy.SMTP)


def test_routed_message_stores_report(db, aggregate_xml):
    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    address = control_plane.active_addresses(db, domain)[0]
    rcpt = f"{address.local_part}@dmarc.reporthost.net"

    raw = process_message(
        db,
        build_report_email(aggregate_xml, rcpt),
        source_ip="209.85.220.41",
        mail_from="noreply-dmarc-support@google.com",
        rcpt_to=rcpt,
    )

    assert raw.status == "routed"
    report = db.scalar(select(AggregateReport))
    assert report is not None
    assert report.tenant_id == tenant.id
    assert report.domain_id == domain.id
    assert len(report.records) == 2


def test_unknown_rcpt_is_quarantined_not_dropped(db, aggregate_xml):
    raw = process_message(
        db,
        build_report_email(aggregate_xml, "nosuchaddress@dmarc.reporthost.net"),
        rcpt_to="nosuchaddress@dmarc.reporthost.net",
    )
    assert raw.status == "unrouted"
    # the report is still parsed and stored, attached to the quarantine tenant
    report = db.scalar(select(AggregateReport))
    assert report is not None
    assert db.scalar(select(RawMessage)).content  # original kept verbatim


def test_duplicate_reports_are_ignored(db, aggregate_xml):
    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    address = control_plane.active_addresses(db, domain)[0]
    rcpt = f"{address.local_part}@dmarc.reporthost.net"
    content = build_report_email(aggregate_xml, rcpt)

    process_message(db, content, rcpt_to=rcpt)
    process_message(db, content, rcpt_to=rcpt)

    reports = db.scalars(select(AggregateReport)).all()
    assert len(reports) == 1


def test_garbage_message_is_kept_as_failed(db):
    raw = process_message(db, b"not a mime report at all", rcpt_to="")
    assert raw.status in {"unrouted", "failed"}
    assert db.scalar(select(RawMessage)) is not None
