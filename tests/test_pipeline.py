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


def test_mail_to_a_retired_address_is_still_attributed(db, aggregate_xml):
    """A half-finished rotation must not send reports to quarantine."""
    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    old = control_plane.active_addresses(db, domain)[0]
    control_plane.mint_address(db, domain)
    old.active = False
    db.flush()

    rcpt = f"{old.local_part}@dmarc.reporthost.net"
    raw = process_message(db, build_report_email(aggregate_xml, rcpt), rcpt_to=rcpt)

    assert raw.status == "retired"
    assert "deactivated address" in raw.error
    report = db.scalar(select(AggregateReport))
    assert report.domain_id == domain.id  # attributed, not quarantined


def test_duplicates_are_labelled_not_failed(db, aggregate_xml):
    """A forwarded copy of a report we hold is not a failure."""
    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    rcpt = f"{control_plane.active_addresses(db, domain)[0].local_part}@dmarc.reporthost.net"
    content = build_report_email(aggregate_xml, rcpt)

    assert process_message(db, content, rcpt_to=rcpt).status == "routed"
    second = process_message(db, content, rcpt_to=rcpt)
    assert second.status == "duplicate"
    assert len(db.scalars(select(AggregateReport)).all()) == 1


def test_reprocess_recovers_messages_after_a_parser_fix(db, aggregate_xml, monkeypatch):
    from dmarc_service.ingest import parsers, pipeline

    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    rcpt = f"{control_plane.active_addresses(db, domain)[0].local_part}@dmarc.reporthost.net"

    # a parser that cannot read the format yet
    monkeypatch.setattr(parsers, "classify", lambda document: "unknown")
    raw = process_message(db, build_report_email(aggregate_xml, rcpt), rcpt_to=rcpt)
    assert raw.status == "failed"
    assert db.scalar(select(AggregateReport)) is None

    # the parser learns the format, and the kept message is re-run
    monkeypatch.undo()
    counts = pipeline.reprocess(db)
    assert counts["recovered"] == 1
    report = db.scalar(select(AggregateReport))
    assert report is not None and report.domain_id == domain.id


def test_reprocess_is_idempotent(db, aggregate_xml):
    """Running it repeatedly must not duplicate or re-fail anything."""
    from dmarc_service.ingest import pipeline

    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    rcpt = f"{control_plane.active_addresses(db, domain)[0].local_part}@dmarc.reporthost.net"
    process_message(db, build_report_email(aggregate_xml, rcpt), rcpt_to=rcpt)

    first = pipeline.reprocess(db)
    second = pipeline.reprocess(db)
    assert first["recovered"] == 0 and second["recovered"] == 0
    assert len(db.scalars(select(AggregateReport)).all()) == 1
