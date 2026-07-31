"""IMAP intake: routing, acknowledgement and failure handling."""

import email
from email.message import EmailMessage

from dmarc_service.ingest import imap


class FakeIMAP:
    """Just enough of imaplib to exercise the fetch loop."""

    def __init__(self, messages):
        self.messages = messages          # {number: raw bytes}
        self.flags, self.copied, self.expunged = {}, [], False
        self.logged_out = False

    def select(self, folder): self.folder = folder
    def search(self, charset, criterion):
        return "OK", [b" ".join(self.messages)]
    def fetch(self, number, spec):
        return "OK", [(b"1 (BODY[] {1})", self.messages[number])]
    def store(self, number, command, flags):
        self.flags.setdefault(number, []).append(flags)
    def copy(self, number, folder): self.copied.append((number, folder))
    def expunge(self): self.expunged = True
    def close(self): pass
    def logout(self): self.logged_out = True


def _report_mail(aggregate_xml, to):
    import gzip
    from email import policy

    message = EmailMessage()
    message["From"] = "noreply-dmarc-support@google.com"
    message["Delivered-To"] = to
    message["Subject"] = "Report domain: example.com"
    message.set_content("report attached")
    message.add_attachment(gzip.compress(aggregate_xml), maintype="application",
                           subtype="gzip", filename="r.xml.gz")
    return message.as_bytes(policy=policy.SMTP)


def test_fetch_routes_by_delivered_to(db, settings_env, monkeypatch, aggregate_xml):
    from sqlalchemy import select

    from dmarc_service.config import get_settings
    from dmarc_service.control_plane import service as cp
    from dmarc_service.db.models import AggregateReport
    from dmarc_service.db.session import session_scope

    tenant = cp.create_tenant(db, "acme", "Acme")
    domain = cp.add_domain(db, tenant, "example.com")
    address = cp.active_addresses(db, domain)[0].local_part
    db.commit()

    monkeypatch.setenv("IMAP_HOST", "imap.example.com")
    monkeypatch.setenv("IMAP_PROCESSED_FOLDER", "Processed")
    get_settings.cache_clear()

    fake = FakeIMAP({b"1": _report_mail(aggregate_xml, f"{address}@dmarc.reporthost.net")})
    monkeypatch.setattr(imap, "_connect", lambda settings: fake)

    counts = imap.fetch_once()
    assert counts == {"seen": 1, "stored": 1, "failed": 0}

    with session_scope() as check:
        report = check.scalar(select(AggregateReport))
        assert report is not None and report.domain_id == domain.id

    # acknowledged only after storing, then filed away
    assert fake.flags[b"1"] == ["\\Seen", "\\Deleted"]
    assert fake.copied == [(b"1", "Processed")]
    assert fake.expunged and fake.logged_out


def test_unparsable_mail_is_kept_but_not_filed(db, settings_env, monkeypatch):
    from dmarc_service.config import get_settings

    monkeypatch.setenv("IMAP_HOST", "imap.example.com")
    get_settings.cache_clear()

    fake = FakeIMAP({b"7": b"Subject: not a report\r\n\r\nhello"})
    monkeypatch.setattr(imap, "_connect", lambda settings: fake)

    counts = imap.fetch_once()
    assert counts["failed"] == 1 and counts["stored"] == 0
    # kept in the database and acknowledged, so the mailbox does not refetch it
    # forever; "dmarc-service reprocess" is what retries it
    assert fake.flags[b"7"] == ["\\Seen"]
    assert fake.copied == []


def test_a_crash_leaves_the_message_unread(db, settings_env, monkeypatch):
    from dmarc_service.config import get_settings
    from dmarc_service.ingest import imap as imap_module

    monkeypatch.setenv("IMAP_HOST", "imap.example.com")
    get_settings.cache_clear()

    fake = FakeIMAP({b"9": b"Subject: x\r\n\r\nbody"})
    monkeypatch.setattr(imap_module, "_connect", lambda settings: fake)

    def boom(*args, **kwargs):
        raise RuntimeError("database gone")

    monkeypatch.setattr(imap_module, "process_message", boom)
    counts = imap_module.fetch_once()
    assert counts["failed"] == 1
    assert b"9" not in fake.flags  # untouched, so the next poll retries it


def test_recipient_header_preference():
    message = email.message_from_string(
        "To: list@example.com\r\nDelivered-To: real@example.net\r\n\r\n"
    )
    assert imap._recipient(message) == "real@example.net"
    assert imap._recipient(email.message_from_string("To: only@example.com\r\n\r\n")) \
        == "only@example.com"
    assert imap._recipient(email.message_from_string("Subject: none\r\n\r\n")) == ""
