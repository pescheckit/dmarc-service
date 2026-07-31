"""Fetch reports from an IMAP mailbox.

Receiving mail directly is the better path: the service mints an address, the
domain owner points rua at it, and no credentials exist anywhere. This module
covers the cases where that is not possible:

- the host cannot accept inbound port 25 (most clouds block it)
- reports have been collecting in an existing mailbox for months
- someone else's mailbox already receives them and cannot be repointed yet

Messages are processed exactly as if they had arrived over SMTP, so routing,
deduplication and the unrouted quarantine behave identically. The recipient is
taken from the envelope headers where present, which keeps per-domain routing
working for a catch-all mailbox.
"""

import email
import imaplib
import logging
import time

from dmarc_service.config import get_settings
from dmarc_service.db.session import session_scope
from dmarc_service.ingest.pipeline import process_message

logger = logging.getLogger(__name__)

# Headers a delivering MTA writes with the address the mail was sent to, in
# order of trustworthiness. "To" is last: reports are often Bcc'd or the
# header carries a list address.
RECIPIENT_HEADERS = ("Delivered-To", "X-Original-To", "X-Envelope-To", "To")


def _recipient(message) -> str:
    for header in RECIPIENT_HEADERS:
        value = message.get(header)
        if value:
            _, address = email.utils.parseaddr(value)
            if address:
                return address
    return ""


class Account:
    """One mailbox to poll, from the database or the environment."""

    def __init__(self, host, port, use_ssl, username, password, folder,
                 processed_folder, row=None):
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.username, self.password = username, password
        self.folder, self.processed_folder = folder, processed_folder
        self.row = row  # the database row, when it came from there

    @classmethod
    def from_row(cls, row):
        from dmarc_service.auth.crypto import decrypt

        return cls(row.host, row.port, row.use_ssl, row.username,
                   decrypt(row.password_encrypted), row.folder,
                   row.processed_folder, row=row)

    @classmethod
    def from_settings(cls, settings):
        return cls(settings.imap_host, settings.imap_port, settings.imap_ssl,
                   settings.imap_username, settings.imap_password,
                   settings.imap_folder, settings.imap_processed_folder)


def accounts(session, settings=None) -> list:
    """Mailboxes configured in the UI, plus the environment one if set."""
    from sqlalchemy import select

    from dmarc_service.db.models import ImapAccount

    settings = settings or get_settings()
    found = [
        Account.from_row(row)
        for row in session.scalars(
            select(ImapAccount).where(ImapAccount.enabled.is_(True)).order_by(ImapAccount.id)
        )
    ]
    if settings.imap_host:
        found.append(Account.from_settings(settings))
    return found


def _connect(account):
    factory = imaplib.IMAP4_SSL if account.use_ssl else imaplib.IMAP4
    client = factory(account.host, account.port)
    client.login(account.username, account.password)
    return client


def fetch_all(settings=None) -> dict:
    """Poll every configured mailbox. Returns combined counts."""
    from dmarc_service.db.models import utcnow

    settings = settings or get_settings()
    totals = {"seen": 0, "stored": 0, "failed": 0, "mailboxes": 0}
    with session_scope() as db:
        configured = accounts(db, settings)

    for account in configured:
        totals["mailboxes"] += 1
        try:
            counts = fetch_once(account)
            result = f"{counts['stored']} stored, {counts['failed']} failed"
        except Exception as exc:  # noqa: BLE001 - one bad mailbox must not stop the rest
            logger.exception("polling %s failed", account.host)
            counts, result = {"seen": 0, "stored": 0, "failed": 0}, str(exc)[:255]
        for key in ("seen", "stored", "failed"):
            totals[key] += counts[key]

        if account.row is not None:
            with session_scope() as db:
                from dmarc_service.db.models import ImapAccount

                row = db.get(ImapAccount, account.row.id)
                if row is not None:
                    row.last_polled_at, row.last_result = utcnow(), result
    return totals


def check(account) -> str:
    """Verify credentials without processing anything."""
    client = _connect(account)
    try:
        status, _ = client.select(account.folder, readonly=True)
        return "" if status == "OK" else f"cannot open folder {account.folder}"
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        client.logout()


def fetch_once(account) -> dict:
    """Process unread messages in one mailbox.

    Messages are acknowledged only after they have been stored, so a crash
    means the message is retried rather than lost.
    """
    counts = {"seen": 0, "stored": 0, "failed": 0}
    client = _connect(account)
    try:
        client.select(account.folder)
        status, data = client.search(None, "UNSEEN")
        if status != "OK":
            return counts

        for number in data[0].split():
            status, payload = client.fetch(number, "(BODY.PEEK[])")
            if status != "OK" or not payload or not payload[0]:
                continue
            raw = payload[0][1]
            counts["seen"] += 1

            message = email.message_from_bytes(raw)
            try:
                with session_scope() as db:
                    stored = process_message(
                        db, raw, mail_from=_sender(message), rcpt_to=_recipient(message)
                    )
                    ok = stored.status in ("routed", "retired", "duplicate")
            except Exception:  # noqa: BLE001 - keep the mailbox moving
                logger.exception("could not process message %s", number)
                counts["failed"] += 1
                continue

            # The raw message is persisted either way, so acknowledge it: an
            # unparsable one is retried by "dmarc-service reprocess", not by
            # fetching it again forever. Only an exception leaves it unread.
            counts["stored" if ok else "failed"] += 1
            client.store(number, "+FLAGS", "\\Seen")
            if ok and account.processed_folder:
                client.copy(number, account.processed_folder)
                client.store(number, "+FLAGS", "\\Deleted")

        if account.processed_folder:
            client.expunge()
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001 - already closed
            pass
        client.logout()

    return counts


def _sender(message) -> str:
    _, address = email.utils.parseaddr(message.get("From", ""))
    return address


def run() -> None:
    """Poll every configured mailbox until stopped."""
    from dmarc_service import metrics

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    settings = get_settings()
    metrics.serve()
    logger.info("polling configured mailboxes every %ss", settings.imap_poll_interval)
    while True:
        try:
            counts = fetch_all(settings)
            if counts["seen"]:
                logger.info("processed %s", counts)
        except Exception:  # noqa: BLE001 - an outage must not end the loop
            logger.exception("IMAP poll failed; retrying")
        time.sleep(settings.imap_poll_interval)
