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


def _connect(settings):
    factory = imaplib.IMAP4_SSL if settings.imap_ssl else imaplib.IMAP4
    client = factory(settings.imap_host, settings.imap_port)
    if not settings.imap_ssl and settings.imap_starttls:
        client.starttls()
    client.login(settings.imap_username, settings.imap_password)
    return client


def fetch_once(settings=None) -> dict:
    """Process unread messages in the configured folder.

    Returns counts. Messages are marked read (and moved, when a destination
    folder is configured) only after they have been stored, so a crash means
    the message is retried rather than lost.
    """
    settings = settings or get_settings()
    if not settings.imap_host:
        raise SystemExit("IMAP_HOST is not set")

    counts = {"seen": 0, "stored": 0, "failed": 0}
    client = _connect(settings)
    try:
        client.select(settings.imap_folder)
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
            if ok and settings.imap_processed_folder:
                client.copy(number, settings.imap_processed_folder)
                client.store(number, "+FLAGS", "\\Deleted")

        if settings.imap_processed_folder:
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
    """Poll the mailbox until stopped."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    settings = get_settings()
    logger.info(
        "polling %s@%s every %ss",
        settings.imap_username, settings.imap_host, settings.imap_poll_interval,
    )
    while True:
        try:
            counts = fetch_once(settings)
            if counts["seen"]:
                logger.info("processed %s", counts)
        except Exception:  # noqa: BLE001 - a mailbox outage must not end the loop
            logger.exception("IMAP poll failed; retrying")
        time.sleep(settings.imap_poll_interval)
