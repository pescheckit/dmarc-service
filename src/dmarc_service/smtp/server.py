"""Inbound SMTP receiver for DMARC/TLS-RPT report mail.

Intake rules (deliberate, see README):
- accept mail from anyone; report senders are google.com/microsoft.com/etc.,
  so SPF/alignment checks against tenant domains would reject our own data
- no greylisting: deferred senders back off and some never retry
- generous size limit: large senders produce huge aggregate reports and a
  size bounce is data we never get again
- catch-all: unknown recipients are accepted and quarantined downstream

Two modes:
- direct: parse and store into the local database
- forward: relay the raw message over HTTPS to a main instance's /api/ingest;
  lets the MTA run on a tiny edge host when the app's cloud blocks port 25
"""

import asyncio
import logging
import ssl

import httpx
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope

from dmarc_service.config import Settings, get_settings

logger = logging.getLogger(__name__)


class ReportHandler:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        # Catch-all: routing/quarantine decisions happen after acceptance.
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope: Envelope) -> str:
        source_ip = session.peer[0] if session.peer else ""
        rcpt_to = envelope.rcpt_tos[0] if envelope.rcpt_tos else ""
        content = bytes(envelope.content or b"")
        logger.info(
            "message from=%s rcpt=%s ip=%s size=%d",
            envelope.mail_from, rcpt_to, source_ip, len(content),
        )
        try:
            if self.settings.smtp_mode == "forward":
                await self._forward(content, source_ip, envelope.mail_from or "", rcpt_to)
            else:
                await asyncio.get_running_loop().run_in_executor(
                    None, self._store, content, source_ip, envelope.mail_from or "", rcpt_to
                )
        except Exception:
            logger.exception("delivery failed; asking sender to retry")
            # Transient failure: senders retry, so a hiccup here loses nothing.
            return "451 Requested action aborted: local error in processing"
        return "250 Message accepted for delivery"

    def _store(self, content: bytes, source_ip: str, mail_from: str, rcpt_to: str) -> None:
        from dmarc_service.db.session import session_scope
        from dmarc_service.ingest.pipeline import process_message

        with session_scope() as db:
            process_message(
                db, content, source_ip=source_ip, mail_from=mail_from, rcpt_to=rcpt_to
            )

    async def _forward(self, content: bytes, source_ip: str, mail_from: str, rcpt_to: str) -> None:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                self.settings.smtp_forward_url,
                content=content,
                headers={
                    "Authorization": f"Bearer {self.settings.smtp_forward_token}",
                    "Content-Type": "message/rfc822",
                    "X-Source-Ip": source_ip,
                    "X-Mail-From": mail_from,
                    "X-Rcpt-To": rcpt_to,
                },
            )
            response.raise_for_status()


def build_controller(settings: Settings | None = None, port: int | None = None) -> Controller:
    settings = settings or get_settings()
    if settings.smtp_mode == "forward" and not settings.smtp_forward_url:
        raise SystemExit("SMTP_MODE=forward requires SMTP_FORWARD_URL")

    tls_context = None
    if settings.smtp_tls_cert and settings.smtp_tls_key:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(settings.smtp_tls_cert, settings.smtp_tls_key)

    return Controller(
        ReportHandler(settings),
        hostname=settings.smtp_host,
        port=port if port is not None else settings.smtp_port,
        data_size_limit=settings.smtp_max_message_bytes,
        tls_context=tls_context,  # STARTTLS offered when set, never required
    )


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    settings = get_settings()
    if settings.smtp_mode == "direct":
        # The edge/forward variant is stateless; only direct mode touches the DB.
        from dmarc_service import metrics
        from dmarc_service.control_plane.service import bootstrap
        from dmarc_service.db.session import session_scope

        with session_scope() as db:
            bootstrap(db)
        # No DNS refresh here: the web process does that, and doing it in
        # both would double the lookups for identical numbers.
        metrics.serve()

    controller = build_controller(settings)
    controller.start()
    logger.info(
        "smtp receiver listening on %s:%s (mode=%s)",
        settings.smtp_host, settings.smtp_port, settings.smtp_mode,
    )
    try:
        asyncio.new_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
