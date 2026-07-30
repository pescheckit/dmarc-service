"""End-to-end SMTP tests: real client, real aiosmtpd server, both modes."""

import smtplib
import socket
import time

from sqlalchemy import select

from tests.test_pipeline import build_report_email


def _free_port() -> int:
    # aiosmtpd's Controller.start() probes the configured port, so it cannot
    # bind port 0 itself; reserve one the usual racy-but-fine way.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _send(port: int, content: bytes, rcpt: str) -> None:
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as client:
        client.sendmail("noreply-dmarc-support@google.com", [rcpt], content)


def _wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_direct_mode_end_to_end(db, aggregate_xml):
    from dmarc_service.config import get_settings
    from dmarc_service.control_plane import service as control_plane
    from dmarc_service.db.models import AggregateReport
    from dmarc_service.db.session import session_scope
    from dmarc_service.smtp.server import build_controller

    tenant = control_plane.create_tenant(db, "acme", "Acme")
    domain = control_plane.add_domain(db, tenant, "example.com")
    address = control_plane.active_addresses(db, domain)[0]
    db.commit()
    rcpt = f"{address.local_part}@dmarc.reporthost.net"

    port = _free_port()
    controller = build_controller(get_settings(), port=port)
    controller.start()
    try:
        _send(port, build_report_email(aggregate_xml, rcpt), rcpt)

        def stored():
            with session_scope() as check:
                return check.scalar(select(AggregateReport)) is not None

        assert _wait_for(stored), "report did not appear in the database"
        with session_scope() as check:
            report = check.scalar(select(AggregateReport))
            assert report.org_name == "google.com"
            assert report.domain_id == domain.id
    finally:
        controller.stop()


def test_oversized_message_is_rejected(settings_env, db, monkeypatch):
    from dmarc_service.config import get_settings
    from dmarc_service.smtp.server import build_controller

    monkeypatch.setenv("SMTP_MAX_MESSAGE_BYTES", "1000")
    get_settings.cache_clear()

    port = _free_port()
    controller = build_controller(get_settings(), port=port)
    controller.start()
    try:
        big = b"x" * 5000
        try:
            _send(port, b"Subject: big\r\n\r\n" + big, "x@dmarc.reporthost.net")
        except smtplib.SMTPException:
            return  # rejected, as intended
        raise AssertionError("oversized message was accepted")
    finally:
        controller.stop()


def test_forward_mode_relays_to_ingest(settings_env, monkeypatch, aggregate_xml):
    """Edge mode: SMTP in, authenticated HTTPS POST out to /api/ingest."""
    import httpx

    from dmarc_service import smtp as smtp_package
    from dmarc_service.api.app import app
    from dmarc_service.config import get_settings
    from dmarc_service.db.models import Base
    from dmarc_service.db.session import get_engine

    monkeypatch.setenv("SMTP_MODE", "forward")
    monkeypatch.setenv("SMTP_FORWARD_URL", "http://main-instance/api/ingest")
    monkeypatch.setenv("SMTP_FORWARD_TOKEN", "test-ingest-token")
    get_settings.cache_clear()

    Base.metadata.create_all(get_engine())

    # Point the edge's HTTP client at the FastAPI app in-process.
    class AppBoundClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs["transport"] = httpx.ASGITransport(app=app)
            super().__init__(**kwargs)

    monkeypatch.setattr(smtp_package.server.httpx, "AsyncClient", AppBoundClient)

    from dmarc_service.smtp.server import build_controller

    with __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(app) as api:
        port = _free_port()
        controller = build_controller(get_settings(), port=port)
        controller.start()
        try:
            rcpt = "someone@dmarc.reporthost.net"
            _send(port, build_report_email(aggregate_xml, rcpt), rcpt)

            def arrived():
                return len(api.get("/api/reports").json()) == 1

            assert _wait_for(arrived), "forwarded report did not reach /api/ingest"
        finally:
            controller.stop()
