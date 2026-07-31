import socket
import urllib.error
import urllib.request

import pytest

from dmarc_service.config import get_settings
from dmarc_service.control_plane import service as control_plane
from dmarc_service.ingest.pipeline import process_message

from .test_pipeline import build_report_email


def _scrape(server, token: str = "") -> str:
    port = server.server_address[1]
    request = urllib.request.Request(f"http://127.0.0.1:{port}/metrics")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _report(db, aggregate_xml: bytes) -> None:
    """One stored report for example.com, visible to other connections."""
    tenant = control_plane.create_tenant(db, "acme", "Acme Ltd")
    domain = control_plane.add_domain(db, tenant, "example.com")
    rcpt = f"{domain.addresses[0].local_part}@dmarc.reporthost.net"
    process_message(db, build_report_email(aggregate_xml, rcpt), rcpt_to=rcpt)
    db.commit()  # the metrics listener reads on its own connection


@pytest.fixture()
def metrics_server(db, monkeypatch):
    from dmarc_service import metrics

    monkeypatch.setenv("METRICS_ENABLED", "true")
    monkeypatch.setenv("METRICS_HOST", "127.0.0.1")
    monkeypatch.setenv("METRICS_PORT", str(_free_port()))
    monkeypatch.setenv("METRICS_TOKEN", "scrape-me")
    get_settings.cache_clear()

    server = metrics.serve()
    assert server is not None
    yield server
    server.shutdown()
    server.server_close()


def test_disabled_by_default(settings_env):
    """Nobody publishes their tenant list by accident."""
    from dmarc_service import metrics

    assert metrics.serve() is None


def test_enabling_without_a_token_refuses_to_start(settings_env, monkeypatch):
    from dmarc_service import metrics

    monkeypatch.setenv("METRICS_ENABLED", "true")
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="METRICS_TOKEN"):
        metrics.serve()


def test_unauthenticated_is_possible_but_explicit(db, monkeypatch):
    from dmarc_service import metrics

    monkeypatch.setenv("METRICS_ENABLED", "true")
    monkeypatch.setenv("METRICS_HOST", "127.0.0.1")
    monkeypatch.setenv("METRICS_PORT", str(_free_port()))
    monkeypatch.setenv("METRICS_ALLOW_UNAUTHENTICATED", "true")
    get_settings.cache_clear()

    server = metrics.serve()
    try:
        assert server is not None
        assert "dmarc_build_info" in _scrape(server)
    finally:
        server.shutdown()
        server.server_close()


def test_scrape_requires_the_token(metrics_server):
    for token in ("", "not-the-token"):
        with pytest.raises(urllib.error.HTTPError) as raised:
            _scrape(metrics_server, token=token)
        assert raised.value.code == 401

    assert "dmarc_collector_up 1.0" in _scrape(metrics_server, token="scrape-me")


def test_reports_domain_state(metrics_server, db, aggregate_xml):
    _report(db, aggregate_xml)

    body = _scrape(metrics_server, token="scrape-me")
    assert "dmarc_domains 1.0" in body
    assert "dmarc_tenants 1.0" in body
    assert 'dmarc_messages_reported_total{domain="example.com"' in body
    assert 'dmarc_last_report_timestamp_seconds{domain="example.com"}' in body
    assert "dmarc_messages_received_total" in body


def test_labels_can_be_dropped(metrics_server, db, aggregate_xml, monkeypatch):
    """An operator may consider the domain list more sensitive than the
    numbers. Totals stay available without naming anyone."""
    _report(db, aggregate_xml)

    monkeypatch.setenv("METRICS_LABELS", "false")
    get_settings.cache_clear()

    body = _scrape(metrics_server, token="scrape-me")
    assert "example.com" not in body
    assert 'dmarc_messages_reported_total{result=' in body


def test_source_ips_never_become_labels(metrics_server, db, aggregate_xml):
    """The cardinality trap: a busy domain sees tens of thousands of source
    IPs, and one careless label would take Prometheus down with it."""
    _report(db, aggregate_xml)

    body = _scrape(metrics_server, token="scrape-me")
    assert "209.85.220.41" not in body


def test_collector_survives_a_broken_database(metrics_server, monkeypatch):
    """A database blip should surface as a gauge, not a failed scrape:
    Prometheus reads a 500 as target-down and learns nothing else."""
    from dmarc_service import metrics

    def explode(*args, **kwargs):
        raise RuntimeError("database gone")

    monkeypatch.setattr(metrics.DatabaseCollector, "_collect", explode)
    assert "dmarc_collector_up 0.0" in _scrape(metrics_server, token="scrape-me")
