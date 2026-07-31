import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def settings_env(tmp_path, monkeypatch):
    """Fresh settings + sqlite database per test."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("REPORT_HOST", "dmarc.reporthost.net")
    monkeypatch.setenv("EXTERNAL_URL", "https://dmarc.reporthost.net")
    monkeypatch.setenv("TENANCY_MODE", "multi")
    monkeypatch.setenv("INGEST_TOKEN", "test-ingest-token")
    monkeypatch.setenv("API_TOKEN", "")
    monkeypatch.setenv("CREDENTIALS_KEY", "test-credentials-key")

    from dmarc_service.config import get_settings
    from dmarc_service.control_plane.service import clear_dns_cache
    from dmarc_service.db.session import reset_engine

    get_settings.cache_clear()
    reset_engine()
    clear_dns_cache()
    yield os.environ
    get_settings.cache_clear()
    reset_engine()


@pytest.fixture()
def db(settings_env):
    from dmarc_service.control_plane.service import bootstrap
    from dmarc_service.db.models import Base
    from dmarc_service.db.session import get_engine, session_scope

    Base.metadata.create_all(get_engine())
    with session_scope() as session:
        bootstrap(session)
    with session_scope() as session:
        yield session


@pytest.fixture()
def client(settings_env):
    from fastapi.testclient import TestClient

    from dmarc_service.api.app import app
    from dmarc_service.db.models import Base
    from dmarc_service.db.session import get_engine

    Base.metadata.create_all(get_engine())
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def aggregate_xml() -> bytes:
    return (FIXTURES / "google_aggregate.xml").read_bytes()


@pytest.fixture()
def tlsrpt_json() -> bytes:
    return (FIXTURES / "tlsrpt.json").read_bytes()
