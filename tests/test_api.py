import gzip


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_tenant_domain_flow(client):
    response = client.post("/api/tenants", json={"slug": "acme", "name": "Acme Inc"})
    assert response.status_code == 201

    response = client.post("/api/tenants/acme/domains", json={"name": "example.com"})
    assert response.status_code == 201
    body = response.json()
    assert len(body["addresses"]) == 1
    local_part = body["addresses"][0]["local_part"]

    dns = client.get("/api/domains/example.com/dns").json()
    names = {record["name"] for record in dns}
    assert "_dmarc.example.com" in names
    assert "_smtp._tls.example.com" in names
    assert any(local_part in record["content"] for record in dns)

    # rotation: mint a second, then deactivate the first
    response = client.post("/api/domains/example.com/addresses")
    assert response.status_code == 201
    second = response.json()["local_part"]
    response = client.delete(f"/api/domains/example.com/addresses/{local_part}")
    assert response.status_code == 200

    dns = client.get("/api/domains/example.com/dns").json()
    dmarc = next(r for r in dns if r["name"] == "_dmarc.example.com")
    assert second in dmarc["content"]
    assert local_part not in dmarc["content"]


def test_ingest_endpoint_requires_token(client, aggregate_xml, tlsrpt_json):
    from tests.test_pipeline import build_report_email

    content = build_report_email(aggregate_xml, "x@dmarc.reporthost.net")
    response = client.post("/api/ingest", content=content)
    assert response.status_code == 401

    response = client.post(
        "/api/ingest",
        content=content,
        headers={
            "Authorization": "Bearer test-ingest-token",
            "X-Rcpt-To": "x@dmarc.reporthost.net",
            "X-Source-Ip": "203.0.113.5",
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "unrouted"  # no such address minted

    reports = client.get("/api/reports").json()
    assert len(reports) == 1
    assert reports[0]["org_name"] == "google.com"
    assert reports[0]["message_count"] == 10


def test_tlsrpt_endpoint_unauthenticated(client, tlsrpt_json):
    # reports about unregistered domains are rejected (injection hardening)
    response = client.post("/tlsrpt", content=tlsrpt_json)
    assert response.status_code == 400

    client.post("/api/tenants", json={"slug": "acme", "name": "Acme"})
    client.post("/api/tenants/acme/domains", json={"name": "example.com"})
    response = client.post(
        "/tlsrpt", content=gzip.compress(tlsrpt_json),
        headers={"Content-Type": "application/tlsrpt+gzip"},
    )
    assert response.status_code == 201

    reports = client.get("/api/tls-reports").json()
    assert len(reports) == 1
    assert reports[0]["organization_name"] == "Google Inc."
    assert reports[0]["source"] == "https"


def test_tlsrpt_rejects_garbage(client):
    assert client.post("/tlsrpt", content=b"never json").status_code == 400


def test_api_token_enforced(settings_env, monkeypatch):
    from fastapi.testclient import TestClient

    from dmarc_service.api.app import app
    from dmarc_service.config import get_settings
    from dmarc_service.db.models import Base
    from dmarc_service.db.session import get_engine

    monkeypatch.setenv("API_TOKEN", "sekrit")
    get_settings.cache_clear()
    Base.metadata.create_all(get_engine())

    with TestClient(app) as client:
        assert client.get("/api/reports").status_code == 401
        response = client.get("/api/reports", headers={"Authorization": "Bearer sekrit"})
        assert response.status_code == 200
        # TLS-RPT endpoint must stay open regardless (RFC 8460)
        assert client.post("/tlsrpt", content=b"{}").status_code in {201, 400}


def test_ui_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "dmarc-service" in response.text


def test_summary(client, aggregate_xml):
    from tests.test_pipeline import build_report_email

    client.post(
        "/api/ingest",
        content=build_report_email(aggregate_xml, "x@dmarc.reporthost.net"),
        headers={"Authorization": "Bearer test-ingest-token", "X-Rcpt-To": "x@dmarc.reporthost.net"},
    )
    summary = client.get("/api/summary").json()
    assert summary["messages_by_disposition"] == {"none": 7, "quarantine": 3}
    assert summary["unrouted_messages"] == 1


def test_not_indexable_by_search_engines_or_ai(client):
    robots = client.get("/robots.txt")
    assert robots.status_code == 200
    for agent in ("User-agent: *", "GPTBot", "ClaudeBot", "Google-Extended", "PerplexityBot"):
        assert agent in robots.text
    assert "Allow:" not in robots.text

    # every response carries the header, even ones nobody links to
    for path in ("/", "/login", "/healthz", "/docs"):
        header = client.get(path).headers.get("x-robots-tag", "")
        assert "noindex" in header and "noai" in header


def test_favicon_is_served(client):
    response = client.get("/favicon.svg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert response.text.startswith("<svg")
