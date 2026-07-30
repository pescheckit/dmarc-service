"""First-user setup, login, personal API tokens, SSO config, access control."""


def test_fresh_install_redirects_to_setup(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/setup"


def test_setup_creates_admin_and_logs_in(client):
    response = client.post(
        "/setup", data={"email": "bram@pescheck.io", "password": "supersecret"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    # session cookie set; dashboard now renders
    assert "Latest aggregate reports" in client.get("/").text
    # setup is one-shot: second attempt bounces to login
    response = client.post(
        "/setup", data={"email": "evil@example.com", "password": "hackhackhack"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login"


def test_password_login(client):
    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/logout")
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"

    response = client.post(
        "/login", data={"email": "a@b.nl", "password": "wrong"}, follow_redirects=False
    )
    assert response.status_code == 401

    response = client.post(
        "/login", data={"email": "a@b.nl", "password": "longenough"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "Settings" in client.get("/").text


def test_ui_domain_flow_shows_dns_records(client):
    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "pescheck", "name": "Pescheck"})
    response = client.post(
        "/tenants/pescheck/domains", data={"name": "pescheck.me"}, follow_redirects=True
    )
    assert "_dmarc.pescheck.me" in response.text
    assert "v=DMARC1" in response.text
    assert "_smtp._tls.pescheck.me" in response.text


def test_personal_api_token_roundtrip(client):
    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    page = client.post("/settings/tokens", data={"name": "ci"}, follow_redirects=True).text
    token = page.split("<code class=\"rec\">")[1].split("</code>")[0]
    assert token.startswith("dmk_")

    # token works on the API (API is closed now that a user exists)
    assert client.get("/api/reports").status_code == 401
    response = client.get("/api/reports", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

    # revoke → token dies
    token_id = page.split('action="/settings/tokens/')[1].split("/revoke")[0]
    client.post(f"/settings/tokens/{token_id}/revoke")
    response = client.get("/api/reports", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_sso_settings_admin_only(client):
    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    response = client.post(
        "/settings/sso",
        data={
            "name": "Pescheck SSO",
            "issuer": "https://login.microsoftonline.com/tenant/v2.0",
            "client_id": "abc",
            "client_secret": "xyz",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    # login page now offers the SSO button
    client.post("/logout")
    assert "Sign in with Pescheck SSO" in client.get("/login").text


def test_report_detail_and_docs(client, aggregate_xml):
    from tests.test_pipeline import build_report_email

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post(
        "/api/ingest",
        content=build_report_email(aggregate_xml, "x@dmarc.reporthost.net"),
        headers={"Authorization": "Bearer test-ingest-token", "X-Rcpt-To": "x@dmarc.reporthost.net"},
    )
    dashboard = client.get("/").text
    assert "details →" in dashboard

    detail = client.get("/reports/1")
    assert detail.status_code == 200
    assert "209.85.220.41" in detail.text          # passing source
    assert "203.0.113.66" in detail.text           # failing source
    assert "spammer.example" in detail.text        # authenticated-as hint
    assert "7 passed" in detail.text and "3 failed" in detail.text

    # API docs behind login
    assert client.get("/docs").status_code == 200
    assert "/api/reports" in client.get("/openapi.json").text
    client.post("/logout")
    assert client.get("/docs", follow_redirects=False).status_code == 303
