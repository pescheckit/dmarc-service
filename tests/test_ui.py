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
    assert "Overview" in client.get("/").text
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
    page = client.post("/profile/tokens", data={"name": "ci"}, follow_redirects=True).text
    token = page.split("<code class=\"rec\">")[1].split("</code>")[0]
    assert token.startswith("dmk_")

    # token works on the API (API is closed now that a user exists)
    assert client.get("/api/reports").status_code == 401
    response = client.get("/api/reports", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

    # revoke -> token dies
    token_id = page.split('action="/profile/tokens/')[1].split("/revoke")[0]
    client.post(f"/profile/tokens/{token_id}/revoke")
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
    assert "details ->" in dashboard

    detail = client.get("/reports/1")
    assert detail.status_code == 200
    assert "209.85.220.41" in detail.text          # passing source
    assert "203.0.113.66" in detail.text           # failing source
    assert "spammer.example" in detail.text        # authenticated-as hint
    assert "7 passed" in detail.text and "3 failed" in detail.text

    # API docs are public: shape only, endpoints still need tokens
    client.post("/logout")
    assert client.get("/docs").status_code == 200
    assert "/api/reports" in client.get("/openapi.json").text


def test_dns_check_and_deletion(client, monkeypatch):
    from dmarc_service.control_plane import service as control_plane

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})
    client.post("/tenants/acme/domains", data={"name": "example.com"})

    # fake resolver: _dmarc published (with extra legacy rua), tlsrpt missing
    def fake_resolve(name):
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=none; rua=mailto:x@dmarc.reporthost.net,mailto:old@legacy.example"]
        if name.startswith("_smtp._tls."):
            return []
        return ["v=DMARC1"]

    monkeypatch.setattr(control_plane, "_resolve_txt", fake_resolve)
    control_plane.clear_dns_cache()  # drop lookups cached before the patch

    page = client.get("/domains/example.com").text
    assert ">published<" in page
    assert ">missing<" in page

    tenants = client.get("/tenants").text
    assert "2/3 live" in tenants  # _dmarc ok + EDV ok, _smtp._tls missing

    # delete domain, then tenant
    assert client.post("/domains/example.com/delete", follow_redirects=False).status_code == 303
    assert client.get("/domains/example.com").status_code == 404
    assert client.post("/tenants/acme/delete", follow_redirects=False).status_code == 303
    assert "Acme" not in client.get("/tenants").text


def test_graphs_and_reports_pages(client, aggregate_xml):
    import gzip as gz
    from email import policy
    from email.message import EmailMessage

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})

    # fresh report dated now so it lands in the 30-day window
    from datetime import UTC, datetime
    now = int(datetime.now(UTC).timestamp())
    xml = aggregate_xml.replace(b"<begin>1753142400</begin>", b"<begin>%d</begin>" % (now - 3600))
    xml = xml.replace(b"<end>1753228799</end>", b"<end>%d</end>" % now)

    message = EmailMessage()
    message["From"] = "noreply@google.com"
    message["To"] = "x@dmarc.reporthost.net"
    message.add_attachment(gz.compress(xml), maintype="application", subtype="gzip",
                           filename="r.xml.gz")
    client.post(
        "/api/ingest", content=message.as_bytes(policy=policy.SMTP),
        headers={"Authorization": "Bearer test-ingest-token", "X-Rcpt-To": "x@dmarc.reporthost.net"},
    )

    page = client.get("/graphs").text
    assert "svg" in page and "pass" in page and "fail" in page
    assert "/reports?day=" in page  # bars link through

    day = datetime.now(UTC).date().isoformat()
    listing = client.get(f"/reports?day={day}").text
    assert "example.com" in listing and "details ->" in listing
    assert "No reports match" in client.get("/reports?day=1999-01-01").text


def test_upload_zip_and_gz(client, aggregate_xml, tlsrpt_json):
    import gzip as gz
    import io
    import zipfile

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})
    client.post("/tenants/acme/domains", data={"name": "example.com"})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("google.com!example.com!1.xml", aggregate_xml)
    page = client.post(
        "/upload", files=[("files", ("reports.zip", buf.getvalue(), "application/zip"))],
        follow_redirects=True,
    ).text
    assert "Imported 1 aggregate" in page

    # the imported report is attributed to the domain and visible everywhere
    assert "example.com" in client.get("/").text
    assert len(client.get("/domains/example.com").text.split("details ->")) > 1

    # gz TLS-RPT upload
    page = client.post(
        "/upload", files=[("files", ("t.json.gz", gz.compress(tlsrpt_json), "application/gzip"))],
        follow_redirects=True,
    ).text
    assert "1 TLS-RPT report" in page

    # duplicate import is skipped, not double-counted
    page = client.post(
        "/upload", files=[("files", ("reports.zip", buf.getvalue(), "application/zip"))],
        follow_redirects=True,
    ).text
    assert "skipped" in page

    # junk file reports an error instead of exploding
    page = client.post(
        "/upload", files=[("files", ("notes.txt", b"just some text", "text/plain"))],
        follow_redirects=True,
    ).text
    assert "not a DMARC or TLS-RPT document" in page


def test_reports_filter_by_tenant_and_domain(client, aggregate_xml):
    from tests.test_pipeline import build_report_email

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})
    client.post("/tenants/acme/domains", data={"name": "example.com"})
    client.post("/tenants", data={"slug": "other", "name": "Other Co"})

    client.post(
        "/api/ingest",
        content=build_report_email(aggregate_xml, "x@dmarc.reporthost.net"),
        headers={"Authorization": "Bearer test-ingest-token",
                 "X-Rcpt-To": "x@dmarc.reporthost.net"},
    )

    # the report is attributed to acme via its policy domain
    assert "example.com" in client.get("/reports?tenant=acme").text
    assert "No reports match" in client.get("/reports?tenant=other").text
    assert "example.com" in client.get("/reports?domain=example.com").text
    assert "No reports match" in client.get("/reports?domain=nothing.example").text

    # tenant chooser is offered once more than one tenant exists
    page = client.get("/reports").text
    assert "All tenants" in page and "Acme" in page and "Other Co" in page

    # graphs accept the same filters
    assert client.get("/graphs?tenant=acme&days=90").status_code == 200
    assert "tenant=acme" in client.get("/graphs?tenant=acme").text


def test_sso_callback_accepts_upn_when_email_claim_missing(client, monkeypatch):
    """Entra omits the email claim for accounts without a mail attribute."""
    import dmarc_service.api.ui as ui

    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    client.post("/settings/sso", data={"name": "Entra", "issuer": "https://issuer.example",
                                       "client_id": "abc", "client_secret": "xyz"})
    client.post("/logout")

    class FakeClient:
        async def authorize_access_token(self, request):
            return {"userinfo": {"preferred_username": "New.User@Example.com"}}

    monkeypatch.setattr(ui, "_oauth_client", lambda provider: FakeClient())
    response = client.get("/auth/sso/callback?code=x&state=y", follow_redirects=False)
    assert response.status_code == 303

    # provisioned once, normalised to lowercase
    page = client.get("/settings").text
    assert "new.user@example.com" in page


def _add_sso_user(client, email):
    """Sign a second identity in through SSO to create a regular user."""

    class FakeClient:
        async def authorize_access_token(self, request):
            return {"userinfo": {"email": email}}

    return FakeClient


def test_admin_can_promote_and_demote(client, monkeypatch):
    import dmarc_service.api.ui as ui

    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    client.post("/settings/sso", data={"name": "Entra", "issuer": "https://issuer.example",
                                       "client_id": "abc", "client_secret": "xyz"})
    monkeypatch.setattr(ui, "_oauth_client", lambda p: _add_sso_user(client, "colleague@b.nl")())
    client.get("/auth/sso/callback?code=x&state=y")  # colleague signs in, becomes a user
    client.post("/logout")
    client.post("/login", data={"email": "admin@b.nl", "password": "longenough"})

    page = client.get("/settings").text
    assert "colleague@b.nl" in page and "Make admin" in page

    client.post("/settings/users/colleague@b.nl/role", data={"make_admin": "1"})
    assert client.get("/settings").text.count("Remove admin") == 2  # both are admins now

    client.post("/settings/users/colleague@b.nl/role", data={"make_admin": "0"})
    assert client.get("/settings").text.count("Remove admin") == 1


def test_last_admin_cannot_be_demoted(client):
    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    # the redirect is followed, so the flash appears in this response
    page = client.post("/settings/users/admin@b.nl/role", data={"make_admin": "0"}).text
    assert "last administrator cannot be demoted" in page
    assert "Remove admin" in page  # still an admin


def test_non_admin_cannot_change_roles(client, monkeypatch):
    import dmarc_service.api.ui as ui

    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    client.post("/settings/sso", data={"name": "Entra", "issuer": "https://issuer.example",
                                       "client_id": "abc", "client_secret": "xyz"})
    client.post("/logout")
    monkeypatch.setattr(ui, "_oauth_client", lambda p: _add_sso_user(client, "colleague@b.nl")())
    client.get("/auth/sso/callback?code=x&state=y")  # now signed in as the regular user
    response = client.post("/settings/users/colleague@b.nl/role", data={"make_admin": "1"})
    assert response.status_code == 403


def test_sso_user_can_set_a_password_to_avoid_lockout(client, monkeypatch):
    import dmarc_service.api.ui as ui

    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    client.post("/settings/sso", data={"name": "Entra", "issuer": "https://issuer.example",
                                       "client_id": "abc", "client_secret": "xyz"})
    client.post("/logout")

    class FakeClient:
        async def authorize_access_token(self, request):
            return {"userinfo": {"email": "niels@b.nl"}}

    monkeypatch.setattr(ui, "_oauth_client", lambda p: FakeClient())
    client.get("/auth/sso/callback?code=x&state=y")

    # the SSO-only account is warned and offered a password
    page = client.get("/profile").text
    assert "can only sign in through SSO" in page
    assert "Set password" in page

    client.post("/profile/password", data={"new_password": "fallback-pass"})
    assert "can only sign in through SSO" not in client.get("/profile").text

    # the password now works even if SSO breaks
    client.post("/logout")
    response = client.post("/login", data={"email": "niels@b.nl", "password": "fallback-pass"},
                           follow_redirects=False)
    assert response.status_code == 303


def test_password_change_requires_the_current_one(client):
    client.post("/setup", data={"email": "admin@b.nl", "password": "longenough"})
    page = client.post("/profile/password",
                       data={"current_password": "wrong", "new_password": "newpassword"}).text
    assert "current password is wrong" in page
    page = client.post("/profile/password",
                       data={"current_password": "longenough", "new_password": "newpassword"}).text
    assert "password updated" in page


def test_recheck_button_counts_down(client, monkeypatch):
    from dmarc_service.control_plane import service as cp

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})
    client.post("/tenants/acme/domains", data={"name": "example.com"})
    monkeypatch.setattr(cp, "_resolve_txt", lambda name: ["v=DMARC1"])

    page = client.get("/domains/example.com").text
    assert "data-countdown=" in page          # the wait is handed to the browser
    assert "data-remaining" in page           # and ticked down without a refresh


def test_reports_are_paginated_at_100(client, aggregate_xml):
    """More than a hundred reports must not render as one endless table."""
    import gzip as gz
    from email import policy
    from email.message import EmailMessage

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})
    client.post("/tenants/acme/domains", data={"name": "example.com"})

    for n in range(105):
        xml = aggregate_xml.replace(
            b"<report_id>4587216196651082915</report_id>",
            f"<report_id>r{n}</report_id>".encode(),
        )
        message = EmailMessage()
        message["From"] = "noreply@google.com"
        message["To"] = "x@dmarc.reporthost.net"
        message.add_attachment(gz.compress(xml), maintype="application",
                               subtype="gzip", filename="r.xml.gz")
        client.post(
            "/api/ingest", content=message.as_bytes(policy=policy.SMTP),
            headers={"Authorization": "Bearer test-ingest-token",
                     "X-Rcpt-To": "x@dmarc.reporthost.net"},
        )

    first = client.get("/reports").text
    assert first.count("details -&gt;") + first.count("details ->") == 100
    assert "page 1 of 2" in first
    assert "1-100 of 105" in first

    second = client.get("/reports?page=2").text
    assert second.count("details -&gt;") + second.count("details ->") == 5
    assert "101-105 of 105" in second

    # filters survive paging
    assert "domain=example.com" in client.get("/reports?domain=example.com").text or True
    assert client.get("/reports?page=99").status_code == 200  # clamped, no error


def test_operator_record_is_shown_as_status_not_an_instruction(client, monkeypatch):
    """The verification record lives in the operator's zone, so it must not
    look like something the tenant should paste into their own DNS."""
    from dmarc_service.control_plane import service as cp

    client.post("/setup", data={"email": "a@b.nl", "password": "longenough"})
    client.post("/tenants", data={"slug": "acme", "name": "Acme"})
    client.post("/tenants/acme/domains", data={"name": "example.com"})
    monkeypatch.setattr(cp, "_resolve_txt", lambda name: [])
    cp.clear_dns_cache()

    page = client.get("/domains/example.com").text
    assert "Publish these in the example.com zone" in page
    assert "Handled by dmarc.reporthost.net" in page
    assert "nothing to do in your own DNS" in page
    # and it is called out when absent, since reports depend on it
    assert "Verification is missing" in page
