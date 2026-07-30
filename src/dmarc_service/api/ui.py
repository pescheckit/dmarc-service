"""Web UI: first-user setup, password + SSO login, tenants/domains/DNS,
admin settings (SSO provider, users) and personal API tokens."""

from pathlib import Path

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select

from dmarc_service.auth import service as auth
from dmarc_service.config import get_settings
from dmarc_service.control_plane import service as control_plane
from dmarc_service.db.models import (
    AggregateRecord,
    AggregateReport,
    ApiToken,
    Domain,
    RawMessage,
    Tenant,
    User,
)
from dmarc_service.db.session import session_scope

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _current_user(request: Request, db) -> User | None:
    user_id = request.session.get("user_id")
    return db.get(User, user_id) if user_id else None


def _login_redirect(db) -> RedirectResponse:
    target = "/setup" if auth.user_count(db) == 0 else "/login"
    return RedirectResponse(target, status_code=303)


def _ctx(request: Request, user: User, **extra) -> dict:
    return {
        "request": request,
        "report_host": get_settings().report_host,
        "user": {"email": user.email, "is_admin": user.is_admin},
        **extra,
    }


# --- first-user setup ---


@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    with session_scope() as db:
        if auth.user_count(db) > 0:
            return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html", {"error": ""})


@router.post("/setup")
def setup(request: Request, email: str = Form(...), password: str = Form(...)):
    with session_scope() as db:
        if auth.user_count(db) > 0:
            return RedirectResponse("/login", status_code=303)
        if len(password) < 8:
            return templates.TemplateResponse(
                request, "setup.html", {"error": "Password must be at least 8 characters"},
                status_code=400,
            )
        user = auth.create_user(db, email, password, is_admin=True)
        request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


# --- login / logout ---


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    with session_scope() as db:
        if auth.user_count(db) == 0:
            return RedirectResponse("/setup", status_code=303)
        provider = auth.get_provider(db)
        sso_name = provider.name if provider else ""
    return templates.TemplateResponse(request, "login.html", {"error": "", "sso_name": sso_name})


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with session_scope() as db:
        user = auth.authenticate(db, email, password)
        if user is None:
            provider = auth.get_provider(db)
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Wrong email or password", "sso_name": provider.name if provider else ""},
                status_code=401,
            )
        request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --- SSO (OIDC) ---


def _oauth_client(provider):
    oauth = OAuth()
    oauth.register(
        "sso",
        server_metadata_url=f"{provider.issuer}/.well-known/openid-configuration",
        client_id=provider.client_id,
        client_secret=provider.client_secret,
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth.sso


@router.get("/auth/sso/login")
async def sso_login(request: Request):
    with session_scope() as db:
        provider = auth.get_provider(db)
    if provider is None:
        raise HTTPException(status_code=404, detail="SSO not configured")
    redirect_uri = f"{get_settings().external_url}/auth/sso/callback"
    return await _oauth_client(provider).authorize_redirect(request, redirect_uri)


@router.get("/auth/sso/callback")
async def sso_callback(request: Request):
    with session_scope() as db:
        provider = auth.get_provider(db)
    if provider is None:
        raise HTTPException(status_code=404, detail="SSO not configured")
    token = await _oauth_client(provider).authorize_access_token(request)
    email = (token.get("userinfo") or {}).get("email")
    if not email:
        raise HTTPException(status_code=400, detail="SSO provider returned no email claim")
    with session_scope() as db:
        user = auth.find_or_provision_sso_user(db, email)
        request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


# --- pages ---


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        reports = db.scalars(
            select(AggregateReport).order_by(AggregateReport.date_end.desc()).limit(50)
        ).all()
        rows = [_report_row(db, r) for r in reports]
        unrouted = db.scalar(
            select(func.count(RawMessage.id)).where(RawMessage.status == "unrouted")
        )
        return templates.TemplateResponse(
            request, "index.html", _ctx(request, user, reports=rows, unrouted=unrouted)
        )


@router.get("/tenants", response_class=HTMLResponse)
def tenants_page(request: Request, error: str = ""):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        tenants = []
        for tenant in db.scalars(select(Tenant).order_by(Tenant.slug)):
            domains = [
                {
                    "name": d.name,
                    "addresses": [a.local_part for a in control_plane.active_addresses(db, d)],
                }
                for d in tenant.domains
            ]
            tenants.append({"slug": tenant.slug, "name": tenant.name, "domains": domains})
        return templates.TemplateResponse(
            request,
            "tenants.html",
            _ctx(
                request,
                user,
                tenants=tenants,
                error=error,
                multi_tenant=get_settings().tenancy_mode == "multi",
            ),
        )


@router.post("/tenants")
def create_tenant_form(request: Request, slug: str = Form(...), name: str = Form("")):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        if db.scalar(select(Tenant).where(Tenant.slug == slug)):
            return RedirectResponse("/tenants?error=tenant+exists", status_code=303)
        control_plane.create_tenant(db, slug, name or slug)
    return RedirectResponse("/tenants", status_code=303)


@router.post("/tenants/{slug}/domains")
def add_domain_form(request: Request, slug: str, name: str = Form(...)):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        if db.scalar(select(Domain).where(Domain.name == name.lower().strip("."))):
            return RedirectResponse("/tenants?error=domain+exists", status_code=303)
        domain = control_plane.add_domain(db, tenant, name)
        return RedirectResponse(f"/domains/{domain.name}", status_code=303)


@router.get("/domains/{name}", response_class=HTMLResponse)
def domain_page(request: Request, name: str):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        dns = control_plane.required_dns_records(db, domain)
        addresses = [
            {"local_part": a.local_part, "active": a.active}
            for a in sorted(domain.addresses, key=lambda a: (not a.active, a.local_part))
        ]
        reports = db.scalars(
            select(AggregateReport)
            .where(AggregateReport.policy_domain == domain.name)
            .order_by(AggregateReport.date_end.desc())
            .limit(20)
        ).all()
        rows = [_report_row(db, r) for r in reports]
        return templates.TemplateResponse(
            request,
            "domain.html",
            _ctx(request, user, domain={"name": domain.name}, dns=dns,
                 addresses=addresses, reports=rows),
        )


@router.post("/domains/{name}/addresses/mint")
def mint_address_form(request: Request, name: str):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        control_plane.mint_address(db, domain)
    return RedirectResponse(f"/domains/{name}", status_code=303)


@router.post("/domains/{name}/addresses/{local_part}/deactivate")
def deactivate_address_form(request: Request, name: str, local_part: str):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        for address in domain.addresses:
            if address.local_part == local_part:
                address.active = False
    return RedirectResponse(f"/domains/{name}", status_code=303)


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def report_page(request: Request, report_id: int):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        report = db.get(AggregateReport, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        records = []
        for r in sorted(report.records, key=lambda r: -r.count):
            ok = r.dkim_result == "pass" or r.spf_result == "pass"
            # Who actually sent it: the domain that authenticated, if any —
            # this is what separates "our misconfigured tool" from spoofing.
            sender_hint = r.auth_dkim_domain or r.auth_spf_domain or r.envelope_from
            records.append(
                {
                    "source_ip": r.source_ip,
                    "count": r.count,
                    "ok": ok,
                    "disposition": r.disposition,
                    "dkim": r.dkim_result or "-",
                    "spf": r.spf_result or "-",
                    "header_from": r.header_from,
                    "sender_hint": sender_hint,
                    "auth_dkim": f"{r.auth_dkim_domain}: {r.auth_dkim_result}" if r.auth_dkim_domain else "-",
                    "auth_spf": f"{r.auth_spf_domain}: {r.auth_spf_result}" if r.auth_spf_domain else "-",
                }
            )
        return templates.TemplateResponse(
            request,
            "report.html",
            _ctx(request, user, report=_report_row(db, report), records=records),
        )


# --- settings: personal API tokens + admin (SSO, users) ---


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        tokens = [
            {"id": t.id, "name": t.name, "prefix": t.prefix, "created_at": t.created_at}
            for t in db.scalars(
                select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.id)
            )
        ]
        provider = auth.get_provider(db)
        users = []
        if user.is_admin:
            users = [
                {"email": u.email, "is_admin": u.is_admin, "sso": u.password_hash is None}
                for u in db.scalars(select(User).order_by(User.email))
            ]
        new_token = request.session.pop("new_token", None)
        return templates.TemplateResponse(
            request,
            "settings.html",
            _ctx(
                request,
                user,
                tokens=tokens,
                new_token=new_token,
                users=users,
                sso={
                    "configured": provider is not None,
                    "name": provider.name if provider else "",
                    "issuer": provider.issuer if provider else "",
                    "client_id": provider.client_id if provider else "",
                },
                callback_url=f"{get_settings().external_url}/auth/sso/callback",
            ),
        )


@router.post("/settings/tokens")
def create_token(request: Request, name: str = Form("token")):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        request.session["new_token"] = auth.mint_api_token(db, user, name)
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/tokens/{token_id}/revoke")
def revoke_token(request: Request, token_id: int):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        auth.revoke_api_token(db, user, token_id)
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/sso")
def save_sso(
    request: Request,
    name: str = Form("SSO"),
    issuer: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="admin only")
        auth.set_provider(
            db, name=name, issuer=issuer, client_id=client_id, client_secret=client_secret
        )
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/sso/remove")
def remove_sso(request: Request):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="admin only")
        auth.remove_provider(db)
    return RedirectResponse("/settings", status_code=303)


def _report_row(db, report: AggregateReport) -> dict:
    # A message "passes DMARC" when at least one aligned mechanism passed.
    passed = case(
        (
            (AggregateRecord.dkim_result == "pass") | (AggregateRecord.spf_result == "pass"),
            AggregateRecord.count,
        ),
        else_=0,
    )
    total, ok = db.execute(
        select(func.sum(AggregateRecord.count), func.sum(passed)).where(
            AggregateRecord.report_id == report.id
        )
    ).one()
    total = int(total or 0)
    ok = int(ok or 0)
    return {
        "id": report.id,
        "org_name": report.org_name,
        "policy_domain": report.policy_domain,
        "date_begin": report.date_begin,
        "date_end": report.date_end,
        "policy_p": report.policy_p,
        "message_count": total,
        "pass_count": ok,
        "fail_count": total - ok,
    }
