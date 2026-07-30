"""Web UI: first-user setup, password + SSO login, tenants/domains/DNS,
admin settings (SSO provider, users) and personal API tokens."""

from datetime import UTC
from pathlib import Path

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select

from dmarc_service.auth import service as auth
from dmarc_service.config import get_settings
from dmarc_service.control_plane import service as control_plane
from dmarc_service.db.models import (
    UNROUTED_TENANT_SLUG,
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
        series = _daily_series(db, "", 30)
        totals = {
            "pass": sum(d["pass"] for d in series),
            "fail": sum(d["fail"] for d in series),
        }
        totals["total"] = totals["pass"] + totals["fail"]
        totals["rate"] = round(100 * totals["pass"] / totals["total"]) if totals["total"] else None
        return templates.TemplateResponse(
            request,
            "index.html",
            _ctx(request, user, reports=rows, unrouted=unrouted, totals=totals),
        )


@router.get("/tenants", response_class=HTMLResponse)
def tenants_page(request: Request, error: str = ""):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        tenants = []
        for tenant in db.scalars(select(Tenant).order_by(Tenant.slug)):
            domains = []
            for d in tenant.domains:
                checks = control_plane.check_dns_records(
                    control_plane.required_dns_records(db, d)
                )
                ok = sum(1 for c in checks if c["status"] == "ok")
                domains.append(
                    {
                        "name": d.name,
                        "addresses": [
                            a.local_part for a in control_plane.active_addresses(db, d)
                        ],
                        "dns_ok": ok,
                        "dns_total": len(checks),
                    }
                )
            tenants.append(
                {
                    "slug": tenant.slug,
                    "name": tenant.name,
                    "domains": domains,
                    # the quarantine pseudo-tenant never owns domains directly
                    "system": tenant.slug == UNROUTED_TENANT_SLUG,
                }
            )
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
        if tenant.slug == UNROUTED_TENANT_SLUG:
            return RedirectResponse(
                "/tenants?error=the+quarantine+cannot+own+domains", status_code=303
            )
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
        required = control_plane.required_dns_records(db, domain)
        dns = control_plane.check_dns_records(required)
        checked_age = control_plane.dns_checked_age([r.name for r in required])
        summary = {
            "ok": sum(1 for r in dns if r["status"] == "ok"),
            "total": len(dns),
            "problems": [r for r in dns if r["status"] != "ok"],
        }
        summary["all_ok"] = summary["ok"] == summary["total"]
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
                 addresses=addresses, reports=rows, summary=summary,
                 just_checked=request.session.pop("dns_rechecked", False),
                 checked_age=int(checked_age) if checked_age is not None else None,
                 recheck_wait=int(control_plane.DNS_RECHECK_INTERVAL - checked_age)
                 if checked_age is not None
                 and checked_age < control_plane.DNS_RECHECK_INTERVAL
                 else 0),
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
            # Who actually sent it: the domain that authenticated, if any -
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


# --- graphs & report browsing ---


def _pass_case():
    return case(
        (
            (AggregateRecord.dkim_result == "pass") | (AggregateRecord.spf_result == "pass"),
            AggregateRecord.count,
        ),
        else_=0,
    )


def _daily_series(db, domain: str, days: int) -> list[dict]:
    """Per-day pass/fail message totals, bucketed on the report period start."""
    from datetime import UTC, datetime, timedelta

    since = datetime.now(UTC) - timedelta(days=days)
    query = (
        select(
            AggregateReport.date_begin,
            func.sum(AggregateRecord.count),
            func.sum(_pass_case()),
        )
        .join(AggregateRecord)
        .where(AggregateReport.date_begin >= since)
        .group_by(AggregateReport.id)
    )
    if domain:
        query = query.where(AggregateReport.policy_domain == domain)

    buckets: dict = {}
    for begin, total, ok in db.execute(query):
        day = begin.date()
        entry = buckets.setdefault(day, {"pass": 0, "fail": 0})
        entry["pass"] += int(ok or 0)
        entry["fail"] += int(total or 0) - int(ok or 0)

    start = (datetime.now(UTC) - timedelta(days=days)).date()
    out = []
    for offset in range(days + 1):
        day = start + timedelta(days=offset)
        entry = buckets.get(day, {"pass": 0, "fail": 0})
        out.append({"day": day, "pass": entry["pass"], "fail": entry["fail"]})
    return out


def _chart_geometry(series: list[dict], domain: str) -> dict:
    """Server-rendered stacked-bar geometry. Pass sits on the baseline, fail
    stacks on top with a 2px surface gap (position + texture carry the
    distinction for color-blind readers; color is reinforcement)."""
    width, height, left, bottom, top = 920, 240, 44, 26, 10
    plot_w, plot_h = width - left - 8, height - bottom - top
    n = len(series)
    slot = plot_w / max(n, 1)
    bar_w = max(slot - 2, 3)
    peak = max((d["pass"] + d["fail"] for d in series), default=0) or 1

    bars = []
    for i, d in enumerate(series):
        x = left + i * slot + 1
        pass_h = plot_h * d["pass"] / peak
        fail_h = plot_h * d["fail"] / peak
        gap = 2 if (pass_h > 0 and fail_h > 0) else 0
        bars.append(
            {
                "x": round(x, 1),
                "w": round(bar_w, 1),
                "pass_y": round(top + plot_h - pass_h, 1),
                "pass_h": round(pass_h, 1),
                "fail_y": round(top + plot_h - pass_h - gap - fail_h, 1),
                "fail_h": round(fail_h, 1),
                "day": d["day"],
                "pass": d["pass"],
                "fail": d["fail"],
                "show_label": i % max(n // 10, 1) == 0,
                "link": f"/reports?day={d['day'].isoformat()}"
                + (f"&domain={domain}" if domain else ""),
            }
        )
    return {
        "width": width,
        "height": height,
        "baseline": top + plot_h,
        "left": left,
        "top": top,
        "peak": peak,
        "mid": peak // 2,
        "mid_y": round(top + plot_h / 2, 1),
        "bars": bars,
    }


@router.get("/graphs", response_class=HTMLResponse)
def graphs_page(request: Request, domain: str = "", days: int = 30):
    days = 90 if days >= 90 else 30
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        domains = [d.name for d in db.scalars(select(Domain).order_by(Domain.name))]
        if domain and domain not in domains:
            domain = ""
        series = _daily_series(db, domain, days)
        totals = {
            "pass": sum(d["pass"] for d in series),
            "fail": sum(d["fail"] for d in series),
        }
        totals["total"] = totals["pass"] + totals["fail"]
        totals["rate"] = round(100 * totals["pass"] / totals["total"]) if totals["total"] else None
        return templates.TemplateResponse(
            request,
            "graphs.html",
            _ctx(
                request,
                user,
                chart=_chart_geometry(series, domain),
                series=[d for d in series if d["pass"] or d["fail"]],
                totals=totals,
                domains=domains,
                domain=domain,
                days=days,
            ),
        )


@router.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        return templates.TemplateResponse(
            request,
            "upload.html",
            _ctx(request, user, result=request.session.pop("upload_result", None)),
        )


@router.post("/upload")
async def upload_reports(request: Request, files: list[UploadFile] = File(...)):
    from dmarc_service.ingest.pipeline import process_upload

    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)

        totals = {"aggregate": 0, "tlsrpt": 0, "skipped": 0, "files": 0}
        errors: list[str] = []
        for upload in files:
            content = await upload.read()
            if not content:
                continue
            try:
                stored = process_upload(db, upload.filename or "upload", content)
            except Exception as exc:  # noqa: BLE001 - report per file, keep going
                errors.append(f"{upload.filename}: {exc}")
                continue
            totals["files"] += 1
            for key in ("aggregate", "tlsrpt", "skipped"):
                totals[key] += stored[key]

        request.session["upload_result"] = {**totals, "errors": errors[:10]}
    return RedirectResponse("/upload", status_code=303)


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, domain: str = "", day: str = ""):
    from datetime import date, datetime, time

    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        query = select(AggregateReport).order_by(AggregateReport.date_end.desc())
        if domain:
            query = query.where(AggregateReport.policy_domain == domain.lower())
        picked = None
        if day:
            try:
                picked = date.fromisoformat(day)
            except ValueError:
                picked = None
        if picked:
            day_start = datetime.combine(picked, time.min, tzinfo=UTC)
            day_end = datetime.combine(picked, time.max, tzinfo=UTC)
            # reports whose period overlaps the picked day
            query = query.where(
                AggregateReport.date_begin <= day_end, AggregateReport.date_end >= day_start
            )
        reports = db.scalars(query.limit(200)).all()
        rows = [_report_row(db, r) for r in reports]
        domains = [d.name for d in db.scalars(select(Domain).order_by(Domain.name))]
        return templates.TemplateResponse(
            request,
            "reports.html",
            _ctx(request, user, reports=rows, domains=domains, domain=domain,
                 day=picked.isoformat() if picked else ""),
        )


@router.post("/domains/{name}/dns/recheck")
def recheck_dns(request: Request, name: str):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        required = control_plane.required_dns_records(db, domain)
        request.session["dns_rechecked"] = control_plane.force_dns_recheck(
            [r.name for r in required]
        )
    return RedirectResponse(f"/domains/{name}", status_code=303)


@router.post("/domains/{name}/delete")
def delete_domain_form(request: Request, name: str):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        control_plane.delete_domain(db, domain)
    return RedirectResponse("/tenants", status_code=303)


@router.post("/tenants/{slug}/delete")
def delete_tenant_form(request: Request, slug: str):
    with session_scope() as db:
        user = _current_user(request, db)
        if user is None:
            return _login_redirect(db)
        tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        if tenant.slug == UNROUTED_TENANT_SLUG:
            raise HTTPException(status_code=400, detail="the quarantine tenant is built-in")
        if not control_plane.delete_tenant(db, tenant):
            return RedirectResponse(
                "/tenants?error=delete+the+tenant%27s+domains+first", status_code=303
            )
    return RedirectResponse("/tenants", status_code=303)


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
