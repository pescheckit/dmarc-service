"""FastAPI application: JSON API, TLS-RPT https endpoint, and the web UI."""

import gzip
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from dmarc_service.config import get_settings
from dmarc_service.control_plane import service as control_plane
from dmarc_service.db.models import (
    AggregateRecord,
    AggregateReport,
    Domain,
    RawMessage,
    Tenant,
    TlsReport,
)
from dmarc_service.db.session import session_scope
from dmarc_service.ingest.pipeline import process_message, process_tlsrpt_http


@asynccontextmanager
async def lifespan(app: FastAPI):
    with session_scope() as db:
        control_plane.bootstrap(db)
    yield


# Docs are re-served behind UI login (see api/ui.py), not exposed publicly.
app = FastAPI(
    title="dmarc-service",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().session_secret or secrets.token_hex(32),
    same_site="lax",
    https_only=False,  # cookie Secure flag is the proxy's concern
)

from dmarc_service.api import ui  # noqa: E402  (router needs `app` patterns above)

app.include_router(ui.router)


# --- auth dependencies ---


def require_api_token(authorization: str = Header(default="")) -> None:
    """Accepts the static API_TOKEN (automation/back-compat) or any personal
    token minted in the UI. The API is only open when neither exists —
    i.e. a fresh install that hasn't completed /setup yet."""
    from dmarc_service.auth import service as auth

    settings = get_settings()
    bearer = authorization.removeprefix("Bearer ").strip()
    if settings.api_token and bearer == settings.api_token:
        return
    with session_scope() as db:
        if bearer and auth.resolve_api_token(db, bearer) is not None:
            return
        if not settings.api_token and auth.user_count(db) == 0:
            return  # bootstrap: nothing to authenticate against yet
    raise HTTPException(status_code=401, detail="invalid or missing API token")


def require_ingest_token(authorization: str = Header(default="")) -> None:
    settings = get_settings()
    if not settings.ingest_token:
        raise HTTPException(status_code=404, detail="ingest endpoint disabled")
    if authorization != f"Bearer {settings.ingest_token}":
        raise HTTPException(status_code=401, detail="invalid or missing ingest token")


# --- health ---


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# --- TLS-RPT https rua endpoint (RFC 8460 §5.3: unauthenticated POST) ---


@app.post("/tlsrpt", status_code=201)
async def tlsrpt(request: Request):
    body = await request.body()
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    try:
        with session_scope() as db:
            stored = process_tlsrpt_http(db, body)
    except Exception as exc:  # malformed sender input, reply 400
        raise HTTPException(status_code=400, detail=f"unparsable TLS-RPT report: {exc}") from exc
    return {"stored": stored}


# --- ingest endpoint for forward-mode SMTP edges ---


@app.post("/api/ingest", status_code=201, dependencies=[Depends(require_ingest_token)])
async def ingest(
    request: Request,
    x_source_ip: str = Header(default=""),
    x_mail_from: str = Header(default=""),
    x_rcpt_to: str = Header(default=""),
):
    content = await request.body()
    if not content:
        raise HTTPException(status_code=400, detail="empty message")
    with session_scope() as db:
        raw = process_message(
            db, content, source_ip=x_source_ip, mail_from=x_mail_from, rcpt_to=x_rcpt_to
        )
        return {"id": raw.id, "status": raw.status}


# --- control plane ---


class TenantIn(BaseModel):
    slug: str
    name: str = ""


class DomainIn(BaseModel):
    name: str


def _control_plane_guard():
    if not get_settings().control_plane_enabled:
        raise HTTPException(status_code=404, detail="control plane disabled")


@app.post("/api/tenants", status_code=201, dependencies=[Depends(require_api_token)])
def create_tenant(body: TenantIn):
    _control_plane_guard()
    if get_settings().tenancy_mode == "single":
        raise HTTPException(status_code=400, detail="single-tenant mode: tenants are implicit")
    with session_scope() as db:
        if db.scalar(select(Tenant).where(Tenant.slug == body.slug)):
            raise HTTPException(status_code=409, detail="tenant exists")
        tenant = control_plane.create_tenant(db, body.slug, body.name or body.slug)
        return {"id": tenant.id, "slug": tenant.slug}


@app.get("/api/tenants", dependencies=[Depends(require_api_token)])
def list_tenants():
    with session_scope() as db:
        return [
            {"id": t.id, "slug": t.slug, "name": t.name}
            for t in db.scalars(select(Tenant).order_by(Tenant.slug))
        ]


@app.post(
    "/api/tenants/{slug}/domains", status_code=201, dependencies=[Depends(require_api_token)]
)
def add_domain(slug: str, body: DomainIn):
    _control_plane_guard()
    with session_scope() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        if db.scalar(select(Domain).where(Domain.name == body.name.lower())):
            raise HTTPException(status_code=409, detail="domain exists")
        domain = control_plane.add_domain(db, tenant, body.name)
        return _domain_out(db, domain)


@app.get("/api/domains/{name}/dns", dependencies=[Depends(require_api_token)])
def domain_dns(name: str):
    with session_scope() as db:
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        return [
            {
                "zone": r.zone,
                "name": r.name,
                "type": r.type,
                "content": r.content,
                "published_by": r.published_by,
            }
            for r in control_plane.required_dns_records(db, domain)
        ]


@app.post(
    "/api/domains/{name}/addresses", status_code=201, dependencies=[Depends(require_api_token)]
)
def rotate_address(name: str):
    """Mint an additional active address (rotation step 1). Deactivate the
    old one with DELETE once DNS has propagated."""
    _control_plane_guard()
    with session_scope() as db:
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        address = control_plane.mint_address(db, domain)
        return {"local_part": address.local_part, "active": True}


@app.delete(
    "/api/domains/{name}/addresses/{local_part}", dependencies=[Depends(require_api_token)]
)
def deactivate_address(name: str, local_part: str):
    with session_scope() as db:
        domain = db.scalar(select(Domain).where(Domain.name == name.lower()))
        if domain is None:
            raise HTTPException(status_code=404, detail="domain not found")
        for address in domain.addresses:
            if address.local_part == local_part:
                address.active = False
                return {"local_part": local_part, "active": False}
        raise HTTPException(status_code=404, detail="address not found")


def _domain_out(db, domain: Domain) -> dict:
    return {
        "id": domain.id,
        "name": domain.name,
        "addresses": [
            {"local_part": a.local_part, "active": a.active}
            for a in control_plane.active_addresses(db, domain)
        ],
        "dns": [
            {
                "zone": r.zone,
                "name": r.name,
                "type": r.type,
                "content": r.content,
                "published_by": r.published_by,
            }
            for r in control_plane.required_dns_records(db, domain)
        ],
    }


# --- reports ---


@app.get("/api/reports", dependencies=[Depends(require_api_token)])
def list_reports(domain: str = "", limit: int = 50, offset: int = 0):
    limit = min(limit, 500)
    with session_scope() as db:
        query = select(AggregateReport).order_by(AggregateReport.date_end.desc())
        if domain:
            query = query.where(AggregateReport.policy_domain == domain.lower())
        reports = db.scalars(query.limit(limit).offset(offset)).all()
        return [_report_summary(db, r) for r in reports]


@app.get("/api/reports/{report_id}", dependencies=[Depends(require_api_token)])
def report_detail(report_id: int):
    with session_scope() as db:
        report = db.get(AggregateReport, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        out = _report_summary(db, report)
        out["records"] = [
            {
                "source_ip": r.source_ip,
                "count": r.count,
                "disposition": r.disposition,
                "dkim": r.dkim_result,
                "spf": r.spf_result,
                "header_from": r.header_from,
                "auth_dkim_domain": r.auth_dkim_domain,
                "auth_dkim_result": r.auth_dkim_result,
                "auth_spf_domain": r.auth_spf_domain,
                "auth_spf_result": r.auth_spf_result,
            }
            for r in report.records
        ]
        return out


@app.get("/api/tls-reports", dependencies=[Depends(require_api_token)])
def list_tls_reports(limit: int = 50):
    with session_scope() as db:
        reports = db.scalars(
            select(TlsReport).order_by(TlsReport.date_end.desc()).limit(min(limit, 500))
        ).all()
        return [
            {
                "id": r.id,
                "organization_name": r.organization_name,
                "report_id": r.report_id,
                "date_begin": r.date_begin,
                "date_end": r.date_end,
                "source": r.source,
            }
            for r in reports
        ]


@app.get("/api/summary", dependencies=[Depends(require_api_token)])
def summary(domain: str = ""):
    with session_scope() as db:
        query = (
            select(
                AggregateRecord.disposition,
                func.sum(AggregateRecord.count),
            )
            .join(AggregateReport)
            .group_by(AggregateRecord.disposition)
        )
        if domain:
            query = query.where(AggregateReport.policy_domain == domain.lower())
        dispositions = {row[0]: int(row[1]) for row in db.execute(query)}
        unrouted = db.scalar(
            select(func.count(RawMessage.id)).where(RawMessage.status == "unrouted")
        )
        return {"messages_by_disposition": dispositions, "unrouted_messages": unrouted}


def _report_summary(db, report: AggregateReport) -> dict:
    total = db.scalar(
        select(func.sum(AggregateRecord.count)).where(AggregateRecord.report_id == report.id)
    )
    return {
        "id": report.id,
        "org_name": report.org_name,
        "report_id": report.report_id,
        "policy_domain": report.policy_domain,
        "date_begin": report.date_begin,
        "date_end": report.date_end,
        "policy_p": report.policy_p,
        "message_count": int(total or 0),
    }


# --- misc ---


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")
