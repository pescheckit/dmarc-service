"""Database schema.

Design notes:
- report_addresses are bearer tokens: anyone who knows an address can inject
  reports for that domain, so local parts are unguessable and rotatable.
  A domain may have two active addresses during a rotation window.
- The "unrouted" tenant quarantines mail whose recipient matches no active
  address (typo'd records, mid-rotation stragglers) instead of dropping it.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


UNROUTED_TENANT_SLUG = "unrouted"


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    domains: Mapped[list["Domain"]] = relationship(back_populates="tenant")


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="domains")
    addresses: Mapped[list["ReportAddress"]] = relationship(back_populates="domain")


class ReportAddress(Base):
    __tablename__ = "report_addresses"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), index=True)
    local_part: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    domain: Mapped[Domain] = relationship(back_populates="addresses")


class RawMessage(Base):
    """Every message accepted over SMTP or /api/ingest, verbatim."""

    __tablename__ = "raw_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_ip: Mapped[str] = mapped_column(String(45), default="")
    mail_from: Mapped[str] = mapped_column(String(320), default="")
    rcpt_to: Mapped[str] = mapped_column(String(320), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[bytes] = mapped_column(LargeBinary)
    # routed | unrouted | failed
    status: Mapped[str] = mapped_column(String(16), default="routed", index=True)
    error: Mapped[str] = mapped_column(Text, default="")


class AggregateReport(Base):
    __tablename__ = "aggregate_reports"
    __table_args__ = (
        UniqueConstraint("org_name", "report_id", "policy_domain", name="uq_aggregate_report"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domains.id"), index=True)
    raw_message_id: Mapped[int | None] = mapped_column(ForeignKey("raw_messages.id"))

    org_name: Mapped[str] = mapped_column(String(255))
    org_email: Mapped[str] = mapped_column(String(320), default="")
    report_id: Mapped[str] = mapped_column(String(255))
    date_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    date_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    policy_domain: Mapped[str] = mapped_column(String(253), index=True)
    policy_adkim: Mapped[str] = mapped_column(String(1), default="r")
    policy_aspf: Mapped[str] = mapped_column(String(1), default="r")
    policy_p: Mapped[str] = mapped_column(String(16), default="none")
    policy_sp: Mapped[str] = mapped_column(String(16), default="")
    policy_pct: Mapped[int] = mapped_column(Integer, default=100)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    records: Mapped[list["AggregateRecord"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )


class AggregateRecord(Base):
    __tablename__ = "aggregate_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("aggregate_reports.id"), index=True)

    source_ip: Mapped[str] = mapped_column(String(45))
    count: Mapped[int] = mapped_column(Integer)
    disposition: Mapped[str] = mapped_column(String(16), default="none")
    dkim_result: Mapped[str] = mapped_column(String(16), default="")
    spf_result: Mapped[str] = mapped_column(String(16), default="")
    header_from: Mapped[str] = mapped_column(String(253), default="")
    envelope_from: Mapped[str] = mapped_column(String(253), default="")
    auth_dkim_domain: Mapped[str] = mapped_column(String(253), default="")
    auth_dkim_result: Mapped[str] = mapped_column(String(16), default="")
    auth_spf_domain: Mapped[str] = mapped_column(String(253), default="")
    auth_spf_result: Mapped[str] = mapped_column(String(16), default="")

    report: Mapped[AggregateReport] = relationship(back_populates="records")


class TlsReport(Base):
    __tablename__ = "tls_reports"
    __table_args__ = (
        UniqueConstraint("organization_name", "report_id", name="uq_tls_report"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    domain_id: Mapped[int | None] = mapped_column(ForeignKey("domains.id"), index=True)
    raw_message_id: Mapped[int | None] = mapped_column(ForeignKey("raw_messages.id"))

    organization_name: Mapped[str] = mapped_column(String(255))
    report_id: Mapped[str] = mapped_column(String(255))
    date_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    date_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    contact_info: Mapped[str] = mapped_column(String(320), default="")
    # Raw report JSON, kept whole: policies/summaries/failure details.
    body: Mapped[str] = mapped_column(Text)
    # via SMTP (mailto) or HTTPS POST to /tlsrpt
    source: Mapped[str] = mapped_column(String(8), default="smtp")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
