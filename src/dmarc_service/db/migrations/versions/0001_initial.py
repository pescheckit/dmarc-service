"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-29

Tables are spelled out rather than taken from the models: the models keep
growing, and generating this revision from them would create tables that
later revisions also create, which breaks every fresh installation.
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("name", sa.String(253), nullable=False, unique=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "report_addresses",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), nullable=False, index=True),
        sa.Column("local_part", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "raw_messages",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("mail_from", sa.String(320), nullable=False),
        sa.Column("rcpt_to", sa.String(320), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("content", sa.LargeBinary, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, index=True),
        sa.Column("error", sa.Text, nullable=False),
    )
    op.create_table(
        "aggregate_reports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), index=True),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), index=True),
        sa.Column("raw_message_id", sa.Integer, sa.ForeignKey("raw_messages.id")),
        sa.Column("org_name", sa.String(255), nullable=False),
        sa.Column("org_email", sa.String(320), nullable=False),
        sa.Column("report_id", sa.String(255), nullable=False),
        sa.Column("date_begin", sa.DateTime(timezone=True), nullable=False),
        sa.Column("date_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_domain", sa.String(253), nullable=False, index=True),
        sa.Column("policy_adkim", sa.String(1), nullable=False),
        sa.Column("policy_aspf", sa.String(1), nullable=False),
        sa.Column("policy_p", sa.String(16), nullable=False),
        sa.Column("policy_sp", sa.String(16), nullable=False),
        sa.Column("policy_pct", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_name", "report_id", "policy_domain", name="uq_aggregate_report"),
    )
    op.create_table(
        "aggregate_records",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "report_id", sa.Integer, sa.ForeignKey("aggregate_reports.id"),
            nullable=False, index=True,
        ),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("count", sa.Integer, nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        sa.Column("dkim_result", sa.String(16), nullable=False),
        sa.Column("spf_result", sa.String(16), nullable=False),
        sa.Column("header_from", sa.String(253), nullable=False),
        sa.Column("envelope_from", sa.String(253), nullable=False),
        sa.Column("auth_dkim_domain", sa.String(253), nullable=False),
        sa.Column("auth_dkim_result", sa.String(16), nullable=False),
        sa.Column("auth_spf_domain", sa.String(253), nullable=False),
        sa.Column("auth_spf_result", sa.String(16), nullable=False),
    )
    op.create_table(
        "tls_reports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), index=True),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), index=True),
        sa.Column("raw_message_id", sa.Integer, sa.ForeignKey("raw_messages.id")),
        sa.Column("organization_name", sa.String(255), nullable=False),
        sa.Column("report_id", sa.String(255), nullable=False),
        sa.Column("date_begin", sa.DateTime(timezone=True), nullable=False),
        sa.Column("date_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("contact_info", sa.String(320), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.UniqueConstraint("organization_name", "report_id", name="uq_tls_report"),
    )


def downgrade() -> None:
    for table in (
        "tls_reports",
        "aggregate_records",
        "aggregate_reports",
        "raw_messages",
        "report_addresses",
        "domains",
        "tenants",
    ):
        op.drop_table(table)
