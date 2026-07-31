"""imap accounts

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-31

"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "imap_accounts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("use_ssl", sa.Boolean, nullable=False),
        sa.Column("username", sa.String(320), nullable=False),
        sa.Column("password_encrypted", sa.Text, nullable=False),
        sa.Column("folder", sa.String(255), nullable=False),
        sa.Column("processed_folder", sa.String(255), nullable=False),
        sa.Column("catch_all", sa.Boolean, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_result", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("imap_accounts")
