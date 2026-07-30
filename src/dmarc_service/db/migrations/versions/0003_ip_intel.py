"""ip intelligence cache

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-30

"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ip_intel",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ip", sa.String(45), nullable=False, unique=True, index=True),
        sa.Column("ptr", sa.String(253), nullable=False),
        sa.Column("netname", sa.String(128), nullable=False),
        sa.Column("org", sa.String(255), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ip_intel")
