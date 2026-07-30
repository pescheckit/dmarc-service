"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-29

"""
from alembic import op

from dmarc_service.db.models import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Initial revision creates the schema straight from the models; later
    # revisions must be written as explicit alembic operations.
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind())
