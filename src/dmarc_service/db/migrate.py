from pathlib import Path

from alembic import command
from alembic.config import Config

from dmarc_service.config import get_settings


def _alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    config.set_main_option("sqlalchemy.url", get_settings().database_url)
    return config


def upgrade() -> None:
    command.upgrade(_alembic_config(), "head")
