"""Application settings, all overridable via environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Core
    database_url: str = "sqlite:///./dmarc.db"
    external_url: str = "http://localhost:8000"
    # The hostname reports are addressed to, e.g. "dmarc.example.com".
    # Report addresses look like <local_part>@<report_host>.
    report_host: str = "localhost"

    # Tenancy
    tenancy_mode: Literal["single", "multi"] = "multi"
    control_plane_enabled: bool = True
    # Name of the implicit tenant in single-tenant mode
    default_tenant: str = "default"

    # Auth. Empty string disables the check (e.g. UI/API protected upstream).
    api_token: str = ""
    # Cookie-signing key; empty = random per process (sessions reset on restart).
    session_secret: str = ""
    # Token the SMTP edge uses to POST raw messages to /api/ingest.
    # Required for /api/ingest; the endpoint is disabled when empty.
    ingest_token: str = ""

    # Backups. One URL holds everything needed:
    #   s3://<access-key>:<secret-key>@<endpoint-host>/<bucket>[/<prefix>]
    # e.g. s3://KEY:SECRET@s3.eu-central-1.wasabisys.com/dmarc-backups/prod
    backup_s3_url: str = ""
    backup_retention_days: int = 30

    # Web
    web_host: str = "0.0.0.0"
    web_port: int = 8000

    # SMTP receiver
    smtp_host: str = "0.0.0.0"
    smtp_port: int = 2525
    smtp_max_message_bytes: int = 52_428_800  # 50 MB; big aggregate reports are real
    # direct: parse and store into the database.
    # forward: relay raw messages to another instance's /api/ingest (for
    # environments where the web app runs somewhere port 25 is blocked).
    smtp_mode: Literal["direct", "forward"] = "direct"
    smtp_forward_url: str = ""  # e.g. https://dmarc.example.com/api/ingest
    smtp_forward_token: str = ""
    # Optional STARTTLS. Opportunistic: plaintext is still accepted.
    smtp_tls_cert: str = ""
    smtp_tls_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
