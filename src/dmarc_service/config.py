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

    # Key for secrets stored in the database (mailbox passwords). Falls back
    # to session_secret; keep it out of the database itself.
    credentials_key: str = ""

    # IMAP intake (optional). The default path is receiving mail directly on
    # port 25; poll a mailbox instead when that is impossible, or to import
    # reports that already collect somewhere.
    imap_host: str = ""
    imap_port: int = 993
    imap_ssl: bool = True
    imap_starttls: bool = False
    imap_username: str = ""
    imap_password: str = ""
    imap_folder: str = "INBOX"
    # Where to move processed mail; empty leaves it in place, marked read.
    imap_processed_folder: str = ""
    imap_poll_interval: int = 300

    # Backups. One URL holds everything needed:
    #   s3://<access-key>:<secret-key>@<endpoint-host>/<bucket>[/<prefix>]
    # e.g. s3://KEY:SECRET@s3.eu-central-1.wasabisys.com/dmarc-backups/prod
    backup_s3_url: str = ""
    backup_retention_days: int = 30

    # Web
    web_host: str = "0.0.0.0"
    web_port: int = 8000

    # Prometheus metrics, served on their own listener and never on the web
    # port. The labels name your tenants and domains and say which of them
    # have no working DMARC record, which is a target list, so this must not
    # follow the UI onto the public internet. Off unless asked for, and it
    # refuses to start without a token unless you opt out in writing.
    metrics_enabled: bool = False
    metrics_host: str = "0.0.0.0"  # containers need this; the port stays private
    metrics_port: int = 9100
    metrics_token: str = ""  # scrapers send "Authorization: Bearer <token>"
    metrics_allow_unauthenticated: bool = False
    # Include tenant, domain and mailbox names as labels. Turn this off to
    # publish only totals, for a Prometheus shared more widely than the data.
    metrics_labels: bool = True
    # Seconds between the background DNS/SPF checks behind the per-domain
    # gauges. Scrapes read the last result and never wait on a lookup.
    metrics_dns_interval: int = 900

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
