"""Database backup to any S3-compatible object storage.

Reports cannot be re-fetched: senders will not resend yesterday's aggregate
report, so a lost database is lost history. This dumps the database, uploads
it, and prunes old copies. It works with AWS S3, Scaleway Object Storage,
MinIO, Backblaze B2 and friends, since all of them speak the S3 API.

Run it from cron, a systemd timer, or a Kubernetes CronJob:

    dmarc-service backup
"""

import gzip
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlparse

from dmarc_service.config import get_settings

logger = logging.getLogger(__name__)


def _dump_postgres(database_url: str, target: Path) -> None:
    """pg_dump into a gzipped custom-format file."""
    parsed = urlparse(database_url.replace("postgresql+psycopg://", "postgresql://"))
    env = dict(os.environ)
    if parsed.password:
        env["PGPASSWORD"] = parsed.password

    command = [
        "pg_dump",
        "--host", parsed.hostname or "localhost",
        "--port", str(parsed.port or 5432),
        "--username", parsed.username or "postgres",
        "--dbname", (parsed.path or "/").lstrip("/"),
        "--no-owner",
        "--no-privileges",
    ]
    with tempfile.NamedTemporaryFile(delete=False) as plain:
        result = subprocess.run(command, stdout=plain, stderr=subprocess.PIPE, env=env, check=False)
        plain_path = Path(plain.name)
    if result.returncode != 0:
        plain_path.unlink(missing_ok=True)
        raise RuntimeError(f"pg_dump failed: {result.stderr.decode()[:400]}")

    with plain_path.open("rb") as src, gzip.open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
    plain_path.unlink(missing_ok=True)


def _dump_sqlite(database_url: str, target: Path) -> None:
    source = Path(database_url.split("///")[-1])
    if not source.exists():
        raise RuntimeError(f"sqlite database {source} not found")
    with source.open("rb") as src, gzip.open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)


def create_dump(directory: Path) -> Path:
    settings = get_settings()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = directory / f"dmarc-{stamp}.sql.gz"
    if settings.database_url.startswith("sqlite"):
        _dump_sqlite(settings.database_url, target)
    else:
        _dump_postgres(settings.database_url, target)
    return target


class Destination:
    """Everything the uploader needs, parsed from one S3 URL."""

    def __init__(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ("s3", "s3s", "https"):
            raise ValueError("backup URL must start with s3://")
        if not parsed.hostname or not parsed.username:
            raise ValueError(
                "backup URL must look like "
                "s3://<access-key>:<secret-key>@<endpoint-host>/<bucket>[/<prefix>]"
            )
        path = (parsed.path or "").strip("/").split("/", 1)
        if not path or not path[0]:
            raise ValueError("backup URL is missing the bucket name")

        self.access_key = unquote(parsed.username)
        self.secret_key = unquote(parsed.password or "")
        self.endpoint = f"https://{parsed.hostname}"
        if parsed.port:
            self.endpoint += f":{parsed.port}"
        self.bucket = path[0]
        self.prefix = path[1].strip("/") if len(path) > 1 else ""

    def key_for(self, filename: str) -> str:
        return f"{self.prefix}/{filename}" if self.prefix else filename


def _client(destination: "Destination"):
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=destination.endpoint,
        aws_access_key_id=destination.access_key,
        aws_secret_access_key=destination.secret_key,
        # S3-compatible providers ignore the region but boto3 insists on one
        region_name="us-east-1",
    )


def run() -> str:
    """Dump, upload, prune. Returns the object key written."""
    settings = get_settings()
    if not settings.backup_s3_url:
        raise SystemExit("BACKUP_S3_URL is not set; nothing to back up to")
    destination = Destination(settings.backup_s3_url)

    with tempfile.TemporaryDirectory() as workdir:
        dump = create_dump(Path(workdir))
        size = dump.stat().st_size
        key = destination.key_for(dump.name)
        _client(destination).upload_file(str(dump), destination.bucket, key)
        logger.info("uploaded %s (%d bytes)", key, size)

    removed = prune(destination, settings.backup_retention_days)
    if removed:
        logger.info("pruned %d expired backup(s)", removed)
    return key


def prune(destination: "Destination", retention_days: int) -> int:
    """Delete backups older than the retention window."""
    if retention_days <= 0:
        return 0

    client = _client(destination)
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    paginator = client.get_paginator("list_objects_v2")

    removed = 0
    for page in paginator.paginate(Bucket=destination.bucket, Prefix=destination.prefix):
        for obj in page.get("Contents", []) or []:
            if obj["LastModified"] < cutoff:
                client.delete_object(Bucket=destination.bucket, Key=obj["Key"])
                removed += 1
    return removed
