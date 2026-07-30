"""Backups: URL parsing, dumping, upload and retention."""

import gzip
from pathlib import Path

import pytest

from dmarc_service import backup


def test_destination_parses_a_wasabi_url():
    d = backup.Destination(
        "s3://AKIAEXAMPLE:se%2Fcret%2Bkey@s3.eu-central-1.wasabisys.com/dmarc-backups/prod"
    )
    assert d.endpoint == "https://s3.eu-central-1.wasabisys.com"
    assert d.bucket == "dmarc-backups"
    assert d.prefix == "prod"
    assert d.access_key == "AKIAEXAMPLE"
    assert d.secret_key == "se/cret+key"  # percent-encoding survives
    assert d.key_for("dump.sql.gz") == "prod/dump.sql.gz"


def test_destination_without_prefix():
    d = backup.Destination("s3://key:secret@s3.example.com/bucket")
    assert d.prefix == ""
    assert d.key_for("dump.sql.gz") == "dump.sql.gz"


@pytest.mark.parametrize(
    "url",
    ["https://no-scheme-support", "s3://s3.example.com/bucket", "s3://k:s@host"],
)
def test_bad_urls_are_rejected(url):
    with pytest.raises(ValueError):
        backup.Destination(url)


def test_sqlite_dump_round_trip(db, tmp_path, settings_env):
    dump = backup.create_dump(tmp_path)
    assert dump.exists() and dump.name.endswith(".sql.gz")
    with gzip.open(dump, "rb") as handle:
        assert handle.read(16).startswith(b"SQLite format 3")


def test_run_uploads_and_prunes(db, tmp_path, settings_env, monkeypatch):
    from datetime import UTC, datetime, timedelta

    monkeypatch.setenv("BACKUP_S3_URL", "s3://k:s@s3.example.com/bucket/prefix")
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "7")
    from dmarc_service.config import get_settings

    get_settings.cache_clear()

    uploaded, deleted = [], []
    old = datetime.now(UTC) - timedelta(days=30)
    fresh = datetime.now(UTC)

    class FakeClient:
        def upload_file(self, path, bucket, key):
            uploaded.append((Path(path).name, bucket, key))

        def get_paginator(self, _):
            class Paginator:
                def paginate(self, **kwargs):
                    return [{"Contents": [
                        {"Key": "prefix/old.sql.gz", "LastModified": old},
                        {"Key": "prefix/new.sql.gz", "LastModified": fresh},
                    ]}]
            return Paginator()

        def delete_object(self, Bucket, Key):  # noqa: N803 - boto3 signature
            deleted.append(Key)

    monkeypatch.setattr(backup, "_client", lambda destination: FakeClient())
    key = backup.run()

    assert key.startswith("prefix/dmarc-") and key.endswith(".sql.gz")
    assert uploaded and uploaded[0][1] == "bucket"
    assert deleted == ["prefix/old.sql.gz"]  # only what is past retention
