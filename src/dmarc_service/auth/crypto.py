"""Encrypt secrets that have to live in the database.

Mailbox passwords cannot be hashed: the poller needs to present them. They are
encrypted instead, with a key derived from CREDENTIALS_KEY when set, otherwise
SESSION_SECRET. Keeping the key outside the database means a dump on its own
does not hand over mailbox access.
"""

import base64
import hashlib

from dmarc_service.config import get_settings


def _key() -> bytes:
    settings = get_settings()
    secret = settings.credentials_key or settings.session_secret
    if not secret:
        raise SystemExit(
            "set CREDENTIALS_KEY (or SESSION_SECRET) before storing mailbox "
            "credentials, otherwise they cannot be encrypted"
        )
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


def encrypt(value: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_key()).encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_key()).decrypt(value.encode()).decode()
