"""Account, session, SSO, and API-token logic.

Model: the first account created becomes the admin. The admin can configure
one OIDC SSO provider; users signing in through it are auto-provisioned as
regular users. Every signed-in user can mint personal API tokens (hashed at
rest, shown once) that work as Bearer auth on /api/*.
"""

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dmarc_service.db.models import ApiToken, AuthProvider, User

_hasher = PasswordHasher()

TOKEN_PREFIX = "dmk_"


def user_count(session: Session) -> int:
    return session.scalar(select(func.count(User.id))) or 0


def create_user(
    session: Session, email: str, password: str | None, *, is_admin: bool = False
) -> User:
    user = User(
        email=email.lower().strip(),
        password_hash=_hasher.hash(password) if password else None,
        is_admin=is_admin,
    )
    session.add(user)
    session.flush()
    return user


def authenticate(session: Session, email: str, password: str) -> User | None:
    user = session.scalar(select(User).where(User.email == email.lower().strip()))
    if user is None or not user.password_hash:
        return None
    try:
        _hasher.verify(user.password_hash, password)
    except VerifyMismatchError:
        return None
    return user


def find_or_provision_sso_user(session: Session, email: str) -> User:
    user = session.scalar(select(User).where(User.email == email.lower().strip()))
    if user is None:
        # First user overall becomes admin even via SSO (fresh install edge case).
        user = create_user(session, email, None, is_admin=user_count(session) == 0)
    return user


def get_provider(session: Session) -> AuthProvider | None:
    return session.scalar(select(AuthProvider).where(AuthProvider.enabled.is_(True)))


def set_provider(
    session: Session, *, name: str, issuer: str, client_id: str, client_secret: str
) -> AuthProvider:
    # Single-provider model: replace whatever is configured.
    for existing in session.scalars(select(AuthProvider)):
        session.delete(existing)
    provider = AuthProvider(
        name=name or "SSO",
        issuer=issuer.rstrip("/"),
        client_id=client_id,
        client_secret=client_secret,
        enabled=True,
    )
    session.add(provider)
    session.flush()
    return provider


def remove_provider(session: Session) -> None:
    for existing in session.scalars(select(AuthProvider)):
        session.delete(existing)


# --- API tokens ---


def mint_api_token(session: Session, user: User, name: str) -> str:
    """Returns the cleartext token exactly once."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    session.add(
        ApiToken(
            user_id=user.id,
            name=name or "token",
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            prefix=token[:12],
        )
    )
    session.flush()
    return token


def revoke_api_token(session: Session, user: User, token_id: int) -> bool:
    token = session.get(ApiToken, token_id)
    if token is None or token.user_id != user.id:
        return False
    session.delete(token)
    return True


def resolve_api_token(session: Session, token: str) -> User | None:
    row = session.scalar(
        select(ApiToken).where(
            ApiToken.token_hash == hashlib.sha256(token.encode()).hexdigest()
        )
    )
    return session.get(User, row.user_id) if row else None
