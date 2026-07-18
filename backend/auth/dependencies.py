"""
TrustField - Auth Dependencies
Password hashing, JWT creation/verification, and FastAPI dependencies
for authenticating requests and enforcing role-based access control.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config import settings
from db.database import get_db
from db.models import User, UserRole

logger = logging.getLogger(__name__)

# ─── Password Hashing ──────────────────────────────────────────────────────
#
# We call the bcrypt library directly rather than going through passlib's
# CryptContext. passlib 1.7.4's bcrypt backend runs an internal self-test
# (detect_wrap_bug) that is incompatible with bcrypt>=4.1's stricter 72-byte
# password enforcement, causing a ValueError before any real hashing happens.
# bcrypt itself works correctly — only passlib's wrapper around it is broken
# for this version pairing — so we bypass passlib for this one operation.
#
# bcrypt has a hard 72-byte input limit; passwords are truncated to that
# length before hashing, matching bcrypt's own documented behavior.

_BCRYPT_MAX_BYTES = 72


def _truncate_to_bcrypt_limit(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plaintext password against its stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            _truncate_to_bcrypt_limit(plain_password),
            hashed_password.encode("utf-8"),
        )
    except ValueError as exc:
        logger.warning(f"Password verification failed: {exc}")
        return False


def get_password_hash(password: str) -> str:
    """Hash a plaintext password for storage."""
    hashed = bcrypt.hashpw(_truncate_to_bcrypt_limit(password), bcrypt.gensalt())
    return hashed.decode("utf-8")


# ─── JWT Handling ───────────────────────────────────────────────────────────

ACCESS_TOKEN_SUBJECT_KEY = "sub"


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict] = None,
) -> str:
    """
    Create a signed JWT access token.

    `subject` is typically the user's id (as a string) or email.
    """
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {ACCESS_TOKEN_SUBJECT_KEY: str(subject), "exp": expire}
    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.
    Raises jose.JWTError if the token is invalid, expired, or malformed.
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


# ─── FastAPI Dependencies ───────────────────────────────────────────────────

# tokenUrl points at the future login endpoint. It only affects the OpenAPI
# docs' "Authorize" button — it does not need to exist yet for
# get_current_user to work with a manually-supplied bearer token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=True)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Decode the bearer token, load the corresponding user from the database,
    and return it. Raises 401 if the token is invalid/expired or the user
    no longer exists/is inactive.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        user_id = payload.get(ACCESS_TOKEN_SUBJECT_KEY)
        if user_id is None:
            raise credentials_exception
    except JWTError as exc:
        logger.warning(f"JWT validation failed: {exc}")
        raise credentials_exception from exc

    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
    except (TypeError, ValueError) as exc:
        raise credentials_exception from exc

    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return user


def require_role(*allowed_roles: UserRole):
    """
    Dependency factory for role-based access control.

    Usage:
        @router.delete("/{alert_id}", dependencies=[Depends(require_role(UserRole.ADMIN))])
        async def delete_alert(...):
            ...

    Or, to also receive the user object:
        current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))
    """

    def _checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Requires one of roles: {[r.value for r in allowed_roles]}, "
                    f"but user has role: {current_user.role.value}"
                ),
            )
        return current_user

    return _checker