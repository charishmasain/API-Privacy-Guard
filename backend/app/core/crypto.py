"""Credential encryption + sensitive-value masking helpers.

Bearer tokens are encrypted at rest with Fernet (AES-128-CBC + HMAC) using a
locally generated key stored outside the DB in data/.secret.key.
Full credentials are NEVER logged or returned to the frontend.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import KEY_FILE

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as fh:
                key = fh.read().strip()
        else:
            key = Fernet.generate_key()
            # restrict to owner on POSIX; best-effort on Windows
            fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        _fernet = Fernet(key)
    return _fernet


def encrypt_token(plaintext: str) -> str:
    """Encrypt a bearer token for storage at rest."""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a stored token. Raises ValueError when the key does not match."""
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:  # pragma: no cover
        raise ValueError("Unable to decrypt stored credential") from exc


def mask_token(token: str) -> str:
    """Return a display-safe mask such as 'mock****3f8a'. Never exposes the full value."""
    if not token:
        return "****"
    if len(token) <= 8:
        return "****"
    return f"{token[:4]}****{token[-4:]}"

