"""
EclipseCode Auth
-----------------
Salted SHA-256 password hashing for admin credentials.
Replaces the hardcoded 'admin123' from v1.

Passwords are never stored in plaintext — only their salted hash.
Credentials are stored in a local JSON file: .ec_credentials
"""

import os
import json
import hashlib
from pathlib import Path
from core.exceptions import AuthenticationError

CREDENTIALS_FILE = ".ec_credentials"
SALT_SIZE = 32


def _hash_password(password: str, salt: bytes) -> str:
    """Return SHA-256 hex digest of password + salt."""
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def setup_admin(password: str) -> None:
    """
    Create admin credentials file with a salted hash.
    Call this once on first run.
    Raises AuthenticationError if credentials already exist.
    """
    if Path(CREDENTIALS_FILE).exists():
        raise AuthenticationError(
            "Credentials already exist.",
            details="Delete .ec_credentials to reset."
        )
    if len(password) < 8:
        raise AuthenticationError("Password must be at least 8 characters.")

    salt = os.urandom(SALT_SIZE)
    hashed = _hash_password(password, salt)
    payload = {
        "salt": salt.hex(),
        "hash": hashed
    }
    Path(CREDENTIALS_FILE).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("[Auth] Admin credentials saved.")


def verify_admin(password: str) -> bool:
    """
    Verify a password against stored credentials.
    Returns True if correct, False otherwise.
    Raises AuthenticationError if no credentials file exists.
    """
    if not Path(CREDENTIALS_FILE).exists():
        raise AuthenticationError(
            "No admin credentials found.",
            details="Run setup_admin() to create credentials first."
        )
    payload = json.loads(Path(CREDENTIALS_FILE).read_text(encoding="utf-8"))
    salt = bytes.fromhex(payload["salt"])
    expected = payload["hash"]
    return _hash_password(password, salt) == expected


def credentials_exist() -> bool:
    """Return True if admin credentials have been set up."""
    return Path(CREDENTIALS_FILE).exists()