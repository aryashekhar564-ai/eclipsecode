"""
EclipseCode Key Manager
------------------------
Handles all three key models:

    Model A — Password:
        User password → PBKDF2 → 32-byte AES key
        Salt is randomly generated per operation and stored in the .ec header.
        Same password + same salt always produces the same key.

    Model B — Key File:
        A random 32-byte AES key is generated and saved to a .eckey file.
        Encrypting and decrypting both require the same .eckey file.

    Model C — Keypair (RSA):
        A 2048-bit RSA keypair is generated.
        Public key (.pub) encrypts, private key (.priv) decrypts.
        Used for secure file sharing between people.
"""

import os
import json
import base64
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from core.exceptions import (
    KeyDerivationError,
    KeyFileNotFoundError,
    KeyManagementError,
)

# PBKDF2 settings — these are the industry standard minimums
PBKDF2_ITERATIONS = 600_000   # OWASP 2023 recommendation for SHA-256
PBKDF2_KEY_LENGTH = 32        # 32 bytes = 256-bit key (AES-256 ready)
SALT_SIZE         = 32        # 32 random bytes = 256-bit salt


# ── Model A — Password-Based ──────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Generate a cryptographically random salt."""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from a password and salt using PBKDF2-HMAC-SHA256.

    The same password + salt always produces the same key, which is how
    decryption works — we re-derive the key rather than storing it.

    Raises KeyDerivationError if password is empty.
    """
    if not password:
        raise KeyDerivationError(
            "Password cannot be empty.",
            details="Provide a non-empty password for key derivation."
        )

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def salt_to_hex(salt: bytes) -> str:
    """Convert salt bytes to hex string for storage in .ec header."""
    return salt.hex()


def salt_from_hex(hex_str: str) -> bytes:
    """Recover salt bytes from hex string stored in .ec header."""
    return bytes.fromhex(hex_str)


# ── Model B — Key File ────────────────────────────────────────────────────────

def generate_keyfile(output_path: str) -> bytes:
    """
    Generate a random 32-byte AES key and save it to a .eckey file.
    Returns the raw key bytes.

    The .eckey file is JSON containing the base64-encoded key:
        { "version": "1", "key": "<base64>" }
    """
    key = os.urandom(PBKDF2_KEY_LENGTH)
    payload = {
        "version": "1",
        "key": base64.b64encode(key).decode("utf-8")
    }
    path = Path(output_path)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[KeyManager] Key file saved to: {path.resolve()}")
    return key


def load_keyfile(path: str) -> bytes:
    """
    Load a 32-byte AES key from a .eckey file.
    Raises KeyFileNotFoundError if the file doesn't exist.
    Raises KeyManagementError if the file is malformed.
    """
    p = Path(path)
    if not p.exists():
        raise KeyFileNotFoundError(str(p.resolve()))

    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
        key = base64.b64decode(payload["key"])
    except (json.JSONDecodeError, KeyError, Exception) as e:
        raise KeyManagementError(
            f"Failed to read key file: {path}",
            details=str(e)
        )

    if len(key) != PBKDF2_KEY_LENGTH:
        raise KeyManagementError(
            f"Key file contains a key of invalid length: {len(key)} bytes.",
            details=f"Expected {PBKDF2_KEY_LENGTH} bytes."
        )

    return key


# ── Model C — RSA Keypair ─────────────────────────────────────────────────────

def generate_keypair(output_prefix: str) -> tuple[str, str]:
    """
    Generate a 2048-bit RSA keypair and save to:
        <output_prefix>.pub   ← public key (share this)
        <output_prefix>.priv  ← private key (keep this secret)

    Returns (pub_path, priv_path).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key (PEM, unencrypted)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (PEM)
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    priv_path = f"{output_prefix}.priv"
    pub_path  = f"{output_prefix}.pub"

    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)

    print(f"[KeyManager] Public key saved to:  {pub_path}")
    print(f"[KeyManager] Private key saved to: {priv_path}")
    print(f"[KeyManager] Keep your .priv file secret — never share it.")

    return pub_path, priv_path


def load_public_key(path: str):
    """Load an RSA public key from a .pub PEM file."""
    p = Path(path)
    if not p.exists():
        raise KeyFileNotFoundError(str(p.resolve()))
    return serialization.load_pem_public_key(p.read_bytes(), backend=default_backend())


def load_private_key(path: str):
    """Load an RSA private key from a .priv PEM file."""
    p = Path(path)
    if not p.exists():
        raise KeyFileNotFoundError(str(p.resolve()))
    return serialization.load_pem_private_key(
        p.read_bytes(),
        password=None,
        backend=default_backend()
    )


def rsa_encrypt(data: bytes, public_key) -> bytes:
    """
    Encrypt bytes using RSA-OAEP with SHA-256.
    Note: RSA can only encrypt small amounts of data directly.
    For files, AES encrypts the file and RSA encrypts the AES key.
    This is called hybrid encryption and is how real tools work.
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(data: bytes, private_key) -> bytes:
    """Decrypt RSA-OAEP encrypted bytes using a private key."""
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )