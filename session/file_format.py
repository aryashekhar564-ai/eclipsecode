"""
EclipseCode File Format (.ec)
------------------------------
Every encrypted file produced by EclipseCode has this structure:

    [4 bytes]  Magic number: b"EC02"
    [4 bytes]  Header length (unsigned int, big-endian)
    [N bytes]  JSON header (UTF-8)
    [remaining] Raw ciphertext bytes

The JSON header contains everything needed to decrypt the file:
    {
        "cipher":    "aes",
        "mode":      "password" | "keyfile" | "keypair",
        "salt":      "<hex>",      # for PBKDF2 (password mode)
        "iv":        "<hex>",      # for AES (generated per operation)
        "pub_key":   "<hex>",      # for RSA keypair mode
        "sha256":    "<hex>",      # SHA-256 of the ORIGINAL plaintext
        "filename":  "report.pdf", # original filename for restore
        "timestamp": "2026-06-04T10:30:00"
    }

This means the user never has to remember which cipher or parameters
were used — the file remembers everything.
"""

import json
import struct
import hashlib
from datetime import datetime, timezone
from core.exceptions import FileFormatError

MAGIC = b"EC02"
MAGIC_SIZE = 4
HEADER_LEN_SIZE = 4  # unsigned int = 4 bytes


def compute_sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected_hex: str) -> bool:
    """Return True if SHA-256 of data matches the expected hex string."""
    return hashlib.sha256(data).hexdigest() == expected_hex


def build_header(
    cipher_id: str,
    mode: str,
    original_filename: str,
    plaintext_sha256: str,
    salt_hex: str = "",
    iv_hex: str = "",
    pub_key_hex: str = "",
) -> dict:
    """
    Build the metadata dictionary that goes into the .ec file header.

    Args:
        cipher_id:          e.g. "aes", "caesar"
        mode:               "password", "keyfile", or "keypair"
        original_filename:  e.g. "report.pdf"
        plaintext_sha256:   SHA-256 of the original file before encryption
        salt_hex:           PBKDF2 salt (password mode only)
        iv_hex:             AES initialisation vector (AES only)
        pub_key_hex:        RSA public key hex (keypair mode only)
    """
    return {
        "cipher":    cipher_id,
        "mode":      mode,
        "salt":      salt_hex,
        "iv":        iv_hex,
        "pub_key":   pub_key_hex,
        "sha256":    plaintext_sha256,
        "filename":  original_filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def pack(header: dict, ciphertext: bytes) -> bytes:
    """
    Pack a header dict + ciphertext into a complete .ec file as bytes.

    Structure:
        MAGIC (4) | header_length (4) | header_json (N) | ciphertext
    """
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    header_length = struct.pack(">I", len(header_bytes))  # big-endian unsigned int
    return MAGIC + header_length + header_bytes + ciphertext


def unpack(ec_bytes: bytes) -> tuple[dict, bytes]:
    """
    Parse a .ec file's raw bytes into (header dict, ciphertext bytes).

    Raises FileFormatError if the file is malformed.
    """
    # Check minimum size: magic + header_length field
    if len(ec_bytes) < MAGIC_SIZE + HEADER_LEN_SIZE:
        raise FileFormatError(
            "File is too short to be a valid .ec file.",
            details="The file may be corrupt or not an EclipseCode file."
        )

    # Verify magic number
    if ec_bytes[:MAGIC_SIZE] != MAGIC:
        raise FileFormatError(
            "Invalid magic number — this is not an EclipseCode .ec file.",
            details=f"Expected {MAGIC}, got {ec_bytes[:MAGIC_SIZE]}"
        )

    # Read header length
    header_length = struct.unpack(">I", ec_bytes[MAGIC_SIZE:MAGIC_SIZE + HEADER_LEN_SIZE])[0]

    # Slice out header bytes
    header_start = MAGIC_SIZE + HEADER_LEN_SIZE
    header_end = header_start + header_length

    if len(ec_bytes) < header_end:
        raise FileFormatError(
            "File header is truncated.",
            details="The file may be corrupt or incomplete."
        )

    header_bytes = ec_bytes[header_start:header_end]

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise FileFormatError(
            "Failed to parse .ec file header.",
            details=str(e)
        )

    # Everything after the header is ciphertext
    ciphertext = ec_bytes[header_end:]

    return header, ciphertext


def write_ec_file(path: str, header: dict, ciphertext: bytes) -> None:
    """Pack and write an .ec file to disk."""
    with open(path, "wb") as f:
        f.write(pack(header, ciphertext))


def read_ec_file(path: str) -> tuple[dict, bytes]:
    """Read an .ec file from disk and return (header, ciphertext)."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise FileFormatError(
            f"Could not read file: {path}",
            details=str(e)
        )
    return unpack(raw)