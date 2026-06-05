"""
EclipseCode Exception Hierarchy
--------------------------------
All exceptions raised within the EclipseCode engine derive from EclipseError.
This lets callers catch at whatever granularity they need:

    except EclipseError:       # catch anything from the engine
    except CipherError:        # catch only cipher-related failures
    except KeyManagementError: # catch only key management failures
"""


class EclipseError(Exception):
    """Base class for all EclipseCode exceptions."""
    def __init__(self, message: str, details: str = ""):
        super().__init__(message)
        self.details = details

    def __str__(self):
        if self.details:
            return f"{super().__str__()} — {self.details}"
        return super().__str__()


# ── Cipher Errors ─────────────────────────────────────────────────────────────

class CipherError(EclipseError):
    """Base class for cipher operation failures."""

class EncryptionError(CipherError):
    """Raised when an encryption operation fails."""

class DecryptionError(CipherError):
    """Raised when a decryption operation fails (wrong key, corrupt data, etc.)."""

class InvalidKeyError(CipherError):
    """Raised when a cipher key is malformed or invalid for the chosen cipher."""

class UnsupportedCipherError(CipherError):
    """Raised when an unrecognised cipher ID is requested from the registry."""
    def __init__(self, cipher_id: str):
        super().__init__(
            f"Cipher '{cipher_id}' is not registered.",
            details="Use CipherRegistry.available() to see supported ciphers."
        )
        self.cipher_id = cipher_id


# ── File / Format Errors ──────────────────────────────────────────────────────

class FileFormatError(EclipseError):
    """Raised when an .ec file is malformed, truncated, or has a bad magic number."""

class IntegrityError(EclipseError):
    """Raised when SHA-256 verification fails — file was tampered with or wrong key."""


# ── Key Management Errors ─────────────────────────────────────────────────────

class KeyManagementError(EclipseError):
    """Base class for key file and derivation failures."""

class KeyFileNotFoundError(KeyManagementError):
    """Raised when a .eckey or .pub/.priv file cannot be located."""
    def __init__(self, path: str):
        super().__init__(
            f"Key file not found: '{path}'",
            details="Check the path or generate a new key with: eclipsecode keygen"
        )
        self.path = path

class KeyDerivationError(KeyManagementError):
    """Raised when PBKDF2 key derivation fails (e.g. empty password)."""


# ── Auth / Security Errors ────────────────────────────────────────────────────

class AuthenticationError(EclipseError):
    """Raised when admin authentication fails."""


# ── Session Errors ────────────────────────────────────────────────────────────

class SessionError(EclipseError):
    """Raised when session history read/write fails."""