"""
EclipseCode Base Classes
-------------------------
Defines the contracts every cipher must follow.
No encryption logic lives here — just the interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CipherMetadata:
    """
    Describes a cipher for display and file-header purposes.
    Every cipher class must declare one of these.
    """
    id: str                          # short unique ID used in .ec headers e.g. "aes", "caesar"
    name: str                        # human-readable name e.g. "AES-128 CBC"
    category: str                    # "classical" or "modern"
    description: str                 # one-line description for the UI
    requires_key: bool = True        # False only for ciphers with no external key (none currently)
    supports_files: bool = True      # whether this cipher can handle raw bytes (all modern ones do)
    params: dict[str, Any] = field(default_factory=dict)  # extra cipher-specific info for the UI


class Cipher(ABC):
    """
    Abstract base class for all EclipseCode ciphers.

    Rules every cipher must follow:
    - encrypt() takes bytes, returns bytes
    - decrypt() takes bytes, returns bytes
    - metadata is a CipherMetadata dataclass describing the cipher
    - trace() returns a list of steps for the visualizer (can be empty list if not supported)
    """

    # Every subclass must define this at class level
    metadata: CipherMetadata

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt raw bytes and return encrypted bytes.
        Raises EncryptionError on failure.
        """

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt raw bytes and return original bytes.
        Raises DecryptionError on failure.
        """

    def trace(self, data: bytes) -> list[dict]:
        """
        Return a step-by-step trace of the encryption process.
        Used by the web visualizer to animate the cipher.
        Default returns empty list — override in ciphers that support it.

        Each step is a dict like:
        {
            "step": 1,
            "label": "Apply Caesar shift",
            "input": "HELLO",
            "output": "KHOOR",
            "detail": "Each letter shifted by 3"
        }
        """
        return []

    def encrypt_text(self, text: str, encoding: str = "utf-8") -> bytes:
        """Convenience wrapper: encrypts a string by encoding it to bytes first."""
        return self.encrypt(text.encode(encoding))

    def decrypt_text(self, data: bytes, encoding: str = "utf-8") -> str:
        """Convenience wrapper: decrypts bytes and decodes the result to a string."""
        return self.decrypt(data).decode(encoding)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id='{self.metadata.id}'>"