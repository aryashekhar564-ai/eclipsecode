"""
EclipseCode Cipher Registry
-----------------------------
A central directory of all available ciphers.
Ciphers register themselves here — the CLI and API
never import cipher classes directly, they always ask
the registry. This is the Factory pattern.

Usage:
    from core.registry import CipherRegistry

    # Get an AES cipher instance
    cipher = CipherRegistry.get("aes", key=my_key)

    # See all available ciphers
    CipherRegistry.available()
"""

from __future__ import annotations
from typing import Type, Any
from core.base import Cipher, CipherMetadata
from core.exceptions import UnsupportedCipherError


class CipherRegistry:
    """
    Singleton registry that maps cipher IDs to their classes.
    
    Cipher classes are registered using the @CipherRegistry.register decorator.
    The registry is populated automatically when cipher modules are imported.
    """

    _registry: dict[str, Type[Cipher]] = {}

    @classmethod
    def register(cls, cipher_class: Type[Cipher]) -> Type[Cipher]:
        """
        Decorator that registers a cipher class by its metadata ID.

        Usage:
            @CipherRegistry.register
            class AESCipher(Cipher):
                metadata = CipherMetadata(id="aes", ...)
        """
        cipher_id = cipher_class.metadata.id
        cls._registry[cipher_id] = cipher_class
        return cipher_class

    @classmethod
    def get(cls, cipher_id: str, **kwargs: Any) -> Cipher:
        """
        Instantiate and return a cipher by its ID.
        Extra kwargs are passed to the cipher's constructor.

        Raises UnsupportedCipherError if the ID is not registered.

        Example:
            cipher = CipherRegistry.get("caesar", shift=13)
            cipher = CipherRegistry.get("aes", key=b"...")
        """
        cipher_id = cipher_id.lower().strip()
        if cipher_id not in cls._registry:
            raise UnsupportedCipherError(cipher_id)
        return cls._registry[cipher_id](**kwargs)

    @classmethod
    def available(cls) -> list[CipherMetadata]:
        """
        Return metadata for all registered ciphers.
        Used by the CLI help text and the web UI cipher picker.
        """
        return [c.metadata for c in cls._registry.values()]

    @classmethod
    def available_by_category(cls) -> dict[str, list[CipherMetadata]]:
        """
        Return ciphers grouped by category (classical / modern).
        Used by the web UI to render the cipher explorer sections.
        """
        result: dict[str, list[CipherMetadata]] = {}
        for cipher_class in cls._registry.values():
            cat = cipher_class.metadata.category
            result.setdefault(cat, []).append(cipher_class.metadata)
        return result

    @classmethod
    def ids(cls) -> list[str]:
        """Return just the list of registered cipher IDs."""
        return list(cls._registry.keys())

    @classmethod
    def load_all(cls) -> None:
        """
        Import all cipher modules so they register themselves.
        Call this once at startup (CLI entry point or API server).
        """
        # classical
        import core.classical.caesar
        import core.classical.vigenere
        import core.classical.substitution
        import core.classical.xor
        # modern
        import core.modern.aes
        import core.modern.rsa