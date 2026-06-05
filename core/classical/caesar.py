"""
Caesar Cipher
--------------
Shifts each letter in the plaintext by a fixed amount.
Classic example: shift=3, A→D, B→E, Z→C

This implementation:
- Preserves case (A→D, a→d)
- Passes through non-alphabetic characters unchanged
- Supports full trace output for the visualizer
- Works on bytes by treating them as UTF-8 text
"""

from core.base import Cipher, CipherMetadata
from core.registry import CipherRegistry
from core.exceptions import InvalidKeyError, EncryptionError, DecryptionError


@CipherRegistry.register
class CaesarCipher(Cipher):

    metadata = CipherMetadata(
        id="caesar",
        name="Caesar Cipher",
        category="classical",
        description="Shifts each letter by a fixed amount. Simple but easily broken.",
        supports_files=False,  # classical ciphers work on text only
        params={"shift": "Integer between 1 and 25"}
    )

    def __init__(self, shift: int = 3):
        if not isinstance(shift, int) or not (1 <= shift <= 25):
            raise InvalidKeyError(
                f"Caesar shift must be an integer between 1 and 25, got: {shift}"
            )
        self.shift = shift

    def _shift_char(self, c: str, shift: int) -> str:
        """Shift a single alphabetic character, preserving case."""
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            return chr((ord(c) - base + shift) % 26 + base)
        return c

    def encrypt(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8")
            result = "".join(self._shift_char(c, self.shift) for c in text)
            return result.encode("utf-8")
        except Exception as e:
            raise EncryptionError("Caesar encryption failed.", details=str(e))

    def decrypt(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8")
            result = "".join(self._shift_char(c, -self.shift) for c in text)
            return result.encode("utf-8")
        except Exception as e:
            raise DecryptionError("Caesar decryption failed.", details=str(e))

    def trace(self, data: bytes) -> list[dict]:
        """Return character-by-character encryption steps for the visualizer."""
        text = data.decode("utf-8")
        steps = []
        result = []

        for i, c in enumerate(text):
            shifted = self._shift_char(c, self.shift)
            result.append(shifted)
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                steps.append({
                    "step": i + 1,
                    "label": f"Shift '{c}' by {self.shift}",
                    "input": c,
                    "output": shifted,
                    "detail": (
                        f"Position {ord(c) - base} + {self.shift} "
                        f"= {(ord(c) - base + self.shift) % 26} → '{shifted}'"
                    )
                })
            else:
                steps.append({
                    "step": i + 1,
                    "label": f"Pass through '{c}'",
                    "input": c,
                    "output": c,
                    "detail": "Non-alphabetic character, no shift applied."
                })

        steps.append({
            "step": len(text) + 1,
            "label": "Complete",
            "input": text,
            "output": "".join(result),
            "detail": f"All characters shifted by {self.shift}."
        })
        return steps