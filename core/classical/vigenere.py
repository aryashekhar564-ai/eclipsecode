"""
Vigenere Cipher
----------------
Polyalphabetic substitution using a repeating keyword.
Each letter is shifted by the corresponding keyword letter's position.
Example: key="KEY", H shifted by K(10), E shifted by E(4), L shifted by Y(24)
"""

from core.base import Cipher, CipherMetadata
from core.registry import CipherRegistry
from core.exceptions import InvalidKeyError, EncryptionError, DecryptionError


@CipherRegistry.register
class VigenereCipher(Cipher):

    metadata = CipherMetadata(
        id="vigenere",
        name="Vigenère Cipher",
        category="classical",
        description="Polyalphabetic substitution using a repeating keyword. Harder to crack than Caesar.",
        supports_files=False,
        params={"key": "Alphabetic string, any length"}
    )

    def __init__(self, key: str = "KEY"):
        if not key or not key.isalpha():
            raise InvalidKeyError("Vigenere key must be a non-empty alphabetic string.")
        self.key = key.upper()

    def _process(self, text: str, encrypt: bool) -> str:
        result = []
        key_idx = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(self.key[key_idx % len(self.key)]) - ord('A')
                shift = shift if encrypt else -shift
                result.append(chr((ord(c) - base + shift) % 26 + base))
                key_idx += 1
            else:
                result.append(c)
        return "".join(result)

    def encrypt(self, data: bytes) -> bytes:
        try:
            return self._process(data.decode("utf-8"), True).encode("utf-8")
        except Exception as e:
            raise EncryptionError("Vigenere encryption failed.", details=str(e))

    def decrypt(self, data: bytes) -> bytes:
        try:
            return self._process(data.decode("utf-8"), False).encode("utf-8")
        except Exception as e:
            raise DecryptionError("Vigenere decryption failed.", details=str(e))

    def trace(self, data: bytes) -> list[dict]:
        text = data.decode("utf-8")
        steps = []
        key_idx = 0
        for i, c in enumerate(text):
            if c.isalpha():
                k = self.key[key_idx % len(self.key)]
                shift = ord(k) - ord('A')
                base = ord('A') if c.isupper() else ord('a')
                out = chr((ord(c) - base + shift) % 26 + base)
                steps.append({
                    "step": i + 1,
                    "label": f"'{c}' + key '{k}'",
                    "input": c,
                    "output": out,
                    "detail": f"Shift {ord(c)-base} + {shift} = {(ord(c)-base+shift)%26} → '{out}'"
                })
                key_idx += 1
            else:
                steps.append({"step": i+1, "label": f"Pass '{c}'", "input": c, "output": c, "detail": "Non-alpha."})
        return steps