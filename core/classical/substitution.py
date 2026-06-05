"""
Substitution Cipher
--------------------
Each letter is replaced by a corresponding letter from a 26-character key.
Example: key="QWERTYUIOPASDFGHJKLZXCVBNM" means A→Q, B→W, C→E...
"""

from core.base import Cipher, CipherMetadata
from core.registry import CipherRegistry
from core.exceptions import InvalidKeyError, EncryptionError, DecryptionError


@CipherRegistry.register
class SubstitutionCipher(Cipher):

    metadata = CipherMetadata(
        id="substitution",
        name="Substitution Cipher",
        category="classical",
        description="Replaces each letter with a fixed alternative from a 26-character key.",
        supports_files=False,
        params={"key": "Exactly 26 unique alphabetic characters"}
    )

    def __init__(self, key: str):
        key = key.upper()
        if len(key) != 26 or not key.isalpha() or len(set(key)) != 26:
            raise InvalidKeyError(
                "Substitution key must be exactly 26 unique alphabetic characters."
            )
        self.key = key
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.enc_map = {self.alphabet[i]: key[i] for i in range(26)}
        self.dec_map = {v: k for k, v in self.enc_map.items()}

    def _process(self, text: str, mapping: dict) -> str:
        result = []
        for c in text:
            up = c.upper()
            if up in mapping:
                mapped = mapping[up]
                result.append(mapped if c.isupper() else mapped.lower())
            else:
                result.append(c)
        return "".join(result)

    def encrypt(self, data: bytes) -> bytes:
        try:
            return self._process(data.decode("utf-8"), self.enc_map).encode("utf-8")
        except Exception as e:
            raise EncryptionError("Substitution encryption failed.", details=str(e))

    def decrypt(self, data: bytes) -> bytes:
        try:
            return self._process(data.decode("utf-8"), self.dec_map).encode("utf-8")
        except Exception as e:
            raise DecryptionError("Substitution decryption failed.", details=str(e))

    def trace(self, data: bytes) -> list[dict]:
        text = data.decode("utf-8")
        steps = []
        for i, c in enumerate(text):
            up = c.upper()
            if up in self.enc_map:
                out = self.enc_map[up]
                out = out if c.isupper() else out.lower()
                steps.append({"step": i+1, "label": f"'{c}'→'{out}'", "input": c, "output": out,
                               "detail": f"Substitution: {up} → {self.enc_map[up]}"})
            else:
                steps.append({"step": i+1, "label": f"Pass '{c}'", "input": c, "output": c, "detail": "Non-alpha."})
        return steps