"""
XOR Cipher
-----------
XORs every byte of the input against a repeating key.
Works on raw bytes so it can handle any file type.
Output is hex-encoded for safe text storage.
"""

from core.base import Cipher, CipherMetadata
from core.registry import CipherRegistry
from core.exceptions import InvalidKeyError, EncryptionError, DecryptionError


@CipherRegistry.register
class XORCipher(Cipher):

    metadata = CipherMetadata(
        id="xor",
        name="XOR Cipher",
        category="classical",
        description="XORs each byte against a repeating key. Fast but not cryptographically secure.",
        supports_files=True,
        params={"key": "Any non-empty string"}
    )

    def __init__(self, key: str = "eclipsecode"):
        if not key:
            raise InvalidKeyError("XOR key cannot be empty.")
        self.key = key.encode("utf-8")

    def _xor(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))

    def encrypt(self, data: bytes) -> bytes:
        try:
            return self._xor(data).hex().encode("utf-8")
        except Exception as e:
            raise EncryptionError("XOR encryption failed.", details=str(e))

    def decrypt(self, data: bytes) -> bytes:
        try:
            raw = bytes.fromhex(data.decode("utf-8"))
            return self._xor(raw)
        except Exception as e:
            raise DecryptionError("XOR decryption failed.", details=str(e))

    def trace(self, data: bytes) -> list[dict]:
        steps = []
        for i, b in enumerate(data[:32]):  # limit trace to first 32 bytes
            k = self.key[i % len(self.key)]
            out = b ^ k
            steps.append({
                "step": i + 1,
                "label": f"Byte {i}: {b:08b} XOR {k:08b}",
                "input": f"0x{b:02X}",
                "output": f"0x{out:02X}",
                "detail": f"{b} XOR {k} = {out}"
            })
        return steps