"""
AES-256 CBC Cipher
-------------------
Industry-standard symmetric encryption.
A fresh random IV is generated for every encrypt call.
The IV is prepended to the ciphertext (first 16 bytes) so
decrypt() can always recover it — no need to store it separately
when using the cipher directly.

When used via the full EclipseCode engine, the IV is also stored
in the .ec file header for an extra layer of explicitness.
"""

import os
from core.base import Cipher, CipherMetadata
from core.registry import CipherRegistry
from core.exceptions import InvalidKeyError, EncryptionError, DecryptionError

from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding
from cryptography.hazmat.backends import default_backend

IV_SIZE = 16   # AES block size = 128 bits
KEY_SIZE = 32  # AES-256 = 32 bytes


@CipherRegistry.register
class AESCipher(Cipher):

    metadata = CipherMetadata(
        id="aes",
        name="AES-256 CBC",
        category="modern",
        description="Industry-standard symmetric encryption. Secure for real-world file encryption.",
        supports_files=True,
        params={"key": "32-byte key (derived from password or key file)"}
    )

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != KEY_SIZE:
            raise InvalidKeyError(
                f"AES key must be exactly {KEY_SIZE} bytes, got {len(key) if isinstance(key, bytes) else type(key)}."
            )
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        try:
            iv = os.urandom(IV_SIZE)
            padder = crypto_padding.PKCS7(128).padder()
            padded = padder.update(data) + padder.finalize()
            cipher = CryptoCipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            return iv + ciphertext  # IV prepended so decrypt can recover it
        except Exception as e:
            raise EncryptionError("AES encryption failed.", details=str(e))

    def decrypt(self, data: bytes) -> bytes:
        try:
            iv, ciphertext = data[:IV_SIZE], data[IV_SIZE:]
            cipher = CryptoCipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = crypto_padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        except Exception as e:
            raise DecryptionError("AES decryption failed. Wrong key or corrupt data.", details=str(e))

    def trace(self, data: bytes) -> list[dict]:
        return [
            {"step": 1, "label": "Generate IV", "input": "", "output": "16 random bytes",
             "detail": "A fresh random Initialisation Vector is generated for every encryption."},
            {"step": 2, "label": "PKCS7 Padding", "input": f"{len(data)} bytes",
             "output": f"{((len(data)//16)+1)*16} bytes",
             "detail": "Data padded to a multiple of 16 bytes (AES block size)."},
            {"step": 3, "label": "AES-256 CBC Rounds", "input": "Padded plaintext + key + IV",
             "output": "Ciphertext", "detail": "14 rounds of SubBytes, ShiftRows, MixColumns, AddRoundKey."},
            {"step": 4, "label": "Prepend IV", "input": "IV + Ciphertext",
             "output": f"{((len(data)//16)+1)*16 + IV_SIZE} bytes total",
             "detail": "IV stored with ciphertext so decryption is always possible."},
        ]