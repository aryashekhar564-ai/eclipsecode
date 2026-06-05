"""
RSA-2048 Cipher
----------------
Asymmetric encryption — different keys for encrypt and decrypt.
Public key encrypts, private key decrypts.

Important: RSA alone can only encrypt small amounts of data (~190 bytes for 2048-bit).
For files, we use HYBRID encryption:
    1. Generate a random AES key
    2. Encrypt the file with AES
    3. Encrypt the AES key with RSA
    4. Store both in the .ec file

This is exactly how HTTPS, PGP, and SSH work.
"""

import os
from core.base import Cipher, CipherMetadata
from core.registry import CipherRegistry
from core.exceptions import InvalidKeyError, EncryptionError, DecryptionError

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

IV_SIZE  = 16
KEY_SIZE = 32


@CipherRegistry.register
class RSACipher(Cipher):

    metadata = CipherMetadata(
        id="rsa",
        name="RSA-2048 (Hybrid)",
        category="modern",
        description="Asymmetric encryption via hybrid RSA+AES. Encrypt with public key, decrypt with private key.",
        supports_files=True,
        params={
            "public_key":  "RSA public key object (for encryption)",
            "private_key": "RSA private key object (for decryption)"
        }
    )

    def __init__(self, public_key=None, private_key=None):
        if public_key is None and private_key is None:
            raise InvalidKeyError("RSA cipher requires at least one of: public_key, private_key.")
        self.public_key  = public_key
        self.private_key = private_key

    def _rsa_encrypt_key(self, aes_key: bytes) -> bytes:
        return self.public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

    def _rsa_decrypt_key(self, encrypted_key: bytes) -> bytes:
        return self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

    def encrypt(self, data: bytes) -> bytes:
        if not self.public_key:
            raise EncryptionError("RSA encryption requires a public key.")
        try:
            # 1. Generate a fresh AES key + IV
            aes_key = os.urandom(KEY_SIZE)
            iv      = os.urandom(IV_SIZE)

            # 2. Encrypt the data with AES
            padder = sym_padding.PKCS7(128).padder()
            padded = padder.update(data) + padder.finalize()
            aes_cipher = CryptoCipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            enc = aes_cipher.encryptor()
            ciphertext = enc.update(padded) + enc.finalize()

            # 3. Encrypt the AES key with RSA
            encrypted_aes_key = self._rsa_encrypt_key(aes_key)

            # 4. Pack: [2 bytes: RSA key length][RSA-encrypted AES key][IV][AES ciphertext]
            rsa_key_len = len(encrypted_aes_key).to_bytes(2, "big")
            return rsa_key_len + encrypted_aes_key + iv + ciphertext

        except Exception as e:
            raise EncryptionError("RSA hybrid encryption failed.", details=str(e))

    def decrypt(self, data: bytes) -> bytes:
        if not self.private_key:
            raise DecryptionError("RSA decryption requires a private key.")
        try:
            # Unpack
            rsa_key_len = int.from_bytes(data[:2], "big")
            encrypted_aes_key = data[2:2 + rsa_key_len]
            iv         = data[2 + rsa_key_len: 2 + rsa_key_len + IV_SIZE]
            ciphertext = data[2 + rsa_key_len + IV_SIZE:]

            # Decrypt AES key with RSA
            aes_key = self._rsa_decrypt_key(encrypted_aes_key)

            # Decrypt data with AES
            aes_cipher = CryptoCipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            dec = aes_cipher.decryptor()
            padded = dec.update(ciphertext) + dec.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()

        except Exception as e:
            raise DecryptionError("RSA hybrid decryption failed.", details=str(e))

    def trace(self, data: bytes) -> list[dict]:
        return [
            {"step": 1, "label": "Generate AES session key", "input": "", "output": "32 random bytes",
             "detail": "A fresh AES-256 key is generated just for this operation."},
            {"step": 2, "label": "AES-256 CBC encrypt data", "input": f"{len(data)} bytes",
             "output": "Ciphertext", "detail": "The actual file is encrypted with AES, not RSA directly."},
            {"step": 3, "label": "RSA-OAEP encrypt AES key", "input": "32-byte AES key",
             "output": "256-byte RSA ciphertext", "detail": "The AES key is encrypted with the recipient's public key."},
            {"step": 4, "label": "Pack output", "input": "RSA-key-len + RSA(AES-key) + IV + AES(data)",
             "output": "Final ciphertext", "detail": "All components packed into a single binary blob."},
        ]