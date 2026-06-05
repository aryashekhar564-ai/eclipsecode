<div align="center">

```
███████╗ ██████╗██╗     ██╗██████╗ ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝██╔════╝██║     ██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
█████╗  ██║     ██║     ██║██████╔╝███████╗█████╗  ██║     ██║   ██║██║  ██║█████╗
██╔══╝  ██║     ██║     ██║██╔═══╝ ╚════██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝
███████╗╚██████╗███████╗██║██║     ███████║███████╗╚██████╗╚██████╔╝██████╔╝███████╗
╚══════╝ ╚═════╝╚══════╝╚═╝╚═╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝╚══════╝
```

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Cryptography](https://img.shields.io/badge/AES--256%20%7C%20RSA--2048-FF0066?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A file encryption platform with interactive cipher visualization.**

AES-256 · RSA-2048 · PBKDF2 · SHA-256 · CLI + Web UI

</div>

---

## Overview

EclipseCode is a Python-based file encryption platform that combines modern cryptographic techniques (AES-256, RSA-2048, PBKDF2) with an interactive cipher visualizer for learning and experimentation. It encrypts any file and wraps the output in a self-describing `.ec` container that stores everything needed for decryption inside the file itself — no flags, no separate metadata to manage.

The project exposes two interfaces over the same engine:

- **CLI** — encrypt and decrypt any file from the terminal, generate keys, view audit logs
- **Web UI** — drag-and-drop file operations, step-by-step cipher visualizer, real-time comparison dashboard

> **Design philosophy:** Classical ciphers (Caesar, Vigenère, Substitution) are exposed through the visualizer as educational tools to show how cryptography evolved. File encryption uses established algorithms — AES-256 CBC and RSA-2048 with OAEP padding — implemented via the Python `cryptography` package rather than any custom primitives.

> **Scope note:** This is a learning and portfolio project. It has not undergone a security audit and should not be used to protect genuinely sensitive data. See [Known Limitations](#known-limitations) for honest notes on the design tradeoffs made.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [The .ec File Format](#the-ec-file-format)
- [Getting Started](#getting-started)
- [CLI Reference](#cli-reference)
- [Web UI](#web-ui)
- [Key Models](#key-models)
- [Security Design](#security-design)
- [Known Limitations](#known-limitations)
- [API Reference](#api-reference)
- [Dependencies](#dependencies)

---

## Features

### Cryptography
- **AES-256 CBC** with a fresh randomly generated IV per operation and PKCS7 padding
- **RSA-2048 Hybrid Encryption** — file encrypted with AES, AES key encrypted with RSA-OAEP; uses a hybrid encryption approach similar in concept to systems such as PGP
- **PBKDF2-HMAC-SHA256** key derivation at 600,000 iterations per OWASP 2023 recommendations
- **SHA-256 hash verification** on every decryption to detect corruption or wrong key (see [Known Limitations](#known-limitations) for notes on this approach)
- **Classical cipher suite** — Caesar, Vigenère, Substitution, XOR with full step-by-step trace output for the visualizer

### File Format
- **Self-describing `.ec` files** — binary header stores cipher ID, salt, IV, SHA-256 hash, original filename, and timestamp
- **Automatic decryption** — cipher and parameters read from the file header, no extra flags needed
- **Any file type** — images, PDFs, archives, text files, source code

### Key Management
- **Password mode** — PBKDF2 derives a 32-byte key from a user password and a per-operation random salt
- **Key file mode** — random 32-byte key stored in a portable `.eckey` file
- **RSA keypair mode** — 2048-bit keypair; public key encrypts, private key decrypts

### Application Infrastructure
- **Salted credential storage** — admin passwords stored as SHA-256 hash with 32-byte random salt
- **Append-only JSONL audit log** — every operation recorded with timestamp, cipher, mode, filename, and outcome
- **Cipher/mode constraint enforcement** — invalid combinations (e.g. RSA + password) blocked in both UI and API
- **XSS-safe UI** — all dynamic content HTML-escaped before DOM insertion

---

## Architecture

```
eclipsecode/
│
├── core/                        Pure Python encryption engine (no framework dependencies)
│   ├── base.py                  Abstract Cipher base class + CipherMetadata dataclass
│   ├── registry.py              CipherRegistry — Factory pattern, decorator-based auto-registration
│   ├── exceptions.py            Custom exception hierarchy (EclipseError > CipherError > ...)
│   │
│   ├── classical/
│   │   ├── caesar.py            Caesar cipher with character-level step trace
│   │   ├── vigenere.py          Vigenère cipher with correct key-index advancement
│   │   ├── substitution.py      Monoalphabetic substitution with 26-char key validation
│   │   └── xor.py               XOR cipher with hex encoding and byte-level trace
│   │
│   └── modern/
│       ├── aes.py               AES-256 CBC — IV prepended to ciphertext, PKCS7 padding
│       └── rsa.py               RSA-2048 hybrid — AES encrypts data, RSA encrypts AES key
│
├── session/
│   ├── file_format.py           .ec binary container — pack/unpack, magic number, SHA-256
│   └── key_manager.py           PBKDF2 derivation, .eckey files, RSA keypair generation and loading
│
├── security/
│   ├── auth.py                  Salted SHA-256 password hashing, .ec_credentials file management
│   └── audit.py                 Append-only JSONL audit log, admin-gated read and clear
│
├── api/
│   └── server.py                FastAPI server — all routes
│
├── frontend/
│   ├── index.html               Multi-page single-page app
│   ├── style.css                Dark terminal theme with CRT scanline effect
│   └── app.js                   UI logic — constraint enforcement, XSS-safe rendering
│
└── cli.py                       CLI entry point (argparse)
```

### Design Patterns

| Pattern | Where Applied |
|---|---|
| **Factory** | `CipherRegistry.get("aes", key=...)` — callers never import cipher classes directly |
| **Decorator registration** | `@CipherRegistry.register` — ciphers self-register on import |
| **Strategy** | All ciphers share `encrypt(bytes) → bytes` and `decrypt(bytes) → bytes` contracts |
| **Abstract Base Class** | `Cipher` enforces `encrypt`, `decrypt`, and `trace` on every implementation |
| **Singleton** | `CipherRegistry` — one central registry for the entire runtime |

---

## The .ec File Format

Every encrypted file uses a custom binary container:

```
┌──────────────┬────────────────────────────────────────────────────┐
│  4 bytes     │  Magic number: "EC02"                              │
├──────────────┼────────────────────────────────────────────────────┤
│  4 bytes     │  Header length (big-endian unsigned int)           │
├──────────────┼────────────────────────────────────────────────────┤
│  N bytes     │  JSON header (UTF-8 encoded)                       │
├──────────────┼────────────────────────────────────────────────────┤
│  remaining   │  Raw ciphertext                                    │
└──────────────┴────────────────────────────────────────────────────┘
```

**Example header:**

```json
{
  "cipher":    "aes",
  "mode":      "password",
  "salt":      "a3f9c2e1b4d87f3c...",
  "iv":        "",
  "sha256":    "4f77669cb18b63d4...",
  "filename":  "report.pdf",
  "timestamp": "2026-06-04T10:30:00+00:00"
}
```

The header makes decryption automatic. Given only the `.ec` file and the correct credential, EclipseCode recovers the original file regardless of when or how it was encrypted.

---

## Getting Started

### Requirements

- Python 3.11 or higher
- pip

### Installation

```bash
git clone https://github.com/yourusername/eclipsecode.git
cd eclipsecode

# Create virtual environment
python -m venv venv

# Activate — Windows
venv\Scripts\activate

# Activate — macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### First-Time Setup

```bash
python cli.py setup
```

Creates a salted admin credential for accessing audit logs. Run once before any other commands.

---

## CLI Reference

### List available ciphers

```bash
python cli.py ciphers
```

```
=== Available Ciphers ===

  CLASSICAL
    caesar          Caesar Cipher             (text only)
    vigenere        Vigenère Cipher           (text only)
    substitution    Substitution Cipher       (text only)
    xor             XOR Cipher                (files + text)

  MODERN
    aes             AES-256 CBC               (files + text)
    rsa             RSA-2048 (Hybrid)         (files + text)
```

### Key Generation

```bash
# AES symmetric key file
python cli.py keygen --cipher aes --out mykey
# Output: mykey.eckey

# RSA-2048 keypair
python cli.py keygen --cipher rsa --out mykeys
# Output: mykeys.pub  (share with whoever will encrypt files for you)
#         mykeys.priv (keep secret — required for decryption)
```

### Encrypt

```bash
# Password mode
python cli.py encrypt report.pdf --cipher aes --mode password

# Key file mode
python cli.py encrypt report.pdf --cipher aes --mode keyfile --keyfile mykey.eckey

# RSA keypair mode
python cli.py encrypt report.pdf --cipher rsa --mode keypair --pubkey mykeys.pub
```

All modes output `report.pdf.ec`.

### Decrypt

```bash
# Cipher and mode are read automatically from the .ec file header

# Password mode
python cli.py decrypt report.pdf.ec

# Key file mode
python cli.py decrypt report.pdf.ec --keyfile mykey.eckey

# RSA keypair mode
python cli.py decrypt report.pdf.ec --privkey mykeys.priv
```

### Audit Logs

```bash
python cli.py logs
```

Requires the admin password set during setup.

```
=== Audit Log (4 entries) ===

  ✓ 2026-06-04T10:30:00  encrypt    aes        password   report.pdf
  ✓ 2026-06-04T10:31:22  decrypt    aes        password   report.pdf
  ✓ 2026-06-04T10:35:01  keygen     rsa        keypair    mykeys
  ✗ 2026-06-04T10:36:14  decrypt    aes        password   report.pdf
```

---

## Web UI

Start the server:

```bash
uvicorn api.server:app --reload
```

Open `http://localhost:8000`

### Pages

| Page | Description |
|---|---|
| **Home** | Overview, feature cards, animated cipher stream |
| **Encrypt** | Upload any file, choose cipher and key mode, download `.ec` file |
| **Decrypt** | Upload `.ec` file, provide credential, download original |
| **Visualizer** | Select any cipher, type plaintext, watch encryption step by step |
| **Compare** | Encrypt the same text with all classical ciphers — compare output, length, timing |
| **Keygen** | Generate AES key files or RSA keypairs from the browser |

### Cipher and Mode Constraints

| Cipher | Supported Modes | Reason |
|---|---|---|
| AES-256 | Password, Key File | Symmetric — requires a shared secret |
| RSA-2048 | Keypair only | Asymmetric — designed for public/private key model |
| XOR | Password, Key File | Symmetric — requires a shared key |

Enforced in both the UI and the API.

---

## Key Models

### Model A — Password (PBKDF2)

The password is never used as a key directly. PBKDF2-HMAC-SHA256 stretches it into a 32-byte key using a randomly generated per-operation salt stored in the file header.

```
password + random_salt (32 bytes)
    └─→ PBKDF2-HMAC-SHA256 (600,000 iterations)
            └─→ 32-byte AES-256 key
```

### Model B — Key File

A cryptographically random 32-byte key is generated via `os.urandom(32)` and stored base64-encoded in a JSON `.eckey` file.

```json
{
  "version": "1",
  "key": "<base64-encoded 32 random bytes>"
}
```

### Model C — RSA Keypair (Hybrid Encryption)

RSA-2048 alone cannot encrypt files larger than roughly 190 bytes. EclipseCode uses a hybrid approach: AES encrypts the file, and RSA encrypts the AES key. This is a common pattern in asymmetric cryptography systems.

```
Step 1: Generate random 32-byte AES session key
Step 2: Encrypt the file with AES-256 CBC
Step 3: Encrypt the AES key with RSA-OAEP (recipient's public key)
Step 4: Output → [key_length (2B)] + [RSA(AES_key)] + [IV (16B)] + [AES(file)]
```

---

## Security Design

| Component | Implementation |
|---|---|
| Symmetric encryption | AES-256 CBC, random 16-byte IV per operation, PKCS7 padding |
| Asymmetric encryption | RSA-2048, OAEP padding with SHA-256 |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte random salt |
| File integrity check | SHA-256 hash of plaintext stored in header, verified on decryption |
| Credential storage | SHA-256 with 32-byte random salt, stored in `.ec_credentials` |
| Audit log | Append-only JSONL, admin-password-gated read access |
| Crypto backend | Python `cryptography` library — no custom primitives |

---

## Known Limitations

These are intentional design tradeoffs made to keep the project focused. They are worth understanding if you are evaluating this codebase.

**AES-CBC instead of AES-GCM**
CBC mode provides confidentiality but not authentication. AES-GCM is the modern standard for authenticated encryption, which provides both. A production system would use GCM.

**SHA-256 for integrity, not HMAC**
Storing a plaintext SHA-256 hash in the file header is not authenticated integrity verification. An attacker with access to the file could in theory replace both the ciphertext and the hash. HMAC-SHA256 keyed with the derived key would be the correct approach.

**Salted SHA-256 for admin credentials**
The admin credential system uses salted SHA-256. For password storage, memory-hard functions like Argon2, bcrypt, or scrypt are the current recommended standard as they are significantly more resistant to brute-force attacks.

**No security audit**
This project has not been reviewed by a security professional. Do not use it to protect genuinely sensitive data.

**Classical ciphers**
Caesar, Vigenère, and Substitution ciphers are trivially broken and exist in this project solely for educational visualization.

---

## API Reference

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/ciphers` | All registered ciphers grouped by category |
| `POST` | `/api/encrypt` | Encrypt an uploaded file, returns `.ec` file |
| `POST` | `/api/decrypt` | Decrypt an uploaded `.ec` file, returns original |
| `POST` | `/api/trace` | Step-by-step encryption trace for the visualizer |
| `POST` | `/api/compare` | Encrypt text with all classical ciphers simultaneously |
| `POST` | `/api/keygen` | Generate AES key file or RSA keypair |

### Encrypt via API

```bash
curl -X POST http://localhost:8000/api/encrypt \
  -F "file=@report.pdf" \
  -F "cipher_id=aes" \
  -F "mode=password" \
  -F "password=yourpassword" \
  --output report.pdf.ec
```

### Decrypt via API

```bash
curl -X POST http://localhost:8000/api/decrypt \
  -F "file=@report.pdf.ec" \
  -F "password=yourpassword" \
  --output report.pdf
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | AES, RSA, PBKDF2, SHA-256 via BoringSSL/OpenSSL backend |
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `python-multipart` | Multipart form and file upload parsing |

---

## License

MIT License — free to use, modify, and distribute.

---

<div align="center">
<sub>EclipseCode v2.0 · Python · FastAPI · Vanilla JS</sub>
</div>
