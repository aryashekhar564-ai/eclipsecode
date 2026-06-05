"""
EclipseCode FastAPI Server
---------------------------
Serves the web UI and exposes the encryption engine via HTTP.
Run with: uvicorn api.server:app --reload
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
from pathlib import Path

from core.registry import CipherRegistry
CipherRegistry.load_all()

from core.exceptions import EclipseError
from session.file_format import (
    build_header, write_ec_file, read_ec_file,
    compute_sha256, verify_sha256
)
from session.key_manager import (
    generate_salt, derive_key, salt_to_hex, salt_from_hex,
    generate_keyfile, load_keyfile,
    generate_keypair, load_public_key, load_private_key,
    rsa_encrypt, rsa_decrypt
)
from security.audit import log

app = FastAPI(title="EclipseCode", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

TEMP_DIR = Path(tempfile.gettempdir()) / "eclipsecode"
TEMP_DIR.mkdir(exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def root():
    return Path("frontend/index.html").read_text(encoding="utf-8")


@app.get("/api/ciphers")
async def get_ciphers():
    """Return all registered ciphers grouped by category."""
    grouped = CipherRegistry.available_by_category()
    return {
        cat: [
            {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "supports_files": m.supports_files,
                "params": m.params
            }
            for m in ciphers
        ]
        for cat, ciphers in grouped.items()
    }


@app.post("/api/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    cipher_id: str = Form("aes"),
    mode: str = Form("password"),
    password: str = Form(""),
    keyfile: UploadFile = File(None),
    pubkey: UploadFile = File(None),
):
    plaintext = await file.read()
    sha256 = compute_sha256(plaintext)
    filename = file.filename

    # RSA only works with keypair mode
    if cipher_id == "rsa" and mode != "keypair":
        raise HTTPException(400, "RSA cipher requires keypair mode. Use a .pub key file.")

    try:
        if mode == "password":
            if not password:
                raise HTTPException(400, "Password is required for password mode.")
            salt = generate_salt()
            key = derive_key(password, salt)
            cipher = CipherRegistry.get(cipher_id, key=key)
            ciphertext = cipher.encrypt(plaintext)
            header = build_header(
                cipher_id, mode, filename, sha256,
                salt_hex=salt_to_hex(salt)
            )

        elif mode == "keyfile":
            if not keyfile:
                raise HTTPException(400, "Key file is required for keyfile mode.")
            key_bytes = await keyfile.read()
            tmp_key = TEMP_DIR / "upload.eckey"
            tmp_key.write_bytes(key_bytes)
            key = load_keyfile(str(tmp_key))
            cipher = CipherRegistry.get(cipher_id, key=key)
            ciphertext = cipher.encrypt(plaintext)
            header = build_header(cipher_id, mode, filename, sha256)

        elif mode == "keypair":
            if not pubkey:
                raise HTTPException(400, "Public key file is required for keypair mode.")
            pub_bytes = await pubkey.read()
            tmp_pub = TEMP_DIR / "upload.pub"
            tmp_pub.write_bytes(pub_bytes)
            pub_key = load_public_key(str(tmp_pub))
            cipher = CipherRegistry.get("rsa", public_key=pub_key)
            ciphertext = cipher.encrypt(plaintext)
            header = build_header("rsa", mode, filename, sha256)

        else:
            raise HTTPException(400, f"Unknown mode: {mode}")

        out_path = TEMP_DIR / (filename + ".ec")
        write_ec_file(str(out_path), header, ciphertext)
        log("encrypt", "success", cipher_id=cipher_id, mode=mode, filename=filename)
        return FileResponse(
            str(out_path),
            filename=filename + ".ec",
            media_type="application/octet-stream"
        )

    except EclipseError as e:
        log("encrypt", "failure", cipher_id=cipher_id, mode=mode, filename=filename, error=str(e))
        raise HTTPException(400, str(e))


@app.post("/api/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    password: str = Form(""),
    keyfile: UploadFile = File(None),
    privkey: UploadFile = File(None),
):
    ec_bytes = await file.read()
    tmp_ec = TEMP_DIR / file.filename
    tmp_ec.write_bytes(ec_bytes)

    try:
        header, ciphertext = read_ec_file(str(tmp_ec))
        cipher_id = header["cipher"]
        mode      = header["mode"]
        filename  = header["filename"]

        if mode == "password":
            if not password:
                raise HTTPException(400, "Password is required.")
            salt = salt_from_hex(header["salt"])
            key = derive_key(password, salt)
            cipher = CipherRegistry.get(cipher_id, key=key)
            plaintext = cipher.decrypt(ciphertext)

        elif mode == "keyfile":
            if not keyfile:
                raise HTTPException(400, "Key file is required.")
            key_bytes = await keyfile.read()
            tmp_key = TEMP_DIR / "upload.eckey"
            tmp_key.write_bytes(key_bytes)
            key = load_keyfile(str(tmp_key))
            cipher = CipherRegistry.get(cipher_id, key=key)
            plaintext = cipher.decrypt(ciphertext)

        elif mode == "keypair":
            if not privkey:
                raise HTTPException(400, "Private key file is required.")
            priv_bytes = await privkey.read()
            tmp_priv = TEMP_DIR / "upload.priv"
            tmp_priv.write_bytes(priv_bytes)
            priv_key = load_private_key(str(tmp_priv))
            cipher = CipherRegistry.get("rsa", private_key=priv_key)
            plaintext = cipher.decrypt(ciphertext)

        else:
            raise HTTPException(400, f"Unknown mode: {mode}")

        if not verify_sha256(plaintext, header["sha256"]):
            raise HTTPException(400, "Integrity check FAILED. File tampered or wrong key.")

        out_path = TEMP_DIR / filename
        out_path.write_bytes(plaintext)
        log("decrypt", "success", cipher_id=cipher_id, mode=mode, filename=filename)
        return FileResponse(
            str(out_path),
            filename=filename,
            media_type="application/octet-stream"
        )

    except EclipseError as e:
        log("decrypt", "failure", error=str(e))
        raise HTTPException(400, str(e))


@app.post("/api/trace")
async def trace_cipher(
    cipher_id: str = Form(...),
    text: str = Form(...),
    shift: int = Form(3),
    key: str = Form("KEY"),
):
    """Return step-by-step encryption trace for the visualizer."""
    try:
        if cipher_id == "caesar":
            cipher = CipherRegistry.get("caesar", shift=shift)
        elif cipher_id == "vigenere":
            cipher = CipherRegistry.get("vigenere", key=key)
        elif cipher_id == "substitution":
            cipher = CipherRegistry.get("substitution", key=key)
        elif cipher_id == "xor":
            cipher = CipherRegistry.get("xor", key=key)
        elif cipher_id == "aes":
            cipher = CipherRegistry.get("aes", key=os.urandom(32))
        elif cipher_id == "rsa":
            prefix = str(TEMP_DIR / "trace_rsa")
            generate_keypair(prefix)
            pub  = load_public_key(prefix + ".pub")
            priv = load_private_key(prefix + ".priv")
            cipher = CipherRegistry.get("rsa", public_key=pub, private_key=priv)
        else:
            raise HTTPException(400, f"Unknown cipher: {cipher_id}")

        steps     = cipher.trace(text.encode("utf-8"))
        encrypted = cipher.encrypt_text(text)
        return {
            "steps":     steps,
            "encrypted": encrypted if isinstance(encrypted, str) else encrypted.decode("utf-8", errors="replace"),
            "cipher":    cipher_id
        }
    except EclipseError as e:
        raise HTTPException(400, str(e))


@app.post("/api/compare")
async def compare_ciphers(text: str = Form(...)):
    """Encrypt the same text with all classical ciphers and return results."""
    import time
    results = []

    configs = [
        ("caesar",       {"shift": 13}),
        ("vigenere",     {"key": "ECLIPSE"}),
        ("substitution", {"key": "QWERTYUIOPASDFGHJKLZXCVBNM"}),
        ("xor",          {"key": "eclipsecode"}),
    ]

    for cipher_id, kwargs in configs:
        try:
            cipher = CipherRegistry.get(cipher_id, **kwargs)
            start  = time.perf_counter()
            encrypted = cipher.encrypt(text.encode("utf-8"))
            elapsed   = (time.perf_counter() - start) * 1000
            results.append({
                "cipher":  cipher_id,
                "name":    cipher.metadata.name,
                "output":  encrypted.decode("utf-8", errors="replace"),
                "time_ms": round(elapsed, 4),
                "length":  len(encrypted)
            })
        except EclipseError as e:
            results.append({"cipher": cipher_id, "error": str(e)})

    return {"results": results, "input": text}


@app.post("/api/keygen")
async def keygen(
    cipher: str = Form("aes"),
    out: str = Form("mykey")
):
    try:
        if cipher == "rsa":
            pub, priv = generate_keypair(out)
            return {
                "message": f"✓ RSA keypair generated.\n  Public:  {pub}\n  Private: {priv}\n  Keep your .priv file secret."
            }
        else:
            path = out if out.endswith(".eckey") else out + ".eckey"
            generate_keyfile(path)
            return {"message": f"✓ AES key file generated: {path}"}
    except EclipseError as e:
        raise HTTPException(400, str(e))