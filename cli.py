"""
EclipseCode CLI
----------------
Usage examples:

    # First-time setup
    python cli.py setup

    # Encrypt a file (password mode)
    python cli.py encrypt report.pdf --cipher aes --mode password

    # Encrypt a file (key file mode)
    python cli.py encrypt report.pdf --cipher aes --mode keyfile --keyfile mykey.eckey

    # Encrypt a file (keypair mode)
    python cli.py encrypt report.pdf --cipher rsa --mode keypair --pubkey mykeys.pub

    # Decrypt
    python cli.py decrypt report.pdf.ec --mode password
    python cli.py decrypt report.pdf.ec --mode keyfile --keyfile mykey.eckey
    python cli.py decrypt report.pdf.ec --mode keypair --privkey mykeys.priv

    # Generate keys
    python cli.py keygen --cipher aes --out mykey.eckey
    python cli.py keygen --cipher rsa --out mykeys

    # View logs (admin only)
    python cli.py logs

    # List available ciphers
    python cli.py ciphers
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

# Load all ciphers into the registry
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
from security.auth import setup_admin, credentials_exist
from security.audit import log, read_logs


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    """Prompt for a password securely (no echo)."""
    password = getpass.getpass(prompt)
    if confirm:
        confirm_pw = getpass.getpass("Confirm password: ")
        if password != confirm_pw:
            print("[Error] Passwords do not match.")
            sys.exit(1)
    return password


def resolve_output_path(input_path: str, action: str) -> str:
    """
    Determine the output file path.
    encrypt: report.pdf       → report.pdf.ec
    decrypt: report.pdf.ec   → report.pdf  (from header filename)
    """
    if action == "encrypt":
        return input_path + ".ec"
    else:
        return None  # determined at runtime from .ec header


def abort(message: str, action: str = "", cipher: str = "", mode: str = "", filename: str = ""):
    """Print error, log failure, and exit."""
    print(f"[Error] {message}")
    if action:
        log(action, "failure", cipher_id=cipher, mode=mode, filename=filename, error=message)
    sys.exit(1)


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_setup(args):
    """First-time admin setup."""
    if credentials_exist():
        print("[Setup] Admin credentials already exist.")
        print("        Delete .ec_credentials to reset.")
        return

    print("=== EclipseCode First-Time Setup ===")
    print("Create an admin password to protect audit logs.")
    password = get_password("New admin password (min 8 chars): ", confirm=True)
    try:
        setup_admin(password)
        print("[Setup] Done. Run 'python cli.py ciphers' to see available ciphers.")
    except EclipseError as e:
        abort(str(e))


def cmd_ciphers(args):
    """List all registered ciphers grouped by category."""
    print("\n=== Available Ciphers ===\n")
    grouped = CipherRegistry.available_by_category()
    for category, ciphers in grouped.items():
        print(f"  {category.upper()}")
        for m in ciphers:
            file_support = "files + text" if m.supports_files else "text only"
            print(f"    {m.id:<15} {m.name:<25} ({file_support})")
            print(f"                  {m.description}")
        print()


def cmd_keygen(args):
    """Generate a key file or RSA keypair."""
    if args.cipher == "rsa":
        pub, priv = generate_keypair(args.out)
        print(f"\n[Keygen] RSA keypair generated.")
        print(f"  Public key:  {pub}  ← share this")
        print(f"  Private key: {priv} ← keep this secret")
        log("keygen", "success", cipher_id="rsa", mode="keypair", filename=args.out)
    else:
        path = args.out if args.out.endswith(".eckey") else args.out + ".eckey"
        generate_keyfile(path)
        print(f"\n[Keygen] AES key file generated: {path}")
        log("keygen", "success", cipher_id="aes", mode="keyfile", filename=path)


def cmd_encrypt(args):
    """Encrypt a file."""
    input_path = args.file
    if not Path(input_path).exists():
        abort(f"File not found: {input_path}")

    output_path = input_path + ".ec"
    cipher_id   = args.cipher
    mode        = args.mode

    # Read plaintext
    plaintext = Path(input_path).read_bytes()
    sha256    = compute_sha256(plaintext)
    filename  = Path(input_path).name

    try:
        # ── Password mode ──
        if mode == "password":
            password = get_password("Encryption password: ", confirm=True)
            salt     = generate_salt()
            key      = derive_key(password, salt)
            cipher   = CipherRegistry.get(cipher_id, key=key)
            ciphertext = cipher.encrypt(plaintext)
            header   = build_header(
                cipher_id, mode, filename, sha256,
                salt_hex=salt_to_hex(salt)
            )

        # ── Key file mode ──
        elif mode == "keyfile":
            if not args.keyfile:
                abort("--keyfile is required for keyfile mode.", "encrypt", cipher_id, mode, filename)
            key      = load_keyfile(args.keyfile)
            cipher   = CipherRegistry.get(cipher_id, key=key)
            ciphertext = cipher.encrypt(plaintext)
            header   = build_header(cipher_id, mode, filename, sha256)

        # ── Keypair mode ──
        elif mode == "keypair":
            if not args.pubkey:
                abort("--pubkey is required for keypair mode.", "encrypt", cipher_id, mode, filename)
            pub_key  = load_public_key(args.pubkey)
            cipher   = CipherRegistry.get("rsa", public_key=pub_key)
            ciphertext = cipher.encrypt(plaintext)
            header   = build_header("rsa", mode, filename, sha256)

        else:
            abort(f"Unknown mode: {mode}")

        write_ec_file(output_path, header, ciphertext)
        print(f"\n[Encrypt] Done.")
        print(f"  Input:   {input_path}  ({len(plaintext):,} bytes)")
        print(f"  Output:  {output_path} ({Path(output_path).stat().st_size:,} bytes)")
        print(f"  Cipher:  {cipher_id.upper()} | Mode: {mode}")
        print(f"  SHA-256: {sha256[:32]}...")
        log("encrypt", "success", cipher_id=cipher_id, mode=mode, filename=filename)

    except EclipseError as e:
        abort(str(e), "encrypt", cipher_id, mode, filename)


def cmd_decrypt(args):
    """Decrypt a .ec file."""
    input_path = args.file
    if not Path(input_path).exists():
        abort(f"File not found: {input_path}")

    try:
        header, ciphertext = read_ec_file(input_path)
    except EclipseError as e:
        abort(str(e))

    cipher_id = header["cipher"]
    mode      = header["mode"]
    filename  = header["filename"]
    stored_sha256 = header["sha256"]

    # Output goes to original filename in same directory
    output_path = str(Path(input_path).parent / filename)

    try:
        # ── Password mode ──
        if mode == "password":
            password = get_password("Decryption password: ")
            salt     = salt_from_hex(header["salt"])
            key      = derive_key(password, salt)
            cipher   = CipherRegistry.get(cipher_id, key=key)
            plaintext = cipher.decrypt(ciphertext)

        # ── Key file mode ──
        elif mode == "keyfile":
            if not args.keyfile:
                abort("--keyfile is required for keyfile mode.", "decrypt", cipher_id, mode, filename)
            key      = load_keyfile(args.keyfile)
            cipher   = CipherRegistry.get(cipher_id, key=key)
            plaintext = cipher.decrypt(ciphertext)

        # ── Keypair mode ──
        elif mode == "keypair":
            if not args.privkey:
                abort("--privkey is required for keypair mode.", "decrypt", cipher_id, mode, filename)
            priv_key  = load_private_key(args.privkey)
            cipher    = CipherRegistry.get("rsa", private_key=priv_key)
            plaintext = cipher.decrypt(ciphertext)

        else:
            abort(f"Unknown mode: {mode}")

        # Integrity check
        if not verify_sha256(plaintext, stored_sha256):
            abort(
                "Integrity check FAILED. File may be tampered with or wrong key used.",
                "decrypt", cipher_id, mode, filename
            )

        Path(output_path).write_bytes(plaintext)
        print(f"\n[Decrypt] Done.")
        print(f"  Input:   {input_path}")
        print(f"  Output:  {output_path} ({len(plaintext):,} bytes)")
        print(f"  Cipher:  {cipher_id.upper()} | Mode: {mode}")
        print(f"  Integrity: ✓ SHA-256 verified")
        log("decrypt", "success", cipher_id=cipher_id, mode=mode, filename=filename)

    except EclipseError as e:
        abort(str(e), "decrypt", cipher_id, mode, filename)


def cmd_logs(args):
    """View audit logs (admin only)."""
    password = get_password("Admin password: ")
    try:
        entries = read_logs(password)
        if not entries:
            print("[Logs] No entries yet.")
            return
        print(f"\n=== Audit Log ({len(entries)} entries) ===\n")
        for e in entries:
            status_icon = "✓" if e["status"] == "success" else "✗"
            print(f"  {status_icon} {e['timestamp']}  {e['action']:<10} {e['cipher']:<15} {e['mode']:<10} {e['filename']}")
    except EclipseError as e:
        abort(str(e))


# ── Argument Parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eclipsecode",
        description="EclipseCode — File Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py setup
  python cli.py ciphers
  python cli.py keygen --cipher aes --out mykey
  python cli.py keygen --cipher rsa --out mykeys
  python cli.py encrypt secret.pdf --cipher aes --mode password
  python cli.py encrypt secret.pdf --cipher aes --mode keyfile --keyfile mykey.eckey
  python cli.py encrypt secret.pdf --cipher rsa --mode keypair --pubkey mykeys.pub
  python cli.py decrypt secret.pdf.ec --mode password
  python cli.py decrypt secret.pdf.ec --mode keyfile --keyfile mykey.eckey
  python cli.py decrypt secret.pdf.ec --mode keypair --privkey mykeys.priv
  python cli.py logs
        """
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    sub.add_parser("setup", help="First-time admin setup")

    # ciphers
    sub.add_parser("ciphers", help="List available ciphers")

    # keygen
    kg = sub.add_parser("keygen", help="Generate a key file or RSA keypair")
    kg.add_argument("--cipher", choices=["aes", "rsa"], default="aes")
    kg.add_argument("--out", required=True, help="Output file prefix")

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("file", help="File to encrypt")
    enc.add_argument("--cipher", default="aes", help="Cipher to use (default: aes)")
    enc.add_argument("--mode", choices=["password", "keyfile", "keypair"], default="password")
    enc.add_argument("--keyfile", help="Path to .eckey file (keyfile mode)")
    enc.add_argument("--pubkey",  help="Path to .pub file (keypair mode)")

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a .ec file")
    dec.add_argument("file", help=".ec file to decrypt")
    dec.add_argument("--keyfile",  help="Path to .eckey file (keyfile mode)")
    dec.add_argument("--privkey",  help="Path to .priv file (keypair mode)")

    # logs
    sub.add_parser("logs", help="View audit logs (admin only)")

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    commands = {
        "setup":   cmd_setup,
        "ciphers": cmd_ciphers,
        "keygen":  cmd_keygen,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "logs":    cmd_logs,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()