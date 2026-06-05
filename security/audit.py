"""
EclipseCode Audit Log
----------------------
Structured JSON audit log — one entry per line (JSONL format).
Every encrypt/decrypt/keygen operation is logged with:
    - timestamp
    - action
    - cipher used
    - mode (password/keyfile/keypair)
    - filename
    - status (success/failure)
    - error message if failed

Log file: .ec_audit.jsonl
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from core.exceptions import AuthenticationError
from security.auth import verify_admin

AUDIT_FILE = ".ec_audit.jsonl"


def log(
    action: str,
    status: str,
    cipher_id: str = "N/A",
    mode: str = "N/A",
    filename: str = "N/A",
    error: str = ""
) -> None:
    """
    Append a structured log entry to the audit file.

    Args:
        action:    "encrypt", "decrypt", "keygen", "auth"
        status:    "success" or "failure"
        cipher_id: e.g. "aes", "rsa"
        mode:      "password", "keyfile", "keypair"
        filename:  file being operated on
        error:     error message if status is "failure"
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "status":    status,
        "cipher":    cipher_id,
        "mode":      mode,
        "filename":  filename,
    }
    if error:
        entry["error"] = error

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_logs(password: str) -> list[dict]:
    """
    Read and return all audit log entries.
    Requires admin password verification.
    Raises AuthenticationError if password is wrong.
    """
    if not verify_admin(password):
        raise AuthenticationError("Incorrect admin password.")

    if not Path(AUDIT_FILE).exists():
        return []

    entries = []
    for line in Path(AUDIT_FILE).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def clear_logs(password: str) -> None:
    """Clear all audit logs. Requires admin password."""
    if not verify_admin(password):
        raise AuthenticationError("Incorrect admin password.")
    Path(AUDIT_FILE).write_text("", encoding="utf-8")
    print("[Audit] Logs cleared.")