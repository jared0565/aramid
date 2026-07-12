import hashlib, os
from pathlib import Path

def load_or_create_salt(aramid_dir: Path) -> bytes:
    f = aramid_dir / "salt"
    if f.exists():
        return f.read_bytes()
    aramid_dir.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(32)
    f.write_bytes(salt)
    try: os.chmod(f, 0o600)
    except OSError: pass
    return salt

def redact(secret: str, salt: bytes) -> tuple[str, str]:
    preview = f"{secret[:2]}…{secret[-2:]}" if len(secret) >= 5 else "…"
    return preview, hashlib.sha256(salt + secret.encode()).hexdigest()

def scrub(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, f"{s[:2]}…{s[-2:]}" if len(s) >= 5 else "…")
    return text
