from pathlib import Path
from aramid.redact import load_or_create_salt, redact, scrub

def test_salt_is_stable(tmp_path: Path):
    s1 = load_or_create_salt(tmp_path); s2 = load_or_create_salt(tmp_path)
    assert s1 == s2 and len(s1) == 32

def test_redact_hides_body_but_is_stable(tmp_path):
    salt = load_or_create_salt(tmp_path)
    p, h = redact("AKIAABCDEFGH1234", salt)
    assert p == "AK…34" and "ABCDEFGH" not in p
    assert redact("AKIAABCDEFGH1234", salt)[1] == h

def test_scrub_removes_raw_secret_from_logs(tmp_path):
    salt = load_or_create_salt(tmp_path)
    assert "SEKRET" not in scrub("leaked=SEKRETvalue", ["SEKRETvalue"])

def test_hash_depends_on_salt():
    p1, h1 = redact("AKIAABCDEFGH1234", b"salt-one-000000000000000000000000")
    p2, h2 = redact("AKIAABCDEFGH1234", b"salt-two-000000000000000000000000")
    assert h1 != h2 and p1 == p2
