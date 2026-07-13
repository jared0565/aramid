import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import review
from aramid.queue import QueueItem


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


def _commit(root, name, content, msg):
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-m", msg)


def _sha(root, rev="HEAD"):
    p = subprocess.run(["git", "rev-parse", rev], cwd=root, check=True,
                       capture_output=True, text=True)
    return p.stdout.strip()


def _cfg(**over):
    llm = {"packet_max_bytes": 120000, **over}
    return SimpleNamespace(llm=llm, ignore_paths=[".aramid/", "graph-out/", ".graphite*",
                                                  ".cache/", "node_modules/", ".venv/",
                                                  "__pycache__/", ".git/"])


def _item(base, head):
    return QueueItem(id="q1", base=base, head=head, score=80, reasons=("risky",),
                     state="queued", created_at="2026-07-13T12:00:00+00:00",
                     updated_at="2026-07-13T12:00:00+00:00")


def test_packet_contains_diff_body_and_delimiters(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/auth.py", "def login(u):\n    return True\n", "c1")
    base = _sha(r)
    _commit(r, "src/auth.py", "def login(u):\n    return u.admin\n", "c2")
    pkt = review.build_packet(r, _cfg(), _item(base, _sha(r)))
    assert pkt is not None
    assert "UNTRUSTED_DATA_BEGIN" in pkt.text and "UNTRUSTED_DATA_END" in pkt.text
    assert "return u.admin" in pkt.text            # diff + head body
    assert "--- FILE: src/auth.py" in pkt.text
    assert pkt.files == ["src/auth.py"]
    assert "risky" in pkt.text                     # triage reasons in header


def test_packet_filters_graphite_artifacts(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/a.py", "x = 1\n", "c1")
    base = _sha(r)
    _commit(r, "graph-out/graph.json", "{}", "graph")
    _commit(r, "src/a.py", "x = 2\n", "c2")
    pkt = review.build_packet(r, _cfg(), _item(base, _sha(r)))
    assert pkt.files == ["src/a.py"]
    assert "graph-out" not in pkt.text             # spec 8b: never in a packet


def test_packet_empty_when_all_filtered(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/a.py", "x = 1\n", "c1")
    base = _sha(r)
    _commit(r, "graph-out/graph.json", "{}", "graph only")
    assert review.build_packet(r, _cfg(), _item(base, _sha(r))) is None


def test_packet_truncates_at_cap(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/big.py", "# tiny\n", "c1")
    base = _sha(r)
    _commit(r, "src/big.py", "x = 1\n" * 20000, "c2")   # ~120kB body
    pkt = review.build_packet(r, _cfg(packet_max_bytes=5000), _item(base, _sha(r)))
    assert pkt.truncated is True
    assert len(pkt.text.encode("utf-8")) <= 5000 + 2000   # header/markers margin
    assert "TRUNCATED" in pkt.text


def test_redact_masks_secret_shapes():
    text = ("aws = AKIAIOSFODNN7EXAMPLE\n"
            "gh = ghp_" + "a" * 36 + "\n"
            'api_key = "0123456789abcdef0123"\n'
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
            "normal = compute(1, 2)\n")
    out = review.redact_packet(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "ghp_" + "a" * 36 not in out
    assert "0123456789abcdef0123" not in out
    assert "MIIE" not in out
    assert "normal = compute(1, 2)" in out          # non-secrets untouched
    assert "[REDACTED]" in out


def test_dependents_extracted_from_triage(tmp_path):
    import json as _json
    from aramid import triage
    r = _repo(tmp_path)
    _commit(r, "src/aramid/queue.py", "x = 1\n", "c1")
    graph = {"nodes": [{"id": "n1", "kind": "module", "source_file": "src/aramid/queue.py"},
                       {"id": "queue", "kind": "unknown"}],
             "edges": [{"source": "drain", "target": "queue", "kind": "imports"}]}
    (r / "graph-out").mkdir()
    (r / "graph-out" / "graph.json").write_text(_json.dumps(graph), encoding="utf-8")
    assert triage.dependents(r, ["src/aramid/queue.py"]) == ["drain"]
    assert triage.dependents(r, ["src/other.py"]) == []
