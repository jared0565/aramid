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
    assert 'api_key = "[REDACTED]"' in out          # closing quote stays balanced


def test_packet_rename_out_of_ignored_dir_no_leak(tmp_path):
    # FIX 3 regression: a file renamed OUT of an ignored dir (graph-out/)
    # into a tracked path must not leak the ignored dir's name into the
    # packet via a git "rename from graph-out/..." diff header. build_packet
    # scopes diff_text with a single-endpoint (new-path-only) pathspec,
    # which makes git render the rename as a full-file add instead of a
    # tracked rename -- so no "graph-out" text ever reaches pkt.text.
    r = _repo(tmp_path)
    _commit(r, "src/a.py", "x = 1\n", "c1")
    (r / "graph-out").mkdir()
    (r / "graph-out" / "graph.json").write_text("{}", encoding="utf-8")
    _git(r, "add", "graph-out/graph.json")
    _git(r, "commit", "-m", "add graph-out")
    base = _sha(r)
    _git(r, "mv", "graph-out/graph.json", "notes.json")
    _git(r, "commit", "-m", "rename out of graph-out")
    pkt = review.build_packet(r, _cfg(), _item(base, _sha(r)))
    assert pkt is not None
    assert "graph-out" not in pkt.text


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


def test_packet_lists_at_most_fifty_dependents(tmp_path, monkeypatch):
    """The drain confirms a mutant against the unit suite alone, and the
    `deps[:50]` cap was reached only by tests/integration/test_review*.py."""
    r = _repo(tmp_path)
    _commit(r, "src/a.py", "x = 1\n", "base")
    base = _sha(r)
    _commit(r, "src/a.py", "x = 2\n", "head")
    deps = [f"src/dep_{i:02d}.py" for i in range(51)]
    monkeypatch.setattr(review.triage, "dependents", lambda root, files: deps)

    pkt = review.build_packet(r, _cfg(), _item(base, _sha(r)))
    listed = [ln[2:] for ln in pkt.text.splitlines() if ln.startswith("- src/dep_")]
    assert listed == deps[:50]
    assert "src/dep_50.py" not in pkt.text


def test_packet_cap_boundaries_and_the_sections_it_never_writes(tmp_path):
    """Both byte-cap comparisons at their boundary, and the file sections a
    packet must not carry. A diff of exactly the cap is truncated (`>=`); a
    file section landing exactly on the cap is kept (`>`, not `>=`); an
    emptied file and a binary one get no section (`not content or binary`);
    a section header carries the 12-character head prefix."""
    r = _repo(tmp_path)
    _commit(r, "src/a.py", "x = 1\n" * 50, "c1")
    base = _sha(r)
    _commit(r, "src/a.py", "", "c2")
    head = _sha(r)
    diff = review.gitutil.diff_text(r, base, head, paths=["src/a.py"])
    n = len(diff.encode("utf-8"))
    assert n > 100
    pkt = review.build_packet(r, _cfg(packet_max_bytes=n), _item(base, head))
    assert pkt.truncated is True and "TRUNCATED" in pkt.text
    pkt = review.build_packet(r, _cfg(packet_max_bytes=n + 1), _item(base, head))
    assert pkt.truncated is False and "--- FILE:" not in pkt.text, "an emptied file has no section"

    base = head
    (r / "src" / "blob.bin").write_bytes(b"\x00\x01binary")
    _git(r, "add", "src/blob.bin")
    _commit(r, "src/b.py", "y = 2\n", "c3")
    head = _sha(r)
    item = _item(base, head)
    pkt = review.build_packet(r, _cfg(), item)
    assert f"--- FILE: src/b.py (at {head[:12]}) ---\ny = 2\n" in pkt.text
    assert "blob.bin (at" not in pkt.text, "a binary file has no section"

    files = ["src/b.py", "src/blob.bin"]
    diff = review.gitutil.diff_text(r, base, head, paths=files)
    header = ["=== ARAMID REVIEW PACKET ===", f"repo: {r.name}", f"range: {item.range_str}",
              "triage reasons: risky"]
    used = len("\n".join([*header, review._BEGIN, "--- DIFF ---", diff]).encode("utf-8"))
    section = len(f"--- FILE: src/b.py (at {head[:12]}) ---\ny = 2\n".encode("utf-8"))
    pkt = review.build_packet(r, _cfg(packet_max_bytes=used + section), item)
    assert pkt.truncated is False and "--- FILE: src/b.py" in pkt.text, \
        "a section that lands exactly on the cap is kept"
    pkt = review.build_packet(r, _cfg(packet_max_bytes=used + section - 1), item)
    assert pkt.truncated is True and "--- FILE: src/b.py" not in pkt.text
