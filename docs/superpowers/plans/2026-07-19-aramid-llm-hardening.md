# Aramid LLM-Subsystem Hardening Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 9 deferred hardening tickets from the autolearn + Phase 2b reviews: arm.py TOML-rewrite corruption, self-refute auditability, openrouter spend under-logging, consumer cost accounting, fail-open wrap, and the deferred test/comment debt.

**Architecture:** No new modules. Six tasks of surgical edits to `arm.py`, `llm_review.py`, `openrouter.py`, `ledger.py` (comment-only), plus tests. The pre-push block path is untouched: `confirmed=True` remains mintable only by `review.apply_refute` on a survived critical.

**Tech Stack:** Python 3.14, pytest, stdlib only (no new deps).

**Spec:** `docs/superpowers/specs/2026-07-19-aramid-llm-hardening-design.md` (user-approved).

## Global Constraints

- Branch: `feat/llm-hardening` off current `main` (includes spec commit `7c2d7ab`).
- Tests run via `python -m pytest` (tools live in `%APPDATA%\Python\Python314\Scripts`, NOT on PATH — never invoke bare `pytest`/`ruff`; use `python -m`).
- Full suite at branch base: 665 passing. It must stay green after every task.
- Ruff: `python -m ruff check src tests` — the finding count must not increase over the branch-base count (43 pre-existing accepted; new/changed code clean).
- Block-path invariant (every reviewer checks): no change may create a new way for `confirmed` or `refuted` to become `True`. The trust-boundary strip in `consume()` (lines ~299-303) and `apply_refute` stay byte-identical.
- Money invariant: `openrouter._under_cap` / `spend.month_spend_usd` logic untouched; new spend records only ever ADD visibility (a 0.0-cost record cannot loosen the cap).
- New test files must have suite-unique basenames (a duplicate basename breaks `python -m pytest -q` collection — happened before with `test_arm.py`).
- Windows host: file writes use `encoding="utf-8"` explicitly, as all existing code does.

---

### Task 1: arm.py — inline-comment tolerance + root-key placement

The three key-rewrite regexes miss a key line carrying a trailing `# comment`,
so `cmd_arm` inserts a DUPLICATE key and tomllib refuses the file afterwards
("Cannot overwrite a value") — fails closed but corrupts the user's config.
Additionally `_KEY_RE`/`_LLM_KEY_RE` still use `\s*` (spans newlines — the same
class as Task 11's `_AL_KEY_RE` critical, fixed there but not here), and the
semgrep no-key path appends the ROOT key at EOF where it lands inside whatever
`[table]` is last.

**Files:**
- Modify: `src/aramid/commands/arm.py` (lines 18-23 regexes; lines 26-56 helpers; lines 92-96 semgrep branch)
- Test: `tests/unit/test_arm_inline_comments.py` (NEW — basename is suite-unique)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `_armed_sub(key_re, new_line, text, count=0) -> str` (module-private helper; the three call sites below use it). Regexes gain a named group `c` (the optional trailing comment). No public API change; `cmd_arm(root, llm=..., autolearn=...)` signature unchanged.

- [ ] **Step 1: Create the branch**

```powershell
git checkout main; git pull; git checkout -b feat/llm-hardening
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_arm_inline_comments.py`:

```python
"""Inline-comment tolerance + root-key placement for the arm rewrite family
(_KEY_RE / _LLM_KEY_RE / _AL_KEY_RE): a trailing `# comment` on the key line
must be matched (no duplicate-key TOML corruption) and preserved verbatim,
and a missing ROOT key must never be appended inside a trailing [table]."""
import tomllib

from aramid.commands.arm import _arm_autolearn_text, _arm_llm_text, cmd_arm


def test_semgrep_key_with_inline_comment_rewritten_in_place(tmp_path):
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n"
        "semgrep_block_armed = false  # ends the bake\n"
        'bake_started = "2026-07-01"\n', encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    got = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert got == ("schema_version = 1\n"
                   "semgrep_block_armed = true  # ends the bake\n"
                   'bake_started = "2026-07-01"\n')
    assert tomllib.loads(got)["semgrep_block_armed"] is True


def test_semgrep_key_comment_without_space_before_hash(tmp_path):
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false# x\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    got = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert got == "semgrep_block_armed = true# x\n"
    assert tomllib.loads(got)["semgrep_block_armed"] is True


def test_llm_key_with_inline_comment_rewritten_in_place():
    text = "[llm]\nllm_block_armed = false  # baking since 07-01\n"
    got = _arm_llm_text(text)
    assert got == "[llm]\nllm_block_armed = true  # baking since 07-01\n"
    assert tomllib.loads(got)["llm"]["llm_block_armed"] is True


def test_autolearn_key_with_inline_comment_rewritten_in_place():
    text = "[llm.autolearn]\nenabled = true\narmed = false  # shadow\n"
    got = _arm_autolearn_text(text)
    assert got == "[llm.autolearn]\nenabled = true\narmed = true  # shadow\n"
    assert tomllib.loads(got)["llm"]["autolearn"]["armed"] is True


def test_no_duplicate_key_inserted_when_comment_present():
    """The corruption regression: pre-fix, a commented key line missed the
    regex -> a SECOND llm_block_armed was inserted under [llm] -> tomllib
    'Cannot overwrite a value' on every later load."""
    text = "[llm]\nllm_block_armed = false  # note\n"
    got = _arm_llm_text(text)
    assert got.count("llm_block_armed") == 1
    tomllib.loads(got)          # must not raise


def test_semgrep_newline_boundary_not_swallowed(tmp_path):
    """Same family as Task 11's _AL_KEY_RE critical: `\\s*$` in (?m) mode
    swallows the blank line before a following section. The horizontal-only
    classes must preserve the section boundary byte-for-byte."""
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false\n\n[pack]\nenabled = true\n",
        encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    got = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert got == "semgrep_block_armed = true\n\n[pack]\nenabled = true\n"


def test_root_key_inserted_before_first_section_not_eof(tmp_path):
    """Hand-edited config with no root key but a trailing [llm] section:
    the key must land at ROOT scope, not inside the trailing table."""
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n\n[llm]\nenabled = true\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    parsed = tomllib.loads((tmp_path / "aramid.toml").read_text(encoding="utf-8"))
    assert parsed["semgrep_block_armed"] is True
    assert "semgrep_block_armed" not in parsed["llm"]


def test_root_key_appended_at_eof_when_no_sections(tmp_path):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    parsed = tomllib.loads((tmp_path / "aramid.toml").read_text(encoding="utf-8"))
    assert parsed["semgrep_block_armed"] is True
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_arm_inline_comments.py -q`
Expected: FAIL — the three `..._with_inline_comment...`, `no_duplicate_key`, and `root_key_inserted_before_first_section` tests fail (duplicate key inserted / key lands in `[llm]` / `[pack]` boundary case may pass already — that's fine, it locks current behavior). `eof_when_no_sections` passes (existing behavior).

- [ ] **Step 4: Implement**

In `src/aramid/commands/arm.py`, replace the three key regexes (keep `_LLM_SECTION_RE`, `_AL_SECTION_RE`, `_NEXT_SECTION_RE` as-is):

```python
# Key-line rewrite family. Horizontal-whitespace-only classes ([^\S\n]) so a
# match can never swallow the newline/section boundary after the line (the
# Task-11 _AL_KEY_RE lesson, now applied to all three), and an optional
# trailing inline comment is captured in group `c` and preserved verbatim by
# _armed_sub (a missed match here inserts a DUPLICATE key -> tomllib
# "Cannot overwrite a value" corruption).
_KEY_RE = re.compile(
    r"(?m)^semgrep_block_armed[^\S\n]*=[^\S\n]*\S+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_LLM_KEY_RE = re.compile(
    r"(?m)^llm_block_armed[^\S\n]*=[^\S\n]*\S+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_LLM_SECTION_RE = re.compile(r"(?m)^\[llm\]\s*$")
_AL_SECTION_RE = re.compile(r"(?m)^\[llm\.autolearn\]\s*$")
_AL_KEY_RE = re.compile(
    r"(?m)^armed[^\S\n]*=[^\S\n]*\S+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_NEXT_SECTION_RE = re.compile(r"(?m)^\[")


def _armed_sub(key_re: re.Pattern, new_line: str, text: str, count: int = 0) -> str:
    """Comment-preserving key rewrite: whatever trailing `# ...` the old line
    carried is re-emitted verbatim after the new value."""
    return key_re.sub(lambda m: new_line + (m.group("c") or ""), text, count=count)
```

Update the three substitution call sites:

In `_arm_llm_text` (line ~32):

```python
    if _LLM_KEY_RE.search(text):
        return _armed_sub(_LLM_KEY_RE, "llm_block_armed = true", text)
```

In `_arm_autolearn_text` (line ~52):

```python
        if _AL_KEY_RE.search(section):
            return (text[:m.end()] + _armed_sub(_AL_KEY_RE, "armed = true",
                                                section, count=1) + text[span_end:])
```

In `cmd_arm` semgrep branch (lines ~92-96), replace:

```python
    if _KEY_RE.search(text):
        new_text = _KEY_RE.sub("semgrep_block_armed = true", text)
    else:
        prefix = "" if not text or text.endswith("\n") else "\n"
        new_text = text + prefix + "semgrep_block_armed = true\n"
```

with:

```python
    if _KEY_RE.search(text):
        new_text = _armed_sub(_KEY_RE, "semgrep_block_armed = true", text)
    else:
        m = _NEXT_SECTION_RE.search(text)
        if m:
            # A bare key appended at EOF would land inside whatever [table]
            # happens to be last (e.g. the [llm] section arm --llm writes) --
            # a ROOT key must be inserted before the first section header.
            new_text = (text[:m.start()] + "semgrep_block_armed = true\n"
                        + text[m.start():])
        else:
            prefix = "" if not text or text.endswith("\n") else "\n"
            new_text = text + prefix + "semgrep_block_armed = true\n"
```

- [ ] **Step 5: Run the new tests — all pass**

Run: `python -m pytest tests/unit/test_arm_inline_comments.py -q`
Expected: 8 passed.

- [ ] **Step 6: Run every existing arm test (regression)**

Run: `python -m pytest tests/integration/test_arm.py tests/unit/test_arm_llm.py tests/unit/test_arm_autolearn.py tests/integration/test_cli_dispatch.py -q`
Expected: all pass, zero failures. (These lock the no-comment paths byte-for-byte.)

- [ ] **Step 7: Commit**

```powershell
git add src/aramid/commands/arm.py tests/unit/test_arm_inline_comments.py
git commit -m "fix(arm): key regexes tolerate+preserve inline comments; root key never lands in a trailing table"
```

---

### Task 2: self-refute audit flag + README correction

`review.select_refuter` falls back to the reviewer's own arm when no other
provider is available (single-provider installs). Nothing marks that
explicitly: telemetry needs a join to spot it and the persisted finding
carries no trace, while the README claims an unqualified "cross-provider
refute".

**Files:**
- Modify: `src/aramid/consumers/llm_review.py` (refute loop, lines ~331-371)
- Modify: `README.md` (two sentences)
- Test: `tests/unit/test_llm_consumer.py` (one new test, one strengthened)

**Interfaces:**
- Consumes: `review.select_refuter(arms, reviewer_arm, avail) -> Arm` (unchanged).
- Produces: every `refute_infos` entry now carries `"self_refute": bool`; a self-refuted verdict's reason is prefixed `"self-refute: "` (renders as `[refute survived: self-refute: …]` / `[refuted: self-refute: …]` in the persisted explanation). `review.apply_refute` is UNCHANGED. Task 5's tests may rely on the key existing.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_llm_consumer.py`:

```python
def test_self_refute_flagged_in_telemetry_and_record(tmp_path, monkeypatch):
    """Single-provider install: the refuter falls back to the reviewer's own
    provider -- telemetry marks self_refute=True and the persisted finding's
    message carries the self-refute marker."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical")),
                         ProviderResponse(text=json.dumps(
                             {"refuted": False, "reason": "still real"}))])
    _wire(monkeypatch, a)
    ladder = [
        {"tier": "cheap", "provider": "fake-a", "model": "ma", "effort": "", "min_score": 40},
        {"tier": "frontier", "provider": "fake-a", "model": "ma2", "effort": "", "min_score": 80},
    ]
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, ladder))
    finally:
        led.close()
    (ref,) = got.extra["selection"]["refutes"]
    assert ref["self_refute"] is True
    assert ref["outcome"] == "survived"
    (f,) = got.findings
    assert f.confirmed is True                 # single-provider can still confirm
    assert "self-refute:" in f.message


def test_cross_provider_refute_not_flagged_self(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text=json.dumps(
        {"refuted": False, "reason": "verified"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    (ref,) = got.extra["selection"]["refutes"]
    assert ref["self_refute"] is False
    assert "self-refute" not in got.findings[0].message
```

Also strengthen the existing clipped-path test — in
`test_refute_clipped_outcome_unavailable`, extend the final assert line to:

```python
    assert ref["outcome"] == "unavailable" and ref["refuter_provider"] is None
    assert ref["self_refute"] is False         # no call was made
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_consumer.py -k "self_refute or not_flagged_self or clipped" -q`
Expected: FAIL — `KeyError: 'self_refute'` (key absent from entries).

- [ ] **Step 3: Implement**

In `src/aramid/consumers/llm_review.py`:

The clipped branch (lines ~344-346) — add the key to the entry:

```python
                refute_infos.append({"refuter_provider": None,
                                     "refuter_tier": None,
                                     "self_refute": False,
                                     "outcome": "unavailable",
                                     "latency_s": 0.0})
```

The live-refute branch (lines ~351-370) — replace with:

```python
            else:
                refuter_arm = review.select_refuter(arms, reviewer_arm, avail)
                # Single-provider fallback (spec 2b): the refuter can be the
                # reviewer's own provider. Flag it -- audits must be able to
                # tell an independent confirmation from a self-confirmation.
                self_refute = refuter_arm.provider == reviewer_arm.provider
                rr, rlat = _call(providers_base.PROVIDERS[refuter_arm.provider],
                                 review.render_refute_prompt(cand, packet),
                                 refuter_arm.model, cfg,
                                 timeout_s, effort=refuter_arm.effort)
                _refutes_used += 1
                refutes += 1
                cost += rr.cost_usd
                tokens_in += rr.tokens_in
                tokens_out += rr.tokens_out
                parsed = review.parse_refute_response(rr.text) if not rr.error else None
                refute_infos.append({
                    "refuter_provider": refuter_arm.provider,
                    "refuter_tier": refuter_arm.tier,
                    "self_refute": self_refute,
                    "outcome": ("unavailable" if parsed is None
                                else ("refuted" if parsed[0] else "survived")),
                    "latency_s": rlat})
                if parsed is None:      # transport failure OR malformed refute:
                    parsed = (True, f"refute unavailable ({rr.error or 'malformed'})")
                if self_refute:
                    # Marker rides the reason text into the persisted
                    # explanation: [refute survived: self-refute: ...]
                    parsed = (parsed[0], f"self-refute: {parsed[1]}")
                cand = review.apply_refute(cand, *parsed)
```

(The only changes vs current code: the `self_refute` local, the new dict key,
and the reason-prefix `if`. Everything else byte-identical — reviewers diff it.)

In `README.md`, two edits:

Old: `chain, cross-provider refute, bake-then-arm blocking (detailed below).`
New: `chain, cross-provider refute (self-refute fallback on single-provider installs), bake-then-arm blocking (detailed below).`

Old:
```
every fresh CRITICAL gets one cross-provider refute call before it can be
marked `confirmed`. Findings land in the ledger as WARN — same bake
```
New:
```
every fresh CRITICAL gets one cross-provider refute call before it can be
marked `confirmed` (when only one provider is installed the refute falls
back to the same provider — flagged `self_refute` in selection telemetry
and `self-refute:` in the finding record). Findings land in the ledger as
WARN — same bake
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: all pass (the whole file — proves the two byte-identical claims above didn't break the other ~45 tests).

- [ ] **Step 5: Commit**

```powershell
git add src/aramid/consumers/llm_review.py README.md tests/unit/test_llm_consumer.py
git commit -m "feat(llm): flag self-refute in telemetry and finding record; README stops overclaiming cross-provider"
```

---

### Task 3: openrouter spend visibility (timeout marker + loud write-fail)

A TIMEOUT returns with no spend record (the call may have been billed
server-side); a spend-log write failure is a silent `except OSError: pass`.
Both silently under-count month spend against the cap.

**Files:**
- Modify: `src/aramid/providers/openrouter.py` (timeout branch line ~60-61; spend append lines ~89-95)
- Test: `tests/unit/test_provider_openrouter.py`

**Interfaces:**
- Consumes: `spend.append_spend(entry: dict) -> None` (unchanged; JSON-dumps any dict — the extra `note` key is harmless, `month_spend_usd` reads only `provider`/`at`/`cost_usd`).
- Produces: module-private `_append_spend_or_warn(entry: dict) -> None`. No public API change.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_provider_openrouter.py`:

```python
def test_timeout_appends_zero_cost_marker(monkeypatch, tmp_path):
    """A timed-out call may have been billed server-side: the spend log gets
    a zero-cost marker so audits see the call happened. cost_usd=0.0 means
    the cap math is unchanged."""
    def boom(req, timeout):
        raise TimeoutError()
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", boom)
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_TIMEOUT
    lines = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    assert rec["provider"] == "openrouter" and rec["cost_usd"] == 0.0
    assert "timeout" in rec["note"]
    assert openrouter.available(_cfg()) is True      # marker never trips the cap


def test_spend_write_failure_warns_stderr_success_path(monkeypatch, capsys):
    def fake_urlopen(req, timeout):
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(openrouter.spend, "append_spend",
                        lambda entry: (_ for _ in ()).throw(OSError("disk full")))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == "" and resp.cost_usd == 0.011   # response still returned
    assert "spend log write failed" in capsys.readouterr().err


def test_spend_write_failure_warns_stderr_timeout_path(monkeypatch, capsys):
    def boom(req, timeout):
        raise TimeoutError()
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", boom)
    monkeypatch.setattr(openrouter.spend, "append_spend",
                        lambda entry: (_ for _ in ()).throw(OSError("disk full")))
    resp = openrouter.review("P", "m", 240.0, cfg=_cfg())
    assert resp.error == base.ERR_TIMEOUT
    assert "spend log write failed" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_provider_openrouter.py -k "timeout_appends or write_failure" -q`
Expected: FAIL — no marker file written; no stderr output.

- [ ] **Step 3: Implement**

In `src/aramid/providers/openrouter.py`, add after `_under_cap` (before `installed`):

```python
def _append_spend_or_warn(entry: dict) -> None:
    """A failed spend write means the month sum under-counts from here on --
    that must be LOUD (the cap silently erodes otherwise), but never fatal:
    the response is already paid for and must still reach the caller."""
    try:
        spend.append_spend(entry)
    except OSError:
        print("aramid: openrouter: spend log write failed -- month spend is "
              "now under-counted", file=sys.stderr)
```

Replace the timeout branch:

```python
    except TimeoutError:
        # The request may have completed -- and been billed -- server-side
        # after the client gave up: leave a zero-cost marker so the spend log
        # shows the call happened even though its cost is unknown.
        _append_spend_or_warn({"at": datetime.now(timezone.utc).isoformat(),
                               "provider": NAME, "model": model,
                               "tokens_in": 0, "tokens_out": 0,
                               "cost_usd": 0.0, "note": "timeout -- cost unknown"})
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
```

Replace the success-path append (the whole `try: spend.append_spend(...) except OSError: pass` block):

```python
    _append_spend_or_warn({"at": datetime.now(timezone.utc).isoformat(),
                           "provider": NAME, "model": model,
                           "tokens_in": resp.tokens_in, "tokens_out": resp.tokens_out,
                           "cost_usd": resp.cost_usd})
    return resp
```

- [ ] **Step 4: Run the whole provider test file**

Run: `python -m pytest tests/unit/test_provider_openrouter.py tests/unit/test_spend.py -q`
Expected: all pass (cap/fail-closed tests untouched and green).

- [ ] **Step 5: Commit**

```powershell
git add src/aramid/providers/openrouter.py tests/unit/test_provider_openrouter.py
git commit -m "fix(openrouter): timeout leaves a zero-cost spend marker; spend write failures warn instead of silent pass"
```

---

### Task 4: consumer — cost accounting on spend + fail-open wrap for target_arm/bucket_for

Two `llm_review.py` edits. (a) Cascade and audit paths only add
`cost`/`tokens` when the response PARSES — an unparseable response from a
real call drops its cost from `ConsumerResult.cost` and the selection
telemetry (money spent, books wrong). (b) `target_arm`/`bucket_for` sit
outside any try — verified non-raising today, but a future crash there kills
the item instead of degrading to the ladder.

**Files:**
- Modify: `src/aramid/consumers/llm_review.py` (lines ~134-135, ~241-246, ~273-278)
- Test: `tests/unit/test_llm_consumer.py`

**Interfaces:**
- Consumes: `_audit_cfg(ladder, **al_over)` and `_LADDER_AB` helpers already in the test file; `providers_base.ERR_MALFORMED`.
- Produces: accounting semantics Task 5's call-count tests assume: cascade/audit cost accrues iff the call's `error in ("", ERR_MALFORMED)`; `_reviews_used` still increments only on a PARSED cascade response.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_llm_consumer.py`:

```python
def test_cascade_unparseable_response_still_accounts_cost(tmp_path, monkeypatch):
    """Money accounting on SPEND, not parse success: an armed cascade whose
    re-review comes back as garbage still cost real tokens."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [
        ProviderResponse(text="garbage {{{", tokens_in=100, tokens_out=7,
                         cost_usd=0.5),                       # cascade re-review
        ProviderResponse(text=json.dumps(
            {"refuted": True, "reason": "nope"}))])           # refute
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["cascade"] == {"triggered": True, "trigger": "critical",
                              "applied": False}
    assert got.cost == 0.5                    # the unparseable call is on the books
    assert sel["tokens"]["in"] == 100 and sel["tokens"]["out"] == 7


def test_audit_unparseable_response_still_accounts_cost(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [ProviderResponse(text="garbage {{{", tokens_in=55,
                                          tokens_out=5, cost_usd=0.25)])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_audit_cfg(_LADDER_AB), ledger=led,
                       clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["audit"] == {"performed": False, "tier": "frontier",
                            "new_findings": 0, "missed_criticals": 0}
    assert got.cost == 0.25
    assert sel["tokens"]["in"] == 55 and sel["tokens"]["out"] == 5


def test_target_arm_crash_fails_open_to_ladder(tmp_path, monkeypatch):
    """Structural fail-open (T6): a crash in target_arm degrades to plain
    ladder service (tgt=None -> autolearn consult skipped), never a dead item."""
    from aramid import review as review_mod
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    monkeypatch.setattr(review_mod, "target_arm",
                        lambda *a_, **k: (_ for _ in ()).throw(RuntimeError()))
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.state == "ok"
    sel = got.extra["selection"]
    assert sel["target_tier"] is None and sel["bucket"] == "plain"
    assert sel["served"]["tier"] == "cheap"    # review still served off eff_score


def test_bucket_for_crash_fails_open_to_ladder(tmp_path, monkeypatch):
    from aramid import autolearn as autolearn_mod
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    monkeypatch.setattr(autolearn_mod, "bucket_for",
                        lambda *a_, **k: (_ for _ in ()).throw(RuntimeError()))
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.state == "ok"
    assert got.extra["selection"]["bucket"] == "plain"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_llm_consumer.py -k "unparseable_response_still or crash_fails_open" -q`
Expected: 4 FAIL — cost tests see `got.cost == 0.0`; crash tests raise RuntimeError out of `consume`.

- [ ] **Step 3: Implement**

In `src/aramid/consumers/llm_review.py`:

(a) Wrap lines ~134-135. Replace:

```python
    tgt = review.target_arm(arms, item.score)
    bucket = autolearn.bucket_for(item.reasons)
```

with:

```python
    # Fail-open hardening: neither helper raises today, but a crash here
    # would kill the item instead of degrading to the deterministic ladder
    # (autolearn spec section 11: policy failure -> ladder, never a crash).
    try:
        tgt = review.target_arm(arms, item.score)
        bucket = autolearn.bucket_for(item.reasons)
    except Exception:
        tgt, bucket = None, "plain"
```

(b) Cascade accounting (lines ~241-246). Replace:

```python
                    c2 = None if r2.error else review.parse_review_response(r2.text)
                    if c2 is not None:
                        _reviews_used += 1
                        cost += r2.cost_usd
                        tokens_in += r2.tokens_in
                        tokens_out += r2.tokens_out
```

with:

```python
                    # Cost accrues on SPEND, not on parse success -- an
                    # unparseable response still burned real tokens (same
                    # rule as the primary call above).
                    if r2.error in ("", providers_base.ERR_MALFORMED):
                        cost += r2.cost_usd
                        tokens_in += r2.tokens_in
                        tokens_out += r2.tokens_out
                    c2 = None if r2.error else review.parse_review_response(r2.text)
                    if c2 is not None:
                        _reviews_used += 1
```

(c) Audit accounting (lines ~273-278). Replace:

```python
                _audits_used += 1
                ca = None if ra.error else review.parse_review_response(ra.text)
                if ca is not None:
                    cost += ra.cost_usd
                    tokens_in += ra.tokens_in
                    tokens_out += ra.tokens_out
                    va, _reja = review.verify_findings(ca, packet,
```

with:

```python
                _audits_used += 1
                if ra.error in ("", providers_base.ERR_MALFORMED):
                    cost += ra.cost_usd
                    tokens_in += ra.tokens_in
                    tokens_out += ra.tokens_out
                ca = None if ra.error else review.parse_review_response(ra.text)
                if ca is not None:
                    va, _reja = review.verify_findings(ca, packet,
```

- [ ] **Step 4: Run the full consumer file**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: all pass — including every pre-existing cascade/audit/uplift test (the accounting change is additive-only for scripted responses that parse).

- [ ] **Step 5: Commit**

```powershell
git add src/aramid/consumers/llm_review.py tests/unit/test_llm_consumer.py
git commit -m "fix(llm): account cascade/audit cost on spend not parse; fail-open wrap for target_arm/bucket_for"
```

---

### Task 5: test batch — cascade guard paths, doctor foreign-version, refuted materialization

Pure test additions closing three review-flagged coverage gaps. No src/
changes; if any of these tests fails, STOP and report — that is a real bug,
not a test to adjust.

**Files:**
- Test: `tests/unit/test_llm_consumer.py` (2 new + 1 strengthened)
- Test: `tests/integration/test_doctor.py` (1 new)
- Test: `tests/unit/test_ledger_events.py` (1 new)

**Interfaces:**
- Consumes: `_Fake`, `_wire`, `_cfg`, `_LADDER_AB`, `_item_score`, `_repo` (test helpers, Task 4's final semantics); `aramid.commands.doctor._autolearn_probe_line`; `aramid.autolearn.STATE_VERSION` (== 1); `Ledger.open_findings()`.
- Produces: nothing downstream.

- [ ] **Step 1: cascade guard tests — append to `tests/unit/test_llm_consumer.py`**

```python
def test_cascade_never_triggers_for_top_tier_review(tmp_path, monkeypatch):
    """cascade_trigger's own guard: a frontier-served CRITICAL must not
    trigger (nothing above to escalate to) and must not spend an extra
    review call -- only the cross-provider refute fires."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=json.dumps(
        {"refuted": True, "reason": "no"}))])                 # refute only
    b = _Fake("fake-b", [ProviderResponse(text=_finding_json("critical"))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 80), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["cascade"] == {"triggered": False, "trigger": None,
                              "applied": False}
    assert len(b.calls) == 1          # served review only, no cascade call
    assert len(a.calls) == 1          # the refute


def test_cascade_next_arm_provider_unavailable_no_call(tmp_path, monkeypatch):
    """Armed cascade where the next arm's provider is unavailable: the guard
    must skip the call entirely (and the refuter falls back to self)."""
    class _Off(_Fake):
        def available(self, cfg):
            return False

    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical")),
                         ProviderResponse(text=json.dumps(
                             {"refuted": True, "reason": "nope"}))])
    b = _Off("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["cascade"]["triggered"] is True
    assert sel["cascade"]["applied"] is False
    assert b.calls == []              # unavailable arm never called
    assert len(a.calls) == 2          # served review + (self-)refute
```

Strengthen `test_cascade_skipped_when_review_budget_exhausted` — after the
existing `assert sel["cascade"]["applied"] is False` line, add:

```python
    assert len(a.calls) == 1          # the served review; no cascade call
    assert len(b.calls) == 1          # the refute only
```

- [ ] **Step 2: doctor foreign-version test — append to `tests/integration/test_doctor.py`**

```python
def test_doctor_reports_foreign_autolearn_state_version():
    """T13 gap: a state file from a different aramid version must probe as
    DEGRADED with the --rebuild hint (engine treats it as empty)."""
    import json as _json

    from aramid import autolearn
    from aramid.commands.doctor import _autolearn_probe_line
    autolearn.state_path().write_text(
        _json.dumps({"version": 999, "posteriors": {}}), encoding="utf-8")
    line = _autolearn_probe_line()
    assert "DEGRADED" in line
    assert "foreign state version" in line
    assert "--rebuild" in line
```

(`tests/conftest.py` autouse-patches `autolearn.state_path` to a per-test
tmp_path, so this writes no real machine state.)

- [ ] **Step 3: refuted materialization test — append to `tests/unit/test_ledger_events.py`**

```python
def test_refuted_flag_materializes_through_open_findings(tmp_path):
    """T3 gap: the refuted payload key must survive _materialize into the
    open_findings snapshot (autolearn's rollup reads it from there)."""
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.FINDING_DETECTED, "r1", "2026-07-19T00:00:00Z",
                     finding_id="f-refuted",
                     payload={"tool": "llm-review", "refuted": True}))
    led.append(Event(EventType.FINDING_DETECTED, "r1", "2026-07-19T00:00:00Z",
                     finding_id="f-plain",
                     payload={"tool": "llm-review"}))
    state = led.open_findings()
    led.close()
    assert state["f-refuted"]["refuted"] is True
    assert state["f-plain"].get("refuted", False) is False
```

- [ ] **Step 4: Run all three files**

Run: `python -m pytest tests/unit/test_llm_consumer.py tests/integration/test_doctor.py tests/unit/test_ledger_events.py -q`
Expected: all pass first try (these lock existing behavior). If ANY fails, stop and report the failure verbatim — it means the guarded behavior is broken for real.

- [ ] **Step 5: Commit**

```powershell
git add tests/unit/test_llm_consumer.py tests/integration/test_doctor.py tests/unit/test_ledger_events.py
git commit -m "test: cascade guard paths, doctor foreign-version branch, refuted materialization (T8b/T13/T3)"
```

---

### Task 6: compact() landmine comments + hermetic _cfg autolearn merge

Comment-only src change plus a test-fixture correctness fix.

**Files:**
- Modify: `src/aramid/ledger.py` (comment above `compact` body, line ~106)
- Modify: `tests/unit/test_llm_consumer.py` (`_cfg`, lines ~49-65)

**Interfaces:**
- Consumes: nothing.
- Produces: `_cfg(**over)` now MERGES an `autolearn=` override over the hermetic base instead of replacing it (`audit_every=0` persists unless a test sets it explicitly — `_audit_cfg` does).

- [ ] **Step 1: Add the compact() landmine comment**

In `src/aramid/ledger.py`, directly under `def compact(self) -> int:` insert:

```python
    def compact(self) -> int:
        # LANDMINE -- compact() is currently DEAD CODE (no src/ call sites).
        # Wiring it into a command must solve two integrations first:
        # (1) autolearn.rollup cursors are event COUNTS: compacting shrinks
        #     the list below a stored cursor -> rollup resets to 0 and
        #     RE-FOLDS the surviving events -> posterior double-count. Any
        #     wiring must rebuild the autolearn state (`aramid autolearn
        #     --rebuild`) in the same operation.
        # (2) only the latest CONSUMER_RUN_FINISHED row survives (below), so
        #     llm_review._malformed_attempts loses per-item history and the
        #     malformed-give-up counter silently resets.
```

- [ ] **Step 2: Fix the _cfg autolearn merge**

In `tests/unit/test_llm_consumer.py`, replace the `_cfg` body (lines ~49-65) with:

```python
def _cfg(**over):
    # Default ladder chosen so a score=80 item (the _item() default) selects
    # fake-a as reviewer and fake-b as the cross-provider refuter -- preserving
    # every existing test's fake-a=reviewer / fake-b=refuter assumption.
    ladder = over.pop("ladder", [
        {"tier": "cheap", "provider": "fake-b", "model": "mb", "effort": "", "min_score": 40},
        {"tier": "frontier", "provider": "fake-a", "model": "ma", "effort": "", "min_score": 80},
    ])
    # Hermetic-by-default: an autolearn= override MERGES over the base (it
    # used to replace it, silently reverting audit_every to the code default
    # 8 -> hash-sampled audits desynced scripted providers). audit_every=0
    # persists unless a test sets it explicitly (_audit_cfg does).
    al = {"enabled": True, "armed": False, "audit_every": 0,
          **over.pop("autolearn", {})}
    llm = {"enabled": True, "max_items_per_drain": 3, "call_timeout_s": 240,
           "packet_max_bytes": 120000, "provider_order": ["fake-a", "fake-b"],
           "ladder": ladder, "llm_block_armed": False,
           "autolearn": al,
           **over}
    return SimpleNamespace(llm=llm, ignore_paths=[".aramid/", "graph-out/", ".git/"])
```

- [ ] **Step 3: Verify no test relied on replacement semantics**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: ALL pass. Every `autolearn=` call site (`{"enabled": False}`, `{"enabled": True, "armed": True}`, `_audit_cfg`) now gets `audit_every=0` merged in unless it set its own — strictly MORE deterministic. If a test fails here, it was depending on implicit audits: stop and report (do not adjust the test).

- [ ] **Step 4: Run the ledger tests (comment-only change sanity)**

Run: `python -m pytest tests/unit/test_ledger_compact.py tests/unit/test_ledger_events.py tests/unit/test_ledger_state.py tests/unit/test_ledger_baseline.py -q`
Expected: all pass, unchanged.

- [ ] **Step 5: Commit**

```powershell
git add src/aramid/ledger.py tests/unit/test_llm_consumer.py
git commit -m "docs(ledger): compact() landmine comment; test: _cfg autolearn override merges hermetic base"
```

---

### Final gate (controller runs after Task 6)

- [ ] Full suite: `python -m pytest -q` — expected: 665 + ~20 new, 0 failures (~4-5 min with live tools).
- [ ] Ruff: `python -m ruff check src tests` — finding count must not exceed the branch-base count (run the same command on `main` if a baseline number is needed).
- [ ] Whole-branch adversarial review (sonnet; opus only via SendMessage-resume if it glitches), checking the four spec invariants:
  1. block path: `confirmed`/`refuted` minting unchanged;
  2. fail-open direction (Task 4 wrap can only degrade, never alter success results);
  3. money fail-closed (cap math untouched, markers are 0.0-cost);
  4. arm rewrites tomllib-parse cleanly with exactly one key, comments preserved.
- [ ] Push + CI green, then superpowers:finishing-a-development-branch (user chooses merge/PR).
