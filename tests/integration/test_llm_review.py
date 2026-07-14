"""Spec section 7 integration loop. Fake provider modules are registered
under the REAL provider names (claude-cli/codex-cli) so cmd_drain's default
config chain resolves to them -- no live LLM call anywhere.

Risky-commit fixture note: the original brief sketch overwrote `src/auth.py`
with an IDOR-shaped body, but that alone scores below the default
`[triage].min_score = 40` (path_signal only, 30 points -- `content_signal`'s
regexes don't match a plain `db.get(...)` call, and the path was already
seen at the baseline commit so `novelty_signal` contributes nothing either).
Per the brief's own NOTE, the fixture is strengthened to a NEW file
`src/auth_login.py` with `exec()` content, mirroring `_risky_repo` in
`tests/integration/test_drain.py`: path_signal (+30, "auth"/"login" token)
and content_signal (+25, exec/eval pattern) alone clear the threshold, with
novelty_signal (+20, unseen path on the bootstrap sweep) as a further
margin. The loop's assertions -- not this exact fixture content -- are the
contract.

Doctor-gate note: `cmd_init`'s step 3 refuses to arm hooks (returns 3) unless
both BLOCK-tier tools (gitleaks, semgrep) probe present; neither is a real
invokable binary in this dev/CI environment (see test_init.py's module
docstring). `doctor.probe_toolchain` is faked present here, exactly as
test_init.py already does -- the one seam that must be faked for onboarding
to complete; every runner downstream still tolerates the real tools being
MISSING by design (graceful degradation, proven by the pipeline/runner test
suites), which is why `cmd_drain`/`pipeline.run_gate` calls below are never
faked and still pass.
"""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config as config_mod
from aramid import pipeline, registry
from aramid.commands import doctor as doctor_mod
from aramid.commands import drain as drain_mod
from aramid.commands.arm import cmd_arm
from aramid.commands.drain import cmd_drain
from aramid.commands.init import cmd_init
from aramid.consumers import llm_review
from aramid.ledger import Ledger
from aramid.models import EventType, Gate
from aramid.providers import base as providers_base
from aramid.providers import spend as spend_mod
from aramid.providers.base import ProviderResponse
from aramid.queue import materialize_queue

FILE_BODY = "def run_command(cmd):\n    exec(cmd)\n"
EVIDENCE = "exec(cmd)"


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


class _Fake:
    def __init__(self, name, responses):
        self.NAME = name
        self.responses = list(responses)

    def available(self, cfg):
        return bool(self.responses)

    def installed(self):
        return True

    def review(self, prompt, model, timeout_s, **kw):
        return self.responses.pop(0)


REVIEW_JSON = json.dumps({"findings": [{
    "title": "Arbitrary code execution via exec() on unsanitized input",
    "owasp": "a01", "severity": "critical",
    "file": "src/auth_login.py", "line": 2, "evidence": EVIDENCE,
    "explanation": "exec() runs attacker-controlled input with no validation",
    "fix_hint": "never pass unsanitized input to exec(); use an explicit dispatch table"}]})
REFUTE_SURVIVES = json.dumps({"refuted": False, "reason": "no guard found"})


def _fake_doctor_present(root):
    """Mirrors test_init.py's `_fake_present` -- the one seam that must be
    faked for `cmd_init` to get past its step-3 doctor gate on a machine
    where gitleaks/semgrep are not real invokable binaries."""
    return {
        "gitleaks": doctor_mod.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor_mod.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor_mod.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor_mod.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor_mod.ToolStatus("interpreter", True, sys.executable),
    }


@pytest.fixture
def seam(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path",
                        lambda: tmp_path / "central" / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path",
                        lambda: tmp_path / "central" / "drain.lock")
    monkeypatch.setattr(spend_mod, "spend_path",
                        lambda: tmp_path / "central" / "llm_spend.jsonl")
    # Never let this test read/merge a real ~/.aramid/config.toml off the
    # machine running the suite (config._user_config_path's own docstring
    # flags this as the seam to patch; test_init.py does the same) -- a
    # stray [llm] or [triage] override there would silently break the
    # score-threshold and armed/confirmed assertions below.
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "central" / "no-user-config.toml")
    monkeypatch.setattr(doctor_mod, "probe_toolchain", _fake_doctor_present)
    llm_review.begin_drain()


def _setup_repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "."); _git(r, "commit", "-q", "-m", "c1")
    assert cmd_init(r) in (0, 2)      # onboard: config, hooks, baseline, registry
    (r / "src" / "auth_login.py").write_text(FILE_BODY, encoding="utf-8")
    # --no-verify: cmd_init just installed aramid's own pre-commit hook, and this
    # is fixture scaffolding, not a test of that hook. Without it, on an env where
    # the gate actually runs (CI: gitleaks/ruff present), the pre-commit gate
    # aborts this commit and the test errors at git-commit time. The drain's
    # catch-up sweep (not the post-commit hook) is what triages this range.
    _git(r, "add", "."); _git(r, "commit", "-q", "--no-verify", "-m", "risky change")
    return r


def test_full_loop(tmp_path, monkeypatch, seam):
    r = _setup_repo(tmp_path)
    monkeypatch.setattr(providers_base, "PROVIDERS", {
        "claude-cli": _Fake("claude-cli", [ProviderResponse(text=REVIEW_JSON,
                                                            tokens_in=900,
                                                            tokens_out=80)]),
        "codex-cli": _Fake("codex-cli", [ProviderResponse(text=REFUTE_SURVIVES,
                                                          tokens_in=400,
                                                          tokens_out=20)]),
    })
    # 1. drain reviews the range (catch-up sweep enqueues the new commit).
    # Exit tolerance: check drain.py's actual exit semantics -- a degraded
    # sibling consumer must not fail this assertion.
    assert cmd_drain([str(r)]) in (0, 2)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        state = led.open_findings()
        llm = {fid: rec for fid, rec in state.items()
               if rec.get("source") == "llm" and rec.get("status") == "open"}
        assert len(llm) == 1
        rec = next(iter(llm.values()))
        assert rec["confirmed"] is True and rec["severity"] == "critical"
        assert rec["evidence"] == EVIDENCE
        # consumer run carried token metering in its note
        runs = [e for e in led.events() if e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == "llm-review"]
        assert "tokens_in=1300" in runs[-1].payload["note"]
    finally:
        led.close()

    # 2. baking: pre-push WARNs (exit 0)
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        got = pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led)
        assert got.exit_code == 0
        assert any(f.tool == "llm-review" for f in got.findings)
    finally:
        led.close()

    # 3. arm -> BLOCK (exit 1)
    assert cmd_arm(r, llm=True) == 0
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led).exit_code == 1
    finally:
        led.close()

    # 4. fix the code -> auto-resolve -> pass (exit 0)
    (r / "src" / "auth_login.py").write_text(
        "def run_command(cmd):\n"
        "    ALLOWED = {'status', 'help'}\n"
        "    if cmd in ALLOWED:\n"
        "        dispatch(cmd)\n",
        encoding="utf-8")
    # --no-verify: same reason as _setup_repo -- aramid's own pre-commit hook is
    # installed in this repo; this fix commit is scaffolding for the auto-resolve
    # assertion below, not a test of the pre-commit gate.
    _git(r, "add", "."); _git(r, "commit", "-q", "--no-verify", "-m", "fix exec injection")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, led).exit_code == 0
        resolved = [e for e in led.events() if e.type is EventType.FINDING_RESOLVED
                    and e.payload.get("auto_resolved") == "evidence_gone"]
        assert resolved
    finally:
        led.close()


def test_all_providers_down_holds_item(tmp_path, monkeypatch, seam):
    r = _setup_repo(tmp_path)
    down = SimpleNamespace(NAME="claude-cli", available=lambda cfg: False,
                           installed=lambda: True)
    monkeypatch.setattr(providers_base, "PROVIDERS", {"claude-cli": down})
    assert cmd_drain([str(r)]) in (0, 2)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        items = materialize_queue(led.events())
        assert any(i.state == "queued" for i in items.values())   # queue holds
    finally:
        led.close()


def test_no_providers_installed_drains_item(tmp_path, monkeypatch, seam):
    r = _setup_repo(tmp_path)
    ghost = SimpleNamespace(NAME="claude-cli", available=lambda cfg: False,
                            installed=lambda: False)
    monkeypatch.setattr(providers_base, "PROVIDERS", {"claude-cli": ghost})
    assert cmd_drain([str(r)]) in (0, 2)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        items = materialize_queue(led.events())
        assert items and all(i.state == "drained" for i in items.values())
    finally:
        led.close()
