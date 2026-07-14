# Reviewer Model-Selection Substrate + Deterministic Ladder — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `ollama-cloud` provider, drop OpenRouter from the default reviewer chain, plumb per-provider reasoning effort, and select the reviewer/refuter `(provider, model, effort)` **arm** deterministically by triage risk tier.

**Architecture:** A new `ollama_cloud.py` provider (direct Ollama Cloud HTTP API, `urllib`, `cost_usd=0.0`) joins the self-registering `PROVIDERS`. Providers gain an `effort` kwarg mapped to each surface's native flag. `review.py` gains an `Arm` dataclass plus pure selection functions (`build_arms`, `target_arm`, `reviewer_order`, `select_refuter`). `consume()` selects the reviewer arm by `item.score`, tries it with call-failure fallthrough, and picks a cross-provider refuter — without touching the evidence-binding / refute / `confirmed` block path.

**Tech Stack:** Python 3.14, stdlib only (`urllib`, `subprocess`, `dataclasses`, `tomllib` via existing config), pytest. Windows 11 host.

**Spec:** `docs/superpowers/specs/2026-07-14-aramid-reviewer-model-selection-design.md`

## Global Constraints

- **No live LLM calls in any test.** Fakes / monkeypatched `subprocess` / monkeypatched `urllib.request.urlopen` only. The ONE exception is Task 7's manual effort-value verification — a human/controller step, not a test.
- **Do not alter the evidence-binding, refute, `confirmed`, or refute-budget logic** in `review.py` / `llm_review.py`. Selection changes *which model* runs; it never changes *whether a finding blocks*. The Phase-2b invariant holds: nothing may mint `confirmed=True` that wouldn't otherwise exist.
- **Provider protocol:** a provider module exposes `NAME: str`, `installed() -> bool`, `available(cfg) -> bool`, `review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse` (openrouter also takes `*, cfg`), and self-registers via `base.PROVIDERS[NAME] = sys.modules[__name__]`. Registration only fires when something imports the module — `llm_review.py` imports all default providers (fixed in `c6f1f2a`); `ollama_cloud` MUST be added to that import.
- **`cost_usd = 0.0`** for every flat-rate provider (claude/codex/ollama). Only `openrouter` carries real cost.
- **Effort ships unset (`""` → flag omitted)** until Task 7's live verification confirms accepted values.
- **OpenRouter stays in-tree, opt-in** — dropped from the default `provider_order`/ladder only; `openrouter.py`, its config keys, and its tests are untouched.
- **Run tests via `python -m pytest`** (pytest is not on PATH). Windows shell.
- Branch: `feat/reviewer-model-selection` (off `main` @ `c6f1f2a`, which includes the provider-registration fix). Spec committed `1acc9f7`.

---

### Task 1: `ollama-cloud` provider

**Files:**
- Create: `src/aramid/providers/ollama_cloud.py`
- Create: `tests/unit/test_provider_ollama.py`
- Modify: `src/aramid/consumers/llm_review.py` (add `ollama_cloud` to the provider-registration import)
- Modify: `tests/unit/test_provider_registration.py` (include `ollama-cloud` in the expected set)

**Interfaces:**
- Consumes: `aramid.providers.base` (`ProviderResponse`, `ERR_*`, `PROVIDERS`); `aramid.providers.spend.append_spend`.
- Produces: module `ollama_cloud` with `NAME = "ollama-cloud"`, `installed()`, `available(cfg)`, `review(prompt, model, timeout_s, *, effort="")`. Registered in `PROVIDERS`.

- [ ] **Step 1: Write the failing test** — `tests/unit/test_provider_ollama.py`

```python
import io
import json
import urllib.error

import pytest

from aramid.providers import base, ollama_cloud, spend

RESPONSE = json.dumps({
    "message": {"role": "assistant", "content": '{"findings": []}'},
    "prompt_eval_count": 1800, "eval_count": 42,
})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setenv("OLLAMA_API_KEY", "ol-test")


def test_registers_in_providers():
    assert base.PROVIDERS["ollama-cloud"] is ollama_cloud


def test_available_requires_key(monkeypatch):
    assert ollama_cloud.installed() is True
    assert ollama_cloud.available(None) is True
    monkeypatch.delenv("OLLAMA_API_KEY")
    assert ollama_cloud.installed() is False
    assert ollama_cloud.available(None) is False


def test_review_posts_native_body_and_parses(monkeypatch, tmp_path):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    resp = ollama_cloud.review("PACKET", "deepseek-v4-flash", 240.0)
    assert resp.text == '{"findings": []}'
    assert resp.cost_usd == 0.0
    assert (resp.tokens_in, resp.tokens_out) == (1800, 42)
    assert seen["url"] == "https://ollama.com/api/chat"
    assert seen["auth"] == "Bearer ol-test"
    assert seen["body"]["model"] == "deepseek-v4-flash"
    assert seen["body"]["stream"] is False
    assert seen["body"]["messages"][0]["content"] == "PACKET"
    assert "think" not in seen["body"]          # effort unset -> no think
    logged = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8")
    assert json.loads(logged)["cost_usd"] == 0.0


def test_effort_sets_think(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return io.BytesIO(RESPONSE.encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    ollama_cloud.review("P", "m", 240.0, effort="high")
    assert seen["body"]["think"] is True


def test_missing_key_unavailable(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY")
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_UNAVAILABLE


def test_timeout(monkeypatch):
    def boom(req, timeout):
        raise TimeoutError()
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", boom)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_TIMEOUT


def test_http_429_is_quota(monkeypatch):
    def boom(req, timeout):
        raise urllib.error.HTTPError("u", 429, "rate", {}, None)
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", boom)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_QUOTA


def test_http_401_is_unavailable(monkeypatch):
    def boom(req, timeout):
        raise urllib.error.HTTPError("u", 401, "auth", {}, None)
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", boom)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_UNAVAILABLE


def test_malformed_body_no_message(monkeypatch):
    def fake_urlopen(req, timeout):
        return io.BytesIO(json.dumps({"error": "no such model"}).encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    resp = ollama_cloud.review("P", "m", 240.0)
    assert resp.error == base.ERR_MALFORMED and resp.text == ""


def test_non_string_content_malformed(monkeypatch):
    def fake_urlopen(req, timeout):
        return io.BytesIO(json.dumps({"message": {"content": 123}}).encode("utf-8"))
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_MALFORMED


def test_never_raises_on_garbage(monkeypatch):
    def fake_urlopen(req, timeout):
        return io.BytesIO(b"not json")
    monkeypatch.setattr(ollama_cloud.urllib.request, "urlopen", fake_urlopen)
    assert ollama_cloud.review("P", "m", 240.0).error == base.ERR_ERROR
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_provider_ollama.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.providers.ollama_cloud'`.

- [ ] **Step 3: Implement** — `src/aramid/providers/ollama_cloud.py`

```python
"""ollama-cloud provider (2026-07-14 model-selection spec): the direct Ollama
Cloud HTTP API on the user's Ollama Cloud subscription. stdlib urllib only.
Flat-rate: cost_usd is ALWAYS 0.0 (no OpenRouter-style money cap). Per the
model-source policy this is a dev-time provider; OpenRouter is in-app only.

HTTPError (a subclass of OSError) is caught BEFORE the generic OSError branch
so a 429 maps to ERR_QUOTA and 401/403 to ERR_UNAVAILABLE, matching the CLI
providers' quota semantics; every other failure is ERR_ERROR, and any
unexpected body shape is ERR_MALFORMED (never a silent empty review)."""
import json
import os
import sys
import urllib.error
import urllib.request

from aramid.providers import base
from aramid.providers.base import ProviderResponse

NAME = "ollama-cloud"
_URL = "https://ollama.com/api/chat"


def installed() -> bool:
    return bool(os.environ.get("OLLAMA_API_KEY"))


def available(cfg) -> bool:
    return installed()


def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    key = os.environ.get("OLLAMA_API_KEY")
    if not key:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    payload = {"model": model,
               "messages": [{"role": "user", "content": prompt}],
               "stream": False}
    if effort:
        payload["think"] = True
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return ProviderResponse(text="", error=base.ERR_QUOTA)
        if exc.code in (401, 403):
            return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
        return ProviderResponse(text="", error=base.ERR_ERROR)
    except TimeoutError:
        return ProviderResponse(text="", error=base.ERR_TIMEOUT)
    except (OSError, ValueError):
        return ProviderResponse(text="", error=base.ERR_ERROR)

    try:
        if not isinstance(data, dict):
            return ProviderResponse(text="", error=base.ERR_MALFORMED)
        text = data["message"]["content"]
        if not isinstance(text, str):
            return ProviderResponse(text="", error=base.ERR_MALFORMED)
        tokens_in = int(data.get("prompt_eval_count", 0) or 0)
        tokens_out = int(data.get("eval_count", 0) or 0)
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return ProviderResponse(text="", error=base.ERR_MALFORMED)

    resp = ProviderResponse(text=text, tokens_in=tokens_in, tokens_out=tokens_out,
                            cost_usd=0.0)
    _log(resp, model)
    return resp


def _log(resp: ProviderResponse, model: str) -> None:
    from datetime import datetime, timezone
    from aramid.providers import spend
    try:
        spend.append_spend({"at": datetime.now(timezone.utc).isoformat(),
                            "provider": NAME, "model": model,
                            "tokens_in": resp.tokens_in, "tokens_out": resp.tokens_out,
                            "cost_usd": resp.cost_usd})
    except OSError:
        pass  # observability only -- never fail a successful call over logging


base.PROVIDERS[NAME] = sys.modules[__name__]
```

- [ ] **Step 4: Wire registration** — in `src/aramid/consumers/llm_review.py`, add `ollama_cloud` to the existing provider import (currently `from aramid.providers import claude_cli, codex_cli, openrouter  # noqa: F401`):

```python
from aramid.providers import claude_cli, codex_cli, openrouter, ollama_cloud  # noqa: F401
```

- [ ] **Step 5: Update the registration regression test** — in `tests/unit/test_provider_registration.py`, change both expected sets from `{'claude-cli', 'codex-cli', 'openrouter'}` to `{'claude-cli', 'codex-cli', 'openrouter', 'ollama-cloud'}`.

- [ ] **Step 6: Run to verify pass**

Run: `python -m pytest tests/unit/test_provider_ollama.py tests/unit/test_provider_registration.py -q`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add src/aramid/providers/ollama_cloud.py tests/unit/test_provider_ollama.py src/aramid/consumers/llm_review.py tests/unit/test_provider_registration.py
git commit -m "feat(llm): add ollama-cloud provider (direct cloud API)"
```

---

### Task 2: Per-provider effort plumbing

**Files:**
- Modify: `src/aramid/providers/claude_cli.py` (add `*, effort=""`; append `--effort <e>`)
- Modify: `src/aramid/providers/codex_cli.py` (add `*, effort=""`; append `-c model_reasoning_effort=<e>`)
- Modify: `src/aramid/providers/openrouter.py` (add `effort=""` to signature; body `reasoning.effort`)
- Create: `tests/unit/test_effort_passthrough.py`

**Interfaces:**
- Consumes: `base.run_provider_subprocess` (claude/codex), `urllib` (openrouter).
- Produces: all three `review()` accept `*, effort: str = ""`; a non-empty effort adds the native flag/field, an empty effort omits it. (openrouter keeps `*, cfg`; final signature `review(prompt, model, timeout_s, *, effort="", cfg)`.)

- [ ] **Step 1: Write the failing test** — `tests/unit/test_effort_passthrough.py`

```python
import io
import json

import pytest

from aramid.providers import base, claude_cli, codex_cli, openrouter, spend


@pytest.fixture(autouse=True)
def _spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "s.jsonl")


def _capture_argv(monkeypatch, module):
    seen = {}

    def fake_run(argv, prompt, timeout_s):
        seen["argv"] = argv
        # minimal valid envelope per module so review() parses cleanly
        if module is claude_cli:
            out = json.dumps({"result": "{}", "usage": {"input_tokens": 1, "output_tokens": 1}})
        else:  # codex
            out = (json.dumps({"type": "item.completed",
                               "item": {"type": "agent_message", "text": "{}"}}) + "\n" +
                   json.dumps({"type": "turn.completed",
                               "usage": {"input_tokens": 1, "output_tokens": 1}}))
        return (0, out, "")
    monkeypatch.setattr(base, "run_provider_subprocess", fake_run)
    # ensure the exe resolves
    monkeypatch.setattr(module.shutil, "which", lambda name: f"/usr/bin/{name}")
    return seen


def test_claude_effort_appended(monkeypatch):
    seen = _capture_argv(monkeypatch, claude_cli)
    claude_cli.review("P", "opus", 240.0, effort="high")
    assert "--effort" in seen["argv"]
    assert seen["argv"][seen["argv"].index("--effort") + 1] == "high"


def test_claude_effort_omitted_when_unset(monkeypatch):
    seen = _capture_argv(monkeypatch, claude_cli)
    claude_cli.review("P", "opus", 240.0)          # effort=""
    assert "--effort" not in seen["argv"]


def test_codex_effort_appended(monkeypatch):
    seen = _capture_argv(monkeypatch, codex_cli)
    codex_cli.review("P", "gpt-5.6", 240.0, effort="medium")
    assert "-c" in seen["argv"]
    idx = seen["argv"].index("-c")
    assert seen["argv"][idx + 1] == "model_reasoning_effort=medium"


def test_codex_effort_omitted_when_unset(monkeypatch):
    seen = _capture_argv(monkeypatch, codex_cli)
    codex_cli.review("P", "gpt-5.6", 240.0)
    assert "model_reasoning_effort=" not in " ".join(seen["argv"])


def test_openrouter_effort_in_body(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-x")
    seen = {}

    def fake_urlopen(req, timeout):
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return io.BytesIO(json.dumps(
            {"choices": [{"message": {"content": "{}"}}], "usage": {}}).encode("utf-8"))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fake_urlopen)
    openrouter.review("P", "m", 240.0, effort="low", cfg=SimpleNamespace(llm={}))
    assert seen["body"]["reasoning"] == {"effort": "low"}
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_effort_passthrough.py -q`
Expected: FAIL — `review()` got an unexpected keyword argument `effort`.

- [ ] **Step 3a: Implement claude_cli** — change `review` signature and argv in `src/aramid/providers/claude_cli.py`:

```python
def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    exe = shutil.which("claude")
    if exe is None:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    argv = [exe, "-p", "--model", model, "--output-format", "json"]
    if effort:
        argv += ["--effort", effort]
    got = base.run_provider_subprocess(argv, prompt, timeout_s)
    # ... rest unchanged ...
```

- [ ] **Step 3b: Implement codex_cli** — in `src/aramid/providers/codex_cli.py`:

```python
def review(prompt: str, model: str, timeout_s: float, *, effort: str = "") -> ProviderResponse:
    exe = shutil.which("codex")
    if exe is None:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    argv = [exe, "exec", "--json", "--sandbox", "read-only", "--skip-git-repo-check"]
    if model:
        argv += ["-m", model]
    if effort:
        argv += ["-c", f"model_reasoning_effort={effort}"]
    argv.append("-")
    got = base.run_provider_subprocess(argv, prompt, timeout_s)
    # ... rest unchanged ...
```

- [ ] **Step 3c: Implement openrouter** — in `src/aramid/providers/openrouter.py`, add `effort` to the signature and the request body:

```python
def review(prompt: str, model: str, timeout_s: float, *, effort: str = "", cfg) -> ProviderResponse:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return ProviderResponse(text="", error=base.ERR_UNAVAILABLE)
    if not _under_cap(cfg):
        return ProviderResponse(text="", error=base.ERR_QUOTA)
    body_obj = {"model": model,
                "messages": [{"role": "user", "content": prompt}],
                "usage": {"include": True}}
    if effort:
        body_obj["reasoning"] = {"effort": effort}
    body = json.dumps(body_obj).encode("utf-8")
    # ... rest unchanged ...
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_effort_passthrough.py tests/unit/test_provider_openrouter.py tests/unit/test_provider_claude.py tests/unit/test_provider_codex.py -q`
Expected: PASS (all — existing provider tests still green; they call `review()` without `effort`, which defaults to `""`).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/providers/claude_cli.py src/aramid/providers/codex_cli.py src/aramid/providers/openrouter.py tests/unit/test_effort_passthrough.py
git commit -m "feat(llm): plumb reasoning effort through all providers (unset omits the flag)"
```

---

### Task 3: Arm abstraction + selection functions

**Files:**
- Modify: `src/aramid/review.py` (add `Arm`, `build_arms`, `target_arm`, `reviewer_order`, `select_refuter`)
- Create: `tests/unit/test_arm_selection.py`

**Interfaces:**
- Consumes: `cfg.llm["ladder"]` (list of dicts).
- Produces:
  - `Arm(tier: str, provider: str, model: str, effort: str, min_score: int)` (frozen dataclass)
  - `build_arms(cfg) -> list[Arm]` (drops malformed; sorted asc by `min_score`)
  - `target_arm(arms: list[Arm], score: int) -> Arm | None`
  - `reviewer_order(arms: list[Arm], score: int, available: set[str]) -> list[Arm]`
  - `select_refuter(arms: list[Arm], reviewer_arm: Arm, available: set[str]) -> Arm`

- [ ] **Step 1: Write the failing test** — `tests/unit/test_arm_selection.py`

```python
from types import SimpleNamespace

from aramid import review
from aramid.review import Arm

LADDER = [
    {"tier": "cheap", "provider": "ollama-cloud", "model": "df", "effort": "", "min_score": 40},
    {"tier": "mid", "provider": "codex-cli", "model": "g", "effort": "", "min_score": 60},
    {"tier": "frontier", "provider": "claude-cli", "model": "opus", "effort": "", "min_score": 80},
]
ALL = {"ollama-cloud", "codex-cli", "claude-cli"}


def _cfg(ladder=LADDER):
    return SimpleNamespace(llm={"ladder": ladder})


def test_build_arms_sorts_and_drops_malformed():
    arms = review.build_arms(_cfg(ladder=[
        {"tier": "b", "provider": "p2", "min_score": 80},
        {"tier": "a", "provider": "p1", "min_score": 40},
        {"bad": "entry"},                         # missing keys -> dropped
        "not-a-dict",                             # -> dropped
    ]))
    assert [a.min_score for a in arms] == [40, 80]
    assert [a.tier for a in arms] == ["a", "b"]


def test_target_arm_by_band():
    arms = review.build_arms(_cfg())
    assert review.target_arm(arms, 50).tier == "cheap"
    assert review.target_arm(arms, 65).tier == "mid"
    assert review.target_arm(arms, 95).tier == "frontier"
    assert review.target_arm(arms, 10).tier == "cheap"     # below lowest band
    assert review.target_arm([], 50) is None


def test_reviewer_order_target_first_then_degrade_down_then_up():
    arms = review.build_arms(_cfg())
    # high-risk, all available -> frontier first, then mid, then cheap
    assert [a.tier for a in review.reviewer_order(arms, 95, ALL)] == ["frontier", "mid", "cheap"]
    # low-risk -> cheap first, then mid, then frontier (fallthrough climbs)
    assert [a.tier for a in review.reviewer_order(arms, 45, ALL)] == ["cheap", "mid", "frontier"]


def test_reviewer_order_degrades_when_target_provider_down():
    arms = review.build_arms(_cfg())
    avail = {"codex-cli", "ollama-cloud"}          # claude (frontier) is down
    # high-risk item degrades to the nearest available at/below -> mid then cheap
    assert [a.tier for a in review.reviewer_order(arms, 95, avail)] == ["mid", "cheap"]


def test_reviewer_order_empty_when_nothing_available():
    arms = review.build_arms(_cfg())
    assert review.reviewer_order(arms, 95, set()) == []


def test_reviewer_order_dedupes_provider():
    ladder = LADDER + [{"tier": "frontier2", "provider": "claude-cli",
                        "model": "opus", "effort": "", "min_score": 90}]
    arms = review.build_arms(_cfg(ladder=ladder))
    order = review.reviewer_order(arms, 95, ALL)
    provs = [a.provider for a in order]
    assert len(provs) == len(set(provs))           # each provider once


def test_select_refuter_prefers_different_provider_highest_tier():
    arms = review.build_arms(_cfg())
    reviewer = review.target_arm(arms, 65)          # mid / codex-cli
    ref = review.select_refuter(arms, reviewer, ALL)
    assert ref.provider == "claude-cli"             # frontier, different provider


def test_select_refuter_falls_back_to_self_when_only_one_provider():
    arms = review.build_arms(_cfg())
    reviewer = review.target_arm(arms, 95)          # frontier / claude-cli
    ref = review.select_refuter(arms, reviewer, {"claude-cli"})
    assert ref is reviewer                           # self-refute fallback
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_arm_selection.py -q`
Expected: FAIL — `ImportError: cannot import name 'Arm'`.

- [ ] **Step 3: Implement** — add to `src/aramid/review.py` (near the top-level definitions; `dataclass` is already imported):

```python
@dataclass(frozen=True)
class Arm:
    """A selectable (provider, model, effort) point on the cheap->frontier
    ladder. min_score is the lower bound of the arm's risk band."""
    tier: str
    provider: str
    model: str
    effort: str
    min_score: int


def build_arms(cfg) -> list[Arm]:
    """Parse [[llm.ladder]] into Arms, sorted ascending by min_score. Malformed
    entries are dropped (fail-open) -- never crash selection over bad config."""
    out = []
    for e in cfg.llm.get("ladder", []):
        if not isinstance(e, dict):
            continue
        try:
            out.append(Arm(tier=str(e["tier"]), provider=str(e["provider"]),
                           model=str(e.get("model", "")), effort=str(e.get("effort", "")),
                           min_score=int(e["min_score"])))
        except (KeyError, ValueError, TypeError):
            continue
    out.sort(key=lambda a: a.min_score)
    return out


def target_arm(arms: list[Arm], score: int) -> Arm | None:
    """The risk-appropriate arm IGNORING availability: the highest-min_score
    arm whose band contains score. Below the lowest band -> the cheapest arm.
    None if there are no arms. (arms must be sorted ascending.)"""
    if not arms:
        return None
    chosen = arms[0]
    for a in arms:
        if a.min_score <= score:
            chosen = a
        else:
            break
    return chosen


def reviewer_order(arms: list[Arm], score: int, available: set[str]) -> list[Arm]:
    """Ordered arms to ATTEMPT for the review: the target-tier arm first, then
    degrade to nearest available -- prefer at-or-below the target tier
    (highest first), then climb above it -- deduped by provider. Empty if
    nothing is available. The list (not a single arm) preserves Phase 2b's
    call-failure fallthrough: available() cannot see quota exhaustion, so a
    quota-failed call must still fall through to another provider."""
    tgt = target_arm(arms, score)
    if tgt is None:
        return []
    avail = [a for a in arms if a.provider in available]
    if not avail:
        return []
    at_or_below = [a for a in avail if a.min_score <= tgt.min_score]
    above = [a for a in avail if a.min_score > tgt.min_score]
    ordered = list(reversed(at_or_below)) + above
    seen, out = set(), []
    for a in ordered:
        if a.provider in seen:
            continue
        seen.add(a.provider)
        out.append(a)
    return out


def select_refuter(arms: list[Arm], reviewer_arm: Arm, available: set[str]) -> Arm:
    """The highest-tier available arm whose provider differs from the
    reviewer's (max skeptical power + model-family diversity). Falls back to
    the reviewer's own arm (self-refute) when no other provider is available --
    preserving Phase 2b's single-provider fallback."""
    diff = [a for a in arms if a.provider != reviewer_arm.provider and a.provider in available]
    if diff:
        return diff[-1]     # arms sorted ascending -> last is highest min_score
    return reviewer_arm
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_arm_selection.py -q`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/review.py tests/unit/test_arm_selection.py
git commit -m "feat(llm): arm abstraction + deterministic risk-tiered selection"
```

---

### Task 4: Config — ladder, provider_order, OpenRouter opt-in

**Files:**
- Modify: `src/aramid/data/defaults.toml`
- Modify: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: nothing new (config deep-merge already passes `[llm]` through wholesale).
- Produces: `cfg.llm["ladder"]` (list of 3 arm dicts), `cfg.llm["provider_order"] == ["claude-cli", "codex-cli", "ollama-cloud"]`.

- [ ] **Step 1: Write the failing test** — replace the `provider_order` assertion in `tests/unit/test_config.py::test_llm_defaults_present` and add ladder assertions:

```python
    assert cfg.llm["provider_order"] == ["claude-cli", "codex-cli", "ollama-cloud"]
    ladder = cfg.llm["ladder"]
    assert [a["tier"] for a in ladder] == ["cheap", "mid", "frontier"]
    assert [a["provider"] for a in ladder] == ["ollama-cloud", "codex-cli", "claude-cli"]
    assert [a["min_score"] for a in ladder] == [40, 60, 80]
    assert all(a["effort"] == "" for a in ladder)      # ships unset until verified (Task 7)
```

(Remove the old `assert cfg.llm["provider_order"] == ["claude-cli", "codex-cli", "openrouter"]` line and the now-removed `model_claude`/`model_codex`/`model_ollama` assertions if present — those keys leave the selection path; keep `model_openrouter` since openrouter is opt-in.)

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_config.py::test_llm_defaults_present -q`
Expected: FAIL — `provider_order` still `[..., "openrouter"]`; no `ladder` key.

- [ ] **Step 3: Implement** — in `src/aramid/data/defaults.toml`, under `[llm]`:
  - change `provider_order` to `["claude-cli", "codex-cli", "ollama-cloud"]`;
  - comment `model_openrouter` / `openrouter_monthly_cap_usd` as opt-in/in-app only;
  - append the ladder tables:

```toml
provider_order = ["claude-cli", "codex-cli", "ollama-cloud"]
# openrouter is OPT-IN / in-app only -- NOT part of the dev-time default chain
# (model-source policy). To use it, add "openrouter" to provider_order and an
# openrouter arm to [[llm.ladder]] in a repo's aramid.toml. These keys are read
# only by the opt-in openrouter provider:
model_openrouter = "anthropic/claude-sonnet-4-5"
openrouter_monthly_cap_usd = 5.0

# Reviewer model ladder (deterministic risk-tiered selection, design section 6).
# The arm whose min_score band contains an item's triage score reviews it;
# degrade-to-nearest-available on provider outage. Each tier is a different
# provider so the cross-provider refuter always differs in model family.
# effort ships "" (flag omitted) until the plan's Task 7 live CLI check verifies
# accepted values -- intended: cheap=low, mid=medium, frontier=high.
[[llm.ladder]]
tier = "cheap"
provider = "ollama-cloud"
model = "deepseek-v4-flash"
effort = ""
min_score = 40

[[llm.ladder]]
tier = "mid"
provider = "codex-cli"
model = "gpt-5.6"
effort = ""
min_score = 60

[[llm.ladder]]
tier = "frontier"
provider = "claude-cli"
model = "opus"
effort = ""
min_score = 80
```

Note: keep the existing `max_items_per_drain`, `call_timeout_s`, `packet_max_bytes`, `llm_block_armed`, `max_refutes_per_drain` keys unchanged. Remove `model_claude`, `model_codex`, `model_ollama` (superseded by the ladder).

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_config.py -q`
Expected: PASS. If any other config test asserts the removed `model_*` keys, update it to read from the ladder instead.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/data/defaults.toml tests/unit/test_config.py
git commit -m "feat(llm): default ladder + drop openrouter from default chain"
```

---

### Task 5: Consumer integration — arm-based selection in `consume()`

**Files:**
- Modify: `src/aramid/consumers/llm_review.py` (`_call` gains `model`+`effort`; `consume()` uses arm selection; remove `_model_for`; run note gains `tier`/`model`/`degraded_from`)
- Modify: `tests/unit/test_llm_consumer.py`

**Interfaces:**
- Consumes: `review.build_arms`, `review.reviewer_order`, `review.target_arm`, `review.select_refuter`; `providers_base.PROVIDERS`, `providers_base.chain`.
- Produces: unchanged `ConsumerResult`; run note now contains `tier=<t> model=<m>` and, on degrade, `degraded_from=<target_tier>`.

**Global-constraint reminder for this task:** the verify/dedupe/refute-budget/`confirmed` blocks stay byte-for-byte as they are. Only the provider/model/effort *selection* around them changes. Existing refute-budget and `confirmed`-forgery tests MUST stay green unchanged.

- [ ] **Step 1: Write the failing tests** — modify `tests/unit/test_llm_consumer.py`.

**(1a) `_cfg` must now supply a `ladder`.** CRITICAL: the existing tests all use `_item(...)` with `score=80` and assume `fake-a` is the reviewer and `fake-b` the cross-provider refuter. To preserve that, the DEFAULT test ladder must make a score-80 item select `fake-a`. So put `fake-a` at the frontier tier (`min_score=80`) and `fake-b` at cheap (`min_score=40`):

```python
def _cfg(**over):
    # Default ladder chosen so a score=80 item (the _item() default) selects
    # fake-a as reviewer and fake-b as the cross-provider refuter -- preserving
    # every existing test's fake-a=reviewer / fake-b=refuter assumption.
    ladder = over.pop("ladder", [
        {"tier": "cheap", "provider": "fake-b", "model": "mb", "effort": "", "min_score": 40},
        {"tier": "frontier", "provider": "fake-a", "model": "ma", "effort": "", "min_score": 80},
    ])
    llm = {"enabled": True, "max_items_per_drain": 3, "call_timeout_s": 240,
           "packet_max_bytes": 120000, "provider_order": ["fake-a", "fake-b"],
           "ladder": ladder, "llm_block_armed": False, **over}
    return SimpleNamespace(llm=llm, ignore_paths=[".aramid/", "graph-out/", ".git/"])
```

**(1b) `_Fake` records the models it was called with** (add `self.models = []` in `__init__` and `self.models.append(model)` in `review`; leave `available` returning `True` unchanged):

```python
class _Fake:
    def __init__(self, name, responses):
        self.NAME = name
        self.responses = list(responses)
        self.calls = []
        self.models = []

    def available(self, cfg):
        return True

    def installed(self):
        return True

    def review(self, prompt, model, timeout_s, **kw):
        self.calls.append(prompt)
        self.models.append(model)
        return self.responses.pop(0)
```

**(1c) A helper + explicit-ladder tests.** New selection tests pass their OWN ladder (`cheap=fake-a@40`, `frontier=fake-b@80`) so they don't depend on the default and read naturally:

```python
_LADDER_AB = [
    {"tier": "cheap", "provider": "fake-a", "model": "ma", "effort": "", "min_score": 40},
    {"tier": "frontier", "provider": "fake-b", "model": "mb", "effort": "", "min_score": 80},
]


def _ctx_ladder(r, led, ladder):
    return DrainContext(root=r, cfg=_cfg(ladder=ladder), ledger=led,
                        clock=lambda: NOW.isoformat())


def _item_score(base, head, score):
    return QueueItem(id="q1", base=base, head=head, score=score, reasons=("x",),
                     state="queued", created_at=NOW.isoformat(), updated_at=NOW.isoformat())


def test_high_score_selects_frontier_arm_model_passed(tmp_path, monkeypatch):
    """score>=80 selects the frontier arm (fake-b/mb); the arm's MODEL reaches
    the provider and the note carries tier/model."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [])
    b = _Fake("fake-b", [ProviderResponse(text=_finding_json("high"))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 90),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.state == "ok"
    assert "provider=fake-b" in got.note and "tier=frontier" in got.note
    assert "model=mb" in got.note and b.models == ["mb"]


def test_low_score_selects_cheap_arm(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert "tier=cheap" in got.note and "provider=fake-a" in got.note and "model=ma" in got.note


def test_degrade_when_target_provider_unavailable_notes_it(tmp_path, monkeypatch):
    """score=90 targets frontier (fake-b), but fake-b is unavailable -> degrade
    to cheap (fake-a) and record degraded_from=frontier."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    down = SimpleNamespace(NAME="fake-b", available=lambda cfg: False, installed=lambda: True)
    _wire(monkeypatch, a, down)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 90),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert "tier=cheap" in got.note and "degraded_from=frontier" in got.note


def test_refuter_is_cross_provider_arm(tmp_path, monkeypatch):
    """Critical found by the cheap arm (fake-a) is refuted by the highest-tier
    different provider (fake-b)."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text=json.dumps({"refuted": False, "reason": "real"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.findings[0].confirmed is True
    assert len(b.calls) == 1 and "disprove" in b.calls[0]   # refute went to fake-b
```

**(1d) Existing tests:** they keep using `_ctx(r, led)` (default ladder from 1a) and `_item(...)` (score=80). With the 1a ladder, score=80 → `fake-a` reviewer, `fake-b` refuter — so their `provider=fake-a` / cross-provider-refute assertions still hold. In Step 4, if any existing test asserted the OLD note verbatim (e.g. a note starting `provider=fake-a tokens_in=`), update its substring assertion — the note now reads `provider=fake-a tier=frontier model=ma tokens_in=...` (still contains `provider=fake-a` and `refutes=N`).

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: FAIL — `consume()` still uses first-available + `_model_for`; note lacks `tier=`/`model=`.

- [ ] **Step 3: Implement** — in `src/aramid/consumers/llm_review.py`:

(a) Replace `_call` to take an explicit `model` and `effort`, and delete `_model_for`:

```python
def _call(module, prompt: str, model: str, cfg, timeout_s: float, *, effort: str = ""):
    kwargs = {"effort": effort}
    if module.NAME == "openrouter":
        kwargs["cfg"] = cfg
    try:
        return module.review(prompt, model, timeout_s, **kwargs)
    except Exception:
        return providers_base.ProviderResponse(text="", error=providers_base.ERR_ERROR)
```

(b) In `consume()`, replace the provider-chain reviewer block. Current block (after `packet` is built):

```python
    chain = providers_base.chain(cfg)
    if not chain:
        if not _any_installed(cfg):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="llm skipped: no providers installed")
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    timeout_s = float(cfg.llm.get("call_timeout_s", 240))
    prompt = review.render_review_prompt(packet)
    resp, provider = None, None
    for module in chain:
        r = _call(module, prompt, cfg, timeout_s)
        if r.error in ("", providers_base.ERR_MALFORMED):
            resp, provider = r, module
            break
    if resp is None:
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")
```

becomes:

```python
    arms = review.build_arms(cfg)
    avail = {m.NAME for m in providers_base.chain(cfg)}
    order = review.reviewer_order(arms, item.score, avail)
    if not order:
        if not _any_installed(cfg):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="llm skipped: no providers installed")
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    timeout_s = float(cfg.llm.get("call_timeout_s", 240))
    prompt = review.render_review_prompt(packet)
    tgt = review.target_arm(arms, item.score)
    resp, reviewer_arm = None, None
    for arm in order:                       # target tier first, then degrade/fallthrough
        r = _call(providers_base.PROVIDERS[arm.provider], prompt, arm.model, cfg,
                  timeout_s, effort=arm.effort)
        if r.error in ("", providers_base.ERR_MALFORMED):
            resp, reviewer_arm = r, arm
            break
    if resp is None:
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")
    provider = providers_base.PROVIDERS[reviewer_arm.provider]   # for the refute cross-check
```

(c) In the refute loop, replace the refuter resolution. Current:

```python
            refuter = next((m for m in chain if m.NAME != provider.NAME), provider)
            rr = _call(refuter, review.render_refute_prompt(cand, packet), cfg, timeout_s)
```

becomes:

```python
            refuter_arm = review.select_refuter(arms, reviewer_arm, avail)
            rr = _call(providers_base.PROVIDERS[refuter_arm.provider],
                       review.render_refute_prompt(cand, packet), refuter_arm.model, cfg,
                       timeout_s, effort=refuter_arm.effort)
```

(d) Update the run note to carry tier/model/degrade. Current:

```python
    note = (f"provider={provider.NAME} tokens_in={tokens_in} tokens_out={tokens_out} "
            f"refutes={refutes} hallucination_rejected={rejected}"
            + (f" refute_clipped={clipped}" if clipped else "")
            + (" truncated" if packet.truncated else ""))
```

becomes:

```python
    degraded = (f" degraded_from={tgt.tier}"
                if tgt is not None and reviewer_arm.tier != tgt.tier else "")
    note = (f"provider={reviewer_arm.provider} tier={reviewer_arm.tier}{degraded} "
            f"model={reviewer_arm.model} tokens_in={tokens_in} tokens_out={tokens_out} "
            f"refutes={refutes} hallucination_rejected={rejected}"
            + (f" refute_clipped={clipped}" if clipped else "")
            + (" truncated" if packet.truncated else ""))
```

Delete the now-unused `_model_for` function.

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: PASS (all — new arm tests AND the existing refute-budget/dedupe/`confirmed`/degrade tests). If an existing test asserted the exact old note (`provider=fake-a tokens_in=...` with no `tier=`), update its substring assertion to match the new note (which still contains `provider=fake-a` and `refutes=N`).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers/llm_review.py tests/unit/test_llm_consumer.py
git commit -m "feat(llm): select reviewer/refuter arm by risk tier in consume()"
```

---

### Task 6: status / doctor arm + provider lines

**Files:**
- Modify: `src/aramid/commands/doctor.py` (`probe_providers` adds an `ollama-cloud` line)
- Modify: `src/aramid/commands/status.py` (`_llm_lines` adds a ladder line)
- Modify: `tests/integration/test_doctor.py` and `tests/integration/test_status.py` (or the relevant existing test files — assert the new lines)

**Interfaces:**
- Consumes: `cfg.llm["ladder"]`, `os.environ["OLLAMA_API_KEY"]`.
- Produces: doctor prints an `ollama-cloud` provider line; status prints a `llm ladder:` line.

- [ ] **Step 1: Write the failing test** — add to the doctor test (asserting an ollama-cloud line appears in `probe_providers()` output) and the status test (asserting a `ladder` line). Example doctor assertion:

```python
def test_probe_providers_reports_ollama(monkeypatch):
    from aramid.commands import doctor
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    lines = doctor.probe_providers()
    assert any("ollama-cloud" in ln for ln in lines)
```

Example status assertion (in the existing status test that builds a cfg + ledger):

```python
    assert any(ln.startswith("llm ladder:") for ln in lines)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/integration/test_doctor.py tests/integration/test_status.py -q`
Expected: FAIL — no ollama-cloud / ladder line.

- [ ] **Step 3: Implement**

(a) In `src/aramid/commands/doctor.py`, `probe_providers()`, after the claude/codex loop and before/after the openrouter block, add:

```python
    if not os.environ.get("OLLAMA_API_KEY"):
        lines.append("  MISSING  ollama-cloud no OLLAMA_API_KEY in environment")
    else:
        lines.append("  OK       ollama-cloud key set")
```

(b) In `src/aramid/commands/status.py`, `_llm_lines()`, append a ladder summary before `return lines`:

```python
    ladder = cfg.llm.get("ladder", [])
    if ladder:
        tiers = " -> ".join(f"{a.get('tier')}:{a.get('provider')}" for a in ladder)
        lines.append(f"llm ladder: {tiers}")
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/integration/test_doctor.py tests/integration/test_status.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/doctor.py src/aramid/commands/status.py tests/integration/test_doctor.py tests/integration/test_status.py
git commit -m "feat(llm): report ollama-cloud + ladder in doctor/status"
```

---

### Task 7: Manual effort-value verification + set verified defaults

> **CONTROLLER / HUMAN TASK — not for a subagent.** This is the one step that makes live CLI calls (NOT a test). A subagent must not burn quota guessing; the controller (or user) runs these once and records the outcome.

**Files:**
- Modify: `src/aramid/data/defaults.toml` (set verified `effort` values in the ladder)

**Interfaces:** none (config-only).

- [ ] **Step 1: Verify each CLI accepts its intended effort value.** Run each once and confirm exit 0 (any successful review output is fine; the point is that the flag is accepted, not the content):

```bash
echo "reply with {}" | claude -p --model opus --effort high --output-format json ; echo "claude exit=$?"
echo "reply with {}" | codex exec --json --sandbox read-only --skip-git-repo-check -m gpt-5.6 -c model_reasoning_effort=medium - ; echo "codex exit=$?"
# ollama "think": true is a boolean body field, not a CLI value -- no CLI check needed;
# a bad model name (not a bad think value) is the only failure mode, covered by ERR_ERROR.
```

- [ ] **Step 2: Record the outcome and set defaults.** For each provider whose effort value was accepted (exit 0), set the ladder `effort` in `src/aramid/data/defaults.toml`: `cheap` → `low` (ollama `think:true`), `mid` → `medium` (codex accepted), `frontier` → `high` (claude accepted). For any value that was REJECTED, leave that arm's `effort = ""` and add a `# unverified: <cli> rejected "<value>"` comment. Update the `test_config.py` assertion accordingly (the `all(a["effort"] == "")` check becomes the verified values, or a mix).

- [ ] **Step 3: Note the verification result** in the commit body (which values were confirmed, on which CLI versions).

- [ ] **Step 4: Commit**

```bash
git add src/aramid/data/defaults.toml tests/unit/test_config.py
git commit -m "chore(llm): set verified reasoning-effort defaults in the ladder"
```

**If this task cannot be run** (no live CLI access at execution time): SKIP it — the ladder ships with `effort = ""` everywhere (fail-safe, flag omitted, no tier dies). Record the skip in the SDD ledger so it is not mistaken for done.

---

### Task 8: Docs — README + spec cross-reference

**Files:**
- Modify: `README.md` (Phase 2b provider-chain section)
- Modify: `docs/superpowers/specs/2026-07-13-aramid-phase2b-llm-reviewer-design.md` (one-line pointer to the model-selection spec)

**Interfaces:** none (docs).

- [ ] **Step 1: Update README.** In the Phase 2b section, change the provider chain description from `claude-cli → codex-cli → openrouter` to `claude-cli → codex-cli → ollama-cloud`, note OpenRouter is opt-in/in-app-only, and describe the risk-tiered ladder + `OLLAMA_API_KEY` setup in one short paragraph. Add `OLLAMA_API_KEY` alongside the existing `OPENROUTER_API_KEY` mention.

- [ ] **Step 2: Cross-reference the spec.** Add a one-line note near the top of the Phase 2b spec: `> Superseded in part by 2026-07-14-aramid-reviewer-model-selection-design.md (provider chain + ladder).`

- [ ] **Step 3: Commit**

```bash
git add README.md docs/superpowers/specs/2026-07-13-aramid-phase2b-llm-reviewer-design.md
git commit -m "docs: update provider chain + ladder in README and Phase 2b spec"
```

---

## Final verification (after all tasks)

- [ ] Run the full suite: `python -m pytest -q` — expect all green (≈555 + new tests).
- [ ] Fresh-interpreter registration check includes ollama: `python -c "import aramid.commands.drain; from aramid.providers import base; print(sorted(base.PROVIDERS))"` → must include `ollama-cloud`.
- [ ] Confirm the refute-budget / `confirmed` / evidence-binding tests are unchanged and green (grep the diff: no edits to `verify_findings`, `apply_refute`, `auto_resolve_llm`, `llm_gate_findings`, or the refute-budget loop's dedupe/cap logic).
- [ ] Whole-branch review (subagent-driven-development's final step), then `finishing-a-development-branch`.

## Notes / risks (carried from the spec + advisor)

- **Provisional tier signal:** the triage score measures admission signals, not reasoning need (spec §6.4). This ladder may mis-route; the auto-learn engine (next spec) replaces the signal. Do not "fix" it here.
- **Effort silent-tier-death:** never ship an unverified effort value as an active default — Task 7 gates that. The run note's `tier=`/`degraded_from=` make an outage visible.
- **Block path is off-limits:** if any task's diff touches `confirmed`, `verify_findings`, `apply_refute`, or the refute-budget cap, that is a defect — selection must not reach into the block path.
