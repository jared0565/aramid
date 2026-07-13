import json

import pytest

from aramid.providers import spend


@pytest.fixture(autouse=True)
def _isolated_spend(tmp_path, monkeypatch):
    monkeypatch.setattr(spend, "spend_path", lambda: tmp_path / "llm_spend.jsonl")


def test_append_creates_file_and_dirs(tmp_path):
    spend.append_spend({"at": "2026-07-13T12:00:00+00:00", "provider": "openrouter",
                        "model": "m", "tokens_in": 10, "tokens_out": 5, "cost_usd": 0.01})
    lines = (tmp_path / "llm_spend.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert json.loads(lines[0])["cost_usd"] == 0.01


def test_month_spend_sums_only_current_month_and_provider():
    for at, prov, cost in [("2026-07-01T00:00:00+00:00", "openrouter", 1.0),
                           ("2026-07-13T12:00:00+00:00", "openrouter", 0.5),
                           ("2026-06-30T23:59:59+00:00", "openrouter", 99.0),  # last month
                           ("2026-07-13T12:00:00+00:00", "claude-cli", 0.0)]:  # other provider
        spend.append_spend({"at": at, "provider": prov, "model": "m",
                            "tokens_in": 1, "tokens_out": 1, "cost_usd": cost})
    assert spend.month_spend_usd("openrouter", "2026-07-13T14:00:00+00:00") == 1.5


def test_month_spend_missing_file_is_zero():
    assert spend.month_spend_usd("openrouter", "2026-07-13T12:00:00+00:00") == 0.0


def test_month_spend_corrupt_line_returns_none(tmp_path):
    p = tmp_path / "llm_spend.jsonl"
    p.write_text('{"at": "2026-07-13T12:00:00+00:00", "provider": "openrouter", "cost_usd": 1.0}\n'
                 "NOT JSON AT ALL\n", encoding="utf-8")
    # Fail-closed contract (spec section 6): unreadable spend -> None -> the
    # openrouter provider refuses paid calls. NEVER guess a partial sum.
    assert spend.month_spend_usd("openrouter", "2026-07-13T12:00:00+00:00") is None


@pytest.mark.parametrize("bad_line", [
    "null",  # bare scalar -> AttributeError on rec.get
    "5",  # bare number
    "[1, 2, 3]",  # array, not object
    '{"at": 123, "provider": "openrouter", "cost_usd": 1.0}',  # non-string at -> TypeError
    '{"at": "2026-07-13T12:00:00+00:00", "provider": "openrouter", "cost_usd": {}}',  # non-numeric cost
])
def test_month_spend_misshapen_json_line_returns_none(tmp_path, bad_line):
    # JSON-valid but misshapen lines must ALSO fail closed (return None),
    # never crash: the except must swallow AttributeError/TypeError too.
    p = tmp_path / "llm_spend.jsonl"
    p.write_text(bad_line + "\n", encoding="utf-8")
    assert spend.month_spend_usd("openrouter", "2026-07-13T12:00:00+00:00") is None
