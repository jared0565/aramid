"""FN-53: every gitleaks the runner starts -- its own scan and the inline
second pass -- runs with GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML removed
from its environment. Either one replaces the rules gitleaks scans with, and
the committer's environment is not the gate's configuration.

The real-binary proof, with a control showing either variable hides a
secret, is tests/integration/test_gitleaks_env_cleared_live.py."""
from pathlib import Path

from aramid.runners import gitleaks
from aramid.runners.base import RunContext, RunnerResult, ToolState


def _record(calls):
    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        calls.append((argv, env))
        Path(argv[argv.index("--report-path") + 1]).write_text("[]")
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="",
                            duration_s=0.01, returncode=0)
    return fake_run_subprocess


def test_both_gitleaks_runs_clear_the_config_variables(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(gitleaks, "run_subprocess", _record(calls))
    result = gitleaks.run(RunContext(root=tmp_path, inline_pass=True))
    assert result.state is ToolState.OK
    assert [("--ignore-gitleaks-allow" in argv) for argv, _env in calls] == [False, True]
    for _argv, env in calls:
        assert env == {"GITLEAKS_CONFIG": None, "GITLEAKS_CONFIG_TOML": None}
