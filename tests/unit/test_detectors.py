from pathlib import Path
from aramid import detectors

def test_stack_and_pm(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest"}}')
    (tmp_path / "pnpm-lock.yaml").write_text("")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python", "js"}
    assert detectors.detect_package_manager(tmp_path) == "pnpm"
    assert "npm" in detectors.detect_tests(tmp_path)
