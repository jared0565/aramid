"""tsc's `examined` set -- which files the compilation actually included.

The hole this closes is tsconfig's, and it is ruff's `exclude` in another
costume: `run_tsc` type-checks the PROJECT, not `ctx.files`, so a source file
left out of tsconfig's `include`/`files` is never checked at all. tsc exits 0,
reports nothing about it, and resolution recorded every open finding in it as
`fixed`. Narrowing `include` therefore forged repairs.

Measured on TypeScript 7.0.2 (2026-08-06) against a project with `typescript`
and `@types/node` installed and two source files:

    tsc --noEmit                 0.98s   1 line     (the one diagnostic)
    tsc --noEmit --listFiles     0.93s   66 lines   (1 diagnostic + 65 paths)
    tsc --listFilesOnly          0.65s   65 lines   (paths, no checking)

So `--listFiles` is free in TIME -- within noise of the baseline, since tsc
already reads every one of those files -- but it is NOT free in OUTPUT: 63 of
the 65 paths were lib/`node_modules` `.d.ts` files, and a real application
project emits thousands. A separate `--listFilesOnly` probe would keep the
output clean at the cost of a second parse+resolve of the whole program.

The adapter takes neither trade: one run, and the path lines are CONSUMED
into `examined` rather than left in `raw`. `raw` therefore still holds exactly
the diagnostics it held before, which is what the logs and `parse_tsc` want.
"""
from pathlib import Path

from aramid.runners import typecheck
from aramid.runners.base import RunContext, RunnerResult, ToolState


def _ts_project(tmp_path: Path) -> Path:
    (tmp_path / "tsconfig.json").write_text('{"include":["src"]}', encoding="utf-8")
    binp = typecheck._tsc_bin(tmp_path)
    binp.parent.mkdir(parents=True, exist_ok=True)
    binp.write_text("", encoding="utf-8")
    return binp


def _fake_output(tmp_path: Path, *, diagnostics=(), paths=()) -> str:
    lines = list(diagnostics)
    lines += [(tmp_path / p).as_posix() for p in paths]
    return "\n".join(lines) + "\n"


def _run(tmp_path, monkeypatch, raw, state=ToolState.OK):
    captured = {}

    def fake(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult("tsc.cmd", state, raw=raw)

    monkeypatch.setattr(typecheck, "run_subprocess", fake)
    result = typecheck.run_tsc(RunContext(root=tmp_path))
    return result, captured


def test_run_tsc_asks_tsc_which_files_it_included(tmp_path, monkeypatch):
    _ts_project(tmp_path)

    _, captured = _run(tmp_path, monkeypatch, "")

    assert "--listFiles" in captured["argv"]
    assert "--noEmit" in captured["argv"]


def test_examined_collects_the_listed_files(tmp_path, monkeypatch):
    _ts_project(tmp_path)
    raw = _fake_output(
        tmp_path,
        diagnostics=["src/bad.ts(1,14): error TS2322: Type 'string' is not "
                     "assignable to type 'number'."],
        paths=["src/bad.ts", "src/good.ts"])

    result, _ = _run(tmp_path, monkeypatch, raw)

    assert result.examined == frozenset({"src/bad.ts", "src/good.ts"})


def test_a_file_outside_the_tsconfig_project_is_not_vouched_for(tmp_path, monkeypatch):
    """The whole point: `src/orphan.ts` exists in the tree but tsconfig's
    `include` does not reach it, so tsc never lists it and never checks it."""
    _ts_project(tmp_path)
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "orphan.ts").write_text("export const x = 1;\n", encoding="utf-8")
    raw = _fake_output(tmp_path, paths=["src/included.ts"])

    result, _ = _run(tmp_path, monkeypatch, raw)

    assert result.examined == frozenset({"src/included.ts"})
    assert "src/orphan.ts" not in result.examined


def test_path_lines_are_consumed_and_do_not_reach_raw(tmp_path, monkeypatch):
    """`raw` must still be the diagnostics and nothing else -- a real project
    lists thousands of lib/node_modules .d.ts files, which would otherwise
    flood every log this result is written to."""
    diag = "src/bad.ts(1,14): error TS2322: bad"
    raw = _fake_output(tmp_path, diagnostics=[diag],
                       paths=["src/bad.ts", "src/good.ts"])
    _ts_project(tmp_path)

    result, _ = _run(tmp_path, monkeypatch, raw)

    assert result.raw.strip() == diag
    findings = typecheck.parse_tsc(result, RunContext(root=tmp_path))
    assert len(findings) == 1
    assert findings[0].file == "src/bad.ts"


def test_paths_outside_the_repository_are_dropped(tmp_path, monkeypatch):
    """tsc lists its own bundled `lib.es*.d.ts` from wherever TypeScript is
    installed. Those are real inputs but cannot hold a repo finding."""
    _ts_project(tmp_path)
    outside = (tmp_path.parent / "elsewhere" / "lib.es2022.d.ts").as_posix()
    raw = _fake_output(tmp_path, paths=["src/app.ts"]) .rstrip("\n") + f"\n{outside}\n"

    result, _ = _run(tmp_path, monkeypatch, raw)

    assert result.examined == frozenset({"src/app.ts"})


def test_degraded_run_vouches_for_nothing(tmp_path, monkeypatch):
    _ts_project(tmp_path)

    result, _ = _run(tmp_path, monkeypatch, "", state=ToolState.TIMEOUT)

    assert result.state is ToolState.TIMEOUT
    assert result.examined is not None and not result.examined


def test_mypy_arm_still_reports_that_it_cannot_vouch(tmp_path, monkeypatch):
    """mypy has no `--listFiles` equivalent, so it must report None -- "cannot
    report", falling back -- rather than the empty set, which would block every
    mypy resolution outright."""
    monkeypatch.setattr(
        typecheck, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("mypy", ToolState.OK, raw=""))

    result = typecheck.run_mypy(RunContext(root=tmp_path, files=["a.py"]))

    assert result.examined is None
