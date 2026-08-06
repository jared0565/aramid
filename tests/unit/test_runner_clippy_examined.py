"""clippy's `examined` set -- which .rs files cargo actually compiled.

Split out of test_runner_clippy.py because the mechanism is a file-format
parser with its own hazards (Windows drive letters, Makefile escaping, stale
artifacts) rather than more of the JSON-stream contract that file covers.

Why depfiles at all: `cargo clippy --message-format=json` names only CRATE
ROOTS in its `compiler-artifact` records (`target.src_path`), so the stream
alone cannot say which modules were compiled. The dep-info files cargo writes
alongside each artifact do -- measured on a live crate, the depfile for a lib
target listed exactly `src/lib.rs src/used.rs Cargo.toml` and correctly
omitted an `src/orphan.rs` that no `mod` declaration reached.

Which matters because a finding recorded in a file that later stops being
compiled -- someone deletes the `mod foo;` and leaves foo.rs in the tree --
would otherwise be silently recorded as `fixed`.

Two measurements shape the design, both from a live crate on 2026-08-06:
  - a fully cached re-run still emits every compiler-artifact record, so the
    artifact set is available whether or not anything recompiled; but
  - cached runs do NOT rewrite depfiles (mtimes byte-identical across runs),
    so freshness cannot be established by timestamp. Stale depfiles from
    other feature/profile builds accumulate in the same directory and are
    rejected STRUCTURALLY instead: a depfile counts only if one of its own
    target lines is an artifact THIS run reported.
"""
import json
from pathlib import Path

from aramid.runners import clippy
from aramid.runners.base import RunContext, RunnerResult, ToolState


def _crate(tmp_path: Path) -> Path:
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "probe"\n', encoding="utf-8")
    (tmp_path / "src").mkdir()
    for name in ("lib.rs", "used.rs", "orphan.rs"):
        (tmp_path / "src" / name).write_text("// rust\n", encoding="utf-8")
    deps = tmp_path / "target" / "debug" / "deps"
    deps.mkdir(parents=True)
    return deps


def _artifact(tmp_path: Path, rmeta: Path) -> dict:
    return {
        "reason": "compiler-artifact",
        "manifest_path": str(tmp_path / "Cargo.toml"),
        "target": {"name": "probe", "kind": ["lib"],
                   "src_path": str(tmp_path / "src" / "lib.rs")},
        "filenames": [str(rmeta)],
    }


def _depfile(path: Path, rmeta: Path, deps: str) -> None:
    """A cargo dep-info file: the `.d` itself and the real artifact each get a
    rule, then every dependency repeats as a phony target with no deps."""
    body = [f"{path}: {deps}", "", f"{rmeta}: {deps}", ""]
    body += [f"{d}:" for d in deps.split() ]
    body += ["", "# env-dep:CLIPPY_ARGS="]
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


def _run(tmp_path, monkeypatch, records) -> RunnerResult:
    raw = "\n".join(json.dumps(r) for r in records) + "\n"
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: "cargo-clippy")
    monkeypatch.setattr(
        clippy, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("cargo", ToolState.OK, raw=raw))
    return clippy.run(RunContext(root=tmp_path))


def test_examined_lists_compiled_sources_and_omits_an_unreachable_module(
        tmp_path, monkeypatch):
    """src/orphan.rs is in the tree but no `mod` reaches it, so cargo never
    compiles it and clippy can never report on it. Vouching for it would let
    a finding there resolve itself."""
    deps_dir = _crate(tmp_path)
    rmeta = deps_dir / "libprobe-26d38ca1.rmeta"
    _depfile(deps_dir / "probe-26d38ca1.d", rmeta, "src/lib.rs src/used.rs Cargo.toml")

    result = _run(tmp_path, monkeypatch, [
        _artifact(tmp_path, rmeta),
        {"reason": "build-finished", "success": True},
    ])

    assert result.examined == frozenset({"src/lib.rs", "src/used.rs"})


def test_stale_depfile_from_another_build_is_rejected(tmp_path, monkeypatch):
    """Depfiles are never cleaned up and are not rewritten on a cached run, so
    a directory accumulates one per feature/profile combination ever built.
    Matching on the artifact set this run reported is what keeps an old one
    from vouching for files the current configuration does not compile."""
    deps_dir = _crate(tmp_path)
    live = deps_dir / "libprobe-26d38ca1.rmeta"
    _depfile(deps_dir / "probe-26d38ca1.d", live, "src/lib.rs Cargo.toml")
    # left behind by an earlier build that DID compile orphan.rs
    stale = deps_dir / "libprobe-ffffffff.rmeta"
    _depfile(deps_dir / "probe-ffffffff.d", stale, "src/lib.rs src/orphan.rs Cargo.toml")

    result = _run(tmp_path, monkeypatch, [_artifact(tmp_path, live)])

    assert result.examined == frozenset({"src/lib.rs"})


def test_no_matching_depfile_vouches_for_nothing(tmp_path, monkeypatch):
    """Degradation must block resolution, not fall back to the gate scope --
    the empty set is a positive claim, None would reopen the hole."""
    deps_dir = _crate(tmp_path)
    rmeta = deps_dir / "libprobe-26d38ca1.rmeta"   # no depfile written at all

    result = _run(tmp_path, monkeypatch, [_artifact(tmp_path, rmeta)])

    assert result.examined == frozenset()


def test_workspace_member_deps_resolve_against_the_package_not_the_repo(
        tmp_path, monkeypatch):
    """rustc runs with cwd = the PACKAGE root, so a workspace member's depfile
    says `src/lib.rs` meaning `crates/foo/src/lib.rs`. Resolving those against
    the repo root would silently vouch for the wrong paths."""
    (tmp_path / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    pkg = tmp_path / "crates" / "foo"
    (pkg / "src").mkdir(parents=True)
    (pkg / "Cargo.toml").write_text('[package]\nname = "foo"\n', encoding="utf-8")
    (pkg / "src" / "lib.rs").write_text("// rust\n", encoding="utf-8")
    deps_dir = tmp_path / "target" / "debug" / "deps"
    deps_dir.mkdir(parents=True)
    rmeta = deps_dir / "libfoo-abc.rmeta"
    _depfile(deps_dir / "foo-abc.d", rmeta, "src/lib.rs Cargo.toml")

    record = {
        "reason": "compiler-artifact",
        "manifest_path": str(pkg / "Cargo.toml"),
        "target": {"name": "foo", "kind": ["lib"], "src_path": str(pkg / "src" / "lib.rs")},
        "filenames": [str(rmeta)],
    }

    result = _run(tmp_path, monkeypatch, [record])

    assert result.examined == frozenset({"crates/foo/src/lib.rs"})


def test_examined_excludes_paths_outside_the_repository(tmp_path, monkeypatch):
    """Registry and sysroot sources are real dependencies of the compilation
    but are not files this repo can hold findings against."""
    deps_dir = _crate(tmp_path)
    rmeta = deps_dir / "libprobe-26d38ca1.rmeta"
    outside = (tmp_path.parent / "registry" / "serde.rs").as_posix()
    _depfile(deps_dir / "probe-26d38ca1.d", rmeta, f"src/lib.rs {outside}")

    result = _run(tmp_path, monkeypatch, [_artifact(tmp_path, rmeta)])

    assert result.examined == frozenset({"src/lib.rs"})


def test_degraded_run_vouches_for_nothing(tmp_path, monkeypatch):
    _crate(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: "cargo-clippy")
    monkeypatch.setattr(
        clippy, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("cargo", ToolState.TIMEOUT))

    result = clippy.run(RunContext(root=tmp_path))

    assert result.state is ToolState.TIMEOUT
    assert result.examined is not None and not result.examined


# --- depfile parsing --------------------------------------------------------

def test_parse_depfile_splits_on_colon_space_not_the_drive_letter():
    """A Windows target line begins `C:\\...`; splitting on the first colon
    would take the drive letter as the whole target and lose the rule."""
    text = (r"C:\build\deps\probe-abc.d: src\lib.rs Cargo.toml" + "\n"
            r"C:\build\deps\libprobe-abc.rmeta: src\lib.rs Cargo.toml" + "\n")

    rules = clippy._parse_depfile(text)

    assert [t for t, _ in rules] == [r"C:\build\deps\probe-abc.d",
                                     r"C:\build\deps\libprobe-abc.rmeta"]
    assert rules[0][1] == [r"src\lib.rs", "Cargo.toml"]


def test_parse_depfile_honours_escaped_spaces_but_not_path_separators():
    r"""Makefile escaping uses `\ ` for a literal space. On Windows a lone
    backslash is the path SEPARATOR, so only backslash-space may be treated
    as an escape -- otherwise `src\lib.rs` would be mangled."""
    text = "out.d: " + r"src\my\ mod.rs src\lib.rs" + "\n"

    (_, deps), = clippy._parse_depfile(text)

    assert deps == [r"src\my mod.rs", r"src\lib.rs"]


def test_parse_depfile_skips_phony_lines_and_comments():
    """Every dependency repeats as a target with no deps, and cargo appends
    `# env-dep:` comments. Neither is a rule."""
    text = ("out.d: src/lib.rs\n"
            "\n"
            "src/lib.rs:\n"
            "\n"
            "# env-dep:CLIPPY_ARGS=\n")

    rules = clippy._parse_depfile(text)

    assert rules == [("out.d", ["src/lib.rs"])]
