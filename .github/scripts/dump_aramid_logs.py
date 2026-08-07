"""Print `.aramid/logs/` to the CI job log. Diagnostic only; never fails.

WHY THIS EXISTS. When aramid's gate blocks, the reason lives in
`.aramid/logs/<tool>-<run_id>.log` and nowhere else -- the finding itself
carries `evidence=None`, and the directory is gitignored. On 2026-08-06 the
`windows-latest / py3.14` leg failed at the pre-push gate with
`"rule": "tests-failed"`, passed on re-run with no code change, and the only
artifact naming the failing test died with the container. Six other legs were
green, so this is a real intermittent in the suite of a tool whose entire
claim is that its verdicts are deterministic.

WHY IT IS A FILE AND NOT AN INLINE `shell: python` STEP. It runs under
`if: failure()` and always exits 0, so a broken version prints nothing and
reports success -- indistinguishable from a correct version finding nothing.
Living here makes it executable by `tests/unit/test_ci_log_dump.py`, which
runs it as a subprocess from a temp cwd and pins every branch.

DISCLOSURE. This repository is public, so the job log is public, and "it gets
scrubbed" is NOT the reason that is acceptable: `redact.scrub` is fed only the
secrets recovered from successfully parsed findings, so a crashed scanner
would be redacted against an empty list. The actual reason is that the secret
scanner never puts a secret on a stream we persist -- gitleaks writes its
report to `--report-path`, a temp file that never reaches `.aramid/logs`, and
runs without `-v`, so a real body here is banner plus "INF no leaks found".
`tests/unit/test_ci_log_dump.py` pins both halves. Everything else is scan
output of sources that are already public, and `python-*.log` is the same
pytest output the `Run test suite` step prints unconditionally.

`upload-artifact` would buy nothing -- public-repo artifacts are equally
downloadable -- and would cost another action SHA to pin.

Standard library only, and no aramid import: this must work on a leg where
the install is what broke.
"""
import pathlib
import sys

# `pipeline._log_body` caps STDOUT at 64K but leaves stderr uncapped, so a
# spewing runner can still put megabytes on disk. Truncate from the front:
# pytest prints its short summary last, same rationale as that cap.
CAP = 200_000

# `.aramid/logs` has NO rotation -- one file per runner per gate run, kept
# forever. A fresh CI checkout holds ~5; a real dev checkout was measured at
# 477. Print the newest by mtime and SAY how many were left out: a silent cap
# would make a truncated dump read exactly like a complete one.
MAX_BODIES = 40

LOGS = pathlib.Path(".aramid") / "logs"


def _neutralise(body: str) -> str:
    """A log body is untrusted text and GitHub parses `::cmd::` from any line.
    `::add-mask::x` would redact x from all later output -- a failing test
    could suppress the diagnostic this step exists to print -- and
    `::endgroup::` would close the fold early. One leading space defuses both
    and is visibly a shift rather than a deletion."""
    return "\n".join(
        " " + line if line.startswith("::") else line
        for line in body.splitlines())


def main() -> int:
    # A redirected pipe on Windows gives Python the locale encoding (cp1252),
    # so a single box-drawing character out of pytest raises
    # UnicodeEncodeError -- the dump dies on the exact leg that flakes.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - non-reconfigurable
        pass

    if not LOGS.is_dir():
        print(f"aramid-logs: no {LOGS} directory. The gate wrote no logs -- "
              "it either failed before running any runner, or this job failed "
              "in a step that does not invoke aramid.")
        return 0

    files = sorted(LOGS.glob("*.log"))
    if not files:
        print(f"aramid-logs: {LOGS} exists but contains no *.log file.")
        return 0

    # Inventory FIRST. If GitHub truncates the step, you still learn which
    # runners reported at all -- and an absent runner is itself a diagnosis.
    print(f"aramid-logs: {len(files)} log file(s) under {LOGS} "
          "(one per runner per gate run; CI runs the gate twice):")
    for f in files:
        print(f"  {f.name}  {f.stat().st_size} bytes")

    # Bodies: newest first by mtime, then back to name order to read.
    if len(files) > MAX_BODIES:
        newest = sorted(files, key=lambda p: p.stat().st_mtime)[-MAX_BODIES:]
        print(f"aramid-logs: {len(files) - MAX_BODIES} older file(s) "
              f"inventoried above but NOT printed -- showing the {MAX_BODIES} "
              "most recently written. This directory is never rotated.")
        files = sorted(newest)

    for f in files:
        size = f.stat().st_size
        if size == 0:
            print(f"aramid-logs: {f.name} is EMPTY -- that runner reported "
                  "nothing on either stream.")
            continue
        body = f.read_text(encoding="utf-8", errors="replace")
        if len(body) > CAP:
            body = (f"[{len(body) - CAP} leading characters truncated]\n"
                    f"{body[-CAP:]}")
        print(f"::group::aramid-logs: {f.name} ({size} bytes)")
        print(_neutralise(body))
        print("::endgroup::")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - a diagnostic must never add a failure
        print(f"aramid-logs: dump failed ({exc!r}) -- this does NOT fail the "
              "job; the real failure is in an earlier step.")
        sys.exit(0)
