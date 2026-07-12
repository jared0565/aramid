# aramid
Deterministic security &amp; quality gate engine for git repos. Installs pre-commit/pre-push hooks that run secret scanning (gitleaks), SAST (semgrep/OWASP), linting (ruff/eslint), type checks, dependency audits, and tests — security findings block, quality issues warn. Event-sourced findings ledger, one-command setup: aramid init &lt;repo>.
