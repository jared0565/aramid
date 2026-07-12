import json
from pathlib import Path

def detect_stacks(root: Path, scope: Path) -> set[str]:
    s = set()
    if (root / "pyproject.toml").exists() or any(scope.rglob("*.py")):
        s.add("python")
    if (root / "package.json").exists():
        s.add("js")
    return s

def detect_package_manager(root: Path):
    for f, name in (("package-lock.json", "npm"), ("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn")):
        if (root / f).exists():
            return name
    return None

def detect_tests(root: Path) -> set[str]:
    out = set()
    if (root / "tests").exists() or any(root.rglob("test_*.py")):
        out.add("pytest")
    pj = root / "package.json"
    if pj.exists():
        try:
            if "test" in json.loads(pj.read_text()).get("scripts", {}):
                out.add("npm")
        except (ValueError, OSError):
            pass
    return out

def nested_git_dirs(root: Path) -> list[Path]:
    return [p.parent for p in root.rglob(".git")
            if p.parent.resolve() != root.resolve() and "node_modules" not in p.parts]
