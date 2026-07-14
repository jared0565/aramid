"""Regression: the production drain import path must populate base.PROVIDERS.

Provider modules self-register at import (`base.PROVIDERS[NAME] = module`), but
only if something imports them. drain.py imports its consumers; the llm-review
consumer must in turn import its providers. If that wiring is missing, PROVIDERS
stays empty in production, `chain()` returns [], and every drain reports "no
providers installed" even with the CLIs on PATH -- while the whole test suite
stays green because every consumer test REPLACES PROVIDERS with fakes.

This test runs in a FRESH subprocess interpreter on purpose: within one pytest
process, other tests (test_provider_openrouter.py etc.) `import` the provider
modules directly and register them as a side effect, which would mask a missing
production import. Only a clean interpreter proves the drain path itself wires
registration.
"""
import subprocess
import sys


def test_drain_import_path_registers_all_default_providers():
    code = (
        "import aramid.commands.drain\n"
        "from aramid.providers import base\n"
        "got = set(base.PROVIDERS)\n"
        "need = {'claude-cli', 'codex-cli', 'openrouter'}\n"
        "assert need <= got, f'missing {need - got}; got {got}'\n"
        "print('REGISTERED')\n"
    )
    cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    assert "REGISTERED" in cp.stdout


def test_llm_consumer_import_alone_registers_providers():
    """Importing just the consumer (not the whole drain) is enough -- the
    consumer owns the provider import, so a leaner import path still registers."""
    code = (
        "from aramid.consumers import llm_review\n"
        "from aramid.providers import base\n"
        "assert {'claude-cli', 'codex-cli', 'openrouter'} <= set(base.PROVIDERS)\n"
        "print('REGISTERED')\n"
    )
    cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    assert "REGISTERED" in cp.stdout
