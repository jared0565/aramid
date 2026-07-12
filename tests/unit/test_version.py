import subprocess, sys

def test_version_flag_prints_semver():
    out = subprocess.run([sys.executable, "-m", "aramid", "--version"],
                         capture_output=True, text=True)
    assert out.returncode == 0
    assert out.stdout.strip().startswith("aramid ")
