"""Packaging: the built .pyz runs standalone and keeps exit codes."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_pyz_runs_and_preserves_exit_codes(tmp_path):
    pyz = tmp_path / "sha.pyz"
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_pyz.py"), str(pyz)],
                   check=True, capture_output=True)

    def run(*args):
        return subprocess.run([sys.executable, str(pyz), *args], capture_output=True,
                              text=True, cwd=tmp_path)

    listed = run("list")
    assert listed.returncode == 0 and "ACC-01" in listed.stdout
    assert run("no-such-command").returncode == 3
    (tmp_path / "leak").mkdir()
    (tmp_path / "leak" / "x.txt").write_text("password = hunter2\n")
    assert run("redact-check", "leak").returncode == 1
