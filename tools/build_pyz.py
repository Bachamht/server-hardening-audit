"""Build dist/server-hardening-audit.pyz with the standard library only.

The archive holds the package, its vendored code with licences, and the
bundled controls, frameworks and profiles under server_hardening_audit/_data/.
"""

from __future__ import annotations

import shutil
import sys
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build" / "pyz"
OUT = ROOT / "dist" / "server-hardening-audit.pyz"
PKG = "server_hardening_audit"


def main() -> int:
    shutil.rmtree(BUILD, ignore_errors=True)
    src = ROOT / PKG
    for path in src.rglob("*"):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        if path.suffix == ".py" or path.name in ("LICENSE", "README.md"):
            dest = BUILD / PKG / path.relative_to(src)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
    for data in ("controls", "frameworks", "profiles"):
        if (ROOT / data).is_dir():
            shutil.copytree(ROOT / data, BUILD / PKG / "_data" / data)
    for name in ("LICENSE", "NOTICE"):
        shutil.copy2(ROOT / name, BUILD / name)
    OUT.parent.mkdir(exist_ok=True)
    zipapp.create_archive(BUILD, OUT, interpreter="/usr/bin/env python3",
                          main=f"{PKG}.cli:main", compressed=True)
    print(f"built {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
