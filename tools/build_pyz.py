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
BUILD = ROOT / "build" / "pyz"  # usage: build_pyz.py [OUTPUT]
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
    # Our own __main__: zipapp's generated one discards main()'s return
    # value, which would turn every exit code into 0.
    shutil.copy2(src / "__main__.py", BUILD / "__main__.py")
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    zipapp.create_archive(BUILD, out, interpreter="/usr/bin/env python3", compressed=True)
    print(f"built {out} ({out.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
