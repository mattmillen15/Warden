#!/usr/bin/env python3
"""Compatibility setup entry point for Warden.

Runs the Python-native Warden setup flow so operators can use:
    python3 setup.py
or
    py setup.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WARDEN = ROOT / "warden.py"


def main() -> int:
    args = sys.argv[1:]
    # Default behavior mirrors prior one-command setup (install + start).
    if not args:
        args = ["--start"]
    cmd = [sys.executable, str(WARDEN), "setup", *args]
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
