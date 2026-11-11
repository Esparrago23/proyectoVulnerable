#!/usr/bin/env python3
"""Export only the analyzable target tree, excluding repository metadata."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", nargs="?", help="Destination directory; defaults to a temporary directory")
    args = parser.parse_args()
    destination = Path(args.destination) if args.destination else Path(tempfile.mkdtemp(prefix="proyectoVulnerable-target-"))
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(ROOT / "target", destination, ignore=shutil.ignore_patterns(".git", "meta", "truth", "__pycache__", "node_modules"))
    scanner = ROOT / "truth" / "scripts" / "leak_scan.py"
    result = subprocess.run([sys.executable, str(scanner), str(destination)], cwd=ROOT, text=True)
    if result.returncode:
        raise SystemExit("sanitized export contains leakage findings")
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
