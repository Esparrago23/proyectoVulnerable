#!/usr/bin/env python3
"""Run executable proofs and persist verified/unverified status per case."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "truth" / "reports" / "verification.md"


def main() -> int:
    rows = ["# Verification", "", "| Case | Status | Reason |", "|---|---|---|"]
    cases = list((ROOT / "truth" / "cases").rglob("*.yaml"))
    exit_code = 0
    for path in cases:
        case = yaml.safe_load(path.read_text(encoding="utf-8"))
        test = ROOT / case["proof"]["exploit_test"]
        result = subprocess.run([sys.executable, "-m", "pytest", str(test), "-q"], cwd=ROOT, text=True, capture_output=True)
        status = "verified" if result.returncode == 0 and "skipped" not in result.stdout else "unverified"
        reason = "passed" if status == "verified" else (result.stdout + result.stderr).strip().splitlines()[-1] if (result.stdout + result.stderr).strip() else "test failed"
        exit_code = max(exit_code, result.returncode)
        case["status"] = status
        path.write_text(yaml.safe_dump(case, sort_keys=False, allow_unicode=True), encoding="utf-8")
        rows.append(f"| {case['id']} | {status} | {reason[:180]} |")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
