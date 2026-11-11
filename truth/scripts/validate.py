#!/usr/bin/env python3
"""Validate case schema, anchors, uniqueness, proof references, and generated output."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "target"
SCHEMA = json.loads((ROOT / "truth" / "schema" / "case.schema.json").read_text(encoding="utf-8"))
FORBIDDEN_PROOF = "exists("


def main() -> int:
    errors: list[str] = []
    seen: set[str] = set()
    covered_files: set[str] = set()
    covered_lines = 0
    analyzable_lines = 0
    clean = yaml.safe_load((ROOT / "truth" / "clean_zones.yaml").read_text(encoding="utf-8")) or {}
    for path in sorted((ROOT / "truth" / "cases").glob("*/*.yaml")):
        case = yaml.safe_load(path.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(case, SCHEMA)
        except jsonschema.ValidationError as exc:
            errors.append(f"{path}: {exc.message}")
            continue
        if case["id"] in seen:
            errors.append(f"duplicate id: {case['id']}")
        seen.add(case["id"])
        for loc in case["locations"]:
            covered_files.add(loc["file"])
            file_path = TARGET / loc["file"]
            if not file_path.exists():
                errors.append(f"{case['id']}: missing target file {loc['file']}")
                continue
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            covered_lines += len(lines) if loc.get("primary") else 0
            start, end = loc["lines"]
            if end > len(lines):
                errors.append(f"{case['id']}: line range exceeds {loc['file']}")
            pattern = loc["anchor"].get("pattern", "")
            hits = [index + 1 for index, line in enumerate(lines) if pattern and pattern in line]
            if len(hits) != 1:
                errors.append(f"{case['id']}: anchor occurs {len(hits)} times in {loc['file']}")
            if start not in hits:
                errors.append(f"{case['id']}: lines are stale for anchor in {loc['file']}")
        proof = ROOT / case["proof"]["exploit_test"]
        if not proof.exists():
            errors.append(f"{case['id']}: missing proof {case['proof']['exploit_test']}")
        elif FORBIDDEN_PROOF in proof.read_text(encoding="utf-8"):
            errors.append(f"{case['id']}: proof is only a file-existence assertion")
    for zone in clean.get("clean_zones", []):
        zone_file = zone.get("file", "")
        if not (TARGET / zone_file).exists():
            errors.append(f"clean zone missing: {zone_file}")
        if zone_file in covered_files:
            errors.append(f"clean zone overlaps a case: {zone_file}")
    for path in TARGET.rglob("*"):
        if not path.is_file() or path.suffix not in {".js", ".py"}:
            continue
        if "node_modules" in path.parts or "__pycache__" in path.parts:
            continue
        analyzable_lines += len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    clean_lines = 0
    for zone in clean.get("clean_zones", []):
        zone_path = TARGET / zone.get("file", "")
        if zone_path.exists():
            clean_lines += len(zone_path.read_text(encoding="utf-8", errors="replace").splitlines())
    if analyzable_lines and clean_lines / analyzable_lines < 0.15:
        errors.append(f"clean zones cover {clean_lines}/{analyzable_lines} lines, below 15%")
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Validated {len(seen)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
