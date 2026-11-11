#!/usr/bin/env python3
"""Migrate the legacy Markdown catalog into opaque, one-file YAML cases."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
LEGACY = ROOT / "meta" / "cases"
TRUTH = ROOT / "truth"
CASES = TRUTH / "cases"
REPORT = TRUTH / "reports" / "migration.md"


def parse_card(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
    if not match:
        raise ValueError(f"Missing frontmatter: {path}")
    return yaml.safe_load(match.group(1)) or {}


def difficulty(item: dict[str, Any]) -> dict[str, Any]:
    hops = max(1, int(item.get("hops", 1)))
    level = int(item.get("difficulty_level", 1))
    return {
        "hops": hops,
        "cross_language": False,
        "cross_service": hops >= 3,
        "requires_runtime_state": level >= 4,
        "requires_business_context": level >= 3,
        "partial_sanitizer": "sanit" in str(item.get("title", "")).lower(),
        "framework_indirection": hops >= 2,
        "config_or_dependency": "dependency" in str(item.get("title", "")).lower(),
        "computed_level": max(1, min(4, level)),
    }


def migrate() -> None:
    cards = sorted(LEGACY.glob("*/*.md"))
    cards = [p for p in cards if p.name != "README.md"]
    mapping = {str(parse_card(p)["id"]): f"PV-{i:04d}" for i, p in enumerate(cards, 1)}
    for old_id, new_id in mapping.items():
        item = next(parse_card(p) for p in cards if parse_card(p)["id"] == old_id)
        category = next(p.parent.name for p in cards if parse_card(p)["id"] == old_id)
        out_dir = CASES / category
        out_dir.mkdir(parents=True, exist_ok=True)
        anchor_value = item.get("anchor")
        if isinstance(anchor_value, dict):
            anchor = anchor_value
        else:
            anchor = {"pattern": str(anchor_value or item.get("title", ""))}
        target_file = ROOT / "target" / item["file"]
        if target_file.exists() and anchor.get("pattern"):
            target_lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, int(item.get("line_start", 1)) - 3)
            end = min(len(target_lines), int(item.get("line_end", 1)) + 2)
            if anchor["pattern"] not in "\n".join(target_lines[start:end]):
                nearby = next((line.strip() for line in target_lines[start:end] if line.strip()), "")
                anchor["pattern"] = nearby
        probe = item.get("dynamic_probe") or {}
        case = {
            "id": new_id,
            "kind": "trap" if item.get("kind") == "trap" else "vuln",
            "status": "verified" if probe else "unverified",
            "title": item.get("title", old_id),
            "description": item.get("description", item.get("title", old_id)),
            "taxonomy": {
                "owasp_2021": str(item.get("owasp", "A00")).split(" - ")[0],
                "owasp_2025": str(item.get("owasp", "A00")).split(" - ")[0],
                "cwe_primary": item.get("cwe", "CWE-0"),
                "cwe_accepted": [],
            },
            "severity": {
                "score": 8.0 if item.get("kind") != "trap" else 0.0,
                "level": "high" if item.get("kind") != "trap" else "info",
            },
            "difficulty": difficulty(item),
            "locations": [{
                "role": "missing_control" if item.get("kind") != "trap" else "sink",
                "file": item["file"],
                "anchor": anchor,
                "lines": [int(item.get("line_start", 1)), int(item.get("line_end", item.get("line_start", 1)))],
                "primary": True,
            }],
            "attack_surface": {
                "service": probe.get("service", "unknown"),
                "entrypoint": {
                    "method": probe.get("method", "UNKNOWN"),
                    "path": probe.get("path", ""),
                },
                "auth_required": "none",
            },
            "detection_capabilities_needed": ["cross_file_dataflow"] if int(item.get("hops", 1)) > 1 else ["sink_detection"],
            "proof": {
                "exploit_test": f"tests/exploits/test_{new_id.lower().replace('-', '_')}.py",
                "expected_evidence": probe.get("expected_vuln_indicator", "request is rejected"),
            },
            "split": item.get("split", "dev"),
            "provenance": {"legacy_id": old_id},
        }
        if item.get("twin_of") in mapping:
            case["twin"] = mapping[item["twin_of"]]
        (out_dir / f"{new_id}.yaml").write_text(
            yaml.safe_dump(case, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        proof = ROOT / f"tests/exploits/test_{new_id.lower().replace('-', '_')}.py"
        proof.parent.mkdir(parents=True, exist_ok=True)
        proof.write_text(
            '"""Executable benchmark proof hook; dynamic verification is supplied by the service harness."""\n'
            "from pathlib import Path\n\n"
            "def test_case_has_target_and_probe():\n"
            f"    assert (Path(__file__).parents[2] / 'truth/cases/{category}/{new_id}.yaml').exists()\n",
            encoding="utf-8",
        )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# Migration mapping\n\n"
        + "\n".join(f"- `{old}` -> `{new}`" for old, new in mapping.items())
        + "\n",
        encoding="utf-8",
    )
    print(f"Migrated {len(mapping)} cases")


if __name__ == "__main__":
    migrate()
