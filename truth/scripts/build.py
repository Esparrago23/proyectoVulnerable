#!/usr/bin/env python3
"""Recalculate anchors and generate the benchmark exports and coverage tables."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "truth" / "cases"
GENERATED = ROOT / "truth" / "generated"
OWASP_2025 = {"A01:2021": "A01:2025", "A02:2021": "A04:2025", "A03:2021": "A05:2025", "A04:2021": "A06:2025", "A05:2021": "A02:2025", "A06:2021": "A03:2025", "A07:2021": "A07:2025", "A08:2021": "A08:2025", "A09:2021": "A09:2025", "A10:2021": "A10:2025"}


def load_cases() -> list[dict[str, Any]]:
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(CASES.glob("*/*.yaml"))]


def difficulty(case: dict[str, Any]) -> int:
    d = case["difficulty"]
    score = 1 + min(1, max(0, d.get("hops", 1) - 1) // 2)
    score += sum(bool(d.get(key)) for key in ("cross_language", "cross_service", "requires_runtime_state", "requires_business_context", "partial_sanitizer", "framework_indirection", "config_or_dependency"))
    return max(1, min(4, score))


def recalculate_locations(case: dict[str, Any]) -> None:
    for location in case["locations"]:
        path = ROOT / "target" / location["file"]
        if not path.exists():
            raise ValueError(f"{case['id']}: missing target file {location['file']}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        pattern = location.get("anchor", {}).get("pattern", "")
        hits = [index + 1 for index, line in enumerate(lines) if pattern and pattern in line]
        if len(hits) != 1:
            raise ValueError(f"{case['id']}: anchor must occur exactly once in {location['file']}: {pattern!r} ({len(hits)} hits)")
        old_start = location["lines"][0]
        nearest = min(hits, key=lambda value: abs(value - old_start))
        location["lines"] = [nearest, nearest]


def build() -> None:
    cases = load_cases()
    for case in cases:
        recalculate_locations(case)
        case["difficulty"]["computed_level"] = difficulty(case)
        case["taxonomy"]["owasp_2025"] = OWASP_2025.get(case["taxonomy"]["owasp_2021"], "")
        score = float(case["severity"]["score"])
        case["severity"]["level"] = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
    GENERATED.mkdir(parents=True, exist_ok=True)
    exported = []
    for case in cases:
        primaries = [x for x in case["locations"] if x.get("primary")]
        first = primaries[0]
        exported.append({
            "id": case["id"], "file": first["file"], "line_start": first["lines"][0], "line_end": first["lines"][1],
            "cwe": case["taxonomy"]["cwe_primary"], "owasp": case["taxonomy"]["owasp_2021"], "kind": case["kind"],
            "hops": case["difficulty"]["hops"], "split": case["split"], "language": Path(first["file"]).suffix.lstrip(".") or "generic",
            "title": case["title"], "difficulty_level": case["difficulty"]["computed_level"], "status": case["status"],
            "detection_capabilities_needed": case["detection_capabilities_needed"], "locations": case["locations"],
        })
    (GENERATED / "ground_truth.json").write_text(json.dumps(exported, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    dimensions = {
        "kind": lambda c: c["kind"], "owasp_2021": lambda c: c["taxonomy"]["owasp_2021"],
        "owasp_2025": lambda c: c["taxonomy"]["owasp_2025"], "cwe": lambda c: c["taxonomy"]["cwe_primary"],
        "severity": lambda c: c["severity"]["level"], "difficulty": lambda c: c["difficulty"]["computed_level"],
        "language": lambda c: Path(c["locations"][0]["file"]).suffix.lstrip(".") or "generic",
        "service": lambda c: c["attack_surface"]["service"], "split": lambda c: c["split"],
    }
    lines = ["# Ground truth summary", "", f"Total cases: {len(cases)}", ""]
    for name, getter in dimensions.items():
        counts = Counter(getter(c) for c in cases)
        lines += [f"## {name}", "", "| Value | Count |", "|---|---:|"] + [f"| {key} | {value} |" for key, value in sorted(counts.items(), key=lambda x: str(x[0]))] + [""]
    lines += ["## Cases", "", "| ID | Kind | OWASP 2021 | OWASP 2025 | Severity | Difficulty | Locations |", "|---|---|---|---|---|---:|---|"]
    for case in cases:
        locations = "; ".join(f"{x['file']}:{x['lines'][0]}-{x['lines'][1]}" for x in case["locations"] if x.get("primary"))
        lines.append(f"| {case['id']} | {case['kind']} | {case['taxonomy']['owasp_2021']} | {case['taxonomy']['owasp_2025']} | {case['severity']['level']} | {case['difficulty']['computed_level']} | {locations} |")
    (GENERATED / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    matrix = defaultdict(Counter)
    for case in cases:
        matrix[case["taxonomy"]["owasp_2021"]][case["difficulty"]["computed_level"]] += 1
    matrix_lines = ["# OWASP x difficulty matrix", "", "| OWASP 2021 | L1 | L2 | L3 | L4 | Total |", "|---|---:|---:|---:|---:|---:|"]
    for owasp, counts in sorted(matrix.items()):
        values = [counts[i] for i in range(1, 5)]
        matrix_lines.append(f"| {owasp} | {' | '.join(map(str, values))} | {sum(values)} |")
    (GENERATED / "coverage_matrix.md").write_text("\n".join(matrix_lines) + "\n", encoding="utf-8")
    for case in cases:
        path = next(CASES.rglob(f"{case['id']}.yaml"))
        path.write_text(yaml.safe_dump(case, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"Built {len(cases)} cases")


if __name__ == "__main__":
    build()
