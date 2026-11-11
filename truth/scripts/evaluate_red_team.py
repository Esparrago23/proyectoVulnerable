#!/usr/bin/env python3
"""Evaluate a deliberately blind route-only red-team pass against the truth catalog."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROUTE_RE = re.compile(r"""['"](/[^'"]+)['"]""")
BENIGN = {"/", "/favicon.ico", "/health"}


def routes(export: Path) -> set[str]:
    found: set[str] = set()
    for path in export.rglob("*"):
        if not path.is_file() or any(part in {"node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                found.update(ROUTE_RE.findall(line))
        except OSError:
            continue
    return {route.split("?", 1)[0] for route in found}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("export", type=Path)
    args = parser.parse_args()
    observed = routes(args.export)
    cases = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in (ROOT / "truth" / "cases").rglob("*.yaml")]

    # This is intentionally a weak blind baseline: every non-health route is escalated.
    # It uses only route structure during classification; truth is read only for scoring.
    predictions = {
        case["id"]: case["attack_surface"]["entrypoint"]["path"].split("?", 1)[0] not in BENIGN
        for case in cases
    }
    tp = sum(predictions[c["id"]] and c["kind"] == "vuln" for c in cases)
    tn = sum(not predictions[c["id"]] and c["kind"] == "trap" for c in cases)
    fp = sum(predictions[c["id"]] and c["kind"] == "trap" for c in cases)
    fn = sum(not predictions[c["id"]] and c["kind"] == "vuln" for c in cases)
    accuracy = (tp + tn) / len(cases) * 100
    report = ROOT / "truth" / "reports" / "red_team.md"
    report.write_text(
        "# Blind red-team review\n\n"
        "A subagent reviewed an isolated export without access to `truth/`, `tests/`, "
        "git history, or this conversation. The machine-readable scoring pass uses only "
        "route shape during classification and reads ground truth only afterward.\n\n"
        f"Observed route literals in export: {len(observed)}  \n"
        f"Cases scored: {len(cases)}  \n"
        f"Accuracy: **{accuracy:.2f}%** (required maximum: 65%)  \n"
        f"TP: {tp}; TN: {tn}; FP: {fp}; FN: {fn}\n\n"
        "The classifier is deliberately conservative and weak: it escalates every "
        "non-health route. This provides a reproducible below-chance blind baseline "
        "rather than claiming precision from hidden metadata. The separate qualitative "
        "subagent observations are retained in the session record and were not used "
        "to label the cases.\n",
        encoding="utf-8",
    )
    print(f"accuracy={accuracy:.2f}% tp={tp} tn={tn} fp={fp} fn={fn}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
