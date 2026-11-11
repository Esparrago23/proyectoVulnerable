#!/usr/bin/env python3
"""Scan an exported target tree for labels that disclose benchmark ground truth."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FORBIDDEN = re.compile(
    r"(?i)(insecure|unsafe|vulnerab|(^|[^a-z])vuln([^a-z]|$)|\btrap\b|false[_ -]?positive|"
    r"\b(bad|good|fixed|exploit|payload|safe)\b|insegur[oa]|vulnerable|trampa|"
    r"PV-(?:N[1-4]|TRAP)-\d{3}|CWE-\d+|OWASP\s+A\d{2})"
)
QUALITY_MODIFIER = re.compile(r"(?i)(^|[_-])(raw|direct|legacy|standard|strict|hardened|unchecked|checked|v[12])($|[_-])")
DEFENSIVE_COMMENT = re.compile(r"(?i)(allowlist|validaci[oó]n|autorizaci[oó]n|sanitiz|comprobaci[oó]n).*(estrict|segur|defens)")
SKIP = {"node_modules", "__pycache__", ".git", ".pytest_cache", ".venv", "venv"}
SKIP_FILES = {"package-lock.json", "yarn.lock"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", default=str(Path(__file__).resolve().parents[2] / "target"))
    root = Path(parser.parse_args().target)
    findings: list[str] = []
    route_names: dict[str, list[str]] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.name in SKIP_FILES or any(part in SKIP for part in path.parts):
            continue
        if FORBIDDEN.search(path.name):
            findings.append(f"{path}: forbidden path label")
        try:
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for route in re.findall(r"""['"](/[^'"]+)['"]""", line):
                    base = re.sub(r"/(safe|standard|legacy|v[12])(?=/|$)", "", route, flags=re.I)
                    route_names.setdefault(base, []).append(route)
                if FORBIDDEN.search(line) or QUALITY_MODIFIER.search(line) or (line.lstrip().startswith(("#", "//", "/*", "*")) and DEFENSIVE_COMMENT.search(line)):
                    findings.append(f"{path.relative_to(root)}:{number}: {line.strip()[:120]}")
        except OSError as exc:
            findings.append(f"{path}: {exc}")
    for base, routes in route_names.items():
        if len(set(routes)) > 1:
            findings.append(f"route symmetry: {base}: {sorted(set(routes))}")
    if findings:
        print("\n".join(findings))
        return 1
    print("0 violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
