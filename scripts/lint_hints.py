#!/usr/bin/env python3
"""Linter anti-fugas y verificador de neutralidad para target/ de proyectoVulnerable.

Asegura que el código ejecutable y las plantillas entregadas a los escáneres y agentes
no contengan pistas, respuestas sopladas, comentarios delatadores ni metadatos de ground truth.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = REPO_ROOT / "target"

# Extensiones de código y configuración a auditar
SCANNED_EXTENSIONS = {
    ".py",
    ".js",
    ".json",
    ".html",
    ".md",
    ".env",
    ".backup",
    ".txt",
    ".yml",
    ".yaml",
    ".tf",
}

# Archivos ignorados por ser dependencias o caches
IGNORED_DIRS = {
    "node_modules",
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".venv",
    "venv",
}

# Patrones prohibidos que soplan la clasificación a los modelos LLM o escáneres
FORBIDDEN_PATTERNS = [
    (re.compile(r"(?i)\bvulnerab\w*"), "Palabra clave 'vulnerab*'"),
    (re.compile(r"(?i)\bvuln\b"), "Abreviatura 'vuln'"),
    (re.compile(r"(?i)\bfp[_-]?trap\b"), "Indicador 'fp_trap'"),
    (re.compile(r"(?i)\btrampa\b"), "Término 'trampa'"),
    (re.compile(r"(?i)\bnivel\s*[1-4]\b"), "Clasificación de dificultad 'nivel [1-4]'"),
    (re.compile(r"\bPV-(?:N[1-4]|TRAP)-\d{3}\b"), "ID canónico de caso 'PV-...'"),
    (re.compile(r"(?i)\bfalse[_\s-]?positive\b"), "Indicador 'false positive'"),
    (re.compile(r"(?i)\bcwe-\d+\b"), "Referencia a CWE en código/comentarios"),
    (re.compile(r"(?i)\bowasp\s+a\d{2}\b"), "Referencia a categoría OWASP"),
]


def check_file(path: Path) -> List[Tuple[int, str, str]]:
    """Revisa un archivo línea por línea en busca de patrones prohibidos."""
    findings: List[Tuple[int, str, str]] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        findings.append((0, f"Error al leer archivo: {exc}", "IO_ERROR"))
        return findings

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern, desc in FORBIDDEN_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append((line_num, line.strip(), desc))
                break

    return findings


def lint_target_tree(target_dir: Path) -> Tuple[int, List[str]]:
    """Recorre target_dir y retorna (total_errores, lista_mensajes)."""
    if not target_dir.exists():
        return 1, [f"El directorio target no existe en: {target_dir}"]

    errors: List[str] = []
    checked_files = 0

    for p in sorted(target_dir.rglob("*")):
        if any(ign in p.parts for ign in IGNORED_DIRS):
            continue

        # Validar nombres de directorios y archivos
        if "ground_truth" in p.name.lower():
            errors.append(f"{p}: Nombre de archivo contiene 'ground_truth'")
        if "vulnerabilit" in p.name.lower():
            errors.append(f"{p}: Nombre de ruta contiene 'vulnerabilit'")

        if p.is_file() and p.suffix.lower() in SCANNED_EXTENSIONS:
            checked_files += 1
            file_findings = check_file(p)
            for lnum, line_text, desc in file_findings:
                rel = p.relative_to(target_dir).as_posix()
                errors.append(f"{rel}:{lnum} [{desc}] -> {line_text[:90]}")

    return checked_files, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Linter anti-fugas para target/")
    parser.add_argument("--dir", default=str(TARGET_DIR), help="Directorio target a auditar")
    args = parser.parse_args()

    t_dir = Path(args.dir)
    print(f"[*] Auditando neutralidad de código en: {t_dir}")
    checked, errors = lint_target_tree(t_dir)
    print(f"[*] Archivos examinados: {checked}")

    if errors:
        print(f"[!] SE DETECTARON {len(errors)} PISTAS DELATADORAS EN EL CÓDIGO:")
        for err in errors[:50]:
            print(f"    - {err}")
        if len(errors) > 50:
            print(f"    ... y {len(errors) - 50} hallazgos adicionales.")
        return 1

    print("[+] LINT EXITOSO: 0 pistas delatadoras encontradas en target/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
