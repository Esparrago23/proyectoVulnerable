#!/usr/bin/env python3
"""Compilador y sincronizador de catálogo de vulnerabilidades para proyectoVulnerable v2.

Lee las fichas modulares en meta/cases/**/*.md, valida los rangos de líneas y anchors
contra los archivos en target/, compila meta/ground_truth.json, meta/VULNERABILITIES.md,
calcula meta/manifest.json y sincroniza el entorno hacia los fixtures de benchmarks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = REPO_ROOT / "target"
META_DIR = REPO_ROOT / "meta"
CASES_DIR = META_DIR / "cases"
GT_PATH = META_DIR / "ground_truth.json"
VULN_DOC_PATH = META_DIR / "VULNERABILITIES.md"
README_DOC_PATH = CASES_DIR / "README.md"
MANIFEST_PATH = META_DIR / "manifest.json"

FIXTURE_TARGET_DEST = Path(r"C:\Users\Esparrago\Downloads\demo\backend\benchmarks\fixtures\proyecto_vulnerable")
FIXTURE_META_DEST = Path(r"C:\Users\Esparrago\Downloads\demo\backend\benchmarks\fixtures\proyecto_vulnerable_meta")

ORDERED_CATEGORIES = [
    ("01_injection", "A03 - Inyecciones (SQLi, Command Injection, XSS)"),
    ("02_access_control_idor", "A01 - Control de Acceso Roto, IDOR y Manipulación Lógica"),
    ("03_auth_and_secrets", "A07/A02 - Autenticación, Secretos y Fallas Criptográficas"),
    ("04_ssrf_and_deserialization", "A10/A08 - SSRF y Deserialización Insegura"),
    ("05_misconfiguration", "A05 - Mala Configuración de Seguridad y CORS"),
    ("06_false_positive_traps", "Trampas de Falso Positivo (FP Traps)"),
]


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Parsea el frontmatter YAML y el cuerpo markdown."""
    pattern = re.compile(r"^---\r?\n(.*?)\r?\n---\r?\n(.*)$", re.DOTALL)
    match = pattern.match(content)
    if not match:
        raise ValueError("El archivo no contiene un bloque frontmatter delimitado por '---'.")

    yaml_block = match.group(1)
    body = match.group(2).strip()

    if yaml is not None:
        data = yaml.safe_load(yaml_block) or {}
    else:
        data = {}
        for line in yaml_block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip().strip('"').strip("'")

    return data, body


def load_catalog(cases_dir: Path) -> List[Dict[str, Any]]:
    """Carga todas las fichas .md en orden determinista."""
    items: List[Dict[str, Any]] = []

    for cat_folder, _cat_title in ORDERED_CATEGORIES:
        folder_path = cases_dir / cat_folder
        if not folder_path.exists():
            continue

        md_files = sorted(folder_path.glob("*.md"))
        for md_file in md_files:
            if md_file.name == "README.md":
                continue
            text = md_file.read_text(encoding="utf-8")
            metadata, body = parse_frontmatter(text)
            metadata["_card_path"] = md_file.relative_to(REPO_ROOT).as_posix()
            metadata["_body"] = body
            items.append(metadata)

    return items


def validate_catalog(items: List[Dict[str, Any]], target_dir: Path) -> List[str]:
    """Valida integridad de datos, rangos de líneas y anchors contra archivos reales en target/."""
    errors: List[str] = []
    seen_ids = set()

    for item in items:
        case_id = item.get("id")
        if not case_id:
            errors.append(f"Ficha sin 'id' obligatorio en: {item.get('_card_path')}")
            continue

        if case_id in seen_ids:
            errors.append(f"ID duplicado detectado: {case_id}")
        seen_ids.add(case_id)

        target_rel = item.get("file")
        if not target_rel:
            errors.append(f"[{case_id}] Campo 'file' ausente")
            continue

        target_path = target_dir / target_rel
        if not target_path.exists():
            errors.append(f"[{case_id}] Archivo referenciado no existe en target/: {target_rel}")
            continue

        try:
            line_start = int(item.get("line_start", 0))
            line_end = int(item.get("line_end", 0))
        except (ValueError, TypeError):
            errors.append(f"[{case_id}] line_start o line_end no son enteros válidos")
            continue

        if line_start <= 0 or line_end < line_start:
            errors.append(f"[{case_id}] Rango de líneas inválido: {line_start}-{line_end}")
            continue

        file_content = target_path.read_text(encoding="utf-8", errors="replace")
        file_lines = file_content.splitlines()
        if line_end > len(file_lines):
            errors.append(
                f"[{case_id}] line_end ({line_end}) supera el total de líneas ({len(file_lines)}) en {target_rel}"
            )
            continue

        # Validar anchor si está definido en la ficha
        anchor = item.get("anchor")
        if anchor:
            snippet = "\n".join(file_lines[max(0, line_start - 3) : min(len(file_lines), line_end + 3)])
            if str(anchor) not in snippet:
                errors.append(
                    f"[{case_id}] Anchor '{anchor}' no encontrado en el rango [{line_start}-{line_end}] de {target_rel}"
                )

    return errors


def build_ground_truth(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Construye la lista serializable de ground truth canónico."""
    truth_list = []
    for item in items:
        entry = {
            "id": item["id"],
            "file": item["file"],
            "line_start": int(item["line_start"]),
            "line_end": int(item["line_end"]),
            "cwe": item["cwe"],
            "owasp": item["owasp"],
            "kind": item["kind"],
            "difficulty_level": int(item["difficulty_level"]),
            "hops": int(item.get("hops", 1)),
            "split": item.get("split", "dev"),
            "language": item.get("language", "generic"),
            "title": item["title"],
            "description": item["description"],
            "expected_static_detectors": item.get("expected_static_detectors", []),
            "expected_agent_detectors": item.get("expected_agent_detectors", []),
        }
        if "anchor" in item:
            entry["anchor"] = item["anchor"]
        if "twin_of" in item:
            entry["twin_of"] = item["twin_of"]
        if "files" in item:
            entry["files"] = item["files"]
        if "dynamic_probe" in item:
            entry["dynamic_probe"] = item["dynamic_probe"]
        truth_list.append(entry)
    return truth_list


def build_vulnerabilities_markdown(items: List[Dict[str, Any]]) -> str:
    """Genera VULNERABILITIES.md consolidando todas las fichas en un documento canónico."""
    lines: List[str] = [
        "# Catálogo Oficial de Vulnerabilidades: Proyecto Vulnerable Escalonado",
        "",
        "Este documento constituye la fuente de verdad técnica y documental (Ground Truth) del repositorio `proyectoVulnerable`.",
        "Detalla cada debilidad de seguridad implementada deliberadamente y cada trampa de falso positivo,",
        "clasificadas en **4 niveles de dificultad**, su correspondencia con el **OWASP Top 10**, su **CWE canónico**,",
        "prueba de concepto dinámica (PoC) y remediación recomendada.",
        "",
        "---",
        "",
        f"## Matriz Resumen de Casos ({len(items)} Casos)",
        "",
        "| ID | Nivel | OWASP | CWE | Archivo | Líneas | Tipo | Título |",
        "| :--- | :---: | :--- | :--- | :--- | :---: | :---: | :--- |",
    ]

    for item in items:
        lvl = f"**L{item['difficulty_level']}**"
        kind_str = "**Trampa FP**" if item["kind"] in ("trap", "safe_region") else "Vulnerabilidad"
        lines.append(
            f"| `{item['id']}` | {lvl} | {item['owasp']} | `{item['cwe']}` | "
            f"`{item['file']}` | {item['line_start']}-{item['line_end']} | {kind_str} | {item['title']} |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Detalle Técnico Exhaustivo por Ficha")
    lines.append("")

    for item in items:
        body = item.get("_body", "").strip()
        lines.append(body)
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def sha256_file(path: Path) -> str:
    """Calcula hash SHA-256 de un archivo."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(target_dir: Path, meta_dir: Path, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Genera manifest.json con inventario criptográfico de target y meta."""
    target_files: Dict[str, str] = {}
    for p in sorted(target_dir.rglob("*")):
        if p.is_file() and not any(ign in p.parts for ign in ("__pycache__", ".git", "node_modules", ".pytest_cache")):
            rel = p.relative_to(target_dir).as_posix()
            target_files[rel] = sha256_file(p)

    meta_files: Dict[str, str] = {}
    for p in sorted(meta_dir.rglob("*")):
        if p.is_file() and p.name != "manifest.json" and not any(ign in p.parts for ign in ("__pycache__", ".git")):
            rel = p.relative_to(meta_dir).as_posix()
            meta_files[rel] = sha256_file(p)

    vulns_count = sum(1 for it in items if it.get("kind") == "vuln")
    traps_count = sum(1 for it in items if it.get("kind") in ("trap", "safe_region"))

    return {
        "schema_version": "2.0.0",
        "dataset_name": "proyecto_vulnerable",
        "total_cases": len(items),
        "vulnerabilities_count": vulns_count,
        "traps_count": traps_count,
        "difficulty_distribution": {
            "L1": sum(1 for it in items if int(it.get("difficulty_level", 1)) == 1),
            "L2": sum(1 for it in items if int(it.get("difficulty_level", 1)) == 2),
            "L3": sum(1 for it in items if int(it.get("difficulty_level", 1)) == 3),
            "L4": sum(1 for it in items if int(it.get("difficulty_level", 1)) == 4),
        },
        "target_files_count": len(target_files),
        "meta_files_count": len(meta_files),
        "target_hashes": target_files,
        "meta_hashes": meta_files,
    }


def sync_fixture(source_dir: Path, target_dir: Path) -> int:
    """Sincroniza una copia completa a la carpeta de fixtures."""
    target_dir.parent.mkdir(parents=True, exist_ok=True)

    def _ignore(directory: str, files: List[str]) -> List[str]:
        ignored = []
        for f in files:
            if f in ("__pycache__", ".git", "node_modules", ".pytest_cache"):
                ignored.append(f)
            elif f.endswith(".pyc"):
                ignored.append(f)
        return ignored

    if target_dir.exists():
        shutil.rmtree(target_dir)

    shutil.copytree(source_dir, target_dir, ignore=_ignore)
    total_copied = sum(1 for p in target_dir.rglob("*") if p.is_file())
    return total_copied


def main() -> int:
    parser = argparse.ArgumentParser(description="Compilador y sincronizador de catálogo de proyectoVulnerable.")
    parser.add_argument("--check", action="store_true", help="Solo verifica sin modificar archivos en disco.")
    args = parser.parse_args()

    print(f"[*] Escaneando catálogo en: {CASES_DIR}")
    items = load_catalog(CASES_DIR)
    print(f"[*] Fichas markdown encontradas: {len(items)}")

    if len(items) < 22:
        print(f"[!] ERROR: Se esperaban al menos 22 fichas, pero se encontraron {len(items)}.")
        return 1

    errors = validate_catalog(items, TARGET_DIR)
    if errors:
        print(f"[!] ERROR: Fallaron las validaciones de catálogo ({len(errors)} errores):")
        for err in errors:
            print(f"    - {err}")
        return 1

    print(f"[+] Validación de integridad y rangos de líneas: EXITOSA ({len(items)}/{len(items)} casos válidos)")

    gt_data = build_ground_truth(items)
    gt_json = json.dumps(gt_data, indent=2, ensure_ascii=False) + "\n"
    vuln_md = build_vulnerabilities_markdown(items)

    if args.check:
        if not GT_PATH.exists() or GT_PATH.read_text(encoding="utf-8") != gt_json:
            print("[!] ERROR: ground_truth.json no está sincronizado con las fichas .md.")
            return 1
        if not VULN_DOC_PATH.exists() or VULN_DOC_PATH.read_text(encoding="utf-8") != vuln_md:
            print("[!] ERROR: VULNERABILITIES.md no está sincronizado con las fichas .md.")
            return 1
        print("[+] Modo --check completado con éxito: Todos los artefactos están sincronizados.")
        return 0

    print(f"[*] Escribiendo {GT_PATH}...")
    GT_PATH.write_text(gt_json, encoding="utf-8")

    print(f"[*] Escribiendo {VULN_DOC_PATH}...")
    VULN_DOC_PATH.write_text(vuln_md, encoding="utf-8")

    # Generar manifest con inventario y hashes
    print(f"[*] Generando {MANIFEST_PATH}...")
    manifest_data = build_manifest(TARGET_DIR, META_DIR, items)
    MANIFEST_PATH.write_text(json.dumps(manifest_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Sincronizar target hacia fixture de Docker
    print(f"[*] Sincronizando target/ hacia fixture Docker: {FIXTURE_TARGET_DEST}...")
    try:
        copied_target = sync_fixture(TARGET_DIR, FIXTURE_TARGET_DEST)
        print(f"[+] Sincronización de fixture target exitosa ({copied_target} archivos copiados).")
    except Exception as exc:
        print(f"[!] Advertencia al sincronizar fixture target: {exc}")
        return 1

    # Sincronizar meta hacia fixture de metadatos
    print(f"[*] Sincronizando meta/ hacia fixture metadatos: {FIXTURE_META_DEST}...")
    try:
        copied_meta = sync_fixture(META_DIR, FIXTURE_META_DEST)
        print(f"[+] Sincronización de fixture meta exitosa ({copied_meta} archivos copiados).")
    except Exception as exc:
        print(f"[!] Advertencia al sincronizar fixture meta: {exc}")
        return 1

    print("[+] Catálogo compilado, manifest generado y fixtures sincronizados al 100%.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
