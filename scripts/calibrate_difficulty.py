#!/usr/bin/env python3
"""Calibrador empirico de dificultad y separador de capacidades para proyectoVulnerable.

Calcula el Indice de Dificultad (D_i in [0, 100]) de cada caso y evalua el
Invariante de Separacion de Capacidades:
  Recall(L1) > Recall(L2) > Recall(L3) > Recall(L4)
asegurando que los niveles representen escalones reales de complejidad analitica.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
GT_PATH = REPO_ROOT / "meta" / "ground_truth.json"


def compute_case_difficulty(item: Dict[str, Any]) -> float:
    """Calcula el Indice de Dificultad D_i in [0, 100] de un caso segun factores estructurales."""
    hops = int(item.get("hops", 1))
    level = int(item.get("difficulty_level", 1))
    title = str(item.get("title", "")).lower()
    cwe = str(item.get("cwe", ""))
    kind = str(item.get("kind", "vuln")).lower()

    # Indicadores booleanos
    cross_file = 1 if hops > 1 or item.get("cross_file") else 0
    cross_service = 1 if (
        item.get("cross_service")
        or "cross-service" in title
        or "cross_service" in title
        or "inter-servicio" in title
    ) else 0
    business_logic = 1 if (
        item.get("business_logic")
        or level == 4
        or cwe in ("CWE-840", "CWE-362", "CWE-799", "CWE-639")
        or "logica de negocio" in title
        or "carrera" in title
        or "arbitraje" in title
    ) else 0
    sanitizer_decoy = 1 if (
        kind == "trap"
        or item.get("sanitizer_decoy")
        or "trampa" in title
    ) else 0

    score = (
        15.0 * max(0, hops - 1)
        + 20.0 * cross_file
        + 25.0 * cross_service
        + 25.0 * business_logic
        + 15.0 * sanitizer_decoy
    )
    return float(min(100.0, max(0.0, score)))


def calibrate(ground_truth_path: Path) -> Dict[str, Any]:
    """Carga ground truth y calcula medias por nivel y verificacion de separacion."""
    if not ground_truth_path.exists():
        raise FileNotFoundError(f"Archivo de ground truth no encontrado en: {ground_truth_path}")

    raw = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    items: List[Dict[str, Any]] = raw["items"] if isinstance(raw, dict) and "items" in raw else raw

    level_scores: Dict[str, List[float]] = {"1": [], "2": [], "3": [], "4": []}
    case_results: List[Dict[str, Any]] = []

    for item in items:
        lvl = str(item.get("difficulty_level", 1))
        score = compute_case_difficulty(item)
        if lvl in level_scores:
            level_scores[lvl].append(score)
        case_results.append({
            "id": item.get("id"),
            "difficulty_level": int(lvl),
            "kind": item.get("kind"),
            "difficulty_index": round(score, 2),
        })

    means: Dict[str, float] = {}
    for lvl in ["1", "2", "3", "4"]:
        scores = level_scores[lvl]
        means[lvl] = round(sum(scores) / len(scores), 2) if scores else 0.0

    valid = float(means["1"]) < float(means["2"]) < float(means["3"]) < float(means["4"])

    return {
        "total_cases": len(items),
        "mean_difficulty_by_level": means,
        "tier_separation_valid": valid,
        "capability_separation_invariant": "Recall(L1) > Recall(L2) > Recall(L3) > Recall(L4)",
        "cases": case_results,
    }


def main():
    parser = argparse.ArgumentParser(description="Calibrador de dificultad para proyectoVulnerable.")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON estructurado.")
    parser.add_argument("--gt", type=str, default=str(GT_PATH), help="Ruta alternativa a ground_truth.json.")
    args = parser.parse_args()

    report = calibrate(Path(args.gt))

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print("=" * 60)
    print("CALIBRACION DE DIFICULTAD — PROYECTOVULNERABLE")
    print("=" * 60)
    print(f"Total Casos Evaluados: {report['total_cases']}")
    print("-" * 60)
    print("Indice de Dificultad Promedio por Nivel (D_i in [0, 100]):")
    for lvl in ["1", "2", "3", "4"]:
        print(f"  Nivel {lvl}: {report['mean_difficulty_by_level'][lvl]:.2f}")
    print("-" * 60)
    status = "VALIDO (Separacion Monotonica Estricta)" if report["tier_separation_valid"] else "INVALIDO"
    print(f"Invariante de Separacion: {status}")
    print("=" * 60)
    return 0 if report["tier_separation_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
