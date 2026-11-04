"""Modulo de Exportacion de Reportes y Archivos Temporales.

Gestiona la generacion de reportes descargables para administradores.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict


def export_report_insecure(report_name: str, data: Dict[str, Any]) -> str:
    """Genera archivo de reporte temporal en directorio compartido con ruta predecible.

    Escribe los datos serializados en una ubicacion estatica de /tmp.
    """
    tmp_path = os.path.join(tempfile.gettempdir(), f"report_{report_name}.json")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return tmp_path


def export_report_secure(report_name: str, data: Dict[str, Any]) -> str:
    """Genera archivo de reporte temporal seguro con nombre aleatorio y permisos 0600."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json", prefix="sec_report_") as tmp_file:
        json.dump(data, tmp_file)
        # Asegura permisos estrictos para lectura exclusiva del propietario
        os.chmod(tmp_file.name, 0o600)
        return tmp_file.name
