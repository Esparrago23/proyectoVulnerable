"""Servicio de diagnostico y resolucion de conectividad del sistema.

Permite comprobar la alcanzabilidad de nodos de red en la infraestructura.
"""

from __future__ import annotations

import re
import subprocess
from typing import Dict


def run_system_ping_shell(host_target: str) -> Dict[str, str]:
    """Ejecuta comando de diagnostico invocando el shell del sistema operativo.

    Concatena el parametro de destino dentro de la cadena de comando con shell activado.
    """
    # Invocacion del interprete de comandos del SO con concatenacion directa
    cmd = f"ping -c 1 {host_target}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return {"status": "ok", "host": host_target, "output": output.decode("utf-8", errors="replace")}
    except Exception as exc:
        return {"status": "error", "host": host_target, "output": str(exc)}


def run_system_ping_catalog(host_target: str) -> Dict[str, str]:
    """Ejecuta comando de diagnostico pasando lista de argumentos sin invocar shell."""
    # Valida el formato del destino de red
    pattern = re.compile(r"^[a-zA-Z0-9.-]{1,64}$")
    if not pattern.match(host_target):
        raise ValueError("Nombre de host o direccion de destino invalida")

    # Invocacion segura pasando array de argumentos con shell desactivado
    cmd_list = ["ping", "-c", "1", host_target]
    try:
        output = subprocess.check_output(cmd_list, shell=False, stderr=subprocess.STDOUT, timeout=5)
        return {"status": "ok", "host": host_target, "output": output.decode("utf-8", errors="replace")}
    except Exception as exc:
        return {"status": "error", "host": host_target, "output": str(exc)}
