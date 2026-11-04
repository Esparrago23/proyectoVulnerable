---
id: PV-N2-019
title: "Inyección de Comandos del Sistema Operativo con shell=True en Diagnóstico de Red"
description: "Invocación de utilidades del sistema concatenando argumentos en cadenas de texto ejecutadas en el shell."
kind: vuln
difficulty_level: 2
hops: 2
split: test
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/diagnostic_service.py
line_start: 14
line_end: 25
anchor: 'cmd = f"ping -c 1 {host_target}"'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/diagnostic/ping"
  body: '{"host": "127.0.0.1"}'
  expected_vuln_indicator: "status"
---

# PV-N2-019: Inyección de Comandos vía Shell

## Descripción Técnica
`run_system_ping_shell` en `app_python/diagnostic_service.py` construye la cadena de ejecución interpolando directamente `host_target` y llamando a `subprocess.check_output(cmd, shell=True)`, permitiendo la inyección de metacaracteres como `;` o `|`.
