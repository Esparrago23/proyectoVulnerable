---
id: PV-TRAP-054
title: "Trampa FP: Cross-Service archivo contable con validacion regex de caracteres alfanumericos"
description: "Validacion regex previa con rechazo de cualquier metacaracter antes de empaquetar."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/safe_handlers.py
line_start: 153
line_end: 159
anchor: 'if not re.match(r"^[a-zA-Z0-9_\-\.]+$", archive_name):'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/safe/settlement/archive"
  expected_vuln_indicator: "archived"
---

# PV-TRAP-054: Empaquetado con Regex Estricta

## Descripcion Tecnica
Allowlist estricta de caracteres que impide metacaracteres de ejecucion de comandos.
