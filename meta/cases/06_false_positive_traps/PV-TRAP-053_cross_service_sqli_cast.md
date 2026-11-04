---
id: PV-TRAP-053
title: "Trampa FP: Cross-Service evaluacion de liquidacion con casteo estricto a entero en Python"
description: "El parametro recibido inter-servicio se convierte estrictamente con int() antes de cualquier operacion."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: python
file: app_python/safe_handlers.py
line_start: 147
line_end: 151
anchor: 'clean_id = int(order_id)'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/safe/settlement/eval"
  expected_vuln_indicator: "settled"
---

# PV-TRAP-053: Mitigacion de Inyeccion por Casteo

## Descripcion Tecnica
El casteo int() neutraliza cualquier intento de escape de caracteres de sintaxis SQL.
