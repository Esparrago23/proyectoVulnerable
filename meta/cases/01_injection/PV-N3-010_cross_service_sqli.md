---
id: PV-N3-010
title: "Cross-Service Taint: Inyeccion SQL en liquidacion interna despachada desde Node a Python"
description: "Input recibido en Node despachado a Python /internal/settlement/eval concatenado directamente en SQL."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: python
file: app_python/app.py
line_start: 882
line_end: 895
anchor: "query = f\"SELECT * FROM settlements WHERE id = '{order_id}'\""
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/settlement/eval"
  expected_vuln_indicator: "processed"
---

# PV-N3-010: Cross-Service SQL Injection

## Descripcion Tecnica
Flujo inter-servicio sin sanitizacion cruzada que desemboca en construccion dinamica de SQL.
