---
id: PV-N1-015
title: "Exposicion de variables de entorno del sistema en endpoint de depuracion"
description: "El endpoint /api/debug/env retorna todas las variables de entorno incluyendo claves secretas."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-200
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/app.py
line_start: 870
line_end: 874
anchor: 'return jsonify(dict(os.environ)), 200'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - controls_auditor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/debug/env"
  expected_vuln_indicator: "PATH"
---

# PV-N1-015: Exposicion de Variables de Entorno

## Descripcion Tecnica
Fuga de configuracion sensible a traves de endpoint sin autenticacion.
