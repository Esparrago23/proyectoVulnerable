---
id: PV-N3-011
title: "Cross-Service Taint: Command Injection en ejecucion de archivo comprimido inter-servicio"
description: "Parametro de archivo recibido inter-servicio ejecutado mediante shell=True en subproceso del sistema."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/app.py
line_start: 897
line_end: 906
anchor: 'subprocess.Popen(cmd, shell=True)'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/settlement/archive"
  expected_vuln_indicator: "archived"
---

# PV-N3-011: Cross-Service Command Injection

## Descripcion Tecnica
Paso de argumentos no sanitizados inter-servicio hacia invocacion de shell en el host.
