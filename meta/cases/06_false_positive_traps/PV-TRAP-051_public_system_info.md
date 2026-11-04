---
id: PV-TRAP-051
title: "Trampa FP: Endpoint de estado que retorna unicamente version publica sin secretos"
description: "El endpoint /api/system/public-info responde exclusivamente version semantica publica aprobada."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-200
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/app.py
line_start: 876
line_end: 880
anchor: '"version": "2.4.0"'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/system/public-info"
  expected_vuln_indicator: "2.4.0"
---

# PV-TRAP-051: Metadatos Publicos de Version

## Descripcion Tecnica
Exposicion intencional y segura de numero de compilacion para comprobaciones de salud.
