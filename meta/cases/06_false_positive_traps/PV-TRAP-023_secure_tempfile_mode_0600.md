---
id: PV-TRAP-023
title: "Trampa de Falso Positivo: Creación de Archivos Temporales con Nombre Aleatorio y Permisos 0600"
description: "Generación de archivos temporales mediante NamedTemporaryFile con prefijo aleatorio y chmod 0600 restrictivo."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-377
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/tasks/export_task.py
line_start: 25
line_end: 31
anchor: "def export_report_secure"
twin_of: PV-N1-008
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/reports/export"
  body: '{"report_name": "quarterly_audit", "data": {"status": "ok"}}'
  expected_vuln_indicator: "sec_report_"
---

# PV-TRAP-023: Trampa FP - Archivos Temporales Seguros

## Descripción Técnica
Gemelo seguro de `PV-N1-008`. `export_report_secure` en `app_python/tasks/export_task.py` emplea `tempfile.NamedTemporaryFile` con sufijo y prefijo protegidos, aplicando `os.chmod(..., 0o600)` para garantizar que ningún otro usuario local en un sistema multiusuario pueda leer o escribir el archivo temporal.
