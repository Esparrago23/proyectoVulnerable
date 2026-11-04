---
id: PV-N1-008
title: "Creación insegura de archivos temporales con nombre estático y permisos predeterminados"
description: "Almacenamiento de reportes confidenciales en /tmp con nombres predecibles susceptibles a sobrescritura y symlink attacks."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-377
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/tasks/export_task.py
line_start: 14
line_end: 22
anchor: "open(tmp_path, \"w\""
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/export/raw"
  body: '{"name": "test_audit", "data": {"status": "ok"}}'
  expected_vuln_indicator: "exported"
---

# PV-N1-008: Creación Insegura de Archivos Temporales

## Descripción Técnica
La función `export_report_insecure` en `app_python/tasks/export_task.py` crea archivos en el directorio temporal compartido (`tempfile.gettempdir()`) usando nombres predecibles como `report_{report_name}.json` con `open(tmp_path, "w")`. Esto permite ataques de enlaces simbólicos (symlink hijacking) o lectura por otros usuarios locales del sistema.
