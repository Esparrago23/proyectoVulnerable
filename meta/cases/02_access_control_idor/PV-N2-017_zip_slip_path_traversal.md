---
id: PV-N2-017
title: "Extracción Arbitraria de Archivos en Descompresión de Archivos ZIP (Zip Slip)"
description: "Invocación de extractall sin validar si las rutas de los archivos empaquetados escapan con secuencias '../'."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/archive_extractor.py
line_start: 14
line_end: 23
anchor: "archive.extractall(output_directory)"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/archive/extract"
  body: '{"zip_path": "/nonexistent.zip", "dest_dir": "/tmp"}'
  expected_vuln_indicator: "Fallo"
---

# PV-N2-017: Zip Slip en Extracción de Paquetes

## Descripción Técnica
`extract_bundle_direct` en `app_python/archive_extractor.py` delega en `archive.extractall()`, la cual no garantiza en versiones vulnerables o entornos personalizados que las rutas relativas ascendentes (`../../etc/cron.d/job`) no sobrescriban archivos del sistema.
