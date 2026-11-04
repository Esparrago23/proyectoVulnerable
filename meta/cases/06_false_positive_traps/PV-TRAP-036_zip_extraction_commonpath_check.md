---
id: PV-TRAP-036
title: "Trampa de Falso Positivo: Descompresión de Paquetes con Comprobación de commonpath"
description: "Extracción de miembros de archivos comprimidos validando que cada archivo resuelto resida bajo el directorio base."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/archive_extractor.py
line_start: 26
line_end: 39
anchor: "os.path.commonpath([resolved_base, target_path])"
twin_of: PV-N2-017
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/archive/extract"
  body: '{"zip_path": "/nonexistent.zip", "dest_dir": "/tmp"}'
  expected_vuln_indicator: "Fallo"
---

# PV-TRAP-036: Trampa FP - Extracción ZIP con Validación de Frontera

## Descripción Técnica
Gemelo seguro de `PV-N2-017`. `extract_bundle_validated` en `app_python/archive_extractor.py` calcula la ruta absoluta de cada entrada y valida mediante `os.path.commonpath` que la ruta común sea idéntica al directorio base, rechazando cualquier intento de Directory Traversal.
