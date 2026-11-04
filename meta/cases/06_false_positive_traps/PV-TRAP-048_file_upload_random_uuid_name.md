---
id: PV-TRAP-048
title: "Trampa de Falso Positivo: Almacenamiento de Archivos con Nombre UUID y Extensión Validada"
description: "Asignación de identificador aleatorio único UUID y validación estricta de extensiones autorizadas."
kind: trap
difficulty_level: 2
hops: 2
split: test
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/uploadController.js
line_start: 29
line_end: 50
anchor: "ALLOWED_EXTS.has(ext)"
twin_of: PV-N2-020
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/upload/file"
  body: '{"filename": "test.txt", "content": "sample content"}'
  expected_vuln_indicator: "saved"
---

# PV-TRAP-048: Trampa FP - Carga de Archivos Asegurada

## Descripción Técnica
Gemelo seguro de `PV-N2-020`. `handleFileUploadSafe` descarta el nombre provisto por el usuario, valida la extensión contra un allowlist y almacena el archivo bajo un UUID v4 completamente seguro e impredecible.
