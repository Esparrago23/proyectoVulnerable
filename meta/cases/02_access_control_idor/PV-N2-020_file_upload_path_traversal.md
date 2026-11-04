---
id: PV-N2-020
title: "Salto de Directorio en Carga de Archivos Adjuntos (Path Traversal in Upload)"
description: "Almacenamiento de archivos adjuntos preservando el nombre provisto por el usuario permitiendo sobrescrituras en el host."
kind: vuln
difficulty_level: 2
hops: 2
split: test
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/uploadController.js
line_start: 14
line_end: 27
anchor: "path.join(UPLOADS_DIR, filename)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/upload/file"
  body: '{"filename": "test.txt", "content": "sample content"}'
  expected_vuln_indicator: "saved"
---

# PV-N2-020: Salto de Directorio en Carga de Archivos

## Descripción Técnica
`handleFileUploadRaw` en `app_node/controllers/uploadController.js` concatena `filename` directamente con `UPLOADS_DIR`, permitiendo que nombres como `../../etc/cron.d/pwn` escapen del directorio designado.
