---
id: PV-N2-021
title: "Configuración CORS Permisiva con Aceptación de Origen 'null'"
description: "Reflejo del encabezado Access-Control-Allow-Origin ante solicitudes con cabecera Origin: null y credenciales habilitadas."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 65
line_end: 73
anchor: "origin === 'null'"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/shared/reports"
  expected_vuln_indicator: "Access-Control-Allow-Origin: null"
---

# PV-N2-021: Origen Null Permitido en CORS

## Descripción Técnica
El middleware en `app_node/server.js` para `/api/shared/reports` comprueba `origin === 'null'` y devuelve cabeceras permitiendo credenciales, habilitando la extracción de datos desde sandboxed iframes o esquemas `data:`.
