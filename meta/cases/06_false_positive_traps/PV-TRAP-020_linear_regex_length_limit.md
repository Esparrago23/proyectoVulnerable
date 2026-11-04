---
id: PV-TRAP-020
title: "Trampa de Falso Positivo: Validación con Expresión Regular Lineal y Límite de Longitud"
description: "Comprobación de formato de identificador de cuenta con regex O(n) acotada a 32 caracteres evitando ReDoS."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-1333
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/controllers/searchController.js
line_start: 93
line_end: 101
anchor: "function validateAccountNameSafe"
twin_of: PV-N2-008
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/account/validate?name=aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
  expected_vuln_indicator: '{"name":"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!","valid":false}'
---

# PV-TRAP-020: Trampa FP - Regex Lineal con Límite de Tamaño

## Descripción Técnica
Gemelo seguro de `PV-N2-008`. `validateAccountNameSafe` en `app_node/controllers/searchController.js` descarta de inmediato entradas con más de 32 caracteres y aplica una expresión regular con cuantificador lineal simple (`/^[a-zA-Z0-9]{1,32}$/`), previniendo la catástrofe por retroceso (ReDoS).
