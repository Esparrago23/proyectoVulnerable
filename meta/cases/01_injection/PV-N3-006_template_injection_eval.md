---
id: PV-N3-006
title: "Inyección de Plantillas del Servidor (SSTI) en Node.js vía new Function"
description: "Evaluación de cadenas de plantilla controladas por el cliente usando literales de plantilla y new Function."
kind: vuln
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-1336
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/templateController.js
line_start: 9
line_end: 21
anchor: "new Function('username'"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/template/render"
  body: '{"template": "Hola ${username}", "username": "admin"}'
  expected_vuln_indicator: "Hola admin"
---

# PV-N3-006: Inyección de Plantilla en Node.js

## Descripción Técnica
`renderCustomTemplate` en `app_node/controllers/templateController.js` interpola la cadena `templateStr` dentro de un constructor `new Function(...)`, permitiendo a un atacante inyectar expresiones como `${process.mainModule.require('child_process').execSync('id')}` logrando ejecución remota de código.
