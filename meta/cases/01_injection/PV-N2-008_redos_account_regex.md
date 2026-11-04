---
id: PV-N2-008
title: "Regular Expression Denial of Service (ReDoS) por cuantificadores anidados"
description: "Validación de identificadores de cuenta mediante expresión regular con complejidad temporal exponencial O(2^n)."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-1333
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/controllers/searchController.js
line_start: 84
line_end: 90
anchor: "/^([a-zA-Z0-9]+)+$/"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/validate/account?name=aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
  expected_vuln_indicator: "valid"
---

# PV-N2-008: ReDoS por Cuantificadores Anidados

## Descripción Técnica
En `app_node/controllers/searchController.js`, `validateAccountName` emplea la expresión regular `/^([a-zA-Z0-9]+)+$/`. Los cuantificadores anidados `(+)+` generan retroceso catastrófico (catastrophic backtracking) cuando una cadena larga casi coincide pero falla al final, bloqueando el bucle de eventos de Node.js.
