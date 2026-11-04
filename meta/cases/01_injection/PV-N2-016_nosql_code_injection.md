---
id: PV-N2-016
title: "Inyección de Expresiones de Código en Filtrado de Colecciones (NoSQL Injection)"
description: "Construcción dinámica de funciones de filtro JavaScript a partir de parámetros no saneados del usuario."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-943
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/catalogController.js
line_start: 14
line_end: 25
anchor: "new Function('item'"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/catalog/search?filter=true"
  expected_vuln_indicator: "Servidor Rack 1U"
---

# PV-N2-016: Inyección NoSQL en Expresión de Catálogo

## Descripción Técnica
`queryCatalogNoSql` en `app_node/controllers/catalogController.js` concatena el parámetro `filter` directamente en el constructor `new Function(...)`, permitiendo a un atacante ejecutar código JavaScript arbitrario durante el filtrado.
