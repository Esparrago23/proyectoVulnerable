---
id: PV-TRAP-021
title: "Trampa de Falso Positivo: Encabezado HTTP Personalizado con Saneamiento CRLF"
description: "Asignación de encabezado HTTP eliminando secuencias de retorno de carro y salto de línea."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-113
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/searchController.js
line_start: 112
line_end: 117
anchor: "function setCustomHeaderSafe"
twin_of: PV-N2-009
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/tracking-header?tag=clean%0d%0aInjected-Header:%20pwned"
  expected_vuln_indicator: "cleanInjected-Header: pwned"
---

# PV-TRAP-021: Trampa FP - Encabezado HTTP con Saneamiento de Saltos de Línea

## Descripción Técnica
Gemelo seguro de `PV-N2-009`. `setCustomHeaderSafe` en `app_node/controllers/searchController.js` elimina cualquier ocurrencia de caracteres `\r` y `\n` antes de invocar `res.setHeader`, eliminando la posibilidad de HTTP Response Splitting o inyección de cookies/cabeceras maliciosas.
