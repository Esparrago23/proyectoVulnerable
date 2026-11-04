---
id: PV-N2-009
title: "HTTP Response Splitting / CRLF Injection en cabecera personalizada"
description: "Inyección de caracteres de retorno de carro y salto de línea en la cabecera X-Custom-Tracking."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-113
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/searchController.js
line_start: 105
line_end: 110
anchor: "res.setHeader('X-Custom-Tracking', tag)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/headers/tracking?tag=test"
  expected_vuln_indicator: "header_set"
---

# PV-N2-009: Inyección CRLF en Cabecera de Respuesta

## Descripción Técnica
La función `setCustomHeader` en `app_node/controllers/searchController.js` asigna el parámetro `tag` directamente a `res.setHeader('X-Custom-Tracking', tag)`. Sin sanitizar `\r` (`%0d`) ni `\n` (`%0a`), un atacante puede forzar la inyección de cabeceras arbitrarias (Set-Cookie, etc.) o provocar división de respuesta HTTP.
