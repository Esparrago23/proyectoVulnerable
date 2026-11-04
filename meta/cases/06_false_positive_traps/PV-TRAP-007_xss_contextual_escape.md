---
id: PV-TRAP-007
title: "Trampa de Falso Positivo: XSS Neutralizado mediante Codificación Contextual HTML"
description: "Renderizado HTML seguro tras escapar exhaustivamente caracteres reservados con escapeHtml."
kind: trap
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-79
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/searchController.js
line_start: 51
line_end: 64
anchor: "safeQuery = escapeHtml(query)"
twin_of: PV-N2-001
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
  expected_vuln_indicator: "&lt;script&gt;alert(1)&lt;/script&gt;"
---

# PV-TRAP-007: Trampa FP - Renderizado HTML con Escape Contextual

## Descripción Técnica
A diferencia de `PV-N2-001` (donde se reemplazaba ingenuamente `<script>`), `searchProductsSafe` en `app_node/controllers/searchController.js` procesa la entrada a través de `escapeHtml`, transformando `<`, `>`, `&`, `"` y `'` en entidades HTML seguras. No es vulnerable a XSS reflejado.
