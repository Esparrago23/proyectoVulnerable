---
id: PV-TRAP-018
title: "Trampa de Falso Positivo: Redirección Restringida a Rutas Relativas Locales"
description: "Redirección HTTP en Express que valida que el destino comience con '/' y no contenga esquemas de URL externos."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-601
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/searchController.js
line_start: 74
line_end: 81
anchor: "function redirectSafe"
twin_of: PV-N1-006
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/redirect?url=https://attacker.evil.com"
  expected_vuln_indicator: "Found. Redirecting to /"
---

# PV-TRAP-018: Trampa FP - Redirección Estricta a Rutas Relativas

## Descripción Técnica
Gemelo seguro de `PV-N1-006`. `redirectSafe` en `app_node/controllers/searchController.js` valida que la URL solicitada sea estrictamente un path relativo que comience con `/`, rechazando esquemas absolutos (`http://`, `https://`) y secuencias protocol-relative (`//`), neutralizando el vector de Open Redirect.
