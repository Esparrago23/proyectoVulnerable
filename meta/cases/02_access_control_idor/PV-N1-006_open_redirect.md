---
id: PV-N1-006
title: "Open URL Redirect sin validación de destino en endpoint de navegación"
description: "Redirección abierta a URLs arbitrarias mediante el parámetro url en /api/redirect sin comprobación de dominio."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-601
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/searchController.js
line_start: 67
line_end: 71
anchor: "res.redirect(targetUrl)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/redirect?url=https://evil.com"
  expected_vuln_indicator: "evil.com"
---

# PV-N1-006: Redirección Abierta de URL (Open Redirect)

## Descripción Técnica
La función `redirectExternal` en `app_node/controllers/searchController.js` toma el parámetro de consulta `url` y ejecuta `res.redirect(targetUrl)` directamente. Esto facilita ataques de phishing y robo de credenciales al permitir que enlaces legítimos del dominio redirijan a sitios externos maliciosos.
