---
id: PV-N1-013
title: "Generación de Tokens de Seguridad con Generador Pseudoaleatorio Débil (Math.random)"
description: "Uso de Math.random() para emitir tokens anti-CSRF predecibles mediante ataques de inferencia matemática."
kind: vuln
difficulty_level: 1
hops: 1
split: test
cwe: CWE-338
owasp: "A02:2021 - Cryptographic Failures"
language: javascript
file: app_node/services/tokenUtil.js
line_start: 11
line_end: 17
anchor: "Math.random().toString(36)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/token/csrf"
  expected_vuln_indicator: "csrf_"
---

# PV-N1-013: Generador Pseudoaleatorio Débil en Tokens

## Descripción Técnica
`generateCsrfTokenInsecure` en `app_node/services/tokenUtil.js` recurre a `Math.random()`, un generador pseudoaleatorio no criptográfico cuyos estados internos pueden ser calculados por un observador externo.
