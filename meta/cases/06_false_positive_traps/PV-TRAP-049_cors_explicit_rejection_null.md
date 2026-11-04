---
id: PV-TRAP-049
title: "Trampa de Falso Positivo: Configuración CORS con Rechazo Explícito de Origen 'null'"
description: "Restricción estricta de orígenes autorizados descartando explícitamente el origen 'null' y validando el dominio corporativo."
kind: trap
difficulty_level: 2
hops: 1
split: test
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 76
line_end: 83
anchor: "origin !== 'null'"
twin_of: PV-N2-021
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/reports"
  expected_vuln_indicator: "Access-Control-Allow-Origin"
---

# PV-TRAP-049: Trampa FP - Rechazo de Origen Null en CORS

## Descripción Técnica
Gemelo seguro de `PV-N2-021`. La directiva de CORS para `/api/safe/reports` exige que el origen sea no nulo y coincida exactamente con el portal seguro de la corporación.
