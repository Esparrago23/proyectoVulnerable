---
id: PV-TRAP-013
title: "Trampa de Falso Positivo: CORS con Lista Blanca de Orígenes Exacta y Anclada"
description: "Middleware de CORS que valida estrictamente la cabecera Origin contra una lista fija de cadenas exactas."
kind: trap
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 54
line_end: 62
anchor: "ALLOWED_EXACT_ORIGINS = ['http://partner.corp.internal'"
twin_of: PV-N2-003
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/partner"
  expected_vuln_indicator: "ok"
---

# PV-TRAP-013: Trampa FP - CORS con Lista Blanca Exacta

## Descripción Técnica
Gemelo seguro de `PV-N2-003`. En `app_node/server.js`, la ruta `/api/safe/partner` valida `ALLOWED_EXACT_ORIGINS.includes(origin)`. Al no emplear expresiones regulares sin anclar ni comodines `*` combinados con credenciales, previene ataques de suplantación de origen.
