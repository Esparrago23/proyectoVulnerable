---
id: PV-N4-005
title: "Inyección SQL Multi-Salto Profunda (Nivel 4) en Flujo de Facturación Corporativa"
description: "Flujo inter-archivo de 4 saltos (Controlador -> Pipeline -> Adaptador -> Repositorio) con interpolación de variables en consulta SQLite."
kind: vuln
difficulty_level: 4
hops: 4
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/billingService.js
line_start: 28
line_end: 39
anchor: "SELECT * FROM orders WHERE user_id = '${billingAccount}'"
expected_static_detectors:
  - codeql
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/billing/charge"
  body: '{"account": "admin'' OR ''1''=''1", "ref": "item", "amount": 100}'
  expected_vuln_indicator: "recorded"
---

# PV-N4-005: SQLi Multi-Salto Profunda (Nivel 4)

## Descripción Técnica
`recordDirectTransaction` en `app_node/services/billingService.js` recibe el parámetro `billingAccount` propagado a través de cuatro capas de abstracción consecutivas y lo interpola en una sentencia SQL sin sanitización ni parametrización.
