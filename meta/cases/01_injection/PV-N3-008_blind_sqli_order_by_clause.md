---
id: PV-N3-008
title: "Inyección SQL Ciega en Cláusula ORDER BY de Reportes Analíticos"
description: "Interpolación directa de identificadores de columna en la cláusula ORDER BY donde los parámetros ligados no aplican."
kind: vuln
difficulty_level: 3
hops: 2
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/reportController.js
line_start: 11
line_end: 24
anchor: "ORDER BY ${department} ${sortOrder}"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/reports/audit?dept=item&sort=ASC"
  expected_vuln_indicator: "department"
---

# PV-N3-008: Inyección SQL en ORDER BY

## Descripción Técnica
`queryAuditReportRaw` en `app_node/controllers/reportController.js` concatena los parámetros `department` y `sort` en la cláusula de ordenación, permitiendo inferencia basada en tiempo o subconsultas booleanas.
