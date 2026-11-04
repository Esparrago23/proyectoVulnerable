---
id: PV-TRAP-046
title: "Trampa de Falso Positivo: Ordenación Dinámica Protegida con Lista Blanca de Columnas"
description: "Verificación de columnas contra una lista blanca fija y validación estricta del sentido de ordenación ASC/DESC."
kind: trap
difficulty_level: 3
hops: 2
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/reportController.js
line_start: 26
line_end: 42
anchor: "ALLOWED_COLUMNS.has(department)"
twin_of: PV-N3-008
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/reports/audit?dept=item&sort=ASC"
  expected_vuln_indicator: "department"
---

# PV-TRAP-046: Trampa FP - Ordenación Protegida con Allowlist

## Descripción Técnica
Gemelo seguro de `PV-N3-008`. `queryAuditReportSafe` descarta de forma determinante cualquier valor que no pertenezca al conjunto cerrado `ALLOWED_COLUMNS`, asignando una columna por defecto y un sentido validado.
