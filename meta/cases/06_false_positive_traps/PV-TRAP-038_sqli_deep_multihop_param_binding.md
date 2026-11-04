---
id: PV-TRAP-038
title: "Trampa de Falso Positivo: Flujo de Facturación Multi-Salto con Sentencia Parametrizada"
description: "Propagación de entrada a través de 4 capas finalizando en una consulta con vinculación estricta de parámetros en la capa DAO."
kind: trap
difficulty_level: 4
hops: 4
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/billingService.js
line_start: 41
line_end: 51
anchor: "SELECT * FROM orders WHERE user_id = ? AND item = ?"
twin_of: PV-N4-005
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/billing/charge"
  body: '{"account": "admin'' OR ''1''=''1", "ref": "item", "amount": 100}'
  expected_vuln_indicator: "recorded"
---

# PV-TRAP-038: Trampa FP - Facturación Multi-Salto con Parámetros Ligados

## Descripción Técnica
Gemelo seguro de `PV-N4-005`. A pesar de que los parámetros cruzan cuatro niveles de componentes modulares, `recordSecureTransaction` utiliza `dbClient.db.all(sql, [billingAccount, invoiceRef], ...)` neutralizando de forma categórica la inyección.
