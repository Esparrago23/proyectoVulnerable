---
id: PV-TRAP-008
title: "Trampa de Falso Positivo: Consulta SQL Multi-Salto Parametrizada en Capa DAO"
description: "Capa DAO con consulta parametrizada mediante placeholders (?, [userId]) en lugar de concatenación."
kind: trap
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/models/dbClient.js
line_start: 66
line_end: 73
anchor: "db.all(query, [userId]"
twin_of: PV-N3-001
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/orders/user/1"
  expected_vuln_indicator: "Laptop Pro"
---

# PV-TRAP-008: Trampa FP - Consulta DAO Parametrizada

## Descripción Técnica
Gemelo seguro de `PV-N3-001`. En `queryOrderSafe`, el parámetro `userId` viaja a través de las capas de controlador y servicio, pero al llegar al sink SQL en `dbClient.js`, se utiliza una consulta parametrizada con valores ligados (`db.all(query, [userId], ...)`), imposibilitando la inyección SQL.
