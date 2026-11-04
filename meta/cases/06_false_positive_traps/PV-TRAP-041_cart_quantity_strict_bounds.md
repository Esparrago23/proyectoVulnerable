---
id: PV-TRAP-041
title: "Trampa de Falso Positivo: Cálculo de Carrito con Validación Estricta de Cantidades Positivas"
description: "Verificación de tipo numérico entero positivo acotado (1 a 100) antes de calcular importes en el pedido."
kind: trap
difficulty_level: 4
hops: 1
split: test
cwe: CWE-1284
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/cartController.js
line_start: 32
line_end: 60
anchor: "isNaN(qty) || qty <= 0 || qty > 100"
twin_of: PV-N4-007
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/cart/total"
  body: '{"items": [{"itemId": "item_1", "quantity": 2}]}'
  expected_vuln_indicator: "totalAmount"
---

# PV-TRAP-041: Trampa FP - Validación Estricta de Cantidades

## Descripción Técnica
Gemelo seguro de `PV-N4-007`. `calculateCartTotalSafe` exige `parseInt(..., 10)` y rechaza de inmediato valores no numéricos, menores o iguales a cero o superiores al límite operativo permitido.
