---
id: PV-N4-007
title: "Manipulación Lógica de Importe de Carrito por Cantidades Negativas"
description: "Cálculo de importe total de compra multiplicando precios unitarios por cantidades recibidas sin validar signo positivo."
kind: vuln
difficulty_level: 4
hops: 1
split: test
cwe: CWE-1284
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/cartController.js
line_start: 15
line_end: 30
anchor: "unitPrice * qty"
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/cart/total"
  body: '{"items": [{"itemId": "item_1", "quantity": -2}]}'
  expected_vuln_indicator: "totalAmount"
---

# PV-N4-007: Manipulación Lógica de Importe de Carrito

## Descripción Técnica
`calculateCartTotal` en `app_node/controllers/cartController.js` acepta valores arbitrarios de cantidad en los artículos del pedido sin verificar que sean enteros positivos, permitiendo saldos negativos en la compra.
