---
id: PV-N4-010
title: "Falla de Logica de Negocio: Condicion de carrera TOCTOU en aplicacion concurrente de cupon"
description: "Comprobacion de limite de uso separada temporalmente del incremento permitiendo multiples canjes simultaneos."
kind: vuln
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/orderController.js
line_start: 57
line_end: 71
anchor: 'if (coupon.used >= coupon.limit) {'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/orders/coupon/race"
  expected_vuln_indicator: "discountApplied"
---

# PV-N4-010: Carrera TOCTOU en Cupon

## Descripcion Tecnica
Ventana de tiempo entre check y use sin transaccion serializada ni cerrojo atomico.
