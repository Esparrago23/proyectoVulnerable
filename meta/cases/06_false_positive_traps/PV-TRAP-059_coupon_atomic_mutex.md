---
id: PV-TRAP-059
title: "Trampa FP: Aplicacion de cupon protegida con bloqueo mutex atomico contra carreras"
description: "El cerrojo isCouponLocked serializa las solicitudes concurrentes impidiendo canjes duplicados."
kind: trap
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/orderController.js
line_start: 73
line_end: 93
anchor: 'isCouponLocked = true;'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/orders/coupon/atomic"
  expected_vuln_indicator: "Operacion en curso"
---

# PV-TRAP-059: Exclusion Mutua en Canje de Cupon

## Descripcion Tecnica
Bloqueo atomico en memoria que asegura aislamiento de la operacion critica.
