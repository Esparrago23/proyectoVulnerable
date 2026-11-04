---
id: PV-N2-022
title: "Modificacion de estado de orden sin verificacion de pertenencia de usuario (IDOR)"
description: "El controlador actualiza el estado de pedidos basandose unicamente en el ID recibido sin validar propietario."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/orderController.js
line_start: 30
line_end: 39
anchor: 'orderStore[orderId].status = newStatus;'
expected_static_detectors:
  - njsscan
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/orders/102/status"
  expected_vuln_indicator: "completed"
---

# PV-N2-022: IDOR en Estado de Orden

## Descripcion Tecnica
Falta de verificacion de pertenencia en modificacion de entidad de negocio.
