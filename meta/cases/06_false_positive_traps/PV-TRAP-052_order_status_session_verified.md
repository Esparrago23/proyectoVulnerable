---
id: PV-TRAP-052
title: "Trampa FP: Modificacion de orden con validacion estricta de sesion y propietario"
description: "Verificacion previa de req.session.userId contra el propietario registrado de la orden antes de mutar."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/orderController.js
line_start: 41
line_end: 55
anchor: 'if (order.ownerId !== currentUser) {'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/orders/101/status"
  expected_vuln_indicator: "success"
---

# PV-TRAP-052: Modificacion Segura de Orden

## Descripcion Tecnica
Control de acceso por atributo validado en middleware antes del cambio de estado.
