---
id: PV-TRAP-042
title: "Trampa de Falso Positivo: Decremento Atómico de Existencias con Exclusión Mutua"
description: "Comprobación y descuento de stock ejecutados como una única instrucción atómica protegida por un cerrojo mutex."
kind: trap
difficulty_level: 4
hops: 2
split: test
cwe: CWE-367
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/inventory_service.py
line_start: 40
line_end: 49
anchor: "with _STOCK_LOCK:"
twin_of: PV-N4-008
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/inventory/decrement"
  body: '{"item_id": "prod_laptop", "count": 1}'
  expected_vuln_indicator: "Reserva de existencias completada de forma atomica"
---

# PV-TRAP-042: Trampa FP - Control Atómico de Inventario

## Descripción Técnica
Gemelo seguro de `PV-N4-008`. `decrement_inventory_atomic` realiza la comprobación y el decremento bajo el bloqueo `with _STOCK_LOCK`, impidiendo cualquier sobreventa por condiciones de carrera.
