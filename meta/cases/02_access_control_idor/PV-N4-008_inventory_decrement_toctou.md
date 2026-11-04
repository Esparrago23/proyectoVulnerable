---
id: PV-N4-008
title: "Condición de Carrera Tiempo-de-Comprobación a Tiempo-de-Uso (TOCTOU) en Inventario"
description: "Verificación separada de disponibilidad y decremento de existencias que posibilita sobreventas bajo concurrencia."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-367
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/inventory_service.py
line_start: 21
line_end: 37
anchor: "time.sleep(0.01)"
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/inventory/decrement"
  body: '{"item_id": "prod_laptop", "count": 1}'
  expected_vuln_indicator: "Reserva de existencias completada"
---

# PV-N4-008: Carrera TOCTOU en Control de Existencias

## Descripción Técnica
`decrement_inventory_check` en `app_python/tasks/inventory_service.py` introduce una ventana temporal entre la comprobación del stock y la asignación final, provocando inconsistencias en el inventario ante accesos simultáneos.
