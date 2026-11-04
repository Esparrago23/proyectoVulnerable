---
id: PV-TRAP-040
title: "Trampa de Falso Positivo: Aplicación de Cupones con Bloqueo Atómico de Sincronización"
description: "Operación de verificación y registro de cupones protegida por un cerrojo mutex impidiendo el canje concurrente."
kind: trap
difficulty_level: 4
hops: 2
split: test
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 42
line_end: 59
anchor: "with _LOCK:"
twin_of: PV-N4-006
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/coupon/apply"
  body: '{"user": "alice", "coupon": "WELCOME20", "amount": 100.0}'
  expected_vuln_indicator: "Descuento de 20%"
---

# PV-TRAP-040: Trampa FP - Canje Atómico de Cupones

## Descripción Técnica
Gemelo seguro de `PV-N4-006`. `apply_coupon_discount_safe` ejecuta la consulta y el registro dentro de un bloque `with _LOCK`, garantizando la serialización absoluta y la imposibilidad de canjes concurrentes.
