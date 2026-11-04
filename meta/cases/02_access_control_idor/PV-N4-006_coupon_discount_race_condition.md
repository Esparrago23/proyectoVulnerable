---
id: PV-N4-006
title: "Condición de Carrera en Aplicación de Cupones de Descuento (Business Logic Flaw)"
description: "Comprobación no atómica de canje previo que permite la reutilización concurrente de cupones de un solo uso."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 21
line_end: 39
anchor: "REDEEMED_COUPONS.add(redemption_key)"
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/coupon/apply"
  body: '{"user": "alice", "coupon": "WELCOME20", "amount": 100.0}'
  expected_vuln_indicator: "Descuento de 20%"
---

# PV-N4-006: Falla Lógica de Negocio en Canje de Cupones

## Descripción Técnica
`apply_coupon_discount` en `app_python/tasks/coupon_service.py` valida la presencia de `redemption_key` y posteriormente la añade a la colección sin cerrojo de sincronización, permitiendo a peticiones concurrentes aplicar el beneficio múltiples veces.
