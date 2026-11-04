---
id: PV-TRAP-058
title: "Trampa FP: Conversion de divisas con precision decimal exacta y redondeo bancario"
description: "Uso del modulo Decimal con ROUND_HALF_EVEN que neutraliza cualquier arbitraje de fracciones monetarias."
kind: trap
difficulty_level: 4
hops: 3
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 72
line_end: 80
anchor: 'd_amount = Decimal(str(amount))'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/wallet/convert"
  expected_vuln_indicator: "exact"
---

# PV-TRAP-058: Precision Financiera con Decimal

## Descripcion Tecnica
Redondeo simetrico que preserva la paridad matematica en toda conversion de divisas.
