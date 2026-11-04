---
id: PV-N4-009
title: "Falla de Logica de Negocio: Arbitraje de redondeo en conversion de saldo de billetera"
description: "Truncamiento de decimales intermedios en conversiones bidireccionales que permite acumulacion de centavos."
kind: vuln
difficulty_level: 4
hops: 3
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 65
line_end: 70
anchor: 'step1 = int(amount * rate_a * 100) / 100.0'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/wallet/convert"
  expected_vuln_indicator: "arbitrage"
---

# PV-N4-009: Arbitraje de Redondeo de Moneda

## Descripcion Tecnica
Error de precision en logica financiera que genera distorsiones de saldo acumulables.
