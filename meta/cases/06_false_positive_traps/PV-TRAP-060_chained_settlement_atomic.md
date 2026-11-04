---
id: PV-TRAP-060
title: "Trampa FP: Transferencia encadenada con verificacion atomica previa de ambas cuentas"
description: "Validacion previa de precondiciones en emisor y receptor antes de mutar los saldos en el libro contable."
kind: trap
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/doc_service.py
line_start: 67
line_end: 76
anchor: 'if receiver not in balances:'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/wallet/chain-settle"
  expected_vuln_indicator: "settled"
---

# PV-TRAP-060: Transferencia con Verificacion Previa

## Descripcion Tecnica
Garantia de consistencia ACID mediante verificacion completa antes de la aplicacion de cambios.
