---
id: PV-N4-011
title: "Falla de Logica de Negocio: Sobregiro en transferencias encadenadas por debito previo a validacion"
description: "Debito aplicado antes de verificar la cuenta destino, fallando en revertir el saldo ante excepciones."
kind: vuln
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/doc_service.py
line_start: 55
line_end: 65
anchor: 'balances[sender] -= amount'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/wallet/chain-settle"
  expected_vuln_indicator: "overdraw"
---

# PV-N4-011: Sobregiro en Liquidacion Encadenada

## Descripcion Tecnica
Modificacion de estado inconsistente ante fallos parciales sin bloque transaccional.
