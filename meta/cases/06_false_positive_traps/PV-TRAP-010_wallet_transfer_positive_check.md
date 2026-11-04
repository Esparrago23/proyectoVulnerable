---
id: PV-TRAP-010
title: "Trampa de Falso Positivo: Transferencia de Fondos con Precondición de Monto Estrictamente Positivo"
description: "Función de transferencia que valida que el monto sea estrictamente superior a cero (amount > 0)."
kind: trap
difficulty_level: 4
hops: 1
split: dev
cwe: CWE-862
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/tasks/worker.py
line_start: 73
line_end: 95
anchor: "if amount <= 0:"
twin_of: PV-N4-004
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/wallet/transfer"
  body: '{"source": "alice", "target": "bob", "amount": 50.0}'
  expected_vuln_indicator: "transfer_completed"
---

# PV-TRAP-010: Trampa FP - Validación de Precondición Aritmética en Saldo

## Descripción Técnica
Gemelo seguro de `PV-N4-004`. `process_wallet_transfer_safe` en `app_python/tasks/worker.py` verifica explícitamente `if amount <= 0: raise ValueError(...)` antes de debitar o acreditar las cuentas, neutralizando la manipulación lógica de saldos mediante números negativos.
