---
id: PV-N4-004
title: "Manipulación Lógica de Saldo mediante Transferencia de Montos Negativos"
description: "Endpoint de transferencia que verifica balance >= amount pero no amount > 0, permitiendo incrementar saldo propio transfiriendo montos negativos."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-862
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/app.py
line_start: 201
line_end: 216
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/wallet/transfer"
  expected_vuln_indicator: "transfer_completed"
---

# PV-N4-004: Falla Lógica de Negocio en Transferencia de Saldo

## Descripción Técnica
En `app_python/app.py` y `app_python/tasks/worker.py`, el endpoint `POST /api/wallet/transfer` permite transferir fondos entre usuarios. La validación comprueba si el usuario cuenta con saldo suficiente mediante `current_balance < amount`. Sin embargo, el sistema omite validar que `amount > 0`. Si un atacante envía un valor negativo (ej. `-500`), la condición de suficiencia se cumple (`balance < -500` es falso), y la operación aritmética `balance -= (-500)` incrementa artificialmente el saldo del remitente debitándolo de la víctima.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `POST /api/wallet/transfer` con JSON conteniendo `source`, `target` y `amount` en `app_python/app.py:201-216`.
2. **Salto a Worker**: Delegación a `worker.process_wallet_transfer` en `app_python/tasks/worker.py:47-70`.
3. **Falla Lógica**: `current_balance < amount` pasa con montos negativos.
4. **Impacto**: Manipulación fraudulenta de saldo e inconsistencia financiera arbitraria.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/wallet/transfer HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "source": "alice",
  "target": "bob",
  "amount": -500.0
}
```
Respuesta esperada: Confirmación con `"status": "transfer_completed"` e incremento del saldo de `alice`.

## Remediación Canónica (Fix)
Validar estrictamente que el monto a transferir sea un número positivo mayor que cero y respetar transaccionalidad:
```python
if amount <= 0:
    raise ValueError("El monto de la transferencia debe ser estrictamente positivo")
```
