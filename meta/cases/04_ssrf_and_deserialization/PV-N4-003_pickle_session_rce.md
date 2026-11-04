---
id: PV-N4-003
title: "Deserialización insegura con pickle.loads sobre datos de sesión en base64"
description: "Ejecución remota de código arbitrario por deserialización de objetos Python no confiables."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-502
owasp: "A08:2021 - Software and Data Integrity Failures"
language: python
file: app_python/tasks/worker.py
line_start: 29
line_end: 37
expected_static_detectors:
  - bandit
  - semgrep
  - codeql
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/session/restore"
  expected_vuln_indicator: "restored"
---

# PV-N4-003: Deserialización Insegura con Pickle (RCE)

## Descripción Técnica
El endpoint `POST /api/session/restore` en `app_python/app.py` recibe una cadena codificada en base64 en `session_data` y delega su reconstrucción a `worker.restore_user_session_state(raw_bytes)`. La implementación invoca directamente `pickle.loads(raw_bytes)`. En Python, el módulo `pickle` no es seguro contra datos maliciosos, permitiendo instanciar objetos con el método mágico `__reduce__` para ejecutar comandos arbitrarios en el sistema operativo durante la deserialización.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `POST /api/session/restore` con `session_data` en base64 en `app.py:183-198`.
2. **Salto a Worker**: Llamada a `worker.restore_user_session_state(raw_bytes)` en `tasks/worker.py:30-37`.
3. **Sink de Deserialización**: `pickle.loads(raw_bytes)` procesa los opcodes del payload.
4. **Impacto**: Ejecución Remota de Código (RCE) con privilegios del intérprete Python.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/session/restore HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "session_data": "gASVFAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwOcHJpbnQoJ3B3bmVkJymUhZRSlC4="
}
```
Respuesta esperada: Confirmación con `"status": "restored"`.

## Remediación Canónica (Fix)
Sustituir formatos de serialización basados en código ejecutable por formatos puramente declarativos como JSON o Protocol Buffers, firmados criptográficamente:
```python
import json

def restore_user_session_state(raw_bytes: bytes) -> dict:
    return json.loads(raw_bytes.decode("utf-8"))
```
