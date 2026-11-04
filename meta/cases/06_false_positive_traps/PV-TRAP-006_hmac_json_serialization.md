---
id: PV-TRAP-006
title: "Trampa de Falso Positivo: Deserialización Segura con HMAC-SHA256 y JSON Exclusivo"
description: "Restaura sesión verificando previamente firma HMAC-SHA256 con compare_digest y parseando con json.loads en vez de pickle."
kind: trap
difficulty_level: 4
hops: 2
split: test
cwe: CWE-502
owasp: "A08:2021 - Software and Data Integrity Failures"
language: python
file: app_python/safe_handlers.py
line_start: 101
line_end: 126
expected_static_detectors:
  - semgrep
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/session/restore"
  expected_vuln_indicator: "Firma HMAC inválida"
---

# PV-TRAP-006: Trampa de Falso Positivo — Deserialización Segura con Firma Criptográfica HMAC

## Descripción Técnica
La función `safe_session_restore` en `app_python/safe_handlers.py` se encarga de reanudar el estado de sesión a partir de un payload codificado. Herramientas SAST configuradas para detectar patrones de deserialización o endpoints de sesión pueden reportar un falso positivo asociándolo con CWE-502. Sin embargo:
1. No se utiliza `pickle`, `yaml.unsafe_load` ni ninguna librería con ejecución implícita de código.
2. Exige una firma criptográfica `HMAC-SHA256` calculada sobre los bytes en bruto de la sesión.
3. Comprueba la firma en tiempo constante (`hmac.compare_digest`) para prevenir ataques de canal lateral temporales.
4. Parsea el contenido exclusivamente con `json.loads()`.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `POST /api/safe/session/restore` con `session_data` y `signature` en `safe_handlers.py:129-144`.
2. **Validación HMAC**: `hmac.compare_digest(expected_sig, signature)` en `safe_handlers.py:114-116`.
3. **Parseo Estricto**: `json.loads(raw_bytes.decode('utf-8'))` (línea 119).
4. **Resultado**: Imposible inyectar objetos ejecutables o payloads de RCE. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/safe/session/restore HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "session_data": "eyJ1c2VyIjoidGVzdCJ9",
  "signature": "invalid_signature"
}
```
Respuesta esperada: Código `400 Bad Request` con mensaje `{"error": "Firma HMAC inválida: Firma HMAC inválida o manipulada"}`.

## Remediación Canónica (Fix)
La implementación actual representa la arquitectura segura recomendada para serialización y transferencia de estados de sesión.
