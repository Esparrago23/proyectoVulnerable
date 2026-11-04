---
id: PV-TRAP-012
title: "Trampa de Falso Positivo: Verificación Estricta de TOTP sin Banderas de Bypass"
description: "Función de validación 2FA que rechaza cualquier parámetro u omisión de depuración y exige código criptográfico válido."
kind: trap
difficulty_level: 4
hops: 1
split: dev
cwe: CWE-287
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/auth/mfa_handler.py
line_start: 48
line_end: 54
anchor: "verify_totp_strict"
twin_of: PV-N4-002
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/mfa"
  body: '{"totp_code": "000000"}'
  expected_vuln_indicator: "inválido"
---

# PV-TRAP-012: Trampa FP - Verificación Estricta de 2FA TOTP

## Descripción Técnica
Gemelo seguro de `PV-N4-002`. La función `verify_totp_strict` en `app_python/auth/mfa_handler.py` calcula el código temporal RFC 6238 y no acepta ningún parámetro `bypass_flag` ni cabecera de depuración, garantizando la exigencia estricta del factor de autenticación.
