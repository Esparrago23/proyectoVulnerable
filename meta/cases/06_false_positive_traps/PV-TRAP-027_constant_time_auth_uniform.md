---
id: PV-TRAP-027
title: "Trampa de Falso Positivo: Autenticación con Mensaje Genérico y Comparación en Tiempo Constante"
description: "Mitigación de enumeración y canales laterales mediante respuesta uniforme 'Credenciales inválidas' y compare_digest."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-204
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/auth_service.py
line_start: 36
line_end: 46
anchor: "hmac.compare_digest"
twin_of: PV-N2-013
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/auth/login-enum"
  body: '{"username": "non_existent_user", "password_hash": "dummy"}'
  expected_vuln_indicator: "Credenciales invalidas"
---

# PV-TRAP-027: Trampa FP - Autenticación en Tiempo Constante

## Descripción Técnica
Gemelo seguro de `PV-N2-013`. `authenticate_constant_time` en `app_python/auth_service.py` evalúa siempre la comparación mediante `hmac.compare_digest` (incluso contra un hash ficticio si el usuario no existe) y devuelve un mensaje unívoco indistinguible.
