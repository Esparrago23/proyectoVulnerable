---
id: PV-TRAP-024
title: "Trampa de Falso Positivo: Validación Criptográfica Estricta de JWT con RS256"
description: "Decodificación y verificación de tokens fijando algoritmo asimétrico RS256 y validando emisor y expiración."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-347
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/jwt_service.py
line_start: 24
line_end: 34
anchor: 'algorithms=["RS256"]'
twin_of: PV-N2-010
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/jwt/decode"
  body: '{"token": "invalid.jwt.token"}'
  expected_vuln_indicator: "error"
---

# PV-TRAP-024: Trampa FP - Verificación Estricta de JWT

## Descripción Técnica
Gemelo seguro de `PV-N2-010`. `decode_token_verified` en `app_python/jwt_service.py` valida la firma con la clave pública RSA corporativa, restringe los algoritmos exclusivamente a `RS256` y exige los campos `exp`, `iss` y `sub`.
