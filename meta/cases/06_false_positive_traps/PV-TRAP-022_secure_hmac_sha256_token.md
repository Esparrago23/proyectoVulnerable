---
id: PV-TRAP-022
title: "Trampa de Falso Positivo: Generación de Tokens de Sesión con HMAC-SHA256"
description: "Emisión de tokens criptográficos robustos utilizando código de autenticación de mensajes basado en hash SHA-256."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-328
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/token_service.py
line_start: 24
line_end: 28
anchor: "def generate_secure_token"
twin_of: PV-N1-007
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/tokens/generate"
  body: '{"user_id": "alice"}'
  expected_vuln_indicator: '"algorithm": "HMAC-SHA256"'
---

# PV-TRAP-022: Trampa FP - Tokens Criptográficos con HMAC-SHA256

## Descripción Técnica
Gemelo seguro de `PV-N1-007`. `generate_secure_token` en `app_python/token_service.py` utiliza HMAC con la función criptográfica segura SHA-256 y clave secreta, reemplazando el uso de hashes MD5 obsoletos y vulnerables a colisiones.
