---
id: PV-TRAP-026
title: "Trampa de Falso Positivo: Generación Criptográfica Segura de Tokens de Recuperación"
description: "Uso del módulo secrets para emitir tokens CSPRNG de 256 bits inmunes a adivinación temporal."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-330
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/auth_service.py
line_start: 59
line_end: 63
anchor: "secrets.token_urlsafe(32)"
twin_of: PV-N2-012
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/auth/reset-token"
  body: '{"username": "admin"}'
  expected_vuln_indicator: "reset_token"
---

# PV-TRAP-026: Trampa FP - Token Criptográfico Seguro

## Descripción Técnica
Gemelo seguro de `PV-N2-012`. `generate_reset_token_secure` en `app_python/auth_service.py` invoca `secrets.token_urlsafe(32)` proveyendo 256 bits de entropía real extraída del generador criptográfico del sistema operativo (`/dev/urandom`).
