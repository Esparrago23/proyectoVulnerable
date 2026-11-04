---
id: PV-N2-010
title: "Bypass de Firma Criptográfica en Verificación de Tokens JWT"
description: "Decodificación de tokens de sesión con verify_signature desactivado permitiendo falsificación de identidad."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-347
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/jwt_service.py
line_start: 14
line_end: 21
anchor: 'options={"verify_signature": False}'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/jwt/decode"
  body: '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzcyI6ImNvcnAifQ."}'
  expected_vuln_indicator: "admin"
---

# PV-N2-010: Bypass de Firma Criptográfica en JWT

## Descripción Técnica
La función `decode_token_legacy` en `app_python/jwt_service.py` omite la verificación criptográfica de la firma digital estableciendo `verify_signature=False`, permitiendo a un atacante alterar los reclamos (claims) del token e impersonar cualquier usuario (`sub=admin`).
