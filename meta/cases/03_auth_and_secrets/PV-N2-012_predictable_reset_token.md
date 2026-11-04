---
id: PV-N2-012
title: "Generación de Token de Restablecimiento de Contraseña Predecible"
description: "Cálculo de token de recuperación utilizando hash MD5 de usuario y marca temporal unix fácilmente deducible."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-330
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/auth_service.py
line_start: 49
line_end: 57
anchor: 'hashlib.md5(seed.encode("utf-8")).hexdigest()'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/auth/reset-token"
  body: '{"username": "admin"}'
  expected_vuln_indicator: "reset_token"
---

# PV-N2-012: Token de Recuperación Predecible

## Descripción Técnica
`generate_reset_token_legacy` en `app_python/auth_service.py` deriva el token de restablecimiento calculando el hash MD5 de `{username}:{timestamp}`, permitiendo a un atacante adivinar tokens de cualquier cuenta generando hashes en la ventana de segundos del ataque.
