---
id: PV-N2-013
title: "Enumeración de Cuentas por Mensajes de Error Diferenciados en Autenticación"
description: "Fuga de información que revela existencia de usuarios mediante mensajes distintos para usuario y contraseña."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-204
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/auth_service.py
line_start: 21
line_end: 34
anchor: '"Usuario no existe en el sistema"'
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/auth/login-enum"
  body: '{"username": "non_existent_user", "password_hash": "dummy"}'
  expected_vuln_indicator: "Usuario no existe"
---

# PV-N2-013: Enumeración de Usuarios en Autenticación

## Descripción Técnica
`authenticate_basic` en `app_python/auth_service.py` responde con `"Usuario no existe en el sistema"` o `"Contraseña incorrecta"`, facilitando a un atacante mapear de forma automatizada las cuentas legítimas registradas en la organización.
