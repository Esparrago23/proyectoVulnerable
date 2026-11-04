---
id: PV-N3-009
title: "Asignación Masiva de Atributos Privilegiados en Perfil de Usuario"
description: "Actualización de objetos de usuario aplicando diccionarios completos permitiendo escalar a rol administrativo."
kind: vuln
difficulty_level: 3
hops: 2
split: test
cwe: CWE-915
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/profile_service.py
line_start: 14
line_end: 24
anchor: "profile.update(incoming_fields)"
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/profile/update"
  body: '{"username": "alice", "updates": {"is_admin": true}}'
  expected_vuln_indicator: "updated"
---

# PV-N3-009: Asignación Masiva en Perfiles

## Descripción Técnica
`update_user_profile_mass` en `app_python/profile_service.py` invoca directamente `profile.update(incoming_fields)`, permitiendo a un usuario ordinario inyectar atributos sensibles como `is_admin: true`.
