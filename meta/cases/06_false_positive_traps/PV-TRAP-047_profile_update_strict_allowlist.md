---
id: PV-TRAP-047
title: "Trampa de Falso Positivo: Actualización de Perfil con Lista Blanca Estricta de Campos DTO"
description: "Filtrado explícito de campos permitidos en la modificación de perfil impidiendo la alteración de roles o permisos."
kind: trap
difficulty_level: 3
hops: 2
split: test
cwe: CWE-915
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/profile_service.py
line_start: 27
line_end: 38
anchor: 'ALLOWED_USER_FIELDS = {"display_name", "bio", "phone"}'
twin_of: PV-N3-009
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/profile/update"
  body: '{"username": "alice", "updates": {"display_name": "Alice Corp"}}'
  expected_vuln_indicator: "updated"
---

# PV-TRAP-047: Trampa FP - Perfil con Allowlist de Atributos

## Descripción Técnica
Gemelo seguro de `PV-N3-009`. `update_user_profile_filtered` filtra de forma estricta los campos contra `ALLOWED_USER_FIELDS`, descartando silenciosamente cualquier atributo privilegiado.
