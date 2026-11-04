---
id: PV-TRAP-057
title: "Trampa FP: Verificacion de JWT fijando algoritmo asimetrico RS256 y trust store local"
description: "El analizador de tokens rechaza cabeceras simetricas o nulas y exige firma asimetrica contra emisor confiable."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-347
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/jwt_service.py
line_start: 24
line_end: 34
anchor: 'algorithms=["RS256"]'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/jwt/decode"
  expected_vuln_indicator: "claims"
---

# PV-TRAP-057: Verificacion Asimetrica de Token

## Descripcion Tecnica
Fijacion estricta de algoritmo RS256 que mitiga inyeccion de cabeceras JWK o bypass de firma.
