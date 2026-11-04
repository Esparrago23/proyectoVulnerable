---
id: PV-N1-007
title: "Uso de algoritmo criptográfico débil (MD5) para generación de tokens de API"
description: "Generación de firmas de autenticación mediante MD5, vulnerable a ataques de colisión y preimagen."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-327
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/token_service.py
line_start: 14
line_end: 21
anchor: "hashlib.md5(payload.encode("
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/token/legacy"
  expected_vuln_indicator: "MD5"
---

# PV-N1-007: Algoritmo Hash Roto (MD5) en Generación de Tokens

## Descripción Técnica
La función `generate_legacy_token` en `app_python/token_service.py` utiliza `hashlib.md5` para calcular la firma de sesión de tokens de API. MD5 está formalmente desaconsejado para fines criptográficos por vulnerabilidades conocidas de colisión.
