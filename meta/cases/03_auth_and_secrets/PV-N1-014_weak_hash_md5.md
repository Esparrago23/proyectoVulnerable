---
id: PV-N1-014
title: "Uso de algoritmo de hash debil MD5 para verificacion de integridad"
description: "Generacion de hashes MD5 susceptibles a colisiones criptograficas para verificacion de paquetes."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-328
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 47
line_end: 50
anchor: 'hashlib.md5(data.encode("utf-8")).hexdigest()'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/crypto/checksum"
  expected_vuln_indicator: "md5"
---

# PV-N1-014: Uso de MD5 Debil

## Descripcion Tecnica
Generacion de digest MD5 para validar integridad sin resistencia a colisiones.
