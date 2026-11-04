---
id: PV-N2-018
title: "Uso de Modo Criptográfico Inseguro (AES-ECB) sin Vector de Inicialización"
description: "Cifrado de datos sensibles con AES en modo ECB donde bloques idénticos producen patrones repetitivos."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-327
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 14
line_end: 28
anchor: "modes.ECB()"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/crypto/encrypt"
  body: '{"text": "confidential_text"}'
  expected_vuln_indicator: "ECB"
---

# PV-N2-018: Cifrado Débil en Modo ECB

## Descripción Técnica
`encrypt_sensitive_data_ecb` en `app_python/crypto_util.py` emplea `modes.ECB()`, el cual no utiliza vector de inicialización y preserva patrones del texto original comprometiendo la confidencialidad.
