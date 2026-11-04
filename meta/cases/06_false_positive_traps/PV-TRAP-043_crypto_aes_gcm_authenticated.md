---
id: PV-TRAP-043
title: "Trampa de Falso Positivo: Cifrado Criptográfico Robusto con AES-256-GCM y Nonce Aleatorio"
description: "Cifrado autenticado AEAD con generación de nonce único de 96 bits por operación y etiqueta de integridad."
kind: trap
difficulty_level: 2
hops: 1
split: test
cwe: CWE-327
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 31
line_end: 42
anchor: "AESGCM(key_bytes[:32])"
twin_of: PV-N2-018
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/crypto/encrypt"
  body: '{"text": "confidential_text"}'
  expected_vuln_indicator: "AES-256-GCM"
---

# PV-TRAP-043: Trampa FP - Cifrado Autenticado con AES-GCM

## Descripción Técnica
Gemelo seguro de `PV-N2-018`. `encrypt_sensitive_data_gcm` emplea `AESGCM` con nonces frescos aleatorios generados mediante `os.urandom(12)`, proveyendo simultáneamente confidencialidad e integridad criptográfica.
