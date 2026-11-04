---
id: PV-TRAP-050
title: "Trampa FP: Clave de cache no criptografica calculada con funcion segura SHA-256"
description: "Generacion de clave de cache indexada usando algoritmo seguro sin uso criptografico de hash roto."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-328
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 52
line_end: 55
anchor: 'hashlib.sha256(data.encode("utf-8")).hexdigest()'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/cache/key"
  expected_vuln_indicator: "cache"
---

# PV-TRAP-050: Clave de Cache SHA-256

## Descripcion Tecnica
Uso valido de funcion de hash SHA-256 para asignacion de claves de almacenamiento rapido.
