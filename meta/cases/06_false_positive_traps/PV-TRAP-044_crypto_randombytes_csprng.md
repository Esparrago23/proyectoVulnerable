---
id: PV-TRAP-044
title: "Trampa de Falso Positivo: Generación Criptográfica de Tokens con crypto.randomBytes"
description: "Emisión de tokens con 256 bits de entropía real provistos por el módulo criptográfico del sistema operativo."
kind: trap
difficulty_level: 1
hops: 1
split: test
cwe: CWE-338
owasp: "A02:2021 - Cryptographic Failures"
language: javascript
file: app_node/services/tokenUtil.js
line_start: 19
line_end: 23
anchor: "crypto.randomBytes(32).toString('hex')"
twin_of: PV-N1-013
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/token/csrf"
  expected_vuln_indicator: "csrf_sec_"
---

# PV-TRAP-044: Trampa FP - Tokens Generados con CSPRNG

## Descripción Técnica
Gemelo seguro de `PV-N1-013`. `generateCsrfTokenSecure` recurre a `crypto.randomBytes(32)`, garantizando resistencia completa frente a cualquier vector de predicción o ataques basados en tiempo.
