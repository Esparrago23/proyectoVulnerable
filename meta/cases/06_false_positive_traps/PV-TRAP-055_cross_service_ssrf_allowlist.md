---
id: PV-TRAP-055
title: "Trampa FP: Cross-Service callback con validacion de allowlist y resolucion de IP privada"
description: "Invocacion delegada hacia safe_webhook_fetch con filtrado exhaustivo de RFC 1918 y dominios autorizados."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/safe_handlers.py
line_start: 161
line_end: 164
anchor: 'return safe_webhook_fetch(callback_url)'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/safe/settlement/callback"
  expected_vuln_indicator: "URL rechazada"
---

# PV-TRAP-055: Callback con Guardrail de Red

## Descripcion Tecnica
Bloqueo de rangos loopback, privados y metadatos de computacion en la nube.
