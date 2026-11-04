---
id: PV-N3-005
title: "Falsificación de Peticiones del Servidor (SSRF) en Cliente Webhook Remoto"
description: "Envío de solicitudes HTTP a URLs externas sin comprobación de rangos de red privada ni bucle local."
kind: vuln
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/ssrf_client.py
line_start: 14
line_end: 24
anchor: "urllib.request.urlopen(req"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/webhook/fetch"
  body: '{"url": "http://127.0.0.1:5001/health"}'
  expected_vuln_indicator: "app_python"
---

# PV-N3-005: SSRF en Cliente de Integración

## Descripción Técnica
`fetch_webhook_simple` en `app_python/ssrf_client.py` invoca `urllib.request.urlopen` directamente sobre la dirección provista por el llamante, permitiendo alcanzar microservicios internos, instancias de metadatos o servicios de bucle local.
