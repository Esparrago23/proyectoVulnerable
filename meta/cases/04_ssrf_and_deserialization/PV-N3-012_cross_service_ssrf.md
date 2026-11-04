---
id: PV-N3-012
title: "Cross-Service Taint: SSRF en descarga de comprobante remoto originado en cliente Node"
description: "URL proporcionada en solicitud inter-servicio conectada directamente con urllib sin validacion de IP privada."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/app.py
line_start: 908
line_end: 919
anchor: 'resp = urllib.request.urlopen(url, timeout=3)'
expected_static_detectors:
  - bandit
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/settlement/callback"
  expected_vuln_indicator: "notified"
---

# PV-N3-012: Cross-Service SSRF

## Descripcion Tecnica
Peticion de retorno disparada a destinos arbitrarios controlados por el cliente.
