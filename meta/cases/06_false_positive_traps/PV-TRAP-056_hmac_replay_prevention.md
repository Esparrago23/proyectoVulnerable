---
id: PV-TRAP-056
title: "Trampa FP: Comunicacion inter-servicio protegida con firma HMAC y verificacion de vigencia temporal"
description: "Firma SHA-256 de carga util con marca temporal que neutraliza peticiones manipuladas o retransmitidas."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-345
owasp: "A07:2021 - Identification and Authentication Failures"
language: javascript
file: app_node/services/internalServiceClient.js
line_start: 24
line_end: 49
anchor: "crypto.createHmac('sha256', internalSecret || 'default_sec')"
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/tasks/webhook?action=audit_sync"
  expected_vuln_indicator: "status"
---

# PV-TRAP-056: Firma HMAC Inter-Servicio

## Descripcion Tecnica
Autenticacion criptografica robusta entre nodos del cluster interno.
