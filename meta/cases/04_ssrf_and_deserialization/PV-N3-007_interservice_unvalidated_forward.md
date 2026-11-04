---
id: PV-N3-007
title: "Falsificación de Peticiones del Servidor Inter-Servicio (SSRF Multi-Componente)"
description: "Reenvío no validado de acciones y destinos desde el servicio Node.js hacia microservicios backend en Python."
kind: vuln
difficulty_level: 3
hops: 3
split: test
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: javascript
file: app_node/services/internalServiceClient.js
line_start: 11
line_end: 22
anchor: "http://127.0.0.1:5001/api/tasks/webhook?action="
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/tasks/forward?action=eval&target=localhost"
  expected_vuln_indicator: "status"
---

# PV-N3-007: SSRF Inter-Servicio sin Restricción

## Descripción Técnica
`forwardInternalTask` en `app_node/services/internalServiceClient.js` compone dinámicamente peticiones HTTP hacia endpoints internos permitiendo la manipulación de acciones y la invocación de rutas no autorizadas en microservicios backend.
