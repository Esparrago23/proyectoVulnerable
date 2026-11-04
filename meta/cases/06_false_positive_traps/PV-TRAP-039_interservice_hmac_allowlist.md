---
id: PV-TRAP-039
title: "Trampa de Falso Positivo: Cliente Inter-Servicio con Allowlist de Acciones y Token HMAC"
description: "Despacho entre microservicios restringido a un conjunto cerrado de acciones auditadas y firmado con HMAC-SHA256."
kind: trap
difficulty_level: 3
hops: 3
split: test
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: javascript
file: app_node/services/internalServiceClient.js
line_start: 24
line_end: 49
anchor: "ALLOWED_ACTIONS = new Set"
twin_of: PV-N3-007
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/tasks/forward?action=audit_sync&target=localhost"
  expected_vuln_indicator: "status"
---

# PV-TRAP-039: Trampa FP - Cliente Inter-Servicio Asegurado

## Descripción Técnica
Gemelo seguro de `PV-N3-007`. `forwardInternalTaskSafe` valida que `action` resida en `ALLOWED_ACTIONS`, firma los parámetros con HMAC y fija la dirección de destino a la interfaz local.
