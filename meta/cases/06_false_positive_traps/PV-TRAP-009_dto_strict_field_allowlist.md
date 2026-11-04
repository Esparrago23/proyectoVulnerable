---
id: PV-TRAP-009
title: "Trampa de Falso Positivo: Actualización de Perfil con Lista Blanca Estricta de Campos (DTO)"
description: "Servicio de perfil que filtra propiedades entrantes contra ALLOWED_MUTABLE_KEYS impidiendo escalación de privilegios."
kind: trap
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-915
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/services/roleService.js
line_start: 32
line_end: 52
anchor: "ALLOWED_MUTABLE_KEYS = ['display_name', 'bio', 'theme']"
twin_of: PV-N3-003
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/users/profile"
  body: '{"userId": 1, "role": "admin", "display_name": "Alice"}'
  expected_vuln_indicator: "user"
---

# PV-TRAP-009: Trampa FP - DTO con Lista Blanca de Campos

## Descripción Técnica
Gemelo seguro de `PV-N3-003`. La función `processProfileUpdateSafe` en `app_node/services/roleService.js` filtra exhaustivamente los atributos mutables permitidos (`display_name`, `bio`, `theme`) y fija `role: 'user'`, evitando que peticiones con `role: admin` modifiquen privilegios en la base de datos.
