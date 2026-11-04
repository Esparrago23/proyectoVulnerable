---
id: PV-TRAP-037
title: "Trampa de Falso Positivo: Mensajes de Notificación con Plantilla Precompilada y Escape"
description: "Generación de notificaciones formateadas mediante plantillas estáticas y saneamiento contextual de variables."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1336
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/templateController.js
line_start: 23
line_end: 31
anchor: "Su solicitud ha sido procesada con exito"
twin_of: PV-N3-006
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/template/render"
  body: '{"username": "admin"}'
  expected_vuln_indicator: "Su solicitud ha sido procesada con exito"
---

# PV-TRAP-037: Trampa FP - Plantilla Estática Precompilada

## Descripción Técnica
Gemelo seguro de `PV-N3-006`. `renderPrecompiledTemplate` en `app_node/controllers/templateController.js` utiliza una plantilla estática precompilada y escapa los caracteres HTML de las variables de entrada sin recurrir a evaluadores dinámicos.
