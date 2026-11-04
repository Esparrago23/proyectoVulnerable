---
id: PV-TRAP-016
title: "Trampa de Falso Positivo: Registro de Comentarios con Codificación de Entidades HTML"
description: "Almacenamiento y renderizado de retroalimentación de clientes tras sanitizar con escapeHtml."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-79
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/feedbackController.js
line_start: 29
line_end: 40
anchor: "escapeHtml(req.body.author"
twin_of: PV-N2-006
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/feedback"
  body: '{"author": "user", "message": "<script>alert(1)</script>"}'
  expected_vuln_indicator: "&lt;script&gt;alert(1)&lt;/script&gt;"
---

# PV-TRAP-016: Trampa FP - Comentarios con Escape de Entidades HTML

## Descripción Técnica
Gemelo seguro de `PV-N2-006`. `postFeedbackSafe` en `app_node/controllers/feedbackController.js` codifica contextualemnte los campos `author` y `message` antes de insertarlos en SQLite y generar la tarjeta de respuesta, evitando la inyección de secuencias de comandos almacenadas.
