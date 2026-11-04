---
id: PV-N2-006
title: "Stored Cross-Site Scripting (XSS) en comentarios de retroalimentación"
description: "Inserción y renderizado de comentarios de clientes sin sanitización ni codificación contextual de entidades HTML."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-79
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/feedbackController.js
line_start: 16
line_end: 27
anchor: "dbClient.insertFeedbackRaw(author, message"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/feedback"
  body: '{"author": "attacker", "message": "<script>alert(1)</script>"}'
  expected_vuln_indicator: "<script>alert(1)</script>"
---

# PV-N2-006: Stored XSS en Módulo de Comentarios

## Descripción Técnica
En `app_node/controllers/feedbackController.js`, la función `postFeedbackRaw` recibe `author` y `message` desde el cuerpo de la petición y los almacena en la base de datos sin codificar entidades HTML. Al renderizar la respuesta o al ser leídos por otros usuarios, el código malicioso se ejecuta en el navegador del cliente.
