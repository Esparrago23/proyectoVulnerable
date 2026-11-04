---
id: PV-TRAP-025
title: "Trampa de Falso Positivo: Regeneración Estricta de Identificador de Sesión"
description: "Emisión de un identificador de sesión totalmente nuevo mediante regenerate() al autenticar credenciales."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-384
owasp: "A07:2021 - Identification and Authentication Failures"
language: javascript
file: app_node/controllers/sessionController.js
line_start: 25
line_end: 47
anchor: "req.session.regenerate"
twin_of: PV-N2-011
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/session/login"
  body: '{"username": "alice", "password": "secretPassword123"}'
  expected_vuln_indicator: "authenticated"
---

# PV-TRAP-025: Trampa FP - Renovación Segura de Sesión

## Descripción Técnica
Gemelo seguro de `PV-N2-011`. `loginSecure` en `app_node/controllers/sessionController.js` ejecuta `req.session.regenerate` invalidando el ID previo y asignando una nueva cookie de sesión aleatoria antes de fijar las propiedades de usuario.
