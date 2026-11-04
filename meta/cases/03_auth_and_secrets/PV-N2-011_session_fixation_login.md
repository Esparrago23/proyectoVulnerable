---
id: PV-N2-011
title: "Fijación de Sesión por Omisión de Regeneración de Identificador"
description: "Asignación de privilegios a la sesión existente tras autenticación sin emitir un nuevo identificador de sesión."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-384
owasp: "A07:2021 - Identification and Authentication Failures"
language: javascript
file: app_node/controllers/sessionController.js
line_start: 9
line_end: 23
anchor: "req.session.user = username"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/session/login"
  body: '{"username": "alice", "password": "secretPassword123"}'
  expected_vuln_indicator: "legacy_sess_id_fixed"
---

# PV-N2-011: Fijación de Sesión en Login

## Descripción Técnica
`loginInsecure` en `app_node/controllers/sessionController.js` vincula las credenciales del usuario a la sesión HTTP preexistente sin invocar `regenerate()`, permitiendo a un atacante que conozca el identificador fijado secuestrar la sesión tras el inicio exitoso.
