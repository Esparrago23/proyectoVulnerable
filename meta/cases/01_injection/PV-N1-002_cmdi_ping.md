---
id: PV-N1-002
title: "Command Injection con child_process.exec() directo en pingHostDirect"
description: "Paso directo de input no sanitizado al shell del sistema operativo."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/userController.js
line_start: 20
line_end: 30
expected_static_detectors:
  - semgrep
  - njsscan
  - codeql
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/tools/ping?host=127.0.0.1%3Bwhoami"
  expected_vuln_indicator: "result"
---

# PV-N1-002: Command Injection Directo en pingHostDirect

## Descripción Técnica
La función `pingHostDirect` en `app_node/controllers/userController.js` concatena el parámetro `req.query.host` en un comando de shell (`ping -c 1 ${targetHost}`) y lo ejecuta directamente con `child_process.exec()`. La invocación de una subshell permite a un atacante introducir metacaracteres de separación de comandos (`;`, `&`, `|`) para ejecutar instrucciones arbitrarias en el host con los privilegios del proceso Node.js.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `req.query.host` obtenido en `pingHostDirect` (línea 21).
2. **Sink OS**: Concatena en cadena de comando ejecutada mediante `exec(command, ...)` (líneas 23-24).
3. **Impacto**: Ejecución arbitraria de comandos a nivel de sistema operativo (RCE).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/tools/ping?host=127.0.0.1%3Bwhoami HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Objeto JSON con el campo `result` conteniendo la salida del comando inyectado.

## Remediación Canónica (Fix)
Evitar invocar subshells y validar el parámetro contra una expresión regular estricta de direcciones IP, utilizando `child_process.execFile` con argumentos aislados:
```javascript
const { execFile } = require('child_process');
const IP_REGEX = /^[a-zA-Z0-9.-]+$/;
if (!IP_REGEX.test(targetHost)) {
  return res.status(400).json({ error: 'Host inválido' });
}
execFile('ping', ['-c', '1', targetHost], (err, stdout) => { ... });
```
