---
id: PV-N1-001
title: "SQL Injection directa por concatenación string en getUserDirect"
description: "El parámetro req.query.id se concatena directamente en la cadena SQL sin usar queries parametrizadas."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/userController.js
line_start: 11
line_end: 17
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
  path: "/api/users/direct?id=1%20OR%201=1"
  expected_vuln_indicator: "alice"
---

# PV-N1-001: SQL Injection Directa en getUserDirect

## Descripción Técnica
El endpoint `GET /api/users/direct` en `app_node/controllers/userController.js` recibe el parámetro de consulta `id` y lo concatena directamente en una instrucción SQL ejecutada contra la base de datos SQLite en memoria (`SELECT * FROM users WHERE id = ` + userId). Al no emplear marcadores de posición (`?`), un atacante puede alterar la semántica de la consulta SQL e inyectar operadores booleanos, uniones o comandos adicionales.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `req.query.id` en `userController.getUserDirect(req, res)` (línea 10).
2. **Sink SQL**: Concatena `userId` en `sql` y ejecuta `dbClient.db.all(sql, ...)` (líneas 12-13).
3. **Impacto**: Lectura no autorizada de registros completos de la tabla `users` mediante inyección tautológica (`1 OR 1=1`).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/users/direct?id=1%20OR%201=1 HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Lista con todos los usuarios registrados en la base de datos (`alice`, `bob`, `admin`).

## Remediación Canónica (Fix)
Utilizar consultas parametrizadas con marcadores de posición (`?`):
```javascript
const sql = "SELECT * FROM users WHERE id = ?";
dbClient.db.all(sql, [userId], (err, rows) => {
  if (err) return res.status(500).json({ error: err.message });
  res.json({ users: rows });
});
```
