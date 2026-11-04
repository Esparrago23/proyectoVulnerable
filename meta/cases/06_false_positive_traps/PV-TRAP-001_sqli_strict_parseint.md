---
id: PV-TRAP-001
title: "Trampa de Falso Positivo: Concatenación SQL con parseInt estricto previo"
description: "El valor está completamente validado como entero numérico antes de interpolar."
kind: trap
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/safe/safeSanitizers.js
line_start: 8
line_end: 22
expected_static_detectors:
  - semgrep
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/user?id=1%20OR%201=1"
  expected_vuln_indicator: "ID numérico requerido"
---

# PV-TRAP-001: Trampa de Falso Positivo — SQLi Mitigado con parseInt Estricto

## Descripción Técnica
La función `getSafeUserById` en `app_node/safe/safeSanitizers.js` construye una consulta SQL mediante interpolación de cadenas (`const safeSql = \`SELECT * FROM users WHERE id = ${parsedId}\``). Herramientas estáticas SAST basadas en reglas regex o sintaxis superficial pueden alertar un falso positivo por concatenación de variables en SQL. Sin embargo, el valor interpolado es el resultado directo de `Number.parseInt(rawId, 10)` tras verificar explícitamente `Number.isNaN(parsedId) || parsedId <= 0`. Es matemáticamente imposible inyectar caracteres de sintaxis SQL.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.id` en `safeSanitizers.js:10`.
2. **Validación Estricta**: `Number.parseInt(rawId, 10)` y rechazo si es `NaN` o no positivo (líneas 11-15).
3. **Interpolación Segura**: `safeSql = SELECT * FROM users WHERE id = ${parsedId}` (línea 18).
4. **Resultado**: El código es seguro. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/user?id=1%20OR%201=1 HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Código `400 Bad Request` con `{"error": "ID numérico requerido"}`.

## Remediación Canónica (Fix)
Aunque es seguro, la práctica recomendada para evitar ruidos de escáneres y garantizar defensas en profundidad es utilizar siempre parámetros preparados:
```javascript
dbClient.db.all("SELECT * FROM users WHERE id = ?", [parsedId], callback);
```
