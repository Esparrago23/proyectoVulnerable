---
id: PV-TRAP-005
title: "Trampa de Falso Positivo: Ejecución con execFile y Validación Regex IPv4 Estricta"
description: "Invoca ping usando execFile con array de argumentos y validación regex IPv4 estricta sin invocar shell."
kind: trap
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/safe/safeSanitizers.js
line_start: 61
line_end: 78
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/ping?host=127.0.0.1%3Bwhoami"
  expected_vuln_indicator: "Dirección IPv4 inválida"
---

# PV-TRAP-005: Trampa de Falso Positivo — Command Execution Mitigado con execFile y Regex IPv4

## Descripción Técnica
La función `getSafePing` en `app_node/safe/safeSanitizers.js` ejecuta la utilidad de diagnóstico `ping`. Escáneres que buscan llamadas al módulo `child_process` marcan frecuentemente esta función como sospechosa de Command Injection (CWE-78). Sin embargo, la función es inmune a inyección:
1. Valida el parámetro contra una expresión regular IPv4 estricta (`/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/`), rechazando de raíz cualquier metarácter de shell (`;`, `&`, `|`, `` ` ``, `$`).
2. Utiliza `child_process.execFile` en lugar de `exec`, pasando los argumentos como un vector tipado de cadenas sin iniciar una subshell del sistema operativo.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.host` en `safeSanitizers.js:63`.
2. **Validación Regex**: Rechazo temprano si no cumple el patrón IPv4 (líneas 64-68).
3. **Invocación Segura**: `execFile('ping', [pingFlag, '1', host])` ejecuta el binario sin shell (líneas 71-77).
4. **Resultado**: La ejecución está completamente contenida. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/ping?host=127.0.0.1%3Bwhoami HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Código `400 Bad Request` con mensaje `{"error": "Dirección IPv4 inválida"}`.

## Remediación Canónica (Fix)
La implementación actual es canónica y completamente segura para invocar ejecutables externos.
