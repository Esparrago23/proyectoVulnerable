---
id: PV-TRAP-002
title: "Trampa de Falso Positivo: Descarga con basename y lista blanca estricta"
description: "Utiliza path.basename y comparación contra array de archivos autorizados."
kind: trap
difficulty_level: 2
hops: 1
split: test
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/safe/safeSanitizers.js
line_start: 25
line_end: 37
expected_static_detectors:
  - semgrep
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/file?file=../../etc/passwd"
  expected_vuln_indicator: "Archivo no permitido por política"
---

# PV-TRAP-002: Trampa de Falso Positivo — Path Traversal Neutralizado con Basename y Whitelist

## Descripción Técnica
La función `getSafeFile` en `app_node/safe/safeSanitizers.js` gestiona descargas recibiendo `req.query.file`. Escáneres de seguridad pueden señalar un posible Directory Traversal al detectar el flujo hacia respuestas de archivo. No obstante, la función aplica `path.basename(rawFilename)`, eliminando cualquier componente de directorio (`../` o rutas absolutas), y compara el resultado estricto contra una lista blanca en memoria (`['manual.pdf', 'terms.pdf', 'privacy.pdf']`).

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.file` en `safeSanitizers.js:27`.
2. **Aislamiento**: `path.basename` extrae únicamente el nombre final del archivo (línea 30).
3. **Comprobación de Lista Blanca**: `!ALLOWED_FILES.includes(cleanBasename)` devuelve `403 Forbidden` (líneas 31-33).
4. **Resultado**: El código es seguro. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/file?file=../../etc/passwd HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Código `403 Forbidden` con `{"error": "Archivo no permitido por política"}`.

## Remediación Canónica (Fix)
La implementación actual es canónica y completamente segura.
