---
id: PV-N2-002
title: "Path Traversal con reemplazo no recursivo de ../ en downloadAsset"
description: "Filtro naive que puede eludirse mediante codificación URL o secuencias anidadas ....//."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/searchController.js
line_start: 28
line_end: 41
expected_static_detectors:
  - semgrep
  - njsscan
  - codeql
expected_agent_detectors:
  - specialist_authz
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/assets/download?file=....//....//package.json"
  expected_vuln_indicator: "proyecto-vulnerable-node"
---

# PV-N2-002: Path Traversal con Reemplazo Simple de Secuencias `../`

## Descripción Técnica
El endpoint `GET /api/assets/download` en `app_node/controllers/searchController.js` permite descargar archivos a partir del parámetro `file`. Para mitigar lecturas fuera del directorio público, implementa un reemplazo simple: `filename.replace(/\.\.\//g, '')`. Este filtro no es recursivo: secuencias como `....//` se convierten en `../` tras una sola pasada, permitiendo escapar de la raíz pública y leer archivos sensibles del sistema de archivos del servidor.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.file` en `searchController.downloadAsset` (línea 27).
2. **Sanitización Naive**: `filename.replace(/\.\.\//g, '')` (línea 30).
3. **Resolución Insegura**: `path.join(__dirname, '..', 'public', sanitized)` (línea 31).
4. **Sink FS**: `fs.readFile(targetPath, ...)` devuelve el contenido del archivo arbitrario (línea 33).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/assets/download?file=....//....//package.json HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Contenido del archivo `package.json` del proyecto Node.js, conteniendo `"name": "proyecto-vulnerable-node"`.

## Remediación Canónica (Fix)
Utilizar `path.resolve` y verificar que la ruta normalizada comience estrictamente con el prefijo del directorio base permitido:
```javascript
const safeBase = path.resolve(__dirname, '..', 'public');
const resolvedPath = path.resolve(safeBase, filename);
if (!resolvedPath.startsWith(safeBase)) {
  return res.status(403).json({ error: 'Acceso denegado: ruta no permitida' });
}
```
