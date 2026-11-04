---
id: PV-N1-003
title: "CORS permisivo: Wildcard Origin * con Allow-Credentials true"
description: "Configura Access-Control-Allow-Origin: * permitiendo al mismo tiempo credenciales."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 23
line_end: 28
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_authz
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: OPTIONS
  path: "/api/public/data"
  expected_vuln_indicator: "Access-Control-Allow-Origin: *"
---

# PV-N1-003: Mala Configuración de CORS con Comodín y Credenciales

## Descripción Técnica
En `app_node/server.js`, las rutas bajo `/api/public` configuran simultáneamente las cabeceras HTTP `Access-Control-Allow-Origin: *` y `Access-Control-Allow-Credentials: true`. Aunque la especificación formal del W3C/WHATWG prohíbe el uso de credenciales con comodín, múltiples navegadores y clientes HTTP permiten que scripts de cualquier dominio de origen lean respuestas privadas si el servidor no impone validaciones contextuales.

## Traza de Flujo (Flow Trace)
1. **Middleware Express**: Ruta montada en `app_node/server.js:23-28`.
2. **Configuración de Cabeceras**: Establece `*` junto con `Credentials: true` en todas las respuestas.
3. **Impacto**: Filtrado de datos cross-origin e incumplimiento de políticas de aislamiento web.

## Sonda Dinámica de Verificación (Probe)
```http
OPTIONS /api/public/test HTTP/1.1
Host: localhost:3001
Origin: https://attacker.example.com
```
Respuesta esperada: Cabeceras `Access-Control-Allow-Origin: *` y `Access-Control-Allow-Credentials: true` presentes simultáneamente.

## Remediación Canónica (Fix)
Especificar orígenes explícitos basados en listas de dominios autorizados y evitar comodines universales con credenciales:
```javascript
const ALLOWED_ORIGINS = ['https://trusted.corp.internal'];
app.use('/api/public', (req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```
