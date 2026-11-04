---
id: PV-N2-003
title: "CORS con regex permisiva que no ancla fin de cadena en subdominios"
description: "Expresión regular que valida el inicio del origen pero permite subdominios de atacantes."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 31
line_end: 40
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_authz
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/internal/status"
  expected_vuln_indicator: "Access-Control-Allow-Origin: http://corp.internal.evil.com"
---

# PV-N2-003: CORS con Validación Regex No Anclada al Final

## Descripción Técnica
En `app_node/server.js`, las rutas bajo `/api/internal` intentan restringir el acceso a orígenes internos mediante la expresión regular `/^http:\/\/corp\.internal/`. Dado que la expresión carece del ancla de fin de cadena (`$`) o delimitador de puerto/barra (`(?::\d+)?(?:\/|$)?`), cualquier dominio registrado por un atacante cuyo prefijo sea `http://corp.internal` (por ejemplo, `http://corp.internal.evil.com`) es aceptado como origen confiable y reflejado en `Access-Control-Allow-Origin`.

## Traza de Flujo (Flow Trace)
1. **Middleware Express**: Intercepta cabecera `Origin` en `app_node/server.js:31-40`.
2. **Evaluación de Regex**: `/^http:\/\/corp\.internal/.test(origin)` retorna `true` ante subdominios externos coincidentes.
3. **Reflejo Inseguro**: Asigna `Access-Control-Allow-Origin: origin` y `Credentials: true`.
4. **Impacto**: Lectura de endpoints corporativos internos desde navegadores de usuarios engañados por sitios maliciosos.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/internal/status HTTP/1.1
Host: localhost:3001
Origin: http://corp.internal.evil.com
```
Respuesta esperada: Cabecera `Access-Control-Allow-Origin: http://corp.internal.evil.com` devuelta con éxito.

## Remediación Canónica (Fix)
Anclar estrictamente el fin del nombre de host o parsear la URL con el constructor nativo `new URL(origin)`:
```javascript
app.use('/api/internal', (req, res, next) => {
  const origin = req.headers.origin || '';
  if (/^http:\/\/corp\.internal(?::\d+)?$/.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```
