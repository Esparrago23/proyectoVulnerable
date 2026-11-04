---
id: PV-N2-001
title: "Reflected XSS con sanitizador ingenuo que solo elimina script una vez"
description: "Sanitizador naive fácilmente evadible con etiquetas anidadas o eventos HTML."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-79
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/searchController.js
line_start: 10
line_end: 25
expected_static_detectors:
  - semgrep
  - codeql
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
  expected_vuln_indicator: "<img src=x onerror=alert(1)>"
---

# PV-N2-001: XSS Reflejado con Sanitizador Naive de Una Pasada

## Descripción Técnica
En `app_node/controllers/searchController.js`, el endpoint `searchProducts` intenta sanitizar el parámetro `q` mediante un reemplazo de texto simple (`query.replace('<script>', '').replace('</script>', '')`). Este filtro no es recursivo, no analiza mayúsculas/minúsculas ni previene el uso de otros elementos HTML y manejadores de eventos como `<img src=x onerror=...>`, `<svg onload=...>` o anidamientos como `<scr<script>ipt>`.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `req.query.q` en `searchController.searchProducts` (línea 9).
2. **Filtro Defectuoso**: `query.replace('<script>', '').replace('</script>', '')` (línea 12).
3. **Sink HTML**: Interpolación directa en plantilla HTML enviada al cliente con `Content-Type: text/html` (líneas 14-22).
4. **Impacto**: Ejecución de scripts JavaScript en el contexto del navegador del usuario.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: HTML que refleja intacto el payload `<img src=x onerror=alert(1)>`.

## Remediación Canónica (Fix)
Realizar codificación contextual de entidades HTML antes de reflejar entradas en el cuerpo del documento o emplear bibliotecas canónicas de sanitización:
```javascript
function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  }[m]));
}
```
