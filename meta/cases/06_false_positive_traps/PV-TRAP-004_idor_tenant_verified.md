---
id: PV-TRAP-004
title: "Trampa de Falso Positivo: Facturación con Validación Estricta de Tenant ID"
description: "Endpoint de facturación que parece IDOR pero valida estrictamente invoice.tenant_id !== req.headers['x-tenant-id']."
kind: trap
difficulty_level: 4
hops: 2
split: test
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/safe/safeSanitizers.js
line_start: 39
line_end: 58
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/invoices/502"
  expected_vuln_indicator: "Acceso denegado: factura no pertenece a este tenant"
---

# PV-TRAP-004: Trampa de Falso Positivo — IDOR Mitigado con Aislamiento de Tenant

## Descripción Técnica
La función `getSafeInvoiceForTenant` en `app_node/safe/safeSanitizers.js` recupera facturas mediante `dbClient.getInvoiceById(invoiceId)`. A diferencia del endpoint vulnerable `PV-N4-001`, este controlador compara de manera explícita el inquilino autenticado (`req.headers['x-tenant-id']`) con la propiedad `invoice.tenant_id` retornada por la consulta. Si no coinciden, aborta inmediatamente con `403 Forbidden`. Los analizadores estáticos que detectan parámetros numéricos directos sin evaluar la lógica posterior pueden clasificarlo erróneamente como IDOR.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.params.id` y `req.headers['x-tenant-id']` en `safeSanitizers.js:40-41`.
2. **Consulta a DAO**: Recuperación de la factura por ID (línea 47).
3. **Control de Acceso Multi-Inquilino**: `if (invoice.tenant_id !== tenantId)` retorna `403 Forbidden` (líneas 52-54).
4. **Resultado**: El acceso cross-tenant está bloqueado. La alerta constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/invoices/502 HTTP/1.1
Host: localhost:3001
X-Tenant-Id: tenant_alpha
```
Respuesta esperada: Código `403 Forbidden` con mensaje `{"error": "Acceso denegado: factura no pertenece a este tenant"}` al solicitar una factura perteneciente a `tenant_beta`.

## Remediación Canónica (Fix)
La implementación actual es segura y canónica para control de acceso basado en inquilinos.
