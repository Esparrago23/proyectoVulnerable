---
id: PV-N4-001
title: "Insecure Direct Object Reference (IDOR) sin validación de tenant de factura"
description: "Permite acceder a facturas de otras organizaciones cambiando el identificador numérico."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/invoiceController.js
line_start: 7
line_end: 19
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/invoices/502"
  expected_vuln_indicator: "Beta Industries"
---

# PV-N4-001: IDOR en Acceso a Facturas Multi-Inquilino

## Descripción Técnica
El endpoint `GET /api/invoices/:id` en `app_node/controllers/invoiceController.js` valida que la petición incluya una cabecera de sesión de usuario autenticado (`X-User-Session`), pero en ningún momento compara el `tenant_id` de la factura recuperada de la base de datos contra el tenant del usuario emisor. Como resultado, cualquier usuario legítimo de una organización puede acceder a datos financieros confidenciales de clientes de otras organizaciones modificando el ID en la URL.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.params.id` y `req.headers['x-user-session']` en `invoiceController.getInvoiceDetails` (líneas 7-8).
2. **Salto a Servicio**: `PaymentService.verifyInvoiceAccess` comprueba la presencia de sesión pero omite el chequeo de inquilino (línea 13).
3. **Consulta DAO**: `dbClient.getInvoiceById(invoiceId)` ejecuta `SELECT * FROM invoices WHERE id = ?`.
4. **Impacto**: Fuga de datos de facturación entre tenants no relacionados (Multi-tenancy bypass).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/invoices/502 HTTP/1.1
Host: localhost:3001
X-User-Session: user_alpha
```
Respuesta esperada: Retorno de la factura 502 perteneciente a `tenant_beta` (`Beta Industries`).

## Remediación Canónica (Fix)
Verificar en la capa de acceso a datos o servicio que el `tenant_id` del registro coincida con el inquilino autenticado:
```javascript
function verifyInvoiceAccess(tenantId, invoiceId, callback) {
  dbClient.getInvoiceById(invoiceId, (err, invoice) => {
    if (err) return callback(err, null);
    if (!invoice || invoice.tenant_id !== tenantId) {
      return callback(new Error('Acceso denegado a este recurso'), null);
    }
    callback(null, invoice);
  });
}
```
