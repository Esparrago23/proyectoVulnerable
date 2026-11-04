---
id: PV-N3-001
title: "SQLi Multi-Salto: controller -> service -> DAO concatenado en queryOrderRaw"
description: "Flujo de taint inter-archivo que cruza controlador, servicio y DAO donde se concatena en SQL."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/models/dbClient.js
line_start: 34
line_end: 41
anchor: "db.all(query"
expected_static_detectors:
  - codeql
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/orders/user/1%20UNION%20SELECT%20999,999,'Test',9999,'probe'"
  expected_vuln_indicator: "probe"
---

# PV-N3-001: SQL Injection Multi-Salto a través de Tres Capas

## Descripción Técnica
Esta vulnerabilidad representa un flujo de contaminación inter-archivo (`CROSS_FILE_TAINT`) que atraviesa tres capas arquitectónicas:
1. `app_node/controllers/orderController.js`: Recibe `req.params.userId`.
2. `app_node/services/paymentService.js`: Valida únicamente que no sea nulo, arma la cláusula `user_id = ${userIdString}` y delega al modelo.
3. `app_node/models/dbClient.js`: Concatena `rawCondition` directamente en `SELECT * FROM orders WHERE ${rawCondition}` y lo ejecuta.

Los escáneres estáticos de archivo único pierden el rastro del taint al cruzar límites de módulos (`orderController` $\to$ `paymentService` $\to$ `dbClient`).

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.params.userId` en `orderController.js:9`.
2. **Salto 1 $\to$ 2**: Paso hacia `PaymentService.searchOrdersByUser(userId)` en `paymentService.js:12`.
3. **Salto 2 $\to$ 3**: Formación de `condition = "user_id = " + userIdString` y paso a `dbClient.queryOrderRaw(condition)` en `paymentService.js:19-20`.
4. **Sink (DAO)**: Inyección directa en SQLite en `dbClient.js:32-34`.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/orders/user/1%20UNION%20SELECT%20999,999,'Test',9999,'probe' HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Fila sintetizada con status `probe` proveniente de la unión SQL inyectada.

## Remediación Canónica (Fix)
Propagar parámetros estructurados a través de todas las capas en lugar de cadenas SQL en bruto:
```javascript
// dbClient.js
function queryOrdersByUserId(userId, callback) {
  db.all("SELECT * FROM orders WHERE user_id = ?", [userId], callback);
}
```
