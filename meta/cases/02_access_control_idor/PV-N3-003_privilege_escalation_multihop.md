---
id: PV-N3-003
title: "Escalación de Privilegios Multi-Salto por Merge de Propiedades en roleService"
description: "Flujo multi-salto (controlador -> servicio -> DAO) con mezcla ciega de propiedades permitiendo inyectar rol de administrador."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-269
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/services/roleService.js
line_start: 13
line_end: 26
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/users/profile"
  expected_vuln_indicator: "admin"
---

# PV-N3-003: Escalación de Privilegios Multi-Salto por Asignación Masiva

## Descripción Técnica
El endpoint `POST /api/users/profile` permite actualizar atributos de perfil de un usuario. La petición atraviesa tres capas:
1. `app_node/controllers/userController.js`: Recibe `req.body` y llama a `RoleService.processProfileUpdate`.
2. `app_node/services/roleService.js`: Ejecuta `Object.assign({ role: 'user' }, profileUpdates)`. Al no filtrar propiedades restringidas, el atacante puede inyectar `"role": "admin"`.
3. `app_node/models/dbClient.js`: Persiste directamente `mergedProfile.role` en la tabla `users` de SQLite sin verificar autorizaciones administrativas.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.body` en `userController.updateUserProfile`.
2. **Salto 1 $\to$ 2**: Paso hacia `RoleService.processProfileUpdate(userId, profileUpdates)` en `services/roleService.js:13-26`.
3. **Salto 2 $\to$ 3**: `Object.assign` sobrescribe la clave `role` con el valor del payload del atacante y delega en `dbClient.updateUserProfile`.
4. **Sink (DAO)**: Actualización de privilegios en base de datos (`UPDATE users SET role = ? WHERE id = ?`).

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/users/profile HTTP/1.1
Host: localhost:3001
Content-Type: application/json

{
  "userId": 1,
  "displayName": "Alice Hacker",
  "role": "admin"
}
```
Respuesta esperada: Objeto JSON del usuario actualizado con `"role": "admin"`.

## Remediación Canónica (Fix)
Aplicar una lista blanca estricta de atributos modificables por el usuario, excluyendo campos de control de acceso y privilegios:
```javascript
const ALLOWED_FIELDS = ['displayName', 'bio', 'avatarUrl'];
const safeUpdates = {};
for (const key of ALLOWED_FIELDS) {
  if (key in profileUpdates) {
    safeUpdates[key] = profileUpdates[key];
  }
}
```
