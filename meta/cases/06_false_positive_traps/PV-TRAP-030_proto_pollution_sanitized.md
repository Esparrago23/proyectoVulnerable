---
id: PV-TRAP-030
title: "Trampa de Falso Positivo: Combinación Segura de Objetos con Filtro de Claves Prohibidas"
description: "Fusión recursiva bloqueando explícitamente __proto__, constructor y prototype y creando mapas sin prototipo."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-1321
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/mergeUtil.js
line_start: 23
line_end: 41
anchor: "FORBIDDEN_KEYS.has(key)"
twin_of: PV-N2-015
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/config/merge"
  body: '{"__proto__": {"polluted": true}}'
  expected_vuln_indicator: "production"
---

# PV-TRAP-030: Trampa FP - Combinación Segura contra Prototype Pollution

## Descripción Técnica
Gemelo seguro de `PV-N2-015`. `deepMergeSecure` en `app_node/services/mergeUtil.js` descarta de forma tajante las claves `__proto__`, `constructor` y `prototype`, empleando diccionarios puros instanciados mediante `Object.create(null)`.
