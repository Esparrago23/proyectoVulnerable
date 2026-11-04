---
id: PV-TRAP-035
title: "Trampa de Falso Positivo: Filtrado de Catálogo con Comparaciones Fuertemente Tipadas"
description: "Búsqueda en inventario mediante comparadores estrictos de atributos de objeto sin evaluación dinámica de código."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-943
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/catalogController.js
line_start: 27
line_end: 38
anchor: "item.category === category"
twin_of: PV-N2-016
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/catalog/search?category=hardware"
  expected_vuln_indicator: "Servidor Rack 1U"
---

# PV-TRAP-035: Trampa FP - Filtrado de Propiedades Seguro

## Descripción Técnica
Gemelo seguro de `PV-N2-016`. `queryCatalogSafe` en `app_node/controllers/catalogController.js` evalúa predicados booleanos estáticos sobre `item.category` e `item.price` convertidos explícitamente a tipos primitivos seguros.
