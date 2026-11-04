---
id: PV-N2-015
title: "Contaminación de Prototipos de Objetos (Prototype Pollution) en Combinación Recursiva"
description: "Fusión recursiva de objetos JSON sin bloquear __proto__ ni constructor permitiendo modificar Object.prototype."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-1321
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/mergeUtil.js
line_start: 9
line_end: 21
anchor: "deepMergeInsecure(target[key], source[key])"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/config/merge"
  body: '{"__proto__": {"polluted": true}}'
  expected_vuln_indicator: "production"
---

# PV-N2-015: Prototype Pollution en Mezcla de Objetos

## Descripción Técnica
`deepMergeInsecure` en `app_node/services/mergeUtil.js` recorre recursivamente las claves de la fuente asignándolas al objeto destino sin filtrar propiedades especiales como `__proto__`, permitiendo contaminar `Object.prototype`.
