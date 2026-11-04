---
id: PV-N1-010
title: "Dependencia de Terceros Vulnerable en Node.js (Lodash Prototype Pollution)"
description: "Declaración en package.json de la versión lodash@4.17.15 sujeta a vulnerabilidad de contaminación de prototipos."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: package.json
line_start: 1
line_end: 22
anchor: '"lodash": "4.17.15"'
expected_static_detectors:
  - trivy_sca
  - osv
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "package.json"
  expected_vuln_indicator: "lodash"
---

# PV-N1-010: Paquete de Dependencia Vulnerable en Node.js

## Descripción Técnica
`package.json` declara `"lodash": "4.17.15"` afectada por CVE-2020-8203 y CVE-2019-10744, donde los métodos `zipObjectDeep` y `defaultsDeep` permiten la manipulación del prototipo base `Object.prototype`.
