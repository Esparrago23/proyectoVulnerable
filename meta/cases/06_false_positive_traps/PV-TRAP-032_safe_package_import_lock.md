---
id: PV-TRAP-032
title: "Trampa de Falso Positivo: Declaración de Módulo Express con Versión Parcheada"
description: "Uso de express 4.18.2 sin dependencias vulnerables transitivas en el archivo de manifiesto."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: package.json
line_start: 1
line_end: 22
anchor: '"express": "^4.18.2"'
twin_of: PV-N1-010
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "package.json"
  expected_vuln_indicator: "express"
---

# PV-TRAP-032: Trampa FP - Manifiesto con Versión Parcheada

## Descripción Técnica
Gemelo seguro de `PV-N1-010`. `package.json` incluye `"express": "^4.18.2"`, versión madura y mantenida que no presenta vulnerabilidades activas registradas en las bases de datos de seguridad CVE/NVD.
