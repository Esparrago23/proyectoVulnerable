---
id: PV-TRAP-031
title: "Trampa de Falso Positivo: Especificación de Librería Criptográfica en Versión Saneada"
description: "Uso de la librería cryptography en versión auditada y exenta de fallos conocidos en manifiesto."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: requirements.txt
line_start: 1
line_end: 7
anchor: "cryptography==39.0.1"
twin_of: PV-N1-009
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "requirements.txt"
  expected_vuln_indicator: "cryptography==39.0.1"
---

# PV-TRAP-031: Trampa FP - Dependencia con Versión Estable

## Descripción Técnica
Gemelo seguro de `PV-N1-009`. La declaración de `cryptography==39.0.1` en `requirements.txt` representa un componente auditado con fijación exacta de versión y sin vectores de vulnerabilidad conocidos aplicables al alcance del servicio.
