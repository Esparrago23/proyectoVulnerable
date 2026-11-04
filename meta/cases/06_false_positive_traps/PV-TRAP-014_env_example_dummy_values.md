---
id: PV-TRAP-014
title: "Trampa de Falso Positivo: Archivo de Plantilla de Entorno con Valores Sintéticos"
description: "Archivo .env.example que contiene variables de ejemplo públicas con marcadores de posición evidentes."
kind: trap
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-552
owasp: "A05:2021 - Security Misconfiguration"
language: generic
file: .env.example
line_start: 1
line_end: 5
anchor: "sample_pass_placeholder"
twin_of: PV-N2-004
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: ".env.example"
  expected_vuln_indicator: "sample_pass_placeholder"
---

# PV-TRAP-014: Trampa FP - Archivo .env.example Inofensivo

## Descripción Técnica
Gemelo seguro de `PV-N2-004`. `.env.example` en la raíz contiene cadenas como `postgres://sample_user:sample_pass_placeholder@...`. A diferencia de `.env.backup` (que contiene credenciales reales de staging), este archivo es una plantilla documentada y no representa una fuga de secretos.
