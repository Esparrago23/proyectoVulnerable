---
id: PV-TRAP-033
title: "Trampa de Falso Positivo: Dockerfile con Usuario Dedicado sin Privilegios y Healthcheck"
description: "Imagen de contenedor securizada con creación de usuario appuser, etiqueta inmutable y sonda de salud."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-250
owasp: "A05:2021 - Security Misconfiguration"
language: dockerfile
file: infra/Dockerfile.hardened
line_start: 1
line_end: 18
anchor: "USER appuser"
twin_of: PV-N1-011
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/Dockerfile.hardened"
  expected_vuln_indicator: "USER appuser"
---

# PV-TRAP-033: Trampa FP - Dockerfile con Usuario No Privilegiado

## Descripción Técnica
Gemelo seguro de `PV-N1-011`. `infra/Dockerfile.hardened` utiliza la imagen base inmutable `python:3.11-slim-bookworm`, crea un usuario y grupo sin privilegios (`appuser:appgroup`), y añade directivas de `HEALTHCHECK`.
