---
id: PV-TRAP-011
title: "Trampa de Falso Positivo: Clave Marcador de Posición Claramente Documentada"
description: "Constante de configuración nombrada DUMMY_INTEGRATION_KEY con valor sintético evidente que no constituye un secreto real."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-798
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/config.py
line_start: 7
line_end: 9
anchor: "DUMMY_INTEGRATION_KEY"
twin_of: PV-N1-004
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "app_python/config.py"
  expected_vuln_indicator: "DUMMY_SAMPLE_KEY_NOT_A_SECRET_PLACEHOLDER"
---

# PV-TRAP-011: Trampa FP - Marcador de Posición Sintético

## Descripción Técnica
Gemelo seguro de `PV-N1-004`. En `app_python/config.py`, `DUMMY_INTEGRATION_KEY = "DUMMY_SAMPLE_KEY_NOT_A_SECRET_PLACEHOLDER"` parece una clave de API por entropía o contexto para escáneres ingenuos, pero su valor y prefijo `DUMMY_` indican un marcador de posición de prueba inofensivo.
