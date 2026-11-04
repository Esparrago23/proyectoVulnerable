---
id: PV-N1-009
title: "Dependencia Vulnerable en Ecosistema Python (PyYAML Deserialization RCE)"
description: "Inclusión de versión obsoleta pyyaml==5.3.1 con vulnerabilidad crítica de ejecución remota de código."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: requirements.txt
line_start: 1
line_end: 7
anchor: "pyyaml==5.3.1"
expected_static_detectors:
  - trivy_sca
  - osv
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "requirements.txt"
  expected_vuln_indicator: "pyyaml==5.3.1"
---

# PV-N1-009: Dependencia Insegura en Python

## Descripción Técnica
`requirements.txt` especifica la versión `pyyaml==5.3.1` afectada por CVE-2020-14343, permitiendo a un atacante que controle el documento deserializado ejecutar comandos en el sistema anfitrión.
