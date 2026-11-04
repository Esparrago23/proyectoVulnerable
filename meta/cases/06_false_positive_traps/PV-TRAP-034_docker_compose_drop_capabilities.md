---
id: PV-TRAP-034
title: "Trampa de Falso Positivo: Docker Compose con Sistema de Archivos de Solo Lectura y Reducción de Capacidades"
description: "Composición de servicios endurecida con read_only=true, cap_drop=ALL y puertos vinculados a 127.0.0.1."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-732
owasp: "A05:2021 - Security Misconfiguration"
language: yaml
file: infra/docker-compose.hardened.yml
line_start: 1
line_end: 13
anchor: "cap_drop:"
twin_of: PV-N1-012
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/docker-compose.hardened.yml"
  expected_vuln_indicator: "cap_drop:"
---

# PV-TRAP-034: Trampa FP - Docker Compose Endurecido

## Descripción Técnica
Gemelo seguro de `PV-N1-012`. `infra/docker-compose.hardened.yml` fija `privileged: false`, `read_only: true`, retira todas las capacidades del kernel (`cap_drop: [ALL]`) y restringe la exposición de red a la interfaz de bucle local.
