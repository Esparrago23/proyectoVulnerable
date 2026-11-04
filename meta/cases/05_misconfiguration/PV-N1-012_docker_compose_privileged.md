---
id: PV-N1-012
title: "Mala Configuración IaC: Contenedor en Modo Privilegiado y Montaje de Docker Socket"
description: "Configuración docker-compose otorgando privileged=true y acceso directo al socket del daemon Docker del anfitrión."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-732
owasp: "A05:2021 - Security Misconfiguration"
language: yaml
file: infra/docker-compose.insecure.yml
line_start: 1
line_end: 14
anchor: "privileged: true"
expected_static_detectors:
  - trivy_misconfig
  - checkov
expected_agent_detectors:
  - controls_auditor
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/docker-compose.insecure.yml"
  expected_vuln_indicator: "privileged: true"
---

# PV-N1-012: Contenedor Privilegiado en Docker Compose

## Descripción Técnica
`infra/docker-compose.insecure.yml` define `privileged: true` y monta `/var/run/docker.sock`, lo que otorga al contenedor control completo sobre el daemon de Docker del host y capacidad de comprometer el sistema operativo completo.
