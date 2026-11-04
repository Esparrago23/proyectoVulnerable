---
id: PV-N1-011
title: "Mala Configuración en Imagen Docker: Ejecución como Superusuario Root"
description: "Construcción de contenedor ejecutando el proceso bajo privilegios de root y exponiendo puertos innecesarios."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-250
owasp: "A05:2021 - Security Misconfiguration"
language: dockerfile
file: infra/Dockerfile.insecure
line_start: 1
line_end: 14
anchor: "USER root"
expected_static_detectors:
  - trivy_misconfig
  - checkov
expected_agent_detectors:
  - controls_auditor
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/Dockerfile.insecure"
  expected_vuln_indicator: "USER root"
---

# PV-N1-011: Contenedor con Ejecución como Root

## Descripción Técnica
`infra/Dockerfile.insecure` declara explícitamente `USER root` y utiliza una etiqueta flotante `latest`, lo cual vulnera las buenas prácticas de aislamiento en contenedores y facilita la escalación de privilegios en el host si existe escape.
