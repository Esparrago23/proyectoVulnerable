---
id: PV-N2-005
title: "Server-Side Template Injection (SSTI) con render_template_string en vista previa"
description: "El endpoint /api/render-preview evalua directamente la plantilla suministrada por el usuario con Jinja2 sin sandbox."
kind: vuln
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-1336
owasp: "A03:2021 - Injection"
language: python
file: app_python/app.py
line_start: 517
line_end: 525
anchor: "render_template_string(template_code"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/render-preview"
  body: '{"template": "{{ 7 * 7 }}"}'
  expected_vuln_indicator: "49"
---

# PV-N2-005: Inyección de Plantillas del Servidor (SSTI) en Jinja2

## Descripción Técnica
La ruta `POST /api/render-preview` en `app_python/app.py` recibe un campo `template` en el cuerpo JSON y lo procesa directamente con `render_template_string`. Al no restringir el contexto ni compilar en sandbox estricto, un atacante puede inyectar expresiones Jinja2 (`{{ 7 * 7 }}` o `{{ config.__class__.__init__.__globals__ }}`) para acceder al entorno de ejecución y ejecutar comandos remotos.
