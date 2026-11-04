---
id: PV-TRAP-015
title: "Trampa de Falso Positivo: Renderizado de Plantilla Seguro con Contexto Fijo"
description: "Generación de vista previa mediante render_template sobre plantilla fija con variables de contexto escapadas."
kind: trap
difficulty_level: 2
hops: 1
split: dev
cwe: CWE-1336
owasp: "A03:2021 - Injection"
language: python
file: app_python/app.py
line_start: 527
line_end: 535
anchor: 'render_template("dashboard.html"'
twin_of: PV-N2-005
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/render-preview"
  body: '{"title": "Demo"}'
  expected_vuln_indicator: "Portal Privado"
---

# PV-TRAP-015: Trampa FP - Renderizado Seguro de Plantillas

## Descripción Técnica
Gemelo seguro de `PV-N2-005`. La función `render_template_preview_safe` en `app_python/app.py` invoca `render_template("dashboard.html", ...)` cargando una plantilla estática de confianza desde disco en lugar de evaluar cadenas dinámicas con `render_template_string`.
