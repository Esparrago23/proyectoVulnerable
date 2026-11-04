---
id: PV-TRAP-019
title: "Trampa de Falso Positivo: Consulta Documental con Verificación Estricta de Propiedad (Tenancy)"
description: "Acceso a certificados y documentos corporativos validando que el llamante sea el propietario legítimo."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/doc_service.py
line_start: 42
line_end: 52
anchor: "def get_document_safe"
twin_of: PV-N3-004
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/safe/documents/103?user=alice"
  expected_vuln_indicator: "Acceso no autorizado: el documento no pertenece al usuario activo"
---

# PV-TRAP-019: Trampa FP - Consulta Documental con Validación de Propiedad

## Descripción Técnica
Gemelo seguro de `PV-N3-004`. `get_document_safe` en `app_python/doc_service.py` corrobora que el campo `owner` del registro documental coincida unívocamente con el usuario autenticado (`caller_user`), arrojando `PermissionError` ante cualquier intento de escalamiento horizontal (IDOR).
