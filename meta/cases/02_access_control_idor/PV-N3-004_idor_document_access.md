---
id: PV-N3-004
title: "IDOR en servicio de consulta y descarga de comprobantes documentales"
description: "Acceso no autorizado a certificados y llaves confidenciales de otros usuarios a través de identificadores secuenciales."
kind: vuln
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/doc_service.py
line_start: 35
line_end: 40
anchor: "return doc"
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/documents/103"
  expected_vuln_indicator: "Llave Maestra de Infraestructura"
---

# PV-N3-004: IDOR en Consulta Documental

## Descripción Técnica
En `app_python/doc_service.py`, `get_document_raw` recupera el objeto documental solicitado a partir de su ID sin comparar `doc['owner']` contra la identidad del usuario en sesión (`caller_user`). Un usuario regular puede acceder a documentos confidenciales pertenecientes al administrador (`doc_id=103`).
