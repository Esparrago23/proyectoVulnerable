---
id: PV-TRAP-017
title: "Trampa de Falso Positivo: Parseo XML con Rechazo de DOCTYPE y Entidades Externas"
description: "Parseo de facturas XML en Python verificando la ausencia de declaraciones DTD y entidades externas."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-611
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/xml_parser.py
line_start: 31
line_end: 47
anchor: "def parse_invoice_xml_safe"
twin_of: PV-N2-007
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/invoice/parse"
  body: '{"xml": "<invoice><invoice_id>999</invoice_id><total>150.0</total><vendor>Acme</vendor></invoice>"}'
  expected_vuln_indicator: '"invoice_id": "999"'
---

# PV-TRAP-017: Trampa FP - Parseo XML con Desactivación de Entidades

## Descripción Técnica
Gemelo seguro de `PV-N2-007`. `parse_invoice_xml_safe` en `app_python/xml_parser.py` rechaza explícitamente cualquier documento que contenga `<!DOCTYPE` o `<!ENTITY`, previniendo ataques de inyección XXE, revelación de archivos locales (`file:///etc/passwd`) o consumo abusivo de recursos.
