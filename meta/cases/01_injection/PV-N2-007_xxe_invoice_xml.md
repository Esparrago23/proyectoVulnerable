---
id: PV-N2-007
title: "XML External Entity (XXE) Injection en analizador de facturas tributarias"
description: "Procesamiento de documentos XML mediante analizador estándar sin desactivar la resolución de DTD ni entidades externas."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-611
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/xml_parser.py
line_start: 13
line_end: 28
anchor: "ET.fromstring(xml_content)"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/invoices/xml"
  body: '<?xml version="1.0"?><invoice><invoice_id>999</invoice_id><total>150.0</total><vendor>AcmeCorp</vendor></invoice>'
  expected_vuln_indicator: "AcmeCorp"
---

# PV-N2-007: Inyección de Entidades Externas XML (XXE)

## Descripción Técnica
La función `parse_invoice_xml_raw` en `app_python/xml_parser.py` procesa cadenas XML entrantes mediante `ET.fromstring` sin desactivar la resolución de entidades externas `<!ENTITY>` ni definiciones de tipo de documento `<!DOCTYPE>`. Un atacante puede suministrar un payload XXE para exfiltrar archivos locales del servidor o forzar peticiones SSRF internas.
