---
id: PV-TRAP-029
title: "Trampa de Falso Positivo: Carga Segura de YAML con yaml.safe_load"
description: "Uso de yaml.safe_load restringido a tipos escalares y estructuras básicas de datos."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-502
owasp: "A08:2021 - Software and Data Integrity Failures"
language: python
file: app_python/yaml_parser.py
line_start: 22
line_end: 26
anchor: "yaml.safe_load(yaml_text)"
twin_of: PV-N2-014
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/config/yaml"
  body: 'app_name: CorporatePortal\nversion: 2.0'
  expected_vuln_indicator: "parsed"
---

# PV-TRAP-029: Trampa FP - Cargador Seguro de YAML

## Descripción Técnica
Gemelo seguro de `PV-N2-014`. `parse_config_yaml_safe` en `app_python/yaml_parser.py` utiliza `yaml.safe_load()`, bloqueando la instanciación de clases de Python y serializando exclusivamente cadenas, números, listas y mapas.
