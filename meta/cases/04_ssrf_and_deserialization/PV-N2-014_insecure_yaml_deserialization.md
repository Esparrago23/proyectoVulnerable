---
id: PV-N2-014
title: "Deserialización Insegura de Documentos YAML con yaml.load"
description: "Carga de cadenas YAML empleando yaml.Loader que permite la instanciación de objetos arbitrarios y RCE."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-502
owasp: "A08:2021 - Software and Data Integrity Failures"
language: python
file: app_python/yaml_parser.py
line_start: 14
line_end: 20
anchor: "yaml.load(yaml_text, Loader=yaml.Loader)"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/config/yaml"
  body: 'app_name: CorporatePortal\nversion: 2.0'
  expected_vuln_indicator: "parsed"
---

# PV-N2-014: Deserialización YAML Insegura

## Descripción Técnica
`parse_config_yaml_direct` en `app_python/yaml_parser.py` invoca `yaml.load(..., Loader=yaml.Loader)`, el cual permite etiquetas personalizadas como `!!python/object/apply` ejecutando funciones del sistema operativo de manera arbitraria.
