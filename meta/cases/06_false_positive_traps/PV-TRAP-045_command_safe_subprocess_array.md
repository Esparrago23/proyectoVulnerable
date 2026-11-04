---
id: PV-TRAP-045
title: "Trampa de Falso Positivo: Diagnóstico Seguro con Lista de Argumentos y shell=False"
description: "Ejecución de procesos pasando array de argumentos con validación regex previa y shell desactivado."
kind: trap
difficulty_level: 2
hops: 2
split: test
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/diagnostic_service.py
line_start: 28
line_end: 40
anchor: 'cmd_list = ["ping", "-c", "1", host_target]'
twin_of: PV-N2-019
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/diagnostic/ping"
  body: '{"host": "127.0.0.1"}'
  expected_vuln_indicator: "status"
---

# PV-TRAP-045: Trampa FP - Subproceso Seguro sin Shell

## Descripción Técnica
Gemelo seguro de `PV-N2-019`. `run_system_ping_safe` restringe la entrada a caracteres alfanuméricos mediante regex y utiliza `shell=False` pasando un array de argumentos, impidiendo la interpretación de metacaracteres.
