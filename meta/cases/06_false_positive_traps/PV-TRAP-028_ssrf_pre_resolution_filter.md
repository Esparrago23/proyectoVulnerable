---
id: PV-TRAP-028
title: "Trampa de Falso Positivo: Cliente HTTP con Validación DNS y Filtro de IPs Privadas"
description: "Resolución DNS previa y bloqueo estricto de direcciones RFC 1918, loopback y link-local antes de conectar."
kind: trap
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/ssrf_client.py
line_start: 27
line_end: 46
anchor: "ip_obj.is_private or ip_obj.is_loopback"
twin_of: PV-N3-005
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/webhook/fetch"
  body: '{"url": "http://127.0.0.1:5001/health"}'
  expected_vuln_indicator: "Solo se admiten conexiones bajo el protocolo seguro HTTPS"
---

# PV-TRAP-028: Trampa FP - SSRF Neutralizado con Validación IP

## Descripción Técnica
Gemelo seguro de `PV-N3-005`. `fetch_webhook_filtered` en `app_python/ssrf_client.py` verifica el esquema HTTPS, resuelve el nombre de host contra el DNS local y comprueba mediante `ipaddress` que ninguna IP resuelta pertenezca a redes privadas o bucle local antes de emitir la conexión.
