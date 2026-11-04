---
id: PV-N3-002
title: "SSRF Multi-Salto: Webhook en background sin validación de rangos privados"
description: "Worker que descarga URLs no confiables pudiendo consultar metadatos cloud o servicios internos."
kind: vuln
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/tasks/worker.py
line_start: 10
line_end: 26
expected_static_detectors:
  - semgrep
  - codeql
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/tasks/webhook"
  expected_vuln_indicator: "bytes_received"
---

# PV-N3-002: SSRF Multi-Salto en Tarea en Background

## Descripción Técnica
El endpoint `POST /api/tasks/webhook` en `app_python/app.py` recibe un JSON con el parámetro `url` y lo delega al módulo de tareas asíncronas `tasks.worker.process_webhook_fetch`. Dicho worker ejecuta `urllib.request.urlopen` sin validar el esquema de red, sin resolver DNS contra rangos privados (RFC 1918) y sin bloquear endpoints de metadatos de proveedores cloud (`169.254.169.254`), permitiendo forjar peticiones internas desde el servidor.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `POST /api/tasks/webhook` en `app_python/app.py:168-180`.
2. **Salto a Worker**: Llamada a `worker.process_webhook_fetch(webhook_url)` en `tasks/worker.py:10-27`.
3. **Sink HTTP**: `urllib.request.urlopen(req, timeout=5)` emite la petición TCP hacia la IP de destino.
4. **Impacto**: Acceso a servicios internos de la intranet o exfiltración de credenciales de instancias cloud.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/tasks/webhook HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```
Respuesta esperada: Confirmación con clave `bytes_received` reflejando la respuesta del servicio consultado.

## Remediación Canónica (Fix)
Validar esquema HTTPS estricto, emplear lista blanca de dominios y verificar que las IPs resueltas no pertenezcan a rangos privados o de metadatos:
```python
import ipaddress
import socket

def validate_url(url: str):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Solo HTTPS")
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("IP no permitida")
```
