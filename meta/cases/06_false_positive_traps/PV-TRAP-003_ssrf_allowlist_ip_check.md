---
id: PV-TRAP-003
title: "Trampa de Falso Positivo: SSRF Mitigado con Allowlist de Dominio e IP Privada Bloqueada"
description: "Valida esquema HTTPS, lista blanca de dominios y resolución DNS bloqueando IPs privadas (RFC 1918) y loopback."
kind: trap
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/safe_handlers.py
line_start: 31
line_end: 78
expected_static_detectors:
  - semgrep
  - codeql
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/webhook"
  expected_vuln_indicator: "URL rechazada"
---

# PV-TRAP-003: Trampa de Falso Positivo — SSRF Neutralizado con Allowlist y DNS Resolution

## Descripción Técnica
La función `safe_webhook_fetch` en `app_python/safe_handlers.py` invoca `urllib.request.urlopen(req)`. Un escáner SAST convencional identifica una llamada de red saliente parametrizada por el usuario y emite una alerta de SSRF (CWE-918). Sin embargo, el código implementa defensas completas en profundidad:
1. Valida que el esquema sea obligatoriamente `https`.
2. Restringe el nombre de host a un conjunto estricto de socios (`ALLOWED_PARTNER_DOMAINS = {"api.github.com", "httpbin.org"}`).
3. Resuelve previamente las direcciones IP mediante `socket.getaddrinfo` y comprueba con `ipaddress.ip_address` que ninguna IP sea privada (`is_private`), de bucle local (`is_loopback`), de enlace local (`is_link_local`) o reservada, neutralizando bypasses por DNS rebinding y metadatos cloud.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `POST /api/safe/webhook` con `{"url": "..."}` en `safe_handlers.py:81-94`.
2. **Defensas**: Comprobaciones de esquema, dominio y resolución IP en `safe_handlers.py:38-66`.
3. **Petición Segura**: `urlopen` se ejecuta únicamente contra destinos verificados en internet pública.
4. **Resultado**: La función es segura frente a SSRF. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/safe/webhook HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```
Respuesta esperada: Código `400 Bad Request` con mensaje `{"error": "URL rechazada: Esquema no permitido: solo HTTPS es admitido"}`.

## Remediación Canónica (Fix)
La implementación actual representa el estándar de la industria contra SSRF.
