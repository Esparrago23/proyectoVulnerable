---
id: PV-N1-005
title: "Clave privada RSA PEM sin cifrar embebida en código fuente"
description: "Bloque RSA PRIVATE KEY en texto plano en archivo de configuración."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-321
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/config.py
line_start: 11
line_end: 16
anchor: "JWT_SIGNING_PRIVATE_KEY"
expected_static_detectors:
  - gitleaks
  - trufflehog
  - semgrep
expected_agent_detectors:
  - specialist_secrets
  - specialists_ensemble
dynamic_probe:
  service: none
  method: STATIC
  path: "app_python/config.py"
  expected_vuln_indicator: "BEGIN RSA PRIVATE KEY"
---

# PV-N1-005: Clave Privada Asimétrica RSA PEM Expuesta

## Descripción Técnica
En `app_python/config.py`, la constante `JWT_SIGNING_PRIVATE_KEY` almacena una clave privada RSA completa en formato PEM (`-----BEGIN RSA PRIVATE KEY-----`) sin contraseña de protección ni cifrado. Esta clave es utilizada para firmar tokens JWT o autenticar comunicaciones seguras, por lo que su exposición compromete la integridad criptográfica de cualquier aserción emitida por el servicio.

## Traza de Flujo (Flow Trace)
1. **Definición Estática**: Bloque PEM multilínea definido en `app_python/config.py:8-12`.
2. **Sink**: Carga en memoria por el motor de autenticación sin validación de origen seguro.
3. **Impacto**: Suplantación de identidad mediante forja de firmas digitales y tokens JWT válidos.

## Sonda Dinámica de Verificación (Probe)
```bash
grep -E "BEGIN (RSA )?PRIVATE KEY" app_python/config.py
```
Resultado esperado: Coincidencia con el bloque de encabezado de la clave privada PEM.

## Remediación Canónica (Fix)
Almacenar la clave privada en un archivo protegido con permisos restringidos (`chmod 600`) o utilizar un módulo de seguridad en hardware (HSM / KMS):
```python
import os

JWT_SIGNING_PRIVATE_KEY = os.environ.get("JWT_SIGNING_PRIVATE_KEY")
```
