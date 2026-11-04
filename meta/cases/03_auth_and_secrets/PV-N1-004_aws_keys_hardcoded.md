---
id: PV-N1-004
title: "Claves de API de AWS hardcodeadas en texto plano"
description: "AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY hardcodeadas en archivo de configuración."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-798
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/config.py
line_start: 3
line_end: 6
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
  expected_vuln_indicator: "AKIAIOSFODNN7EXAMPLE"
---

# PV-N1-004: Credenciales de AWS Hardcodeadas en Código Fuente

## Descripción Técnica
En `app_python/config.py`, las variables `AWS_ACCESS_KEY_ID` y `AWS_SECRET_ACCESS_KEY` contienen credenciales estáticas en texto plano (`AKIAIOSFODNN7EXAMPLE`). La exposición de claves criptográficas o tokens de proveedores cloud en el repositorio permite a cualquier entidad con acceso de lectura comprometer la infraestructura y recursos de la nube asociada.

## Traza de Flujo (Flow Trace)
1. **Definición Estática**: Claves asignadas directamente en `app_python/config.py:4-5`.
2. **Sink**: Secretos cargados por módulos de la aplicación y expuestos en control de versiones.
3. **Impacto**: Acceso administrativo no autorizado a servicios en la nube de AWS.

## Sonda Dinámica de Verificación (Probe)
```bash
grep -E "AKIA[0-9A-Z]{16}" app_python/config.py
```
Resultado esperado: Coincidencia directa con la clave `AKIAIOSFODNN7EXAMPLE`.

## Remediación Canónica (Fix)
Eliminar las credenciales del código fuente y consumirlas a través de variables de entorno seguras o un almacén de secretos:
```python
import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
```
