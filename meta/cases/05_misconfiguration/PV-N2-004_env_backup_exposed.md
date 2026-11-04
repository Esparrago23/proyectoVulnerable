---
id: PV-N2-004
title: "Archivo de backup de entorno con contraseñas y canarios expuestos"
description: "Credenciales de base de datos y tokens internos almacenados en archivo .env.backup."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-552
owasp: "A05:2021 - Security Misconfiguration"
language: generic
file: .env.backup
line_start: 1
line_end: 5
expected_static_detectors:
  - gitleaks
  - trufflehog
expected_agent_detectors:
  - specialist_secrets
  - specialists_ensemble
dynamic_probe:
  service: none
  method: STATIC
  path: ".env.backup"
  expected_vuln_indicator: "SuperSecretDevPassword2026"
---

# PV-N2-004: Archivo de Respaldo de Entorno Expuesto en el Repositorio

## Descripción Técnica
En la raíz del repositorio se encuentra el archivo `.env.backup` conteniendo cadenas de conexión de base de datos en texto plano con usuario y contraseña (`DATABASE_URL=postgres://app_user:SuperSecretDevPassword2026@...`), tokens de API internos (`INTERNAL_API_TOKEN`) y canarios de prueba. Los archivos temporales o de backup de configuración comúnmente son indexados por rastreadores web si el servidor los expone estáticamente o quedan comprometidos en repositorios públicos.

## Traza de Flujo (Flow Trace)
1. **Archivo en Árbol**: `.env.backup:1-5`.
2. **Sink**: Secretos de infraestructura accesibles directamente sin autenticación.
3. **Impacto**: Compromiso total de la base de datos PostgreSQL interna y credenciales de API.

## Sonda Dinámica de Verificación (Probe)
```bash
grep "DATABASE_URL" .env.backup
```
Resultado esperado: Coincidencia con la cadena de conexión completa que contiene la contraseña `SuperSecretDevPassword2026`.

## Remediación Canónica (Fix)
Añadir extensiones de respaldo y archivos `.env` a `.gitignore`, revocar las credenciales expuestas y rotar los secretos inmediatamente:
```gitignore
# .gitignore
.env
.env.*
*.backup
*.bak
```
