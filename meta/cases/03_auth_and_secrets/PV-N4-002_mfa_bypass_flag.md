---
id: PV-N4-002
title: "MFA Authentication Bypass mediante bandera skip_mfa o header X-Bypass-MFA"
description: "Lógica defectuosa que autoriza sesiones sin comprobar el código TOTP si se envía la bandera."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-287
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/auth/mfa_handler.py
line_start: 24
line_end: 43
expected_static_detectors: []
expected_agent_detectors:
  - specialist_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/mfa"
  expected_vuln_indicator: "dashboard"
---

# PV-N4-002: Bypass de Autenticación de Doble Factor (MFA)

## Descripción Técnica
En `app_python/auth/mfa_handler.py` y `app_python/app.py`, el flujo de verificación de segundo factor (`/mfa`) evalúa si la petición incluye la cabecera `X-Bypass-MFA: 1` o el parámetro de formulario/URL `skip_mfa=true`. Si alguna de estas condiciones se cumple, `mfa_handler.verify_totp_code` omite por completo la verificación del algoritmo TOTP (RFC 6238) y retorna `True`, permitiendo a un atacante que conozca la contraseña primaria saltarse el segundo factor.

## Traza de Flujo (Flow Trace)
1. **Entrada**: Parámetro `skip_mfa` o header `X-Bypass-MFA` en `app.py:104-106`.
2. **Salto a Módulo de Auth**: Llamada a `mfa_handler.verify_totp_code(..., bypass_flag=True)` (líneas 108-112).
3. **Bypass Lógico**: Rama `if bypass_flag: return True, ...` en `mfa_handler.py:36-37`.
4. **Impacto**: Acceso a la sesión administrativa sin posesión del dispositivo generador de TOTP.

## Sonda Dinámica de Verificación (Probe)
```http
POST /mfa HTTP/1.1
Host: localhost:5001
Content-Type: application/x-www-form-urlencoded
Cookie: session=<cookie_con_pre_auth_user>

totp_code=000000&skip_mfa=true
```
Respuesta esperada: Redirección `302 Found` hacia `/dashboard` con cookie de sesión administrativa emitida.

## Remediación Canónica (Fix)
Eliminar las compuertas de bypass residuales destinadas a pruebas o entornos de desarrollo:
```python
def verify_totp_code(submitted_code: str, secret_key_base32: str) -> Tuple[bool, str]:
    current_code = generate_totp_code(secret_key_base32)
    clean_sub = str(submitted_code or "").strip()
    if secrets.compare_digest(clean_sub, current_code):
        return True, "TOTP verificado correctamente"
    return False, "Código TOTP inválido o expirado"
```
