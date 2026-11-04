"""Script generador de fichas markdown para la Wave 2 (Fase S2)."""

from pathlib import Path

META_CASES = Path(r"C:\Users\Esparrago\Desktop\proyectoVulnerable\meta\cases")

CARDS = [
    # 1. PV-N2-010 (JWT Bypass)
    ("03_auth_and_secrets/PV-N2-010_jwt_none_signature_bypass.md", """---
id: PV-N2-010
title: "Bypass de Firma Criptográfica en Verificación de Tokens JWT"
description: "Decodificación de tokens de sesión con verify_signature desactivado permitiendo falsificación de identidad."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-347
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/jwt_service.py
line_start: 14
line_end: 21
anchor: 'options={"verify_signature": False}'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/jwt/decode"
  body: '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzcyI6ImNvcnAifQ."}'
  expected_vuln_indicator: "admin"
---

# PV-N2-010: Bypass de Firma Criptográfica en JWT

## Descripción Técnica
La función `decode_token_legacy` en `app_python/jwt_service.py` omite la verificación criptográfica de la firma digital estableciendo `verify_signature=False`, permitiendo a un atacante alterar los reclamos (claims) del token e impersonar cualquier usuario (`sub=admin`).
"""),

    # 2. PV-TRAP-024 (JWT RS256 Strict)
    ("06_false_positive_traps/PV-TRAP-024_jwt_rs256_strict_verify.md", """---
id: PV-TRAP-024
title: "Trampa de Falso Positivo: Validación Criptográfica Estricta de JWT con RS256"
description: "Decodificación y verificación de tokens fijando algoritmo asimétrico RS256 y validando emisor y expiración."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-347
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/jwt_service.py
line_start: 24
line_end: 34
anchor: 'algorithms=["RS256"]'
twin_of: PV-N2-010
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/jwt/decode"
  body: '{"token": "invalid.jwt.token"}'
  expected_vuln_indicator: "error"
---

# PV-TRAP-024: Trampa FP - Verificación Estricta de JWT

## Descripción Técnica
Gemelo seguro de `PV-N2-010`. `decode_token_verified` en `app_python/jwt_service.py` valida la firma con la clave pública RSA corporativa, restringe los algoritmos exclusivamente a `RS256` y exige los campos `exp`, `iss` y `sub`.
"""),

    # 3. PV-N2-011 (Session Fixation)
    ("03_auth_and_secrets/PV-N2-011_session_fixation_login.md", """---
id: PV-N2-011
title: "Fijación de Sesión por Omisión de Regeneración de Identificador"
description: "Asignación de privilegios a la sesión existente tras autenticación sin emitir un nuevo identificador de sesión."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-384
owasp: "A07:2021 - Identification and Authentication Failures"
language: javascript
file: app_node/controllers/sessionController.js
line_start: 9
line_end: 23
anchor: "req.session.user = username"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/session/login"
  body: '{"username": "alice", "password": "secretPassword123"}'
  expected_vuln_indicator: "legacy_sess_id_fixed"
---

# PV-N2-011: Fijación de Sesión en Login

## Descripción Técnica
`loginInsecure` en `app_node/controllers/sessionController.js` vincula las credenciales del usuario a la sesión HTTP preexistente sin invocar `regenerate()`, permitiendo a un atacante que conozca el identificador fijado secuestrar la sesión tras el inicio exitoso.
"""),

    # 4. PV-TRAP-025 (Session Regeneration)
    ("06_false_positive_traps/PV-TRAP-025_session_regeneration_login.md", """---
id: PV-TRAP-025
title: "Trampa de Falso Positivo: Regeneración Estricta de Identificador de Sesión"
description: "Emisión de un identificador de sesión totalmente nuevo mediante regenerate() al autenticar credenciales."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-384
owasp: "A07:2021 - Identification and Authentication Failures"
language: javascript
file: app_node/controllers/sessionController.js
line_start: 25
line_end: 47
anchor: "req.session.regenerate"
twin_of: PV-N2-011
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/session/login"
  body: '{"username": "alice", "password": "secretPassword123"}'
  expected_vuln_indicator: "authenticated"
---

# PV-TRAP-025: Trampa FP - Renovación Segura de Sesión

## Descripción Técnica
Gemelo seguro de `PV-N2-011`. `loginSecure` en `app_node/controllers/sessionController.js` ejecuta `req.session.regenerate` invalidando el ID previo y asignando una nueva cookie de sesión aleatoria antes de fijar las propiedades de usuario.
"""),

    # 5. PV-N2-012 (Predictable Reset Token)
    ("03_auth_and_secrets/PV-N2-012_predictable_reset_token.md", """---
id: PV-N2-012
title: "Generación de Token de Restablecimiento de Contraseña Predecible"
description: "Cálculo de token de recuperación utilizando hash MD5 de usuario y marca temporal unix fácilmente deducible."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-330
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/auth_service.py
line_start: 49
line_end: 57
anchor: 'hashlib.md5(seed.encode("utf-8")).hexdigest()'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/auth/reset-token"
  body: '{"username": "admin"}'
  expected_vuln_indicator: "reset_token"
---

# PV-N2-012: Token de Recuperación Predecible

## Descripción Técnica
`generate_reset_token_legacy` en `app_python/auth_service.py` deriva el token de restablecimiento calculando el hash MD5 de `{username}:{timestamp}`, permitiendo a un atacante adivinar tokens de cualquier cuenta generando hashes en la ventana de segundos del ataque.
"""),

    # 6. PV-TRAP-026 (Cryptographic Reset Token)
    ("06_false_positive_traps/PV-TRAP-026_cryptographic_reset_token.md", """---
id: PV-TRAP-026
title: "Trampa de Falso Positivo: Generación Criptográfica Segura de Tokens de Recuperación"
description: "Uso del módulo secrets para emitir tokens CSPRNG de 256 bits inmunes a adivinación temporal."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-330
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/auth_service.py
line_start: 59
line_end: 63
anchor: "secrets.token_urlsafe(32)"
twin_of: PV-N2-012
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/auth/reset-token"
  body: '{"username": "admin"}'
  expected_vuln_indicator: "reset_token"
---

# PV-TRAP-026: Trampa FP - Token Criptográfico Seguro

## Descripción Técnica
Gemelo seguro de `PV-N2-012`. `generate_reset_token_secure` en `app_python/auth_service.py` invoca `secrets.token_urlsafe(32)` proveyendo 256 bits de entropía real extraída del generador criptográfico del sistema operativo (`/dev/urandom`).
"""),

    # 7. PV-N2-013 (User Enumeration)
    ("03_auth_and_secrets/PV-N2-013_user_enumeration_timing.md", """---
id: PV-N2-013
title: "Enumeración de Cuentas por Mensajes de Error Diferenciados en Autenticación"
description: "Fuga de información que revela existencia de usuarios mediante mensajes distintos para usuario y contraseña."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-204
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/auth_service.py
line_start: 21
line_end: 34
anchor: '"Usuario no existe en el sistema"'
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/auth/login-enum"
  body: '{"username": "non_existent_user", "password_hash": "dummy"}'
  expected_vuln_indicator: "Usuario no existe"
---

# PV-N2-013: Enumeración de Usuarios en Autenticación

## Descripción Técnica
`authenticate_basic` en `app_python/auth_service.py` responde con `"Usuario no existe en el sistema"` o `"Contraseña incorrecta"`, facilitando a un atacante mapear de forma automatizada las cuentas legítimas registradas en la organización.
"""),

    # 8. PV-TRAP-027 (Constant Time Uniform Auth)
    ("06_false_positive_traps/PV-TRAP-027_constant_time_auth_uniform.md", """---
id: PV-TRAP-027
title: "Trampa de Falso Positivo: Autenticación con Mensaje Genérico y Comparación en Tiempo Constante"
description: "Mitigación de enumeración y canales laterales mediante respuesta uniforme 'Credenciales inválidas' y compare_digest."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-204
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/auth_service.py
line_start: 36
line_end: 46
anchor: "hmac.compare_digest"
twin_of: PV-N2-013
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/auth/login-enum"
  body: '{"username": "non_existent_user", "password_hash": "dummy"}'
  expected_vuln_indicator: "Credenciales invalidas"
---

# PV-TRAP-027: Trampa FP - Autenticación en Tiempo Constante

## Descripción Técnica
Gemelo seguro de `PV-N2-013`. `authenticate_constant_time` en `app_python/auth_service.py` evalúa siempre la comparación mediante `hmac.compare_digest` (incluso contra un hash ficticio si el usuario no existe) y devuelve un mensaje unívoco indistinguible.
"""),

    # 9. PV-N3-005 (SSRF DNS Rebinding)
    ("04_ssrf_and_deserialization/PV-N3-005_ssrf_dns_rebinding_bypass.md", """---
id: PV-N3-005
title: "Falsificación de Peticiones del Servidor (SSRF) en Cliente Webhook Remoto"
description: "Envío de solicitudes HTTP a URLs externas sin comprobación de rangos de red privada ni bucle local."
kind: vuln
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/ssrf_client.py
line_start: 14
line_end: 24
anchor: "urllib.request.urlopen(req"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/webhook/fetch"
  body: '{"url": "http://127.0.0.1:5001/health"}'
  expected_vuln_indicator: "app_python"
---

# PV-N3-005: SSRF en Cliente de Integración

## Descripción Técnica
`fetch_webhook_simple` en `app_python/ssrf_client.py` invoca `urllib.request.urlopen` directamente sobre la dirección provista por el llamante, permitiendo alcanzar microservicios internos, instancias de metadatos o servicios de bucle local.
"""),

    # 10. PV-TRAP-028 (SSRF Pre-Resolution Filter)
    ("06_false_positive_traps/PV-TRAP-028_ssrf_pre_resolution_filter.md", """---
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
"""),

    # 11. PV-N2-014 (Insecure YAML Deserialization)
    ("04_ssrf_and_deserialization/PV-N2-014_insecure_yaml_deserialization.md", """---
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
  body: "app_name: CorporatePortal\nversion: 2.0"
  expected_vuln_indicator: "parsed"
---

# PV-N2-014: Deserialización YAML Insegura

## Descripción Técnica
`parse_config_yaml_direct` en `app_python/yaml_parser.py` invoca `yaml.load(..., Loader=yaml.Loader)`, el cual permite etiquetas personalizadas como `!!python/object/apply` ejecutando funciones del sistema operativo de manera arbitraria.
"""),

    # 12. PV-TRAP-029 (Safe YAML Loader)
    ("06_false_positive_traps/PV-TRAP-029_safe_yaml_loader.md", """---
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
line_start: 23
line_end: 27
anchor: "yaml.safe_load(yaml_text)"
twin_of: PV-N2-014
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/config/yaml"
  body: "app_name: CorporatePortal\nversion: 2.0"
  expected_vuln_indicator: "parsed"
---

# PV-TRAP-029: Trampa FP - Cargador Seguro de YAML

## Descripción Técnica
Gemelo seguro de `PV-N2-014`. `parse_config_yaml_safe` en `app_python/yaml_parser.py` utiliza `yaml.safe_load()`, bloqueando la instanciación de clases de Python y serializando exclusivamente cadenas, números, listas y mapas.
"""),

    # 13. PV-N2-015 (Prototype Pollution)
    ("01_injection/PV-N2-015_prototype_pollution_merge.md", """---
id: PV-N2-015
title: "Contaminación de Prototipos de Objetos (Prototype Pollution) en Combinación Recursiva"
description: "Fusión recursiva de objetos JSON sin bloquear __proto__ ni constructor permitiendo modificar Object.prototype."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-1321
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/mergeUtil.js
line_start: 9
line_end: 21
anchor: "deepMergeInsecure(target[key], source[key])"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/config/merge"
  body: '{"__proto__": {"polluted": true}}'
  expected_vuln_indicator: "production"
---

# PV-N2-015: Prototype Pollution en Mezcla de Objetos

## Descripción Técnica
`deepMergeInsecure` en `app_node/services/mergeUtil.js` recorre recursivamente las claves de la fuente asignándolas al objeto destino sin filtrar propiedades especiales como `__proto__`, permitiendo contaminar `Object.prototype`.
"""),

    # 14. PV-TRAP-030 (Proto Pollution Sanitized)
    ("06_false_positive_traps/PV-TRAP-030_proto_pollution_sanitized.md", """---
id: PV-TRAP-030
title: "Trampa de Falso Positivo: Combinación Segura de Objetos con Filtro de Claves Prohibidas"
description: "Fusión recursiva bloqueando explícitamente __proto__, constructor y prototype y creando mapas sin prototipo."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-1321
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/mergeUtil.js
line_start: 23
line_end: 41
anchor: "FORBIDDEN_KEYS.has(key)"
twin_of: PV-N2-015
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/config/merge"
  body: '{"__proto__": {"polluted": true}}'
  expected_vuln_indicator: "production"
---

# PV-TRAP-030: Trampa FP - Combinación Segura contra Prototype Pollution

## Descripción Técnica
Gemelo seguro de `PV-N2-015`. `deepMergeSecure` en `app_node/services/mergeUtil.js` descarta de forma tajante las claves `__proto__`, `constructor` y `prototype`, empleando diccionarios puros instanciados mediante `Object.create(null)`.
"""),

    # 15. PV-N2-016 (NoSQL Injection)
    ("01_injection/PV-N2-016_nosql_code_injection.md", """---
id: PV-N2-016
title: "Inyección de Expresiones de Código en Filtrado de Colecciones (NoSQL Injection)"
description: "Construcción dinámica de funciones de filtro JavaScript a partir de parámetros no saneados del usuario."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-943
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/catalogController.js
line_start: 14
line_end: 25
anchor: "new Function('item', `return ${userFilter};`)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/catalog/search?filter=true"
  expected_vuln_indicator: "Servidor Rack 1U"
---

# PV-N2-016: Inyección NoSQL en Expresión de Catálogo

## Descripción Técnica
`queryCatalogNoSql` en `app_node/controllers/catalogController.js` concatena el parámetro `filter` directamente en el constructor `new Function(...)`, permitiendo a un atacante ejecutar código JavaScript arbitrario durante el filtrado.
"""),

    # 16. PV-TRAP-035 (NoSQL Safe Property Filter)
    ("06_false_positive_traps/PV-TRAP-035_nosql_safe_property_filter.md", """---
id: PV-TRAP-035
title: "Trampa de Falso Positivo: Filtrado de Catálogo con Comparaciones Fuertemente Tipadas"
description: "Búsqueda en inventario mediante comparadores estrictos de atributos de objeto sin evaluación dinámica de código."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-943
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/catalogController.js
line_start: 27
line_end: 38
anchor: "item.category === category"
twin_of: PV-N2-016
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/catalog/search?category=hardware"
  expected_vuln_indicator: "Servidor Rack 1U"
---

# PV-TRAP-035: Trampa FP - Filtrado de Propiedades Seguro

## Descripción Técnica
Gemelo seguro de `PV-N2-016`. `queryCatalogSafe` en `app_node/controllers/catalogController.js` evalúa predicados booleanos estáticos sobre `item.category` e `item.price` convertidos explícitamente a tipos primitivos seguros.
"""),

    # 17. PV-N2-017 (Zip Slip)
    ("02_access_control_idor/PV-N2-017_zip_slip_path_traversal.md", """---
id: PV-N2-017
title: "Extracción Arbitraria de Archivos en Descompresión de Archivos ZIP (Zip Slip)"
description: "Invocación de extractall sin validar si las rutas de los archivos empaquetados escapan con secuencias '../'."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/archive_extractor.py
line_start: 14
line_end: 23
anchor: "archive.extractall(output_directory)"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/archive/extract"
  body: '{"zip_path": "/nonexistent.zip", "dest_dir": "/tmp"}'
  expected_vuln_indicator: "Fallo"
---

# PV-N2-017: Zip Slip en Extracción de Paquetes

## Descripción Técnica
`extract_bundle_direct` en `app_python/archive_extractor.py` delega en `archive.extractall()`, la cual no garantiza en versiones vulnerables o entornos personalizados que las rutas relativas ascendentes (`../../etc/cron.d/job`) no sobrescriban archivos del sistema.
"""),

    # 18. PV-TRAP-036 (Zip Commonpath Check)
    ("06_false_positive_traps/PV-TRAP-036_zip_extraction_commonpath_check.md", """---
id: PV-TRAP-036
title: "Trampa de Falso Positivo: Descompresión de Paquetes con Comprobación de commonpath"
description: "Extracción de miembros de archivos comprimidos validando que cada archivo resuelto resida bajo el directorio base."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/archive_extractor.py
line_start: 26
line_end: 39
anchor: "os.path.commonpath([resolved_base, target_path])"
twin_of: PV-N2-017
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/archive/extract"
  body: '{"zip_path": "/nonexistent.zip", "dest_dir": "/tmp"}'
  expected_vuln_indicator: "Fallo"
---

# PV-TRAP-036: Trampa FP - Extracción ZIP con Validación de Frontera

## Descripción Técnica
Gemelo seguro de `PV-N2-017`. `extract_bundle_validated` en `app_python/archive_extractor.py` calcula la ruta absoluta de cada entrada y valida mediante `os.path.commonpath` que la ruta común sea idéntica al directorio base, rechazando cualquier intento de Directory Traversal.
"""),

    # 19. PV-N3-006 (Node Template Injection)
    ("01_injection/PV-N3-006_template_injection_eval.md", """---
id: PV-N3-006
title: "Inyección de Plantillas del Servidor (SSTI) en Node.js vía new Function"
description: "Evaluación de cadenas de plantilla controladas por el cliente usando literales de plantilla y new Function."
kind: vuln
difficulty_level: 3
hops: 2
split: dev
cwe: CWE-1336
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/templateController.js
line_start: 9
line_end: 21
anchor: "new Function('username', `return \\`${templateStr}\\`;`)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/template/render"
  body: '{"template": "Hola ${username}", "username": "admin"}'
  expected_vuln_indicator: "Hola admin"
---

# PV-N3-006: Inyección de Plantilla en Node.js

## Descripción Técnica
`renderCustomTemplate` en `app_node/controllers/templateController.js` interpola la cadena `templateStr` dentro de un constructor `new Function(...)`, permitiendo a un atacante inyectar expresiones como `${process.mainModule.require('child_process').execSync('id')}` logrando ejecución remota de código.
"""),

    # 20. PV-TRAP-037 (Precompiled Template)
    ("06_false_positive_traps/PV-TRAP-037_template_precompiled_safe.md", """---
id: PV-TRAP-037
title: "Trampa de Falso Positivo: Mensajes de Notificación con Plantilla Precompilada y Escape"
description: "Generación de notificaciones formateadas mediante plantillas estáticas y saneamiento contextual de variables."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1336
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/templateController.js
line_start: 23
line_end: 31
anchor: "Su solicitud ha sido procesada con exito"
twin_of: PV-N3-006
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/template/render"
  body: '{"username": "admin"}'
  expected_vuln_indicator: "Su solicitud ha sido procesada con exito"
---

# PV-TRAP-037: Trampa FP - Plantilla Estática Precompilada

## Descripción Técnica
Gemelo seguro de `PV-N3-006`. `renderPrecompiledTemplate` en `app_node/controllers/templateController.js` utiliza una plantilla estática precompilada y escapa los caracteres HTML de las variables de entrada sin recurrir a evaluadores dinámicos.
"""),

    # 21. PV-N1-009 (SCA PyYAML)
    ("05_misconfiguration/PV-N1-009_vulnerable_dependency_python.md", """---
id: PV-N1-009
title: "Dependencia Vulnerable en Ecosistema Python (PyYAML Deserialization RCE)"
description: "Inclusión de versión obsoleta pyyaml==5.3.1 con vulnerabilidad crítica de ejecución remota de código."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: requirements.txt
line_start: 1
line_end: 7
anchor: "pyyaml==5.3.1"
expected_static_detectors:
  - trivy_sca
  - osv
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "requirements.txt"
  expected_vuln_indicator: "pyyaml==5.3.1"
---

# PV-N1-009: Dependencia Insegura en Python

## Descripción Técnica
`requirements.txt` especifica la versión `pyyaml==5.3.1` afectada por CVE-2020-14343, permitiendo a un atacante que controle el documento deserializado ejecutar comandos en el sistema anfitrión.
"""),

    # 22. PV-TRAP-031 (Hardened Dependency Usage)
    ("06_false_positive_traps/PV-TRAP-031_hardened_dependency_usage.md", """---
id: PV-TRAP-031
title: "Trampa de Falso Positivo: Especificación de Librería Criptográfica en Versión Saneada"
description: "Uso de la librería cryptography en versión auditada y exenta de fallos conocidos en manifiesto."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: requirements.txt
line_start: 1
line_end: 7
anchor: "cryptography==39.0.1"
twin_of: PV-N1-009
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "requirements.txt"
  expected_vuln_indicator: "cryptography==39.0.1"
---

# PV-TRAP-031: Trampa FP - Dependencia con Versión Estable

## Descripción Técnica
Gemelo seguro de `PV-N1-009`. La declaración de `cryptography==39.0.1` en `requirements.txt` representa un componente auditado con fijación exacta de versión y sin vectores de vulnerabilidad conocidos aplicables al alcance del servicio.
"""),

    # 23. PV-N1-010 (SCA Lodash Node)
    ("05_misconfiguration/PV-N1-010_vulnerable_dependency_node.md", """---
id: PV-N1-010
title: "Dependencia de Terceros Vulnerable en Node.js (Lodash Prototype Pollution)"
description: "Declaración en package.json de la versión lodash@4.17.15 sujeta a vulnerabilidad de contaminación de prototipos."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: package.json
line_start: 1
line_end: 22
anchor: '"lodash": "4.17.15"'
expected_static_detectors:
  - trivy_sca
  - osv
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "package.json"
  expected_vuln_indicator: "lodash"
---

# PV-N1-010: Paquete de Dependencia Vulnerable en Node.js

## Descripción Técnica
`package.json` declara `"lodash": "4.17.15"` afectada por CVE-2020-8203 y CVE-2019-10744, donde los métodos `zipObjectDeep` y `defaultsDeep` permiten la manipulación del prototipo base `Object.prototype`.
"""),

    # 24. PV-TRAP-032 (Safe Package Lock)
    ("06_false_positive_traps/PV-TRAP-032_safe_package_import_lock.md", """---
id: PV-TRAP-032
title: "Trampa de Falso Positivo: Declaración de Módulo Express con Versión Parcheada"
description: "Uso de express 4.18.2 sin dependencias vulnerables transitivas en el archivo de manifiesto."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-1104
owasp: "A06:2021 - Vulnerable and Outdated Components"
language: generic
file: package.json
line_start: 1
line_end: 22
anchor: '"express": "^4.18.2"'
twin_of: PV-N1-010
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "package.json"
  expected_vuln_indicator: "express"
---

# PV-TRAP-032: Trampa FP - Manifiesto con Versión Parcheada

## Descripción Técnica
Gemelo seguro de `PV-N1-010`. `package.json` incluye `"express": "^4.18.2"`, versión madura y mantenida que no presenta vulnerabilidades activas registradas en las bases de datos de seguridad CVE/NVD.
"""),

    # 25. PV-N1-011 (Dockerfile Root User)
    ("05_misconfiguration/PV-N1-011_dockerfile_root_user.md", """---
id: PV-N1-011
title: "Mala Configuración en Imagen Docker: Ejecución como Superusuario Root"
description: "Construcción de contenedor ejecutando el proceso bajo privilegios de root y exponiendo puertos innecesarios."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-250
owasp: "A05:2021 - Security Misconfiguration"
language: dockerfile
file: infra/Dockerfile.insecure
line_start: 1
line_end: 14
anchor: "USER root"
expected_static_detectors:
  - trivy_misconfig
  - checkov
expected_agent_detectors:
  - controls_auditor
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/Dockerfile.insecure"
  expected_vuln_indicator: "USER root"
---

# PV-N1-011: Contenedor con Ejecución como Root

## Descripción Técnica
`infra/Dockerfile.insecure` declara explícitamente `USER root` y utiliza una etiqueta flotante `latest`, lo cual vulnera las buenas prácticas de aislamiento en contenedores y facilita la escalación de privilegios en el host si existe escape.
"""),

    # 26. PV-TRAP-033 (Dockerfile Hardened)
    ("06_false_positive_traps/PV-TRAP-033_dockerfile_unprivileged_user.md", """---
id: PV-TRAP-033
title: "Trampa de Falso Positivo: Dockerfile con Usuario Dedicado sin Privilegios y Healthcheck"
description: "Imagen de contenedor securizada con creación de usuario appuser, etiqueta inmutable y sonda de salud."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-250
owasp: "A05:2021 - Security Misconfiguration"
language: dockerfile
file: infra/Dockerfile.hardened
line_start: 1
line_end: 18
anchor: "USER appuser"
twin_of: PV-N1-011
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/Dockerfile.hardened"
  expected_vuln_indicator: "USER appuser"
---

# PV-TRAP-033: Trampa FP - Dockerfile con Usuario No Privilegiado

## Descripción Técnica
Gemelo seguro de `PV-N1-011`. `infra/Dockerfile.hardened` utiliza la imagen base inmutable `python:3.11-slim-bookworm`, crea un usuario y grupo sin privilegios (`appuser:appgroup`), y añade directivas de `HEALTHCHECK`.
"""),

    # 27. PV-N1-012 (Docker Compose Privileged)
    ("05_misconfiguration/PV-N1-012_docker_compose_privileged.md", """---
id: PV-N1-012
title: "Mala Configuración IaC: Contenedor en Modo Privilegiado y Montaje de Docker Socket"
description: "Configuración docker-compose otorgando privileged=true y acceso directo al socket del daemon Docker del anfitrión."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-732
owasp: "A05:2021 - Security Misconfiguration"
language: yaml
file: infra/docker-compose.insecure.yml
line_start: 1
line_end: 14
anchor: "privileged: true"
expected_static_detectors:
  - trivy_misconfig
  - checkov
expected_agent_detectors:
  - controls_auditor
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/docker-compose.insecure.yml"
  expected_vuln_indicator: "privileged: true"
---

# PV-N1-012: Contenedor Privilegiado en Docker Compose

## Descripción Técnica
`infra/docker-compose.insecure.yml` define `privileged: true` y monta `/var/run/docker.sock`, lo que otorga al contenedor control completo sobre el daemon de Docker del host y capacidad de comprometer el sistema operativo completo.
"""),

    # 28. PV-TRAP-034 (Docker Compose Hardened)
    ("06_false_positive_traps/PV-TRAP-034_docker_compose_drop_capabilities.md", """---
id: PV-TRAP-034
title: "Trampa de Falso Positivo: Docker Compose con Sistema de Archivos de Solo Lectura y Reducción de Capacidades"
description: "Composición de servicios endurecida con read_only=true, cap_drop=ALL y puertos vinculados a 127.0.0.1."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-732
owasp: "A05:2021 - Security Misconfiguration"
language: yaml
file: infra/docker-compose.hardened.yml
line_start: 1
line_end: 13
anchor: "cap_drop:"
twin_of: PV-N1-012
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: none
  method: STATIC
  path: "infra/docker-compose.hardened.yml"
  expected_vuln_indicator: "cap_drop:"
---

# PV-TRAP-034: Trampa FP - Docker Compose Endurecido

## Descripción Técnica
Gemelo seguro de `PV-N1-012`. `infra/docker-compose.hardened.yml` fija `privileged: false`, `read_only: true`, retira todas las capacidades del kernel (`cap_drop: [ALL]`) y restringe la exposición de red a la interfaz de bucle local.
"""),
]

def main():
    for rel_path, content in CARDS:
        card_file = META_CASES / rel_path
        card_file.parent.mkdir(parents=True, exist_ok=True)
        card_file.write_text(content.strip() + "\n", encoding="utf-8")
        print(f"[+] Escrita ficha: {rel_path}")

if __name__ == "__main__":
    main()
