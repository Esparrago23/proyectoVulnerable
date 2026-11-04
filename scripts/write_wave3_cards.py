"""Script generador de fichas markdown para la Wave 3 (Fase S3).

Lleva el catálogo canónico a exactamente 100 casos empíricos.
"""

from pathlib import Path

META_CASES = Path(r"C:\Users\Esparrago\Desktop\proyectoVulnerable\meta\cases")

CARDS = [
    # 1. PV-N4-005 (Deep Multi-hop SQLi L4)
    ("01_injection/PV-N4-005_sqli_deep_multihop_billing.md", """---
id: PV-N4-005
title: "Inyección SQL Multi-Salto Profunda (Nivel 4) en Flujo de Facturación Corporativa"
description: "Flujo inter-archivo de 4 saltos (Controlador -> Pipeline -> Adaptador -> Repositorio) con interpolación de variables en consulta SQLite."
kind: vuln
difficulty_level: 4
hops: 4
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/billingService.js
line_start: 28
line_end: 39
anchor: "SELECT * FROM orders WHERE user_id = '${billingAccount}'"
expected_static_detectors:
  - codeql
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/billing/charge"
  body: '{"account": "admin'' OR ''1''=''1", "ref": "item", "amount": 100}'
  expected_vuln_indicator: "recorded"
---

# PV-N4-005: SQLi Multi-Salto Profunda (Nivel 4)

## Descripción Técnica
`recordDirectTransaction` en `app_node/services/billingService.js` recibe el parámetro `billingAccount` propagado a través de cuatro capas de abstracción consecutivas y lo interpola en una sentencia SQL sin sanitización ni parametrización.
"""),

    # 2. PV-TRAP-038 (Deep Multi-hop Param Binding L4)
    ("06_false_positive_traps/PV-TRAP-038_sqli_deep_multihop_param_binding.md", """---
id: PV-TRAP-038
title: "Trampa de Falso Positivo: Flujo de Facturación Multi-Salto con Sentencia Parametrizada"
description: "Propagación de entrada a través de 4 capas finalizando en una consulta con vinculación estricta de parámetros en la capa DAO."
kind: trap
difficulty_level: 4
hops: 4
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/services/billingService.js
line_start: 41
line_end: 51
anchor: "SELECT * FROM orders WHERE user_id = ? AND item = ?"
twin_of: PV-N4-005
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/billing/charge"
  body: '{"account": "admin'' OR ''1''=''1", "ref": "item", "amount": 100}'
  expected_vuln_indicator: "recorded"
---

# PV-TRAP-038: Trampa FP - Facturación Multi-Salto con Parámetros Ligados

## Descripción Técnica
Gemelo seguro de `PV-N4-005`. A pesar de que los parámetros cruzan cuatro niveles de componentes modulares, `recordSecureTransaction` utiliza `dbClient.db.all(sql, [billingAccount, invoiceRef], ...)` neutralizando de forma categórica la inyección.
"""),

    # 3. PV-N3-007 (Inter-service Insecure Client)
    ("04_ssrf_and_deserialization/PV-N3-007_interservice_unvalidated_forward.md", """---
id: PV-N3-007
title: "Falsificación de Peticiones del Servidor Inter-Servicio (SSRF Multi-Componente)"
description: "Reenvío no validado de acciones y destinos desde el servicio Node.js hacia microservicios backend en Python."
kind: vuln
difficulty_level: 3
hops: 3
split: test
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: javascript
file: app_node/services/internalServiceClient.js
line_start: 11
line_end: 22
anchor: "http://127.0.0.1:5001/api/tasks/webhook?action="
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/tasks/forward?action=eval&target=localhost"
  expected_vuln_indicator: "status"
---

# PV-N3-007: SSRF Inter-Servicio sin Restricción

## Descripción Técnica
`forwardInternalTask` en `app_node/services/internalServiceClient.js` compone dinámicamente peticiones HTTP hacia endpoints internos permitiendo la manipulación de acciones y la invocación de rutas no autorizadas en microservicios backend.
"""),

    # 4. PV-TRAP-039 (Inter-service Allowlist & HMAC)
    ("06_false_positive_traps/PV-TRAP-039_interservice_hmac_allowlist.md", """---
id: PV-TRAP-039
title: "Trampa de Falso Positivo: Cliente Inter-Servicio con Allowlist de Acciones y Token HMAC"
description: "Despacho entre microservicios restringido a un conjunto cerrado de acciones auditadas y firmado con HMAC-SHA256."
kind: trap
difficulty_level: 3
hops: 3
split: test
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: javascript
file: app_node/services/internalServiceClient.js
line_start: 24
line_end: 49
anchor: "ALLOWED_ACTIONS = new Set"
twin_of: PV-N3-007
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/tasks/forward?action=audit_sync&target=localhost"
  expected_vuln_indicator: "status"
---

# PV-TRAP-039: Trampa FP - Cliente Inter-Servicio Asegurado

## Descripción Técnica
Gemelo seguro de `PV-N3-007`. `forwardInternalTaskSafe` valida que `action` resida en `ALLOWED_ACTIONS`, firma los parámetros con HMAC y fija la dirección de destino a la interfaz local.
"""),

    # 5. PV-N4-006 (Coupon Discount Race Condition)
    ("02_access_control_idor/PV-N4-006_coupon_discount_race_condition.md", """---
id: PV-N4-006
title: "Condición de Carrera en Aplicación de Cupones de Descuento (Business Logic Flaw)"
description: "Comprobación no atómica de canje previo que permite la reutilización concurrente de cupones de un solo uso."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 21
line_end: 39
anchor: "REDEEMED_COUPONS.add(redemption_key)"
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/coupon/apply"
  body: '{"user": "alice", "coupon": "WELCOME20", "amount": 100.0}'
  expected_vuln_indicator: "Descuento de 20%"
---

# PV-N4-006: Falla Lógica de Negocio en Canje de Cupones

## Descripción Técnica
`apply_coupon_discount` en `app_python/tasks/coupon_service.py` valida la presencia de `redemption_key` y posteriormente la añade a la colección sin cerrojo de sincronización, permitiendo a peticiones concurrentes aplicar el beneficio múltiples veces.
"""),

    # 6. PV-TRAP-040 (Atomic Coupon Lock)
    ("06_false_positive_traps/PV-TRAP-040_coupon_discount_atomic_lock.md", """---
id: PV-TRAP-040
title: "Trampa de Falso Positivo: Aplicación de Cupones con Bloqueo Atómico de Sincronización"
description: "Operación de verificación y registro de cupones protegida por un cerrojo mutex impidiendo el canje concurrente."
kind: trap
difficulty_level: 4
hops: 2
split: test
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 42
line_end: 59
anchor: "with _LOCK:"
twin_of: PV-N4-006
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/coupon/apply"
  body: '{"user": "alice", "coupon": "WELCOME20", "amount": 100.0}'
  expected_vuln_indicator: "Descuento de 20%"
---

# PV-TRAP-040: Trampa FP - Canje Atómico de Cupones

## Descripción Técnica
Gemelo seguro de `PV-N4-006`. `apply_coupon_discount_safe` ejecuta la consulta y el registro dentro de un bloque `with _LOCK`, garantizando la serialización absoluta y la imposibilidad de canjes concurrentes.
"""),

    # 7. PV-N4-007 (Cart Quantity Logic Flaw)
    ("02_access_control_idor/PV-N4-007_cart_negative_quantity_manipulation.md", """---
id: PV-N4-007
title: "Manipulación Lógica de Importe de Carrito por Cantidades Negativas"
description: "Cálculo de importe total de compra multiplicando precios unitarios por cantidades recibidas sin validar signo positivo."
kind: vuln
difficulty_level: 4
hops: 1
split: test
cwe: CWE-1284
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/cartController.js
line_start: 15
line_end: 30
anchor: "unitPrice * qty"
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/cart/total"
  body: '{"items": [{"itemId": "item_1", "quantity": -2}]}'
  expected_vuln_indicator: "totalAmount"
---

# PV-N4-007: Manipulación Lógica de Importe de Carrito

## Descripción Técnica
`calculateCartTotal` en `app_node/controllers/cartController.js` acepta valores arbitrarios de cantidad en los artículos del pedido sin verificar que sean enteros positivos, permitiendo saldos negativos en la compra.
"""),

    # 8. PV-TRAP-041 (Cart Strict Integer Bounds)
    ("06_false_positive_traps/PV-TRAP-041_cart_quantity_strict_bounds.md", """---
id: PV-TRAP-041
title: "Trampa de Falso Positivo: Cálculo de Carrito con Validación Estricta de Cantidades Positivas"
description: "Verificación de tipo numérico entero positivo acotado (1 a 100) antes de calcular importes en el pedido."
kind: trap
difficulty_level: 4
hops: 1
split: test
cwe: CWE-1284
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/cartController.js
line_start: 32
line_end: 60
anchor: "isNaN(qty) || qty <= 0 || qty > 100"
twin_of: PV-N4-007
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/cart/total"
  body: '{"items": [{"itemId": "item_1", "quantity": 2}]}'
  expected_vuln_indicator: "totalAmount"
---

# PV-TRAP-041: Trampa FP - Validación Estricta de Cantidades

## Descripción Técnica
Gemelo seguro de `PV-N4-007`. `calculateCartTotalSafe` exige `parseInt(..., 10)` y rechaza de inmediato valores no numéricos, menores o iguales a cero o superiores al límite operativo permitido.
"""),

    # 9. PV-N4-008 (TOCTOU Inventory Race)
    ("02_access_control_idor/PV-N4-008_inventory_decrement_toctou.md", """---
id: PV-N4-008
title: "Condición de Carrera Tiempo-de-Comprobación a Tiempo-de-Uso (TOCTOU) en Inventario"
description: "Verificación separada de disponibilidad y decremento de existencias que posibilita sobreventas bajo concurrencia."
kind: vuln
difficulty_level: 4
hops: 2
split: test
cwe: CWE-367
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/inventory_service.py
line_start: 21
line_end: 37
anchor: "time.sleep(0.01)"
expected_static_detectors: []
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/inventory/decrement"
  body: '{"item_id": "prod_laptop", "count": 1}'
  expected_vuln_indicator: "Reserva de existencias completada"
---

# PV-N4-008: Carrera TOCTOU en Control de Existencias

## Descripción Técnica
`decrement_inventory_check` en `app_python/tasks/inventory_service.py` introduce una ventana temporal entre la comprobación del stock y la asignación final, provocando inconsistencias en el inventario ante accesos simultáneos.
"""),

    # 10. PV-TRAP-042 (Atomic Inventory Decrement)
    ("06_false_positive_traps/PV-TRAP-042_inventory_atomic_decrement.md", """---
id: PV-TRAP-042
title: "Trampa de Falso Positivo: Decremento Atómico de Existencias con Exclusión Mutua"
description: "Comprobación y descuento de stock ejecutados como una única instrucción atómica protegida por un cerrojo mutex."
kind: trap
difficulty_level: 4
hops: 2
split: test
cwe: CWE-367
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/inventory_service.py
line_start: 40
line_end: 50
anchor: "with _STOCK_LOCK:"
twin_of: PV-N4-008
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/inventory/decrement"
  body: '{"item_id": "prod_laptop", "count": 1}'
  expected_vuln_indicator: "Reserva de existencias completada de forma atomica"
---

# PV-TRAP-042: Trampa FP - Control Atómico de Inventario

## Descripción Técnica
Gemelo seguro de `PV-N4-008`. `decrement_inventory_atomic` realiza la comprobación y el decremento bajo el bloqueo `with _STOCK_LOCK`, impidiendo cualquier sobreventa por condiciones de carrera.
"""),

    # 11. PV-N2-018 (AES ECB Mode)
    ("03_auth_and_secrets/PV-N2-018_crypto_weak_cipher_mode_ecb.md", """---
id: PV-N2-018
title: "Uso de Modo Criptográfico Inseguro (AES-ECB) sin Vector de Inicialización"
description: "Cifrado de datos sensibles con AES en modo ECB donde bloques idénticos producen patrones repetitivos."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-327
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 14
line_end: 28
anchor: "modes.ECB()"
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/crypto/encrypt"
  body: '{"text": "confidential_text"}'
  expected_vuln_indicator: "ECB"
---

# PV-N2-018: Cifrado Débil en Modo ECB

## Descripción Técnica
`encrypt_sensitive_data_ecb` en `app_python/crypto_util.py` emplea `modes.ECB()`, el cual no utiliza vector de inicialización y preserva patrones del texto original comprometiendo la confidencialidad.
"""),

    # 12. PV-TRAP-043 (AES-256-GCM Authenticated)
    ("06_false_positive_traps/PV-TRAP-043_crypto_aes_gcm_authenticated.md", """---
id: PV-TRAP-043
title: "Trampa de Falso Positivo: Cifrado Criptográfico Robusto con AES-256-GCM y Nonce Aleatorio"
description: "Cifrado autenticado AEAD con generación de nonce único de 96 bits por operación y etiqueta de integridad."
kind: trap
difficulty_level: 2
hops: 1
split: test
cwe: CWE-327
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 31
line_end: 42
anchor: "AESGCM(key_bytes[:32])"
twin_of: PV-N2-018
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/crypto/encrypt"
  body: '{"text": "confidential_text"}'
  expected_vuln_indicator: "AES-256-GCM"
---

# PV-TRAP-043: Trampa FP - Cifrado Autenticado con AES-GCM

## Descripción Técnica
Gemelo seguro de `PV-N2-018`. `encrypt_sensitive_data_gcm` emplea `AESGCM` con nonces frescos aleatorios generados mediante `os.urandom(12)`, proveyendo simultáneamente confidencialidad e integridad criptográfica.
"""),

    # 13. PV-N1-013 (Math.random PRNG)
    ("03_auth_and_secrets/PV-N1-013_insecure_prng_math_random.md", """---
id: PV-N1-013
title: "Generación de Tokens de Seguridad con Generador Pseudoaleatorio Débil (Math.random)"
description: "Uso de Math.random() para emitir tokens anti-CSRF predecibles mediante ataques de inferencia matemática."
kind: vuln
difficulty_level: 1
hops: 1
split: test
cwe: CWE-338
owasp: "A02:2021 - Cryptographic Failures"
language: javascript
file: app_node/services/tokenUtil.js
line_start: 11
line_end: 17
anchor: "Math.random().toString(36)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/token/csrf"
  expected_vuln_indicator: "csrf_"
---

# PV-N1-013: Generador Pseudoaleatorio Débil en Tokens

## Descripción Técnica
`generateCsrfTokenInsecure` en `app_node/services/tokenUtil.js` recurre a `Math.random()`, un generador pseudoaleatorio no criptográfico cuyos estados internos pueden ser calculados por un observador externo.
"""),

    # 14. PV-TRAP-044 (crypto.randomBytes CSPRNG)
    ("06_false_positive_traps/PV-TRAP-044_crypto_randombytes_csprng.md", """---
id: PV-TRAP-044
title: "Trampa de Falso Positivo: Generación Criptográfica de Tokens con crypto.randomBytes"
description: "Emisión de tokens con 256 bits de entropía real provistos por el módulo criptográfico del sistema operativo."
kind: trap
difficulty_level: 1
hops: 1
split: test
cwe: CWE-338
owasp: "A02:2021 - Cryptographic Failures"
language: javascript
file: app_node/services/tokenUtil.js
line_start: 19
line_end: 23
anchor: "crypto.randomBytes(32).toString('hex')"
twin_of: PV-N1-013
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/token/csrf"
  expected_vuln_indicator: "csrf_sec_"
---

# PV-TRAP-044: Trampa FP - Tokens Generados con CSPRNG

## Descripción Técnica
Gemelo seguro de `PV-N1-013`. `generateCsrfTokenSecure` recurre a `crypto.randomBytes(32)`, garantizando resistencia completa frente a cualquier vector de predicción o ataques basados en tiempo.
"""),

    # 15. PV-N2-019 (Command Injection Shell)
    ("01_injection/PV-N2-019_command_injection_shell_true.md", """---
id: PV-N2-019
title: "Inyección de Comandos del Sistema Operativo con shell=True en Diagnóstico de Red"
description: "Invocación de utilidades del sistema concatenando argumentos en cadenas de texto ejecutadas en el shell."
kind: vuln
difficulty_level: 2
hops: 2
split: test
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/diagnostic_service.py
line_start: 14
line_end: 25
anchor: 'cmd = f"ping -c 1 {host_target}"'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/diagnostic/ping"
  body: '{"host": "127.0.0.1"}'
  expected_vuln_indicator: "status"
---

# PV-N2-019: Inyección de Comandos vía Shell

## Descripción Técnica
`run_system_ping_shell` en `app_python/diagnostic_service.py` construye la cadena de ejecución interpolando directamente `host_target` y llamando a `subprocess.check_output(cmd, shell=True)`, permitiendo la inyección de metacaracteres como `;` o `|`.
"""),

    # 16. PV-TRAP-045 (Safe Subprocess List)
    ("06_false_positive_traps/PV-TRAP-045_command_safe_subprocess_array.md", """---
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
line_end: 42
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
"""),

    # 17. PV-N3-008 (Blind SQLi in ORDER BY)
    ("01_injection/PV-N3-008_blind_sqli_order_by_clause.md", """---
id: PV-N3-008
title: "Inyección SQL Ciega en Cláusula ORDER BY de Reportes Analíticos"
description: "Interpolación directa de identificadores de columna en la cláusula ORDER BY donde los parámetros ligados no aplican."
kind: vuln
difficulty_level: 3
hops: 2
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/reportController.js
line_start: 11
line_end: 24
anchor: "ORDER BY ${department} ${sortOrder}"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/reports/audit?dept=item&sort=ASC"
  expected_vuln_indicator: "department"
---

# PV-N3-008: Inyección SQL en ORDER BY

## Descripción Técnica
`queryAuditReportRaw` en `app_node/controllers/reportController.js` concatena los parámetros `department` y `sort` en la cláusula de ordenación, permitiendo inferencia basada en tiempo o subconsultas booleanas.
"""),

    # 18. PV-TRAP-046 (ORDER BY Allowlist)
    ("06_false_positive_traps/PV-TRAP-046_sqli_order_by_allowlist.md", """---
id: PV-TRAP-046
title: "Trampa de Falso Positivo: Ordenación Dinámica Protegida con Lista Blanca de Columnas"
description: "Verificación de columnas contra una lista blanca fija y validación estricta del sentido de ordenación ASC/DESC."
kind: trap
difficulty_level: 3
hops: 2
split: test
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: javascript
file: app_node/controllers/reportController.js
line_start: 26
line_end: 42
anchor: "ALLOWED_COLUMNS.has(department)"
twin_of: PV-N3-008
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/reports/audit?dept=item&sort=ASC"
  expected_vuln_indicator: "department"
---

# PV-TRAP-046: Trampa FP - Ordenación Protegida con Allowlist

## Descripción Técnica
Gemelo seguro de `PV-N3-008`. `queryAuditReportSafe` descarta de forma determinante cualquier valor que no pertenezca al conjunto cerrado `ALLOWED_COLUMNS`, asignando una columna por defecto y un sentido validado.
"""),

    # 19. PV-N3-009 (Mass Assignment on is_admin)
    ("02_access_control_idor/PV-N3-009_mass_assignment_profile_admin.md", """---
id: PV-N3-009
title: "Asignación Masiva de Atributos Privilegiados en Perfil de Usuario"
description: "Actualización de objetos de usuario aplicando diccionarios completos permitiendo escalar a rol administrativo."
kind: vuln
difficulty_level: 3
hops: 2
split: test
cwe: CWE-915
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/profile_service.py
line_start: 14
line_end: 24
anchor: "profile.update(incoming_fields)"
expected_static_detectors:
  - semgrep
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/profile/update"
  body: '{"username": "alice", "updates": {"is_admin": true}}'
  expected_vuln_indicator: "updated"
---

# PV-N3-009: Asignación Masiva en Perfiles

## Descripción Técnica
`update_user_profile_mass` en `app_python/profile_service.py` invoca directamente `profile.update(incoming_fields)`, permitiendo a un usuario ordinario inyectar atributos sensibles como `is_admin: true`.
"""),

    # 20. PV-TRAP-047 (DTO Whitelist Profile Update)
    ("06_false_positive_traps/PV-TRAP-047_profile_update_strict_allowlist.md", """---
id: PV-TRAP-047
title: "Trampa de Falso Positivo: Actualización de Perfil con Lista Blanca Estricta de Campos DTO"
description: "Filtrado explícito de campos permitidos en la modificación de perfil impidiendo la alteración de roles o permisos."
kind: trap
difficulty_level: 3
hops: 2
split: test
cwe: CWE-915
owasp: "A01:2021 - Broken Access Control"
language: python
file: app_python/profile_service.py
line_start: 27
line_end: 38
anchor: 'ALLOWED_USER_FIELDS = {"display_name", "bio", "phone"}'
twin_of: PV-N3-009
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/profile/update"
  body: '{"username": "alice", "updates": {"display_name": "Alice Corp"}}'
  expected_vuln_indicator: "updated"
---

# PV-TRAP-047: Trampa FP - Perfil con Allowlist de Atributos

## Descripción Técnica
Gemelo seguro de `PV-N3-009`. `update_user_profile_filtered` filtra de forma estricta los campos contra `ALLOWED_USER_FIELDS`, descartando silenciosamente cualquier atributo privilegiado.
"""),

    # 21. PV-N2-020 (File Upload Path Traversal)
    ("02_access_control_idor/PV-N2-020_file_upload_path_traversal.md", """---
id: PV-N2-020
title: "Salto de Directorio en Carga de Archivos Adjuntos (Path Traversal in Upload)"
description: "Almacenamiento de archivos adjuntos preservando el nombre provisto por el usuario permitiendo sobrescrituras en el host."
kind: vuln
difficulty_level: 2
hops: 2
split: test
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/uploadController.js
line_start: 14
line_end: 27
anchor: "path.join(UPLOADS_DIR, filename)"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/upload/file"
  body: '{"filename": "test.txt", "content": "sample content"}'
  expected_vuln_indicator: "saved"
---

# PV-N2-020: Salto de Directorio en Carga de Archivos

## Descripción Técnica
`handleFileUploadRaw` en `app_node/controllers/uploadController.js` concatena `filename` directamente con `UPLOADS_DIR`, permitiendo que nombres como `../../etc/cron.d/pwn` escapen del directorio designado.
"""),

    # 22. PV-TRAP-048 (UUID Safe File Upload)
    ("06_false_positive_traps/PV-TRAP-048_file_upload_random_uuid_name.md", """---
id: PV-TRAP-048
title: "Trampa de Falso Positivo: Almacenamiento de Archivos con Nombre UUID y Extensión Validada"
description: "Asignación de identificador aleatorio único UUID y validación estricta de extensiones autorizadas."
kind: trap
difficulty_level: 2
hops: 2
split: test
cwe: CWE-22
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/uploadController.js
line_start: 29
line_end: 50
anchor: "ALLOWED_EXTS.has(ext)"
twin_of: PV-N2-020
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/upload/file"
  body: '{"filename": "test.txt", "content": "sample content"}'
  expected_vuln_indicator: "saved"
---

# PV-TRAP-048: Trampa FP - Carga de Archivos Asegurada

## Descripción Técnica
Gemelo seguro de `PV-N2-020`. `handleFileUploadSafe` descarta el nombre provisto por el usuario, valida la extensión contra un allowlist y almacena el archivo bajo un UUID v4 completamente seguro e impredecible.
"""),

    # 23. PV-N2-021 (CORS Permissive Null Origin)
    ("05_misconfiguration/PV-N2-021_cors_permissive_null_origin.md", """---
id: PV-N2-021
title: "Configuración CORS Permisiva con Aceptación de Origen 'null'"
description: "Reflejo del encabezado Access-Control-Allow-Origin ante solicitudes con cabecera Origin: null y credenciales habilitadas."
kind: vuln
difficulty_level: 2
hops: 1
split: test
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 65
line_end: 73
anchor: "origin === 'null'"
expected_static_detectors:
  - semgrep
  - njsscan
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/shared/reports"
  expected_vuln_indicator: "Access-Control-Allow-Origin: null"
---

# PV-N2-021: Origen Null Permitido en CORS

## Descripción Técnica
El middleware en `app_node/server.js` para `/api/shared/reports` comprueba `origin === 'null'` y devuelve cabeceras permitiendo credenciales, habilitando la extracción de datos desde sandboxed iframes o esquemas `data:`.
"""),

    # 24. PV-TRAP-049 (CORS Strict Rejection of Null)
    ("06_false_positive_traps/PV-TRAP-049_cors_explicit_rejection_null.md", """---
id: PV-TRAP-049
title: "Trampa de Falso Positivo: Configuración CORS con Rechazo Explícito de Origen 'null'"
description: "Restricción estricta de orígenes autorizados descartando explícitamente el origen 'null' y validando el dominio corporativo."
kind: trap
difficulty_level: 2
hops: 1
split: test
cwe: CWE-942
owasp: "A05:2021 - Security Misconfiguration"
language: javascript
file: app_node/server.js
line_start: 76
line_end: 83
anchor: "origin !== 'null'"
twin_of: PV-N2-021
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/safe/reports"
  expected_vuln_indicator: "Access-Control-Allow-Origin"
---

# PV-TRAP-049: Trampa FP - Rechazo de Origen Null en CORS

## Descripción Técnica
Gemelo seguro de `PV-N2-021`. La directiva de CORS para `/api/safe/reports` exige que el origen sea no nulo y coincida exactamente con el portal seguro de la corporación.
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
