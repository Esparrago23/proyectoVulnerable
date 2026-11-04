#!/usr/bin/env python3
"""Script generador de fichas markdown para la Wave 4 (20 nuevos casos L1-L4)."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "meta" / "cases"

CARDS = [
    # --- LEVEL 1 (2 vulns, 2 traps) ---
    (
        "03_auth_and_secrets/PV-N1-014_weak_hash_md5.md",
        """---
id: PV-N1-014
title: "Uso de algoritmo de hash debil MD5 para verificacion de integridad"
description: "Generacion de hashes MD5 susceptibles a colisiones criptograficas para verificacion de paquetes."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-328
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 47
line_end: 50
anchor: 'hashlib.md5(data.encode("utf-8")).hexdigest()'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_auth_secrets
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/crypto/checksum"
  expected_vuln_indicator: "md5"
---

# PV-N1-014: Uso de MD5 Debil

## Descripcion Tecnica
Generacion de digest MD5 para validar integridad sin resistencia a colisiones.
""",
    ),
    (
        "05_misconfiguration/PV-N1-015_debug_env_exposure.md",
        """---
id: PV-N1-015
title: "Exposicion de variables de entorno del sistema en endpoint de depuracion"
description: "El endpoint /api/debug/env retorna todas las variables de entorno incluyendo claves secretas."
kind: vuln
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-200
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/app.py
line_start: 870
line_end: 874
anchor: 'return jsonify(dict(os.environ)), 200'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - controls_auditor
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/debug/env"
  expected_vuln_indicator: "PATH"
---

# PV-N1-015: Exposicion de Variables de Entorno

## Descripcion Tecnica
Fuga de configuracion sensible a traves de endpoint sin autenticacion.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-050_md5_cache_key.md",
        """---
id: PV-TRAP-050
title: "Trampa FP: Clave de cache no criptografica calculada con funcion segura SHA-256"
description: "Generacion de clave de cache indexada usando algoritmo seguro sin uso criptografico de hash roto."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-328
owasp: "A02:2021 - Cryptographic Failures"
language: python
file: app_python/crypto_util.py
line_start: 52
line_end: 55
anchor: 'hashlib.sha256(data.encode("utf-8")).hexdigest()'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/cache/key"
  expected_vuln_indicator: "cache"
---

# PV-TRAP-050: Clave de Cache SHA-256

## Descripcion Tecnica
Uso valido de funcion de hash SHA-256 para asignacion de claves de almacenamiento rapido.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-051_public_system_info.md",
        """---
id: PV-TRAP-051
title: "Trampa FP: Endpoint de estado que retorna unicamente version publica sin secretos"
description: "El endpoint /api/system/public-info responde exclusivamente version semantica publica aprobada."
kind: trap
difficulty_level: 1
hops: 1
split: dev
cwe: CWE-200
owasp: "A05:2021 - Security Misconfiguration"
language: python
file: app_python/app.py
line_start: 876
line_end: 880
anchor: '"version": "2.4.0"'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: GET
  path: "/api/system/public-info"
  expected_vuln_indicator: "2.4.0"
---

# PV-TRAP-051: Metadatos Publicos de Version

## Descripcion Tecnica
Exposicion intencional y segura de numero de compilacion para comprobaciones de salud.
""",
    ),
    # --- LEVEL 2 (1 vuln, 1 trap) ---
    (
        "02_access_control_idor/PV-N2-022_order_status_idor.md",
        """---
id: PV-N2-022
title: "Modificacion de estado de orden sin verificacion de pertenencia de usuario (IDOR)"
description: "El controlador actualiza el estado de pedidos basandose unicamente en el ID recibido sin validar propietario."
kind: vuln
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/orderController.js
line_start: 30
line_end: 39
anchor: 'orderStore[orderId].status = newStatus;'
expected_static_detectors:
  - njsscan
expected_agent_detectors:
  - specialist_authz_idor
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/orders/102/status"
  expected_vuln_indicator: "completed"
---

# PV-N2-022: IDOR en Estado de Orden

## Descripcion Tecnica
Falta de verificacion de pertenencia en modificacion de entidad de negocio.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-052_order_status_session_verified.md",
        """---
id: PV-TRAP-052
title: "Trampa FP: Modificacion de orden con validacion estricta de sesion y propietario"
description: "Verificacion previa de req.session.userId contra el propietario registrado de la orden antes de mutar."
kind: trap
difficulty_level: 2
hops: 2
split: dev
cwe: CWE-639
owasp: "A01:2021 - Broken Access Control"
language: javascript
file: app_node/controllers/orderController.js
line_start: 41
line_end: 55
anchor: 'if (order.ownerId !== currentUser) {'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/orders/101/status"
  expected_vuln_indicator: "success"
---

# PV-TRAP-052: Modificacion Segura de Orden

## Descripcion Tecnica
Control de acceso por atributo validado en middleware antes del cambio de estado.
""",
    ),
    # --- LEVEL 3 (3 vulns, 5 traps) - Cross-service & polyglot ---
    (
        "01_injection/PV-N3-010_cross_service_sqli.md",
        """---
id: PV-N3-010
title: "Cross-Service Taint: Inyeccion SQL en liquidacion interna despachada desde Node a Python"
description: "Input recibido en Node despachado a Python /internal/settlement/eval concatenado directamente en SQL."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: python
file: app_python/app.py
line_start: 882
line_end: 895
anchor: "query = f\\"SELECT * FROM settlements WHERE id = '{order_id}'\\""
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/settlement/eval"
  expected_vuln_indicator: "processed"
---

# PV-N3-010: Cross-Service SQL Injection

## Descripcion Tecnica
Flujo inter-servicio sin sanitizacion cruzada que desemboca en construccion dinamica de SQL.
""",
    ),
    (
        "01_injection/PV-N3-011_cross_service_cmdi.md",
        """---
id: PV-N3-011
title: "Cross-Service Taint: Command Injection en ejecucion de archivo comprimido inter-servicio"
description: "Parametro de archivo recibido inter-servicio ejecutado mediante shell=True en subproceso del sistema."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/app.py
line_start: 897
line_end: 906
anchor: 'subprocess.Popen(cmd, shell=True)'
expected_static_detectors:
  - semgrep
  - bandit
expected_agent_detectors:
  - specialist_injection
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/settlement/archive"
  expected_vuln_indicator: "archived"
---

# PV-N3-011: Cross-Service Command Injection

## Descripcion Tecnica
Paso de argumentos no sanitizados inter-servicio hacia invocacion de shell en el host.
""",
    ),
    (
        "04_ssrf_and_deserialization/PV-N3-012_cross_service_ssrf.md",
        """---
id: PV-N3-012
title: "Cross-Service Taint: SSRF en descarga de comprobante remoto originado en cliente Node"
description: "URL proporcionada en solicitud inter-servicio conectada directamente con urllib sin validacion de IP privada."
kind: vuln
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/app.py
line_start: 908
line_end: 919
anchor: 'resp = urllib.request.urlopen(url, timeout=3)'
expected_static_detectors:
  - bandit
expected_agent_detectors:
  - specialist_ssrf
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/settlement/callback"
  expected_vuln_indicator: "notified"
---

# PV-N3-012: Cross-Service SSRF

## Descripcion Tecnica
Peticion de retorno disparada a destinos arbitrarios controlados por el cliente.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-053_cross_service_sqli_cast.md",
        """---
id: PV-TRAP-053
title: "Trampa FP: Cross-Service evaluacion de liquidacion con casteo estricto a entero en Python"
description: "El parametro recibido inter-servicio se convierte estrictamente con int() antes de cualquier operacion."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-89
owasp: "A03:2021 - Injection"
language: python
file: app_python/safe_handlers.py
line_start: 147
line_end: 151
anchor: 'clean_id = int(order_id)'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/safe/settlement/eval"
  expected_vuln_indicator: "settled"
---

# PV-TRAP-053: Mitigacion de Inyeccion por Casteo

## Descripcion Tecnica
El casteo int() neutraliza cualquier intento de escape de caracteres de sintaxis SQL.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-054_cross_service_cmdi_quoted.md",
        """---
id: PV-TRAP-054
title: "Trampa FP: Cross-Service archivo contable con validacion regex de caracteres alfanumericos"
description: "Validacion regex previa con rechazo de cualquier metacaracter antes de empaquetar."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-78
owasp: "A03:2021 - Injection"
language: python
file: app_python/safe_handlers.py
line_start: 153
line_end: 159
anchor: 'if not re.match(r"^[a-zA-Z0-9_\\-\\.]+$", archive_name):'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/safe/settlement/archive"
  expected_vuln_indicator: "archived"
---

# PV-TRAP-054: Empaquetado con Regex Estricta

## Descripcion Tecnica
Allowlist estricta de caracteres que impide metacaracteres de ejecucion de comandos.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-055_cross_service_ssrf_allowlist.md",
        """---
id: PV-TRAP-055
title: "Trampa FP: Cross-Service callback con validacion de allowlist y resolucion de IP privada"
description: "Invocacion delegada hacia safe_webhook_fetch con filtrado exhaustivo de RFC 1918 y dominios autorizados."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-918
owasp: "A10:2021 - Server-Side Request Forgery"
language: python
file: app_python/safe_handlers.py
line_start: 161
line_end: 164
anchor: 'return safe_webhook_fetch(callback_url)'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/internal/safe/settlement/callback"
  expected_vuln_indicator: "URL rechazada"
---

# PV-TRAP-055: Callback con Guardrail de Red

## Descripcion Tecnica
Bloqueo de rangos loopback, privados y metadatos de computacion en la nube.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-056_hmac_replay_prevention.md",
        """---
id: PV-TRAP-056
title: "Trampa FP: Comunicacion inter-servicio protegida con firma HMAC y verificacion de vigencia temporal"
description: "Firma SHA-256 de carga util con marca temporal que neutraliza peticiones manipuladas o retransmitidas."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-345
owasp: "A07:2021 - Identification and Authentication Failures"
language: javascript
file: app_node/services/internalServiceClient.js
line_start: 24
line_end: 49
anchor: "crypto.createHmac('sha256', internalSecret || 'default_sec')"
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_node
  method: GET
  path: "/api/tasks/webhook?action=audit_sync"
  expected_vuln_indicator: "status"
---

# PV-TRAP-056: Firma HMAC Inter-Servicio

## Descripcion Tecnica
Autenticacion criptografica robusta entre nodos del cluster interno.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-057_jwt_fixed_public_key.md",
        """---
id: PV-TRAP-057
title: "Trampa FP: Verificacion de JWT fijando algoritmo asimetrico RS256 y trust store local"
description: "El analizador de tokens rechaza cabeceras simetricas o nulas y exige firma asimetrica contra emisor confiable."
kind: trap
difficulty_level: 3
hops: 3
split: dev
cwe: CWE-347
owasp: "A07:2021 - Identification and Authentication Failures"
language: python
file: app_python/jwt_service.py
line_start: 24
line_end: 34
anchor: 'algorithms=["RS256"]'
expected_static_detectors: []
expected_agent_detectors: []
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/jwt/decode"
  expected_vuln_indicator: "claims"
---

# PV-TRAP-057: Verificacion Asimetrica de Token

## Descripcion Tecnica
Fijacion estricta de algoritmo RS256 que mitiga inyeccion de cabeceras JWK o bypass de firma.
""",
    ),
    # --- LEVEL 4 (3 vulns, 3 traps) - Business Logic & Concurrency ---
    (
        "02_access_control_idor/PV-N4-009_balance_arbitrage.md",
        """---
id: PV-N4-009
title: "Falla de Logica de Negocio: Arbitraje de redondeo en conversion de saldo de billetera"
description: "Truncamiento de decimales intermedios en conversiones bidireccionales que permite acumulacion de centavos."
kind: vuln
difficulty_level: 4
hops: 3
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 65
line_end: 70
anchor: 'step1 = int(amount * rate_a * 100) / 100.0'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/wallet/convert"
  expected_vuln_indicator: "arbitrage"
---

# PV-N4-009: Arbitraje de Redondeo de Moneda

## Descripcion Tecnica
Error de precision en logica financiera que genera distorsiones de saldo acumulables.
""",
    ),
    (
        "02_access_control_idor/PV-N4-010_coupon_race_toctou.md",
        """---
id: PV-N4-010
title: "Falla de Logica de Negocio: Condicion de carrera TOCTOU en aplicacion concurrente de cupon"
description: "Comprobacion de limite de uso separada temporalmente del incremento permitiendo multiples canjes simultaneos."
kind: vuln
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/orderController.js
line_start: 57
line_end: 71
anchor: 'if (coupon.used >= coupon.limit) {'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
  - specialists_ensemble
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/orders/coupon/race"
  expected_vuln_indicator: "discountApplied"
---

# PV-N4-010: Carrera TOCTOU en Cupon

## Descripcion Tecnica
Ventana de tiempo entre check y use sin transaccion serializada ni cerrojo atomico.
""",
    ),
    (
        "02_access_control_idor/PV-N4-011_chained_settlement_overdraw.md",
        """---
id: PV-N4-011
title: "Falla de Logica de Negocio: Sobregiro en transferencias encadenadas por debito previo a validacion"
description: "Debito aplicado antes de verificar la cuenta destino, fallando en revertir el saldo ante excepciones."
kind: vuln
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/doc_service.py
line_start: 55
line_end: 65
anchor: 'balances[sender] -= amount'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
  - specialists_ensemble
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/wallet/chain-settle"
  expected_vuln_indicator: "overdraw"
---

# PV-N4-011: Sobregiro en Liquidacion Encadenada

## Descripcion Tecnica
Modificacion de estado inconsistente ante fallos parciales sin bloque transaccional.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-058_decimal_currency_conversion.md",
        """---
id: PV-TRAP-058
title: "Trampa FP: Conversion de divisas con precision decimal exacta y redondeo bancario"
description: "Uso del modulo Decimal con ROUND_HALF_EVEN que neutraliza cualquier arbitraje de fracciones monetarias."
kind: trap
difficulty_level: 4
hops: 3
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/tasks/coupon_service.py
line_start: 72
line_end: 80
anchor: 'd_amount = Decimal(str(amount))'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/wallet/convert"
  expected_vuln_indicator: "exact"
---

# PV-TRAP-058: Precision Financiera con Decimal

## Descripcion Tecnica
Redondeo simetrico que preserva la paridad matematica en toda conversion de divisas.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-059_coupon_atomic_mutex.md",
        """---
id: PV-TRAP-059
title: "Trampa FP: Aplicacion de cupon protegida con bloqueo mutex atomico contra carreras"
description: "El cerrojo isCouponLocked serializa las solicitudes concurrentes impidiendo canjes duplicados."
kind: trap
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-362
owasp: "A04:2021 - Insecure Design"
language: javascript
file: app_node/controllers/orderController.js
line_start: 73
line_end: 93
anchor: 'isCouponLocked = true;'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
dynamic_probe:
  service: app_node
  method: POST
  path: "/api/safe/orders/coupon/atomic"
  expected_vuln_indicator: "Operacion en curso"
---

# PV-TRAP-059: Exclusion Mutua en Canje de Cupon

## Descripcion Tecnica
Bloqueo atomico en memoria que asegura aislamiento de la operacion critica.
""",
    ),
    (
        "06_false_positive_traps/PV-TRAP-060_chained_settlement_atomic.md",
        """---
id: PV-TRAP-060
title: "Trampa FP: Transferencia encadenada con verificacion atomica previa de ambas cuentas"
description: "Validacion previa de precondiciones en emisor y receptor antes de mutar los saldos en el libro contable."
kind: trap
difficulty_level: 4
hops: 4
split: dev
cwe: CWE-840
owasp: "A04:2021 - Insecure Design"
language: python
file: app_python/doc_service.py
line_start: 67
line_end: 76
anchor: 'if receiver not in balances:'
expected_static_detectors: []
expected_agent_detectors:
  - specialist_business_logic
dynamic_probe:
  service: app_python
  method: POST
  path: "/api/safe/wallet/chain-settle"
  expected_vuln_indicator: "settled"
---

# PV-TRAP-060: Transferencia con Verificacion Previa

## Descripcion Tecnica
Garantia de consistencia ACID mediante verificacion completa antes de la aplicacion de cambios.
""",
    ),
]


def main():
    print(f"[*] Generando {len(CARDS)} fichas markdown en {CASES_DIR}...")
    written = 0
    for rel_path, content in CARDS:
        dest = CASES_DIR / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content.strip() + "\n", encoding="utf-8")
        written += 1
        print(f"  [+] Escrito: {rel_path}")
    print(f"[+] Total fichas escritas: {written}")


if __name__ == "__main__":
    main()
