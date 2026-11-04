# Catálogo Oficial de Vulnerabilidades: Proyecto Vulnerable Escalonado

Este documento constituye la fuente de verdad técnica y documental (Ground Truth) del repositorio `proyectoVulnerable`.
Detalla cada debilidad de seguridad implementada deliberadamente y cada trampa de falso positivo,
clasificadas en **4 niveles de dificultad**, su correspondencia con el **OWASP Top 10**, su **CWE canónico**,
prueba de concepto dinámica (PoC) y remediación recomendada.

---

## Matriz Resumen de Casos (120 Casos)

| ID | Nivel | OWASP | CWE | Archivo | Líneas | Tipo | Título |
| :--- | :---: | :--- | :--- | :--- | :---: | :---: | :--- |
| `PV-N1-001` | **L1** | A03:2021 - Injection | `CWE-89` | `app_node/controllers/userController.js` | 11-17 | Vulnerabilidad | SQL Injection directa por concatenación string en getUserDirect |
| `PV-N1-002` | **L1** | A03:2021 - Injection | `CWE-78` | `app_node/controllers/userController.js` | 20-30 | Vulnerabilidad | Command Injection con child_process.exec() directo en pingHostDirect |
| `PV-N2-001` | **L2** | A03:2021 - Injection | `CWE-79` | `app_node/controllers/searchController.js` | 10-25 | Vulnerabilidad | Reflected XSS con sanitizador ingenuo que solo elimina script una vez |
| `PV-N2-005` | **L2** | A03:2021 - Injection | `CWE-1336` | `app_python/app.py` | 517-525 | Vulnerabilidad | Server-Side Template Injection (SSTI) con render_template_string en vista previa |
| `PV-N2-006` | **L2** | A03:2021 - Injection | `CWE-79` | `app_node/controllers/feedbackController.js` | 16-27 | Vulnerabilidad | Stored Cross-Site Scripting (XSS) en comentarios de retroalimentación |
| `PV-N2-007` | **L2** | A05:2021 - Security Misconfiguration | `CWE-611` | `app_python/xml_parser.py` | 13-28 | Vulnerabilidad | XML External Entity (XXE) Injection en analizador de facturas tributarias |
| `PV-N2-008` | **L2** | A05:2021 - Security Misconfiguration | `CWE-1333` | `app_node/controllers/searchController.js` | 84-90 | Vulnerabilidad | Regular Expression Denial of Service (ReDoS) por cuantificadores anidados |
| `PV-N2-009` | **L2** | A03:2021 - Injection | `CWE-113` | `app_node/controllers/searchController.js` | 105-110 | Vulnerabilidad | HTTP Response Splitting / CRLF Injection en cabecera personalizada |
| `PV-N2-015` | **L2** | A03:2021 - Injection | `CWE-1321` | `app_node/services/mergeUtil.js` | 9-21 | Vulnerabilidad | Contaminación de Prototipos de Objetos (Prototype Pollution) en Combinación Recursiva |
| `PV-N2-016` | **L2** | A03:2021 - Injection | `CWE-943` | `app_node/controllers/catalogController.js` | 14-25 | Vulnerabilidad | Inyección de Expresiones de Código en Filtrado de Colecciones (NoSQL Injection) |
| `PV-N2-019` | **L2** | A03:2021 - Injection | `CWE-78` | `app_python/diagnostic_service.py` | 14-25 | Vulnerabilidad | Inyección de Comandos del Sistema Operativo con shell=True en Diagnóstico de Red |
| `PV-N3-001` | **L3** | A03:2021 - Injection | `CWE-89` | `app_node/models/dbClient.js` | 34-41 | Vulnerabilidad | SQLi Multi-Salto: controller -> service -> DAO concatenado en queryOrderRaw |
| `PV-N3-006` | **L3** | A03:2021 - Injection | `CWE-1336` | `app_node/controllers/templateController.js` | 9-21 | Vulnerabilidad | Inyección de Plantillas del Servidor (SSTI) en Node.js vía new Function |
| `PV-N3-008` | **L3** | A03:2021 - Injection | `CWE-89` | `app_node/controllers/reportController.js` | 11-24 | Vulnerabilidad | Inyección SQL Ciega en Cláusula ORDER BY de Reportes Analíticos |
| `PV-N3-010` | **L3** | A03:2021 - Injection | `CWE-89` | `app_python/app.py` | 882-895 | Vulnerabilidad | Cross-Service Taint: Inyeccion SQL en liquidacion interna despachada desde Node a Python |
| `PV-N3-011` | **L3** | A03:2021 - Injection | `CWE-78` | `app_python/app.py` | 897-906 | Vulnerabilidad | Cross-Service Taint: Command Injection en ejecucion de archivo comprimido inter-servicio |
| `PV-N4-005` | **L4** | A03:2021 - Injection | `CWE-89` | `app_node/services/billingService.js` | 28-39 | Vulnerabilidad | Inyección SQL Multi-Salto Profunda (Nivel 4) en Flujo de Facturación Corporativa |
| `PV-N1-006` | **L1** | A01:2021 - Broken Access Control | `CWE-601` | `app_node/controllers/searchController.js` | 67-71 | Vulnerabilidad | Open URL Redirect sin validación de destino en endpoint de navegación |
| `PV-N2-002` | **L2** | A01:2021 - Broken Access Control | `CWE-22` | `app_node/controllers/searchController.js` | 28-41 | Vulnerabilidad | Path Traversal con reemplazo no recursivo de ../ en downloadAsset |
| `PV-N2-017` | **L2** | A01:2021 - Broken Access Control | `CWE-22` | `app_python/archive_extractor.py` | 14-23 | Vulnerabilidad | Extracción Arbitraria de Archivos en Descompresión de Archivos ZIP (Zip Slip) |
| `PV-N2-020` | **L2** | A01:2021 - Broken Access Control | `CWE-22` | `app_node/controllers/uploadController.js` | 14-27 | Vulnerabilidad | Salto de Directorio en Carga de Archivos Adjuntos (Path Traversal in Upload) |
| `PV-N2-022` | **L2** | A01:2021 - Broken Access Control | `CWE-639` | `app_node/controllers/orderController.js` | 30-39 | Vulnerabilidad | Modificacion de estado de orden sin verificacion de pertenencia de usuario (IDOR) |
| `PV-N3-003` | **L3** | A01:2021 - Broken Access Control | `CWE-269` | `app_node/services/roleService.js` | 13-26 | Vulnerabilidad | Escalación de Privilegios Multi-Salto por Merge de Propiedades en roleService |
| `PV-N3-004` | **L3** | A01:2021 - Broken Access Control | `CWE-639` | `app_python/doc_service.py` | 35-40 | Vulnerabilidad | IDOR en servicio de consulta y descarga de comprobantes documentales |
| `PV-N3-009` | **L3** | A01:2021 - Broken Access Control | `CWE-915` | `app_python/profile_service.py` | 14-24 | Vulnerabilidad | Asignación Masiva de Atributos Privilegiados en Perfil de Usuario |
| `PV-N4-001` | **L4** | A01:2021 - Broken Access Control | `CWE-639` | `app_node/controllers/invoiceController.js` | 7-19 | Vulnerabilidad | Insecure Direct Object Reference (IDOR) sin validación de tenant de factura |
| `PV-N4-004` | **L4** | A01:2021 - Broken Access Control | `CWE-862` | `app_python/app.py` | 201-216 | Vulnerabilidad | Manipulación Lógica de Saldo mediante Transferencia de Montos Negativos |
| `PV-N4-006` | **L4** | A04:2021 - Insecure Design | `CWE-362` | `app_python/tasks/coupon_service.py` | 21-39 | Vulnerabilidad | Condición de Carrera en Aplicación de Cupones de Descuento (Business Logic Flaw) |
| `PV-N4-007` | **L4** | A04:2021 - Insecure Design | `CWE-1284` | `app_node/controllers/cartController.js` | 15-30 | Vulnerabilidad | Manipulación Lógica de Importe de Carrito por Cantidades Negativas |
| `PV-N4-008` | **L4** | A04:2021 - Insecure Design | `CWE-367` | `app_python/tasks/inventory_service.py` | 21-37 | Vulnerabilidad | Condición de Carrera Tiempo-de-Comprobación a Tiempo-de-Uso (TOCTOU) en Inventario |
| `PV-N4-009` | **L4** | A04:2021 - Insecure Design | `CWE-840` | `app_python/tasks/coupon_service.py` | 65-70 | Vulnerabilidad | Falla de Logica de Negocio: Arbitraje de redondeo en conversion de saldo de billetera |
| `PV-N4-010` | **L4** | A04:2021 - Insecure Design | `CWE-362` | `app_node/controllers/orderController.js` | 57-71 | Vulnerabilidad | Falla de Logica de Negocio: Condicion de carrera TOCTOU en aplicacion concurrente de cupon |
| `PV-N4-011` | **L4** | A04:2021 - Insecure Design | `CWE-840` | `app_python/doc_service.py` | 55-65 | Vulnerabilidad | Falla de Logica de Negocio: Sobregiro en transferencias encadenadas por debito previo a validacion |
| `PV-N1-004` | **L1** | A07:2021 - Identification and Authentication Failures | `CWE-798` | `app_python/config.py` | 3-6 | Vulnerabilidad | Claves de API de AWS hardcodeadas en texto plano |
| `PV-N1-005` | **L1** | A02:2021 - Cryptographic Failures | `CWE-321` | `app_python/config.py` | 11-16 | Vulnerabilidad | Clave privada RSA PEM sin cifrar embebida en código fuente |
| `PV-N1-007` | **L1** | A02:2021 - Cryptographic Failures | `CWE-327` | `app_python/token_service.py` | 14-21 | Vulnerabilidad | Uso de algoritmo criptográfico débil (MD5) para generación de tokens de API |
| `PV-N1-008` | **L1** | A05:2021 - Security Misconfiguration | `CWE-377` | `app_python/tasks/export_task.py` | 14-22 | Vulnerabilidad | Creación insegura de archivos temporales con nombre estático y permisos predeterminados |
| `PV-N1-013` | **L1** | A02:2021 - Cryptographic Failures | `CWE-338` | `app_node/services/tokenUtil.js` | 11-17 | Vulnerabilidad | Generación de Tokens de Seguridad con Generador Pseudoaleatorio Débil (Math.random) |
| `PV-N1-014` | **L1** | A02:2021 - Cryptographic Failures | `CWE-328` | `app_python/crypto_util.py` | 47-50 | Vulnerabilidad | Uso de algoritmo de hash debil MD5 para verificacion de integridad |
| `PV-N2-010` | **L2** | A07:2021 - Identification and Authentication Failures | `CWE-347` | `app_python/jwt_service.py` | 14-21 | Vulnerabilidad | Bypass de Firma Criptográfica en Verificación de Tokens JWT |
| `PV-N2-011` | **L2** | A07:2021 - Identification and Authentication Failures | `CWE-384` | `app_node/controllers/sessionController.js` | 9-23 | Vulnerabilidad | Fijación de Sesión por Omisión de Regeneración de Identificador |
| `PV-N2-012` | **L2** | A02:2021 - Cryptographic Failures | `CWE-330` | `app_python/auth_service.py` | 49-57 | Vulnerabilidad | Generación de Token de Restablecimiento de Contraseña Predecible |
| `PV-N2-013` | **L2** | A07:2021 - Identification and Authentication Failures | `CWE-204` | `app_python/auth_service.py` | 21-34 | Vulnerabilidad | Enumeración de Cuentas por Mensajes de Error Diferenciados en Autenticación |
| `PV-N2-018` | **L2** | A02:2021 - Cryptographic Failures | `CWE-327` | `app_python/crypto_util.py` | 14-28 | Vulnerabilidad | Uso de Modo Criptográfico Inseguro (AES-ECB) sin Vector de Inicialización |
| `PV-N4-002` | **L4** | A07:2021 - Identification and Authentication Failures | `CWE-287` | `app_python/auth/mfa_handler.py` | 24-43 | Vulnerabilidad | MFA Authentication Bypass mediante bandera skip_mfa o header X-Bypass-MFA |
| `PV-N2-014` | **L2** | A08:2021 - Software and Data Integrity Failures | `CWE-502` | `app_python/yaml_parser.py` | 14-20 | Vulnerabilidad | Deserialización Insegura de Documentos YAML con yaml.load |
| `PV-N3-002` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_python/tasks/worker.py` | 10-26 | Vulnerabilidad | SSRF Multi-Salto: Webhook en background sin validación de rangos privados |
| `PV-N3-005` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_python/ssrf_client.py` | 14-24 | Vulnerabilidad | Falsificación de Peticiones del Servidor (SSRF) en Cliente Webhook Remoto |
| `PV-N3-007` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_node/services/internalServiceClient.js` | 11-22 | Vulnerabilidad | Falsificación de Peticiones del Servidor Inter-Servicio (SSRF Multi-Componente) |
| `PV-N3-012` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_python/app.py` | 908-919 | Vulnerabilidad | Cross-Service Taint: SSRF en descarga de comprobante remoto originado en cliente Node |
| `PV-N4-003` | **L4** | A08:2021 - Software and Data Integrity Failures | `CWE-502` | `app_python/tasks/worker.py` | 29-37 | Vulnerabilidad | Deserialización insegura con pickle.loads sobre datos de sesión en base64 |
| `PV-N1-003` | **L1** | A05:2021 - Security Misconfiguration | `CWE-942` | `app_node/server.js` | 23-28 | Vulnerabilidad | CORS permisivo: Wildcard Origin * con Allow-Credentials true |
| `PV-N1-009` | **L1** | A06:2021 - Vulnerable and Outdated Components | `CWE-1104` | `requirements.txt` | 1-7 | Vulnerabilidad | Dependencia Vulnerable en Ecosistema Python (PyYAML Deserialization RCE) |
| `PV-N1-010` | **L1** | A06:2021 - Vulnerable and Outdated Components | `CWE-1104` | `package.json` | 1-22 | Vulnerabilidad | Dependencia de Terceros Vulnerable en Node.js (Lodash Prototype Pollution) |
| `PV-N1-011` | **L1** | A05:2021 - Security Misconfiguration | `CWE-250` | `infra/Dockerfile.insecure` | 1-14 | Vulnerabilidad | Mala Configuración en Imagen Docker: Ejecución como Superusuario Root |
| `PV-N1-012` | **L1** | A05:2021 - Security Misconfiguration | `CWE-732` | `infra/docker-compose.insecure.yml` | 1-14 | Vulnerabilidad | Mala Configuración IaC: Contenedor en Modo Privilegiado y Montaje de Docker Socket |
| `PV-N1-015` | **L1** | A05:2021 - Security Misconfiguration | `CWE-200` | `app_python/app.py` | 870-874 | Vulnerabilidad | Exposicion de variables de entorno del sistema en endpoint de depuracion |
| `PV-N2-003` | **L2** | A05:2021 - Security Misconfiguration | `CWE-942` | `app_node/server.js` | 31-40 | Vulnerabilidad | CORS con regex permisiva que no ancla fin de cadena en subdominios |
| `PV-N2-004` | **L2** | A05:2021 - Security Misconfiguration | `CWE-552` | `.env.backup` | 1-5 | Vulnerabilidad | Archivo de backup de entorno con contraseñas y canarios expuestos |
| `PV-N2-021` | **L2** | A05:2021 - Security Misconfiguration | `CWE-942` | `app_node/server.js` | 65-73 | Vulnerabilidad | Configuración CORS Permisiva con Aceptación de Origen 'null' |
| `PV-TRAP-001` | **L2** | A03:2021 - Injection | `CWE-89` | `app_node/safe/safeSanitizers.js` | 8-22 | **Trampa FP** | Trampa de Falso Positivo: Concatenación SQL con parseInt estricto previo |
| `PV-TRAP-002` | **L2** | A01:2021 - Broken Access Control | `CWE-22` | `app_node/safe/safeSanitizers.js` | 25-37 | **Trampa FP** | Trampa de Falso Positivo: Descarga con basename y lista blanca estricta |
| `PV-TRAP-003` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_python/safe_handlers.py` | 31-78 | **Trampa FP** | Trampa de Falso Positivo: SSRF Mitigado con Allowlist de Dominio e IP Privada Bloqueada |
| `PV-TRAP-004` | **L4** | A01:2021 - Broken Access Control | `CWE-639` | `app_node/safe/safeSanitizers.js` | 39-58 | **Trampa FP** | Trampa de Falso Positivo: Facturación con Validación Estricta de Tenant ID |
| `PV-TRAP-005` | **L2** | A03:2021 - Injection | `CWE-78` | `app_node/safe/safeSanitizers.js` | 61-78 | **Trampa FP** | Trampa de Falso Positivo: Ejecución con execFile y Validación Regex IPv4 Estricta |
| `PV-TRAP-006` | **L4** | A08:2021 - Software and Data Integrity Failures | `CWE-502` | `app_python/safe_handlers.py` | 101-126 | **Trampa FP** | Trampa de Falso Positivo: Deserialización Segura con HMAC-SHA256 y JSON Exclusivo |
| `PV-TRAP-007` | **L2** | A03:2021 - Injection | `CWE-79` | `app_node/controllers/searchController.js` | 51-64 | **Trampa FP** | Trampa de Falso Positivo: XSS Neutralizado mediante Codificación Contextual HTML |
| `PV-TRAP-008` | **L3** | A03:2021 - Injection | `CWE-89` | `app_node/models/dbClient.js` | 66-73 | **Trampa FP** | Trampa de Falso Positivo: Consulta SQL Multi-Salto Parametrizada en Capa DAO |
| `PV-TRAP-009` | **L3** | A01:2021 - Broken Access Control | `CWE-915` | `app_node/services/roleService.js` | 32-52 | **Trampa FP** | Trampa de Falso Positivo: Actualización de Perfil con Lista Blanca Estricta de Campos (DTO) |
| `PV-TRAP-010` | **L4** | A01:2021 - Broken Access Control | `CWE-862` | `app_python/tasks/worker.py` | 73-95 | **Trampa FP** | Trampa de Falso Positivo: Transferencia de Fondos con Precondición de Monto Estrictamente Positivo |
| `PV-TRAP-011` | **L1** | A07:2021 - Identification and Authentication Failures | `CWE-798` | `app_python/config.py` | 7-9 | **Trampa FP** | Trampa de Falso Positivo: Clave Marcador de Posición Claramente Documentada |
| `PV-TRAP-012` | **L4** | A07:2021 - Identification and Authentication Failures | `CWE-287` | `app_python/auth/mfa_handler.py` | 48-54 | **Trampa FP** | Trampa de Falso Positivo: Verificación Estricta de TOTP sin Banderas de Bypass |
| `PV-TRAP-013` | **L2** | A05:2021 - Security Misconfiguration | `CWE-942` | `app_node/server.js` | 54-62 | **Trampa FP** | Trampa de Falso Positivo: CORS con Lista Blanca de Orígenes Exacta y Anclada |
| `PV-TRAP-014` | **L2** | A05:2021 - Security Misconfiguration | `CWE-552` | `.env.example` | 1-5 | **Trampa FP** | Trampa de Falso Positivo: Archivo de Plantilla de Entorno con Valores Sintéticos |
| `PV-TRAP-015` | **L2** | A03:2021 - Injection | `CWE-1336` | `app_python/app.py` | 527-535 | **Trampa FP** | Trampa de Falso Positivo: Renderizado de Plantilla Seguro con Contexto Fijo |
| `PV-TRAP-016` | **L2** | A03:2021 - Injection | `CWE-79` | `app_node/controllers/feedbackController.js` | 29-40 | **Trampa FP** | Trampa de Falso Positivo: Registro de Comentarios con Codificación de Entidades HTML |
| `PV-TRAP-017` | **L2** | A05:2021 - Security Misconfiguration | `CWE-611` | `app_python/xml_parser.py` | 31-47 | **Trampa FP** | Trampa de Falso Positivo: Parseo XML con Rechazo de DOCTYPE y Entidades Externas |
| `PV-TRAP-018` | **L1** | A01:2021 - Broken Access Control | `CWE-601` | `app_node/controllers/searchController.js` | 74-81 | **Trampa FP** | Trampa de Falso Positivo: Redirección Restringida a Rutas Relativas Locales |
| `PV-TRAP-019` | **L2** | A01:2021 - Broken Access Control | `CWE-639` | `app_python/doc_service.py` | 42-52 | **Trampa FP** | Trampa de Falso Positivo: Consulta Documental con Verificación Estricta de Propiedad (Tenancy) |
| `PV-TRAP-020` | **L2** | A05:2021 - Security Misconfiguration | `CWE-1333` | `app_node/controllers/searchController.js` | 93-101 | **Trampa FP** | Trampa de Falso Positivo: Validación con Expresión Regular Lineal y Límite de Longitud |
| `PV-TRAP-021` | **L2** | A03:2021 - Injection | `CWE-113` | `app_node/controllers/searchController.js` | 112-117 | **Trampa FP** | Trampa de Falso Positivo: Encabezado HTTP Personalizado con Saneamiento CRLF |
| `PV-TRAP-022` | **L1** | A02:2021 - Cryptographic Failures | `CWE-328` | `app_python/token_service.py` | 24-28 | **Trampa FP** | Trampa de Falso Positivo: Generación de Tokens de Sesión con HMAC-SHA256 |
| `PV-TRAP-023` | **L1** | A01:2021 - Broken Access Control | `CWE-377` | `app_python/tasks/export_task.py` | 25-31 | **Trampa FP** | Trampa de Falso Positivo: Creación de Archivos Temporales con Nombre Aleatorio y Permisos 0600 |
| `PV-TRAP-024` | **L2** | A07:2021 - Identification and Authentication Failures | `CWE-347` | `app_python/jwt_service.py` | 24-34 | **Trampa FP** | Trampa de Falso Positivo: Validación Criptográfica Estricta de JWT con RS256 |
| `PV-TRAP-025` | **L2** | A07:2021 - Identification and Authentication Failures | `CWE-384` | `app_node/controllers/sessionController.js` | 25-47 | **Trampa FP** | Trampa de Falso Positivo: Regeneración Estricta de Identificador de Sesión |
| `PV-TRAP-026` | **L1** | A02:2021 - Cryptographic Failures | `CWE-330` | `app_python/auth_service.py` | 59-63 | **Trampa FP** | Trampa de Falso Positivo: Generación Criptográfica Segura de Tokens de Recuperación |
| `PV-TRAP-027` | **L2** | A07:2021 - Identification and Authentication Failures | `CWE-204` | `app_python/auth_service.py` | 36-46 | **Trampa FP** | Trampa de Falso Positivo: Autenticación con Mensaje Genérico y Comparación en Tiempo Constante |
| `PV-TRAP-028` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_python/ssrf_client.py` | 27-46 | **Trampa FP** | Trampa de Falso Positivo: Cliente HTTP con Validación DNS y Filtro de IPs Privadas |
| `PV-TRAP-029` | **L1** | A08:2021 - Software and Data Integrity Failures | `CWE-502` | `app_python/yaml_parser.py` | 22-26 | **Trampa FP** | Trampa de Falso Positivo: Carga Segura de YAML con yaml.safe_load |
| `PV-TRAP-030` | **L2** | A03:2021 - Injection | `CWE-1321` | `app_node/services/mergeUtil.js` | 23-41 | **Trampa FP** | Trampa de Falso Positivo: Combinación Segura de Objetos con Filtro de Claves Prohibidas |
| `PV-TRAP-031` | **L1** | A06:2021 - Vulnerable and Outdated Components | `CWE-1104` | `requirements.txt` | 1-7 | **Trampa FP** | Trampa de Falso Positivo: Especificación de Librería Criptográfica en Versión Saneada |
| `PV-TRAP-032` | **L1** | A06:2021 - Vulnerable and Outdated Components | `CWE-1104` | `package.json` | 1-22 | **Trampa FP** | Trampa de Falso Positivo: Declaración de Módulo Express con Versión Parcheada |
| `PV-TRAP-033` | **L1** | A05:2021 - Security Misconfiguration | `CWE-250` | `infra/Dockerfile.hardened` | 1-18 | **Trampa FP** | Trampa de Falso Positivo: Dockerfile con Usuario Dedicado sin Privilegios y Healthcheck |
| `PV-TRAP-034` | **L1** | A05:2021 - Security Misconfiguration | `CWE-732` | `infra/docker-compose.hardened.yml` | 1-13 | **Trampa FP** | Trampa de Falso Positivo: Docker Compose con Sistema de Archivos de Solo Lectura y Reducción de Capacidades |
| `PV-TRAP-035` | **L1** | A03:2021 - Injection | `CWE-943` | `app_node/controllers/catalogController.js` | 27-38 | **Trampa FP** | Trampa de Falso Positivo: Filtrado de Catálogo con Comparaciones Fuertemente Tipadas |
| `PV-TRAP-036` | **L2** | A01:2021 - Broken Access Control | `CWE-22` | `app_python/archive_extractor.py` | 26-39 | **Trampa FP** | Trampa de Falso Positivo: Descompresión de Paquetes con Comprobación de commonpath |
| `PV-TRAP-037` | **L1** | A03:2021 - Injection | `CWE-1336` | `app_node/controllers/templateController.js` | 23-31 | **Trampa FP** | Trampa de Falso Positivo: Mensajes de Notificación con Plantilla Precompilada y Escape |
| `PV-TRAP-038` | **L4** | A03:2021 - Injection | `CWE-89` | `app_node/services/billingService.js` | 41-51 | **Trampa FP** | Trampa de Falso Positivo: Flujo de Facturación Multi-Salto con Sentencia Parametrizada |
| `PV-TRAP-039` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_node/services/internalServiceClient.js` | 24-49 | **Trampa FP** | Trampa de Falso Positivo: Cliente Inter-Servicio con Allowlist de Acciones y Token HMAC |
| `PV-TRAP-040` | **L4** | A04:2021 - Insecure Design | `CWE-362` | `app_python/tasks/coupon_service.py` | 42-59 | **Trampa FP** | Trampa de Falso Positivo: Aplicación de Cupones con Bloqueo Atómico de Sincronización |
| `PV-TRAP-041` | **L4** | A04:2021 - Insecure Design | `CWE-1284` | `app_node/controllers/cartController.js` | 32-60 | **Trampa FP** | Trampa de Falso Positivo: Cálculo de Carrito con Validación Estricta de Cantidades Positivas |
| `PV-TRAP-042` | **L4** | A04:2021 - Insecure Design | `CWE-367` | `app_python/tasks/inventory_service.py` | 40-49 | **Trampa FP** | Trampa de Falso Positivo: Decremento Atómico de Existencias con Exclusión Mutua |
| `PV-TRAP-043` | **L2** | A02:2021 - Cryptographic Failures | `CWE-327` | `app_python/crypto_util.py` | 31-42 | **Trampa FP** | Trampa de Falso Positivo: Cifrado Criptográfico Robusto con AES-256-GCM y Nonce Aleatorio |
| `PV-TRAP-044` | **L1** | A02:2021 - Cryptographic Failures | `CWE-338` | `app_node/services/tokenUtil.js` | 19-23 | **Trampa FP** | Trampa de Falso Positivo: Generación Criptográfica de Tokens con crypto.randomBytes |
| `PV-TRAP-045` | **L2** | A03:2021 - Injection | `CWE-78` | `app_python/diagnostic_service.py` | 28-40 | **Trampa FP** | Trampa de Falso Positivo: Diagnóstico Seguro con Lista de Argumentos y shell=False |
| `PV-TRAP-046` | **L3** | A03:2021 - Injection | `CWE-89` | `app_node/controllers/reportController.js` | 26-42 | **Trampa FP** | Trampa de Falso Positivo: Ordenación Dinámica Protegida con Lista Blanca de Columnas |
| `PV-TRAP-047` | **L3** | A01:2021 - Broken Access Control | `CWE-915` | `app_python/profile_service.py` | 27-38 | **Trampa FP** | Trampa de Falso Positivo: Actualización de Perfil con Lista Blanca Estricta de Campos DTO |
| `PV-TRAP-048` | **L2** | A01:2021 - Broken Access Control | `CWE-22` | `app_node/controllers/uploadController.js` | 29-50 | **Trampa FP** | Trampa de Falso Positivo: Almacenamiento de Archivos con Nombre UUID y Extensión Validada |
| `PV-TRAP-049` | **L2** | A05:2021 - Security Misconfiguration | `CWE-942` | `app_node/server.js` | 76-83 | **Trampa FP** | Trampa de Falso Positivo: Configuración CORS con Rechazo Explícito de Origen 'null' |
| `PV-TRAP-050` | **L1** | A02:2021 - Cryptographic Failures | `CWE-328` | `app_python/crypto_util.py` | 52-55 | **Trampa FP** | Trampa FP: Clave de cache no criptografica calculada con funcion segura SHA-256 |
| `PV-TRAP-051` | **L1** | A05:2021 - Security Misconfiguration | `CWE-200` | `app_python/app.py` | 876-880 | **Trampa FP** | Trampa FP: Endpoint de estado que retorna unicamente version publica sin secretos |
| `PV-TRAP-052` | **L2** | A01:2021 - Broken Access Control | `CWE-639` | `app_node/controllers/orderController.js` | 41-55 | **Trampa FP** | Trampa FP: Modificacion de orden con validacion estricta de sesion y propietario |
| `PV-TRAP-053` | **L3** | A03:2021 - Injection | `CWE-89` | `app_python/safe_handlers.py` | 147-151 | **Trampa FP** | Trampa FP: Cross-Service evaluacion de liquidacion con casteo estricto a entero en Python |
| `PV-TRAP-054` | **L3** | A03:2021 - Injection | `CWE-78` | `app_python/safe_handlers.py` | 153-159 | **Trampa FP** | Trampa FP: Cross-Service archivo contable con validacion regex de caracteres alfanumericos |
| `PV-TRAP-055` | **L3** | A10:2021 - Server-Side Request Forgery | `CWE-918` | `app_python/safe_handlers.py` | 161-164 | **Trampa FP** | Trampa FP: Cross-Service callback con validacion de allowlist y resolucion de IP privada |
| `PV-TRAP-056` | **L3** | A07:2021 - Identification and Authentication Failures | `CWE-345` | `app_node/services/internalServiceClient.js` | 24-49 | **Trampa FP** | Trampa FP: Comunicacion inter-servicio protegida con firma HMAC y verificacion de vigencia temporal |
| `PV-TRAP-057` | **L3** | A07:2021 - Identification and Authentication Failures | `CWE-347` | `app_python/jwt_service.py` | 24-34 | **Trampa FP** | Trampa FP: Verificacion de JWT fijando algoritmo asimetrico RS256 y trust store local |
| `PV-TRAP-058` | **L4** | A04:2021 - Insecure Design | `CWE-840` | `app_python/tasks/coupon_service.py` | 72-80 | **Trampa FP** | Trampa FP: Conversion de divisas con precision decimal exacta y redondeo bancario |
| `PV-TRAP-059` | **L4** | A04:2021 - Insecure Design | `CWE-362` | `app_node/controllers/orderController.js` | 73-93 | **Trampa FP** | Trampa FP: Aplicacion de cupon protegida con bloqueo mutex atomico contra carreras |
| `PV-TRAP-060` | **L4** | A04:2021 - Insecure Design | `CWE-840` | `app_python/doc_service.py` | 67-76 | **Trampa FP** | Trampa FP: Transferencia encadenada con verificacion atomica previa de ambas cuentas |

---

## Detalle Técnico Exhaustivo por Ficha

# PV-N1-001: SQL Injection Directa en getUserDirect

## Descripción Técnica
El endpoint `GET /api/users/direct` en `app_node/controllers/userController.js` recibe el parámetro de consulta `id` y lo concatena directamente en una instrucción SQL ejecutada contra la base de datos SQLite en memoria (`SELECT * FROM users WHERE id = ` + userId). Al no emplear marcadores de posición (`?`), un atacante puede alterar la semántica de la consulta SQL e inyectar operadores booleanos, uniones o comandos adicionales.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `req.query.id` en `userController.getUserDirect(req, res)` (línea 10).
2. **Sink SQL**: Concatena `userId` en `sql` y ejecuta `dbClient.db.all(sql, ...)` (líneas 12-13).
3. **Impacto**: Lectura no autorizada de registros completos de la tabla `users` mediante inyección tautológica (`1 OR 1=1`).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/users/direct?id=1%20OR%201=1 HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Lista con todos los usuarios registrados en la base de datos (`alice`, `bob`, `admin`).

## Remediación Canónica (Fix)
Utilizar consultas parametrizadas con marcadores de posición (`?`):
```javascript
const sql = "SELECT * FROM users WHERE id = ?";
dbClient.db.all(sql, [userId], (err, rows) => {
  if (err) return res.status(500).json({ error: err.message });
  res.json({ users: rows });
});
```

---

# PV-N1-002: Command Injection Directo en pingHostDirect

## Descripción Técnica
La función `pingHostDirect` en `app_node/controllers/userController.js` concatena el parámetro `req.query.host` en un comando de shell (`ping -c 1 ${targetHost}`) y lo ejecuta directamente con `child_process.exec()`. La invocación de una subshell permite a un atacante introducir metacaracteres de separación de comandos (`;`, `&`, `|`) para ejecutar instrucciones arbitrarias en el host con los privilegios del proceso Node.js.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `req.query.host` obtenido en `pingHostDirect` (línea 21).
2. **Sink OS**: Concatena en cadena de comando ejecutada mediante `exec(command, ...)` (líneas 23-24).
3. **Impacto**: Ejecución arbitraria de comandos a nivel de sistema operativo (RCE).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/tools/ping?host=127.0.0.1%3Bwhoami HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Objeto JSON con el campo `result` conteniendo la salida del comando inyectado.

## Remediación Canónica (Fix)
Evitar invocar subshells y validar el parámetro contra una expresión regular estricta de direcciones IP, utilizando `child_process.execFile` con argumentos aislados:
```javascript
const { execFile } = require('child_process');
const IP_REGEX = /^[a-zA-Z0-9.-]+$/;
if (!IP_REGEX.test(targetHost)) {
  return res.status(400).json({ error: 'Host inválido' });
}
execFile('ping', ['-c', '1', targetHost], (err, stdout) => { ... });
```

---

# PV-N2-001: XSS Reflejado con Sanitizador Naive de Una Pasada

## Descripción Técnica
En `app_node/controllers/searchController.js`, el endpoint `searchProducts` intenta sanitizar el parámetro `q` mediante un reemplazo de texto simple (`query.replace('<script>', '').replace('</script>', '')`). Este filtro no es recursivo, no analiza mayúsculas/minúsculas ni previene el uso de otros elementos HTML y manejadores de eventos como `<img src=x onerror=...>`, `<svg onload=...>` o anidamientos como `<scr<script>ipt>`.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `req.query.q` en `searchController.searchProducts` (línea 9).
2. **Filtro Defectuoso**: `query.replace('<script>', '').replace('</script>', '')` (línea 12).
3. **Sink HTML**: Interpolación directa en plantilla HTML enviada al cliente con `Content-Type: text/html` (líneas 14-22).
4. **Impacto**: Ejecución de scripts JavaScript en el contexto del navegador del usuario.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: HTML que refleja intacto el payload `<img src=x onerror=alert(1)>`.

## Remediación Canónica (Fix)
Realizar codificación contextual de entidades HTML antes de reflejar entradas en el cuerpo del documento o emplear bibliotecas canónicas de sanitización:
```javascript
function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  }[m]));
}
```

---

# PV-N2-005: Inyección de Plantillas del Servidor (SSTI) en Jinja2

## Descripción Técnica
La ruta `POST /api/render-preview` en `app_python/app.py` recibe un campo `template` en el cuerpo JSON y lo procesa directamente con `render_template_string`. Al no restringir el contexto ni compilar en sandbox estricto, un atacante puede inyectar expresiones Jinja2 (`{{ 7 * 7 }}` o `{{ config.__class__.__init__.__globals__ }}`) para acceder al entorno de ejecución y ejecutar comandos remotos.

---

# PV-N2-006: Stored XSS en Módulo de Comentarios

## Descripción Técnica
En `app_node/controllers/feedbackController.js`, la función `postFeedbackRaw` recibe `author` y `message` desde el cuerpo de la petición y los almacena en la base de datos sin codificar entidades HTML. Al renderizar la respuesta o al ser leídos por otros usuarios, el código malicioso se ejecuta en el navegador del cliente.

---

# PV-N2-007: Inyección de Entidades Externas XML (XXE)

## Descripción Técnica
La función `parse_invoice_xml_raw` en `app_python/xml_parser.py` procesa cadenas XML entrantes mediante `ET.fromstring` sin desactivar la resolución de entidades externas `<!ENTITY>` ni definiciones de tipo de documento `<!DOCTYPE>`. Un atacante puede suministrar un payload XXE para exfiltrar archivos locales del servidor o forzar peticiones SSRF internas.

---

# PV-N2-008: ReDoS por Cuantificadores Anidados

## Descripción Técnica
En `app_node/controllers/searchController.js`, `validateAccountName` emplea la expresión regular `/^([a-zA-Z0-9]+)+$/`. Los cuantificadores anidados `(+)+` generan retroceso catastrófico (catastrophic backtracking) cuando una cadena larga casi coincide pero falla al final, bloqueando el bucle de eventos de Node.js.

---

# PV-N2-009: Inyección CRLF en Cabecera de Respuesta

## Descripción Técnica
La función `setCustomHeader` en `app_node/controllers/searchController.js` asigna el parámetro `tag` directamente a `res.setHeader('X-Custom-Tracking', tag)`. Sin sanitizar `\r` (`%0d`) ni `\n` (`%0a`), un atacante puede forzar la inyección de cabeceras arbitrarias (Set-Cookie, etc.) o provocar división de respuesta HTTP.

---

# PV-N2-015: Prototype Pollution en Mezcla de Objetos

## Descripción Técnica
`deepMergeInsecure` en `app_node/services/mergeUtil.js` recorre recursivamente las claves de la fuente asignándolas al objeto destino sin filtrar propiedades especiales como `__proto__`, permitiendo contaminar `Object.prototype`.

---

# PV-N2-016: Inyección NoSQL en Expresión de Catálogo

## Descripción Técnica
`queryCatalogNoSql` en `app_node/controllers/catalogController.js` concatena el parámetro `filter` directamente en el constructor `new Function(...)`, permitiendo a un atacante ejecutar código JavaScript arbitrario durante el filtrado.

---

# PV-N2-019: Inyección de Comandos vía Shell

## Descripción Técnica
`run_system_ping_shell` en `app_python/diagnostic_service.py` construye la cadena de ejecución interpolando directamente `host_target` y llamando a `subprocess.check_output(cmd, shell=True)`, permitiendo la inyección de metacaracteres como `;` o `|`.

---

# PV-N3-001: SQL Injection Multi-Salto a través de Tres Capas

## Descripción Técnica
Esta vulnerabilidad representa un flujo de contaminación inter-archivo (`CROSS_FILE_TAINT`) que atraviesa tres capas arquitectónicas:
1. `app_node/controllers/orderController.js`: Recibe `req.params.userId`.
2. `app_node/services/paymentService.js`: Valida únicamente que no sea nulo, arma la cláusula `user_id = ${userIdString}` y delega al modelo.
3. `app_node/models/dbClient.js`: Concatena `rawCondition` directamente en `SELECT * FROM orders WHERE ${rawCondition}` y lo ejecuta.

Los escáneres estáticos de archivo único pierden el rastro del taint al cruzar límites de módulos (`orderController` $\to$ `paymentService` $\to$ `dbClient`).

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.params.userId` en `orderController.js:9`.
2. **Salto 1 $\to$ 2**: Paso hacia `PaymentService.searchOrdersByUser(userId)` en `paymentService.js:12`.
3. **Salto 2 $\to$ 3**: Formación de `condition = "user_id = " + userIdString` y paso a `dbClient.queryOrderRaw(condition)` en `paymentService.js:19-20`.
4. **Sink (DAO)**: Inyección directa en SQLite en `dbClient.js:32-34`.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/orders/user/1%20UNION%20SELECT%20999,999,'Test',9999,'probe' HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Fila sintetizada con status `probe` proveniente de la unión SQL inyectada.

## Remediación Canónica (Fix)
Propagar parámetros estructurados a través de todas las capas en lugar de cadenas SQL en bruto:
```javascript
// dbClient.js
function queryOrdersByUserId(userId, callback) {
  db.all("SELECT * FROM orders WHERE user_id = ?", [userId], callback);
}
```

---

# PV-N3-006: Inyección de Plantilla en Node.js

## Descripción Técnica
`renderCustomTemplate` en `app_node/controllers/templateController.js` interpola la cadena `templateStr` dentro de un constructor `new Function(...)`, permitiendo a un atacante inyectar expresiones como `${process.mainModule.require('child_process').execSync('id')}` logrando ejecución remota de código.

---

# PV-N3-008: Inyección SQL en ORDER BY

## Descripción Técnica
`queryAuditReportRaw` en `app_node/controllers/reportController.js` concatena los parámetros `department` y `sort` en la cláusula de ordenación, permitiendo inferencia basada en tiempo o subconsultas booleanas.

---

# PV-N3-010: Cross-Service SQL Injection

## Descripcion Tecnica
Flujo inter-servicio sin sanitizacion cruzada que desemboca en construccion dinamica de SQL.

---

# PV-N3-011: Cross-Service Command Injection

## Descripcion Tecnica
Paso de argumentos no sanitizados inter-servicio hacia invocacion de shell en el host.

---

# PV-N4-005: SQLi Multi-Salto Profunda (Nivel 4)

## Descripción Técnica
`recordDirectTransaction` en `app_node/services/billingService.js` recibe el parámetro `billingAccount` propagado a través de cuatro capas de abstracción consecutivas y lo interpola en una sentencia SQL sin sanitización ni parametrización.

---

# PV-N1-006: Redirección Abierta de URL (Open Redirect)

## Descripción Técnica
La función `redirectExternal` en `app_node/controllers/searchController.js` toma el parámetro de consulta `url` y ejecuta `res.redirect(targetUrl)` directamente. Esto facilita ataques de phishing y robo de credenciales al permitir que enlaces legítimos del dominio redirijan a sitios externos maliciosos.

---

# PV-N2-002: Path Traversal con Reemplazo Simple de Secuencias `../`

## Descripción Técnica
El endpoint `GET /api/assets/download` en `app_node/controllers/searchController.js` permite descargar archivos a partir del parámetro `file`. Para mitigar lecturas fuera del directorio público, implementa un reemplazo simple: `filename.replace(/\.\.\//g, '')`. Este filtro no es recursivo: secuencias como `....//` se convierten en `../` tras una sola pasada, permitiendo escapar de la raíz pública y leer archivos sensibles del sistema de archivos del servidor.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.file` en `searchController.downloadAsset` (línea 27).
2. **Sanitización Naive**: `filename.replace(/\.\.\//g, '')` (línea 30).
3. **Resolución Insegura**: `path.join(__dirname, '..', 'public', sanitized)` (línea 31).
4. **Sink FS**: `fs.readFile(targetPath, ...)` devuelve el contenido del archivo arbitrario (línea 33).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/assets/download?file=....//....//package.json HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Contenido del archivo `package.json` del proyecto Node.js, conteniendo `"name": "proyecto-vulnerable-node"`.

## Remediación Canónica (Fix)
Utilizar `path.resolve` y verificar que la ruta normalizada comience estrictamente con el prefijo del directorio base permitido:
```javascript
const safeBase = path.resolve(__dirname, '..', 'public');
const resolvedPath = path.resolve(safeBase, filename);
if (!resolvedPath.startsWith(safeBase)) {
  return res.status(403).json({ error: 'Acceso denegado: ruta no permitida' });
}
```

---

# PV-N2-017: Zip Slip en Extracción de Paquetes

## Descripción Técnica
`extract_bundle_direct` en `app_python/archive_extractor.py` delega en `archive.extractall()`, la cual no garantiza en versiones vulnerables o entornos personalizados que las rutas relativas ascendentes (`../../etc/cron.d/job`) no sobrescriban archivos del sistema.

---

# PV-N2-020: Salto de Directorio en Carga de Archivos

## Descripción Técnica
`handleFileUploadRaw` en `app_node/controllers/uploadController.js` concatena `filename` directamente con `UPLOADS_DIR`, permitiendo que nombres como `../../etc/cron.d/pwn` escapen del directorio designado.

---

# PV-N2-022: IDOR en Estado de Orden

## Descripcion Tecnica
Falta de verificacion de pertenencia en modificacion de entidad de negocio.

---

# PV-N3-003: Escalación de Privilegios Multi-Salto por Asignación Masiva

## Descripción Técnica
El endpoint `POST /api/users/profile` permite actualizar atributos de perfil de un usuario. La petición atraviesa tres capas:
1. `app_node/controllers/userController.js`: Recibe `req.body` y llama a `RoleService.processProfileUpdate`.
2. `app_node/services/roleService.js`: Ejecuta `Object.assign({ role: 'user' }, profileUpdates)`. Al no filtrar propiedades restringidas, el atacante puede inyectar `"role": "admin"`.
3. `app_node/models/dbClient.js`: Persiste directamente `mergedProfile.role` en la tabla `users` de SQLite sin verificar autorizaciones administrativas.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.body` en `userController.updateUserProfile`.
2. **Salto 1 $\to$ 2**: Paso hacia `RoleService.processProfileUpdate(userId, profileUpdates)` en `services/roleService.js:13-26`.
3. **Salto 2 $\to$ 3**: `Object.assign` sobrescribe la clave `role` con el valor del payload del atacante y delega en `dbClient.updateUserProfile`.
4. **Sink (DAO)**: Actualización de privilegios en base de datos (`UPDATE users SET role = ? WHERE id = ?`).

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/users/profile HTTP/1.1
Host: localhost:3001
Content-Type: application/json

{
  "userId": 1,
  "displayName": "Alice Hacker",
  "role": "admin"
}
```
Respuesta esperada: Objeto JSON del usuario actualizado con `"role": "admin"`.

## Remediación Canónica (Fix)
Aplicar una lista blanca estricta de atributos modificables por el usuario, excluyendo campos de control de acceso y privilegios:
```javascript
const ALLOWED_FIELDS = ['displayName', 'bio', 'avatarUrl'];
const safeUpdates = {};
for (const key of ALLOWED_FIELDS) {
  if (key in profileUpdates) {
    safeUpdates[key] = profileUpdates[key];
  }
}
```

---

# PV-N3-004: IDOR en Consulta Documental

## Descripción Técnica
En `app_python/doc_service.py`, `get_document_raw` recupera el objeto documental solicitado a partir de su ID sin comparar `doc['owner']` contra la identidad del usuario en sesión (`caller_user`). Un usuario regular puede acceder a documentos confidenciales pertenecientes al administrador (`doc_id=103`).

---

# PV-N3-009: Asignación Masiva en Perfiles

## Descripción Técnica
`update_user_profile_mass` en `app_python/profile_service.py` invoca directamente `profile.update(incoming_fields)`, permitiendo a un usuario ordinario inyectar atributos sensibles como `is_admin: true`.

---

# PV-N4-001: IDOR en Acceso a Facturas Multi-Inquilino

## Descripción Técnica
El endpoint `GET /api/invoices/:id` en `app_node/controllers/invoiceController.js` valida que la petición incluya una cabecera de sesión de usuario autenticado (`X-User-Session`), pero en ningún momento compara el `tenant_id` de la factura recuperada de la base de datos contra el tenant del usuario emisor. Como resultado, cualquier usuario legítimo de una organización puede acceder a datos financieros confidenciales de clientes de otras organizaciones modificando el ID en la URL.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.params.id` y `req.headers['x-user-session']` en `invoiceController.getInvoiceDetails` (líneas 7-8).
2. **Salto a Servicio**: `PaymentService.verifyInvoiceAccess` comprueba la presencia de sesión pero omite el chequeo de inquilino (línea 13).
3. **Consulta DAO**: `dbClient.getInvoiceById(invoiceId)` ejecuta `SELECT * FROM invoices WHERE id = ?`.
4. **Impacto**: Fuga de datos de facturación entre tenants no relacionados (Multi-tenancy bypass).

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/invoices/502 HTTP/1.1
Host: localhost:3001
X-User-Session: user_alpha
```
Respuesta esperada: Retorno de la factura 502 perteneciente a `tenant_beta` (`Beta Industries`).

## Remediación Canónica (Fix)
Verificar en la capa de acceso a datos o servicio que el `tenant_id` del registro coincida con el inquilino autenticado:
```javascript
function verifyInvoiceAccess(tenantId, invoiceId, callback) {
  dbClient.getInvoiceById(invoiceId, (err, invoice) => {
    if (err) return callback(err, null);
    if (!invoice || invoice.tenant_id !== tenantId) {
      return callback(new Error('Acceso denegado a este recurso'), null);
    }
    callback(null, invoice);
  });
}
```

---

# PV-N4-004: Falla Lógica de Negocio en Transferencia de Saldo

## Descripción Técnica
En `app_python/app.py` y `app_python/tasks/worker.py`, el endpoint `POST /api/wallet/transfer` permite transferir fondos entre usuarios. La validación comprueba si el usuario cuenta con saldo suficiente mediante `current_balance < amount`. Sin embargo, el sistema omite validar que `amount > 0`. Si un atacante envía un valor negativo (ej. `-500`), la condición de suficiencia se cumple (`balance < -500` es falso), y la operación aritmética `balance -= (-500)` incrementa artificialmente el saldo del remitente debitándolo de la víctima.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `POST /api/wallet/transfer` con JSON conteniendo `source`, `target` y `amount` en `app_python/app.py:201-216`.
2. **Salto a Worker**: Delegación a `worker.process_wallet_transfer` en `app_python/tasks/worker.py:47-70`.
3. **Falla Lógica**: `current_balance < amount` pasa con montos negativos.
4. **Impacto**: Manipulación fraudulenta de saldo e inconsistencia financiera arbitraria.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/wallet/transfer HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "source": "alice",
  "target": "bob",
  "amount": -500.0
}
```
Respuesta esperada: Confirmación con `"status": "transfer_completed"` e incremento del saldo de `alice`.

## Remediación Canónica (Fix)
Validar estrictamente que el monto a transferir sea un número positivo mayor que cero y respetar transaccionalidad:
```python
if amount <= 0:
    raise ValueError("El monto de la transferencia debe ser estrictamente positivo")
```

---

# PV-N4-006: Falla Lógica de Negocio en Canje de Cupones

## Descripción Técnica
`apply_coupon_discount` en `app_python/tasks/coupon_service.py` valida la presencia de `redemption_key` y posteriormente la añade a la colección sin cerrojo de sincronización, permitiendo a peticiones concurrentes aplicar el beneficio múltiples veces.

---

# PV-N4-007: Manipulación Lógica de Importe de Carrito

## Descripción Técnica
`calculateCartTotal` en `app_node/controllers/cartController.js` acepta valores arbitrarios de cantidad en los artículos del pedido sin verificar que sean enteros positivos, permitiendo saldos negativos en la compra.

---

# PV-N4-008: Carrera TOCTOU en Control de Existencias

## Descripción Técnica
`decrement_inventory_check` en `app_python/tasks/inventory_service.py` introduce una ventana temporal entre la comprobación del stock y la asignación final, provocando inconsistencias en el inventario ante accesos simultáneos.

---

# PV-N4-009: Arbitraje de Redondeo de Moneda

## Descripcion Tecnica
Error de precision en logica financiera que genera distorsiones de saldo acumulables.

---

# PV-N4-010: Carrera TOCTOU en Cupon

## Descripcion Tecnica
Ventana de tiempo entre check y use sin transaccion serializada ni cerrojo atomico.

---

# PV-N4-011: Sobregiro en Liquidacion Encadenada

## Descripcion Tecnica
Modificacion de estado inconsistente ante fallos parciales sin bloque transaccional.

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

---

# PV-N1-007: Algoritmo Hash Roto (MD5) en Generación de Tokens

## Descripción Técnica
La función `generate_legacy_token` en `app_python/token_service.py` utiliza `hashlib.md5` para calcular la firma de sesión de tokens de API. MD5 está formalmente desaconsejado para fines criptográficos por vulnerabilidades conocidas de colisión.

---

# PV-N1-008: Creación Insegura de Archivos Temporales

## Descripción Técnica
La función `export_report_insecure` en `app_python/tasks/export_task.py` crea archivos en el directorio temporal compartido (`tempfile.gettempdir()`) usando nombres predecibles como `report_{report_name}.json` con `open(tmp_path, "w")`. Esto permite ataques de enlaces simbólicos (symlink hijacking) o lectura por otros usuarios locales del sistema.

---

# PV-N1-013: Generador Pseudoaleatorio Débil en Tokens

## Descripción Técnica
`generateCsrfTokenInsecure` en `app_node/services/tokenUtil.js` recurre a `Math.random()`, un generador pseudoaleatorio no criptográfico cuyos estados internos pueden ser calculados por un observador externo.

---

# PV-N1-014: Uso de MD5 Debil

## Descripcion Tecnica
Generacion de digest MD5 para validar integridad sin resistencia a colisiones.

---

# PV-N2-010: Bypass de Firma Criptográfica en JWT

## Descripción Técnica
La función `decode_token_legacy` en `app_python/jwt_service.py` omite la verificación criptográfica de la firma digital estableciendo `verify_signature=False`, permitiendo a un atacante alterar los reclamos (claims) del token e impersonar cualquier usuario (`sub=admin`).

---

# PV-N2-011: Fijación de Sesión en Login

## Descripción Técnica
`loginInsecure` en `app_node/controllers/sessionController.js` vincula las credenciales del usuario a la sesión HTTP preexistente sin invocar `regenerate()`, permitiendo a un atacante que conozca el identificador fijado secuestrar la sesión tras el inicio exitoso.

---

# PV-N2-012: Token de Recuperación Predecible

## Descripción Técnica
`generate_reset_token_legacy` en `app_python/auth_service.py` deriva el token de restablecimiento calculando el hash MD5 de `{username}:{timestamp}`, permitiendo a un atacante adivinar tokens de cualquier cuenta generando hashes en la ventana de segundos del ataque.

---

# PV-N2-013: Enumeración de Usuarios en Autenticación

## Descripción Técnica
`authenticate_basic` en `app_python/auth_service.py` responde con `"Usuario no existe en el sistema"` o `"Contraseña incorrecta"`, facilitando a un atacante mapear de forma automatizada las cuentas legítimas registradas en la organización.

---

# PV-N2-018: Cifrado Débil en Modo ECB

## Descripción Técnica
`encrypt_sensitive_data_ecb` en `app_python/crypto_util.py` emplea `modes.ECB()`, el cual no utiliza vector de inicialización y preserva patrones del texto original comprometiendo la confidencialidad.

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

---

# PV-N2-014: Deserialización YAML Insegura

## Descripción Técnica
`parse_config_yaml_direct` en `app_python/yaml_parser.py` invoca `yaml.load(..., Loader=yaml.Loader)`, el cual permite etiquetas personalizadas como `!!python/object/apply` ejecutando funciones del sistema operativo de manera arbitraria.

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

---

# PV-N3-005: SSRF en Cliente de Integración

## Descripción Técnica
`fetch_webhook_simple` en `app_python/ssrf_client.py` invoca `urllib.request.urlopen` directamente sobre la dirección provista por el llamante, permitiendo alcanzar microservicios internos, instancias de metadatos o servicios de bucle local.

---

# PV-N3-007: SSRF Inter-Servicio sin Restricción

## Descripción Técnica
`forwardInternalTask` en `app_node/services/internalServiceClient.js` compone dinámicamente peticiones HTTP hacia endpoints internos permitiendo la manipulación de acciones y la invocación de rutas no autorizadas en microservicios backend.

---

# PV-N3-012: Cross-Service SSRF

## Descripcion Tecnica
Peticion de retorno disparada a destinos arbitrarios controlados por el cliente.

---

# PV-N4-003: Deserialización Insegura con Pickle (RCE)

## Descripción Técnica
El endpoint `POST /api/session/restore` en `app_python/app.py` recibe una cadena codificada en base64 en `session_data` y delega su reconstrucción a `worker.restore_user_session_state(raw_bytes)`. La implementación invoca directamente `pickle.loads(raw_bytes)`. En Python, el módulo `pickle` no es seguro contra datos maliciosos, permitiendo instanciar objetos con el método mágico `__reduce__` para ejecutar comandos arbitrarios en el sistema operativo durante la deserialización.

## Traza de Flujo (Flow Trace)
1. **Entrada HTTP**: `POST /api/session/restore` con `session_data` en base64 en `app.py:183-198`.
2. **Salto a Worker**: Llamada a `worker.restore_user_session_state(raw_bytes)` en `tasks/worker.py:30-37`.
3. **Sink de Deserialización**: `pickle.loads(raw_bytes)` procesa los opcodes del payload.
4. **Impacto**: Ejecución Remota de Código (RCE) con privilegios del intérprete Python.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/session/restore HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "session_data": "gASVFAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwOcHJpbnQoJ3B3bmVkJymUhZRSlC4="
}
```
Respuesta esperada: Confirmación con `"status": "restored"`.

## Remediación Canónica (Fix)
Sustituir formatos de serialización basados en código ejecutable por formatos puramente declarativos como JSON o Protocol Buffers, firmados criptográficamente:
```python
import json

def restore_user_session_state(raw_bytes: bytes) -> dict:
    return json.loads(raw_bytes.decode("utf-8"))
```

---

# PV-N1-003: Mala Configuración de CORS con Comodín y Credenciales

## Descripción Técnica
En `app_node/server.js`, las rutas bajo `/api/public` configuran simultáneamente las cabeceras HTTP `Access-Control-Allow-Origin: *` y `Access-Control-Allow-Credentials: true`. Aunque la especificación formal del W3C/WHATWG prohíbe el uso de credenciales con comodín, múltiples navegadores y clientes HTTP permiten que scripts de cualquier dominio de origen lean respuestas privadas si el servidor no impone validaciones contextuales.

## Traza de Flujo (Flow Trace)
1. **Middleware Express**: Ruta montada en `app_node/server.js:23-28`.
2. **Configuración de Cabeceras**: Establece `*` junto con `Credentials: true` en todas las respuestas.
3. **Impacto**: Filtrado de datos cross-origin e incumplimiento de políticas de aislamiento web.

## Sonda Dinámica de Verificación (Probe)
```http
OPTIONS /api/public/test HTTP/1.1
Host: localhost:3001
Origin: https://attacker.example.com
```
Respuesta esperada: Cabeceras `Access-Control-Allow-Origin: *` y `Access-Control-Allow-Credentials: true` presentes simultáneamente.

## Remediación Canónica (Fix)
Especificar orígenes explícitos basados en listas de dominios autorizados y evitar comodines universales con credenciales:
```javascript
const ALLOWED_ORIGINS = ['https://trusted.corp.internal'];
app.use('/api/public', (req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

---

# PV-N1-009: Dependencia Insegura en Python

## Descripción Técnica
`requirements.txt` especifica la versión `pyyaml==5.3.1` afectada por CVE-2020-14343, permitiendo a un atacante que controle el documento deserializado ejecutar comandos en el sistema anfitrión.

---

# PV-N1-010: Paquete de Dependencia Vulnerable en Node.js

## Descripción Técnica
`package.json` declara `"lodash": "4.17.15"` afectada por CVE-2020-8203 y CVE-2019-10744, donde los métodos `zipObjectDeep` y `defaultsDeep` permiten la manipulación del prototipo base `Object.prototype`.

---

# PV-N1-011: Contenedor con Ejecución como Root

## Descripción Técnica
`infra/Dockerfile.insecure` declara explícitamente `USER root` y utiliza una etiqueta flotante `latest`, lo cual vulnera las buenas prácticas de aislamiento en contenedores y facilita la escalación de privilegios en el host si existe escape.

---

# PV-N1-012: Contenedor Privilegiado en Docker Compose

## Descripción Técnica
`infra/docker-compose.insecure.yml` define `privileged: true` y monta `/var/run/docker.sock`, lo que otorga al contenedor control completo sobre el daemon de Docker del host y capacidad de comprometer el sistema operativo completo.

---

# PV-N1-015: Exposicion de Variables de Entorno

## Descripcion Tecnica
Fuga de configuracion sensible a traves de endpoint sin autenticacion.

---

# PV-N2-003: CORS con Validación Regex No Anclada al Final

## Descripción Técnica
En `app_node/server.js`, las rutas bajo `/api/internal` intentan restringir el acceso a orígenes internos mediante la expresión regular `/^http:\/\/corp\.internal/`. Dado que la expresión carece del ancla de fin de cadena (`$`) o delimitador de puerto/barra (`(?::\d+)?(?:\/|$)?`), cualquier dominio registrado por un atacante cuyo prefijo sea `http://corp.internal` (por ejemplo, `http://corp.internal.evil.com`) es aceptado como origen confiable y reflejado en `Access-Control-Allow-Origin`.

## Traza de Flujo (Flow Trace)
1. **Middleware Express**: Intercepta cabecera `Origin` en `app_node/server.js:31-40`.
2. **Evaluación de Regex**: `/^http:\/\/corp\.internal/.test(origin)` retorna `true` ante subdominios externos coincidentes.
3. **Reflejo Inseguro**: Asigna `Access-Control-Allow-Origin: origin` y `Credentials: true`.
4. **Impacto**: Lectura de endpoints corporativos internos desde navegadores de usuarios engañados por sitios maliciosos.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/internal/status HTTP/1.1
Host: localhost:3001
Origin: http://corp.internal.evil.com
```
Respuesta esperada: Cabecera `Access-Control-Allow-Origin: http://corp.internal.evil.com` devuelta con éxito.

## Remediación Canónica (Fix)
Anclar estrictamente el fin del nombre de host o parsear la URL con el constructor nativo `new URL(origin)`:
```javascript
app.use('/api/internal', (req, res, next) => {
  const origin = req.headers.origin || '';
  if (/^http:\/\/corp\.internal(?::\d+)?$/.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

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

---

# PV-N2-021: Origen Null Permitido en CORS

## Descripción Técnica
El middleware en `app_node/server.js` para `/api/shared/reports` comprueba `origin === 'null'` y devuelve cabeceras permitiendo credenciales, habilitando la extracción de datos desde sandboxed iframes o esquemas `data:`.

---

# PV-TRAP-001: Trampa de Falso Positivo — SQLi Mitigado con parseInt Estricto

## Descripción Técnica
La función `getSafeUserById` en `app_node/safe/safeSanitizers.js` construye una consulta SQL mediante interpolación de cadenas (`const safeSql = \`SELECT * FROM users WHERE id = ${parsedId}\``). Herramientas estáticas SAST basadas en reglas regex o sintaxis superficial pueden alertar un falso positivo por concatenación de variables en SQL. Sin embargo, el valor interpolado es el resultado directo de `Number.parseInt(rawId, 10)` tras verificar explícitamente `Number.isNaN(parsedId) || parsedId <= 0`. Es matemáticamente imposible inyectar caracteres de sintaxis SQL.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.id` en `safeSanitizers.js:10`.
2. **Validación Estricta**: `Number.parseInt(rawId, 10)` y rechazo si es `NaN` o no positivo (líneas 11-15).
3. **Interpolación Segura**: `safeSql = SELECT * FROM users WHERE id = ${parsedId}` (línea 18).
4. **Resultado**: El código es seguro. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/user?id=1%20OR%201=1 HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Código `400 Bad Request` con `{"error": "ID numérico requerido"}`.

## Remediación Canónica (Fix)
Aunque es seguro, la práctica recomendada para evitar ruidos de escáneres y garantizar defensas en profundidad es utilizar siempre parámetros preparados:
```javascript
dbClient.db.all("SELECT * FROM users WHERE id = ?", [parsedId], callback);
```

---

# PV-TRAP-002: Trampa de Falso Positivo — Path Traversal Neutralizado con Basename y Whitelist

## Descripción Técnica
La función `getSafeFile` en `app_node/safe/safeSanitizers.js` gestiona descargas recibiendo `req.query.file`. Escáneres de seguridad pueden señalar un posible Directory Traversal al detectar el flujo hacia respuestas de archivo. No obstante, la función aplica `path.basename(rawFilename)`, eliminando cualquier componente de directorio (`../` o rutas absolutas), y compara el resultado estricto contra una lista blanca en memoria (`['manual.pdf', 'terms.pdf', 'privacy.pdf']`).

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.file` en `safeSanitizers.js:27`.
2. **Aislamiento**: `path.basename` extrae únicamente el nombre final del archivo (línea 30).
3. **Comprobación de Lista Blanca**: `!ALLOWED_FILES.includes(cleanBasename)` devuelve `403 Forbidden` (líneas 31-33).
4. **Resultado**: El código es seguro. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/file?file=../../etc/passwd HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Código `403 Forbidden` con `{"error": "Archivo no permitido por política"}`.

## Remediación Canónica (Fix)
La implementación actual es canónica y completamente segura.

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

---

# PV-TRAP-004: Trampa de Falso Positivo — IDOR Mitigado con Aislamiento de Tenant

## Descripción Técnica
La función `getSafeInvoiceForTenant` en `app_node/safe/safeSanitizers.js` recupera facturas mediante `dbClient.getInvoiceById(invoiceId)`. A diferencia del endpoint vulnerable `PV-N4-001`, este controlador compara de manera explícita el inquilino autenticado (`req.headers['x-tenant-id']`) con la propiedad `invoice.tenant_id` retornada por la consulta. Si no coinciden, aborta inmediatamente con `403 Forbidden`. Los analizadores estáticos que detectan parámetros numéricos directos sin evaluar la lógica posterior pueden clasificarlo erróneamente como IDOR.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.params.id` y `req.headers['x-tenant-id']` en `safeSanitizers.js:40-41`.
2. **Consulta a DAO**: Recuperación de la factura por ID (línea 47).
3. **Control de Acceso Multi-Inquilino**: `if (invoice.tenant_id !== tenantId)` retorna `403 Forbidden` (líneas 52-54).
4. **Resultado**: El acceso cross-tenant está bloqueado. La alerta constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/invoices/502 HTTP/1.1
Host: localhost:3001
X-Tenant-Id: tenant_alpha
```
Respuesta esperada: Código `403 Forbidden` con mensaje `{"error": "Acceso denegado: factura no pertenece a este tenant"}` al solicitar una factura perteneciente a `tenant_beta`.

## Remediación Canónica (Fix)
La implementación actual es segura y canónica para control de acceso basado en inquilinos.

---

# PV-TRAP-005: Trampa de Falso Positivo — Command Execution Mitigado con execFile y Regex IPv4

## Descripción Técnica
La función `getSafePing` en `app_node/safe/safeSanitizers.js` ejecuta la utilidad de diagnóstico `ping`. Escáneres que buscan llamadas al módulo `child_process` marcan frecuentemente esta función como sospechosa de Command Injection (CWE-78). Sin embargo, la función es inmune a inyección:
1. Valida el parámetro contra una expresión regular IPv4 estricta (`/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/`), rechazando de raíz cualquier metarácter de shell (`;`, `&`, `|`, `` ` ``, `$`).
2. Utiliza `child_process.execFile` en lugar de `exec`, pasando los argumentos como un vector tipado de cadenas sin iniciar una subshell del sistema operativo.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `req.query.host` en `safeSanitizers.js:63`.
2. **Validación Regex**: Rechazo temprano si no cumple el patrón IPv4 (líneas 64-68).
3. **Invocación Segura**: `execFile('ping', [pingFlag, '1', host])` ejecuta el binario sin shell (líneas 71-77).
4. **Resultado**: La ejecución está completamente contenida. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
GET /api/safe/ping?host=127.0.0.1%3Bwhoami HTTP/1.1
Host: localhost:3001
```
Respuesta esperada: Código `400 Bad Request` con mensaje `{"error": "Dirección IPv4 inválida"}`.

## Remediación Canónica (Fix)
La implementación actual es canónica y completamente segura para invocar ejecutables externos.

---

# PV-TRAP-006: Trampa de Falso Positivo — Deserialización Segura con Firma Criptográfica HMAC

## Descripción Técnica
La función `safe_session_restore` en `app_python/safe_handlers.py` se encarga de reanudar el estado de sesión a partir de un payload codificado. Herramientas SAST configuradas para detectar patrones de deserialización o endpoints de sesión pueden reportar un falso positivo asociándolo con CWE-502. Sin embargo:
1. No se utiliza `pickle`, `yaml.unsafe_load` ni ninguna librería con ejecución implícita de código.
2. Exige una firma criptográfica `HMAC-SHA256` calculada sobre los bytes en bruto de la sesión.
3. Comprueba la firma en tiempo constante (`hmac.compare_digest`) para prevenir ataques de canal lateral temporales.
4. Parsea el contenido exclusivamente con `json.loads()`.

## Traza de Flujo (Flow Trace)
1. **Entrada**: `POST /api/safe/session/restore` con `session_data` y `signature` en `safe_handlers.py:129-144`.
2. **Validación HMAC**: `hmac.compare_digest(expected_sig, signature)` en `safe_handlers.py:114-116`.
3. **Parseo Estricto**: `json.loads(raw_bytes.decode('utf-8'))` (línea 119).
4. **Resultado**: Imposible inyectar objetos ejecutables o payloads de RCE. La alerta de SAST constituye un falso positivo.

## Sonda Dinámica de Verificación (Probe)
```http
POST /api/safe/session/restore HTTP/1.1
Host: localhost:5001
Content-Type: application/json

{
  "session_data": "eyJ1c2VyIjoidGVzdCJ9",
  "signature": "invalid_signature"
}
```
Respuesta esperada: Código `400 Bad Request` con mensaje `{"error": "Firma HMAC inválida: Firma HMAC inválida o manipulada"}`.

## Remediación Canónica (Fix)
La implementación actual representa la arquitectura segura recomendada para serialización y transferencia de estados de sesión.

---

# PV-TRAP-007: Trampa FP - Renderizado HTML con Escape Contextual

## Descripción Técnica
A diferencia de `PV-N2-001` (donde se reemplazaba ingenuamente `<script>`), `searchProductsSafe` en `app_node/controllers/searchController.js` procesa la entrada a través de `escapeHtml`, transformando `<`, `>`, `&`, `"` y `'` en entidades HTML seguras. No es vulnerable a XSS reflejado.

---

# PV-TRAP-008: Trampa FP - Consulta DAO Parametrizada

## Descripción Técnica
Gemelo seguro de `PV-N3-001`. En `queryOrderSafe`, el parámetro `userId` viaja a través de las capas de controlador y servicio, pero al llegar al sink SQL en `dbClient.js`, se utiliza una consulta parametrizada con valores ligados (`db.all(query, [userId], ...)`), imposibilitando la inyección SQL.

---

# PV-TRAP-009: Trampa FP - DTO con Lista Blanca de Campos

## Descripción Técnica
Gemelo seguro de `PV-N3-003`. La función `processProfileUpdateSafe` en `app_node/services/roleService.js` filtra exhaustivamente los atributos mutables permitidos (`display_name`, `bio`, `theme`) y fija `role: 'user'`, evitando que peticiones con `role: admin` modifiquen privilegios en la base de datos.

---

# PV-TRAP-010: Trampa FP - Validación de Precondición Aritmética en Saldo

## Descripción Técnica
Gemelo seguro de `PV-N4-004`. `process_wallet_transfer_safe` en `app_python/tasks/worker.py` verifica explícitamente `if amount <= 0: raise ValueError(...)` antes de debitar o acreditar las cuentas, neutralizando la manipulación lógica de saldos mediante números negativos.

---

# PV-TRAP-011: Trampa FP - Marcador de Posición Sintético

## Descripción Técnica
Gemelo seguro de `PV-N1-004`. En `app_python/config.py`, `DUMMY_INTEGRATION_KEY = "DUMMY_SAMPLE_KEY_NOT_A_SECRET_PLACEHOLDER"` parece una clave de API por entropía o contexto para escáneres ingenuos, pero su valor y prefijo `DUMMY_` indican un marcador de posición de prueba inofensivo.

---

# PV-TRAP-012: Trampa FP - Verificación Estricta de 2FA TOTP

## Descripción Técnica
Gemelo seguro de `PV-N4-002`. La función `verify_totp_strict` en `app_python/auth/mfa_handler.py` calcula el código temporal RFC 6238 y no acepta ningún parámetro `bypass_flag` ni cabecera de depuración, garantizando la exigencia estricta del factor de autenticación.

---

# PV-TRAP-013: Trampa FP - CORS con Lista Blanca Exacta

## Descripción Técnica
Gemelo seguro de `PV-N2-003`. En `app_node/server.js`, la ruta `/api/safe/partner` valida `ALLOWED_EXACT_ORIGINS.includes(origin)`. Al no emplear expresiones regulares sin anclar ni comodines `*` combinados con credenciales, previene ataques de suplantación de origen.

---

# PV-TRAP-014: Trampa FP - Archivo .env.example Inofensivo

## Descripción Técnica
Gemelo seguro de `PV-N2-004`. `.env.example` en la raíz contiene cadenas como `postgres://sample_user:sample_pass_placeholder@...`. A diferencia de `.env.backup` (que contiene credenciales reales de staging), este archivo es una plantilla documentada y no representa una fuga de secretos.

---

# PV-TRAP-015: Trampa FP - Renderizado Seguro de Plantillas

## Descripción Técnica
Gemelo seguro de `PV-N2-005`. La función `render_template_preview_safe` en `app_python/app.py` invoca `render_template("dashboard.html", ...)` cargando una plantilla estática de confianza desde disco en lugar de evaluar cadenas dinámicas con `render_template_string`.

---

# PV-TRAP-016: Trampa FP - Comentarios con Escape de Entidades HTML

## Descripción Técnica
Gemelo seguro de `PV-N2-006`. `postFeedbackSafe` en `app_node/controllers/feedbackController.js` codifica contextualemnte los campos `author` y `message` antes de insertarlos en SQLite y generar la tarjeta de respuesta, evitando la inyección de secuencias de comandos almacenadas.

---

# PV-TRAP-017: Trampa FP - Parseo XML con Desactivación de Entidades

## Descripción Técnica
Gemelo seguro de `PV-N2-007`. `parse_invoice_xml_safe` en `app_python/xml_parser.py` rechaza explícitamente cualquier documento que contenga `<!DOCTYPE` o `<!ENTITY`, previniendo ataques de inyección XXE, revelación de archivos locales (`file:///etc/passwd`) o consumo abusivo de recursos.

---

# PV-TRAP-018: Trampa FP - Redirección Estricta a Rutas Relativas

## Descripción Técnica
Gemelo seguro de `PV-N1-006`. `redirectSafe` en `app_node/controllers/searchController.js` valida que la URL solicitada sea estrictamente un path relativo que comience con `/`, rechazando esquemas absolutos (`http://`, `https://`) y secuencias protocol-relative (`//`), neutralizando el vector de Open Redirect.

---

# PV-TRAP-019: Trampa FP - Consulta Documental con Validación de Propiedad

## Descripción Técnica
Gemelo seguro de `PV-N3-004`. `get_document_safe` en `app_python/doc_service.py` corrobora que el campo `owner` del registro documental coincida unívocamente con el usuario autenticado (`caller_user`), arrojando `PermissionError` ante cualquier intento de escalamiento horizontal (IDOR).

---

# PV-TRAP-020: Trampa FP - Regex Lineal con Límite de Tamaño

## Descripción Técnica
Gemelo seguro de `PV-N2-008`. `validateAccountNameSafe` en `app_node/controllers/searchController.js` descarta de inmediato entradas con más de 32 caracteres y aplica una expresión regular con cuantificador lineal simple (`/^[a-zA-Z0-9]{1,32}$/`), previniendo la catástrofe por retroceso (ReDoS).

---

# PV-TRAP-021: Trampa FP - Encabezado HTTP con Saneamiento de Saltos de Línea

## Descripción Técnica
Gemelo seguro de `PV-N2-009`. `setCustomHeaderSafe` en `app_node/controllers/searchController.js` elimina cualquier ocurrencia de caracteres `\r` y `\n` antes de invocar `res.setHeader`, eliminando la posibilidad de HTTP Response Splitting o inyección de cookies/cabeceras maliciosas.

---

# PV-TRAP-022: Trampa FP - Tokens Criptográficos con HMAC-SHA256

## Descripción Técnica
Gemelo seguro de `PV-N1-007`. `generate_secure_token` en `app_python/token_service.py` utiliza HMAC con la función criptográfica segura SHA-256 y clave secreta, reemplazando el uso de hashes MD5 obsoletos y vulnerables a colisiones.

---

# PV-TRAP-023: Trampa FP - Archivos Temporales Seguros

## Descripción Técnica
Gemelo seguro de `PV-N1-008`. `export_report_secure` en `app_python/tasks/export_task.py` emplea `tempfile.NamedTemporaryFile` con sufijo y prefijo protegidos, aplicando `os.chmod(..., 0o600)` para garantizar que ningún otro usuario local en un sistema multiusuario pueda leer o escribir el archivo temporal.

---

# PV-TRAP-024: Trampa FP - Verificación Estricta de JWT

## Descripción Técnica
Gemelo seguro de `PV-N2-010`. `decode_token_verified` en `app_python/jwt_service.py` valida la firma con la clave pública RSA corporativa, restringe los algoritmos exclusivamente a `RS256` y exige los campos `exp`, `iss` y `sub`.

---

# PV-TRAP-025: Trampa FP - Renovación Segura de Sesión

## Descripción Técnica
Gemelo seguro de `PV-N2-011`. `loginSecure` en `app_node/controllers/sessionController.js` ejecuta `req.session.regenerate` invalidando el ID previo y asignando una nueva cookie de sesión aleatoria antes de fijar las propiedades de usuario.

---

# PV-TRAP-026: Trampa FP - Token Criptográfico Seguro

## Descripción Técnica
Gemelo seguro de `PV-N2-012`. `generate_reset_token_secure` en `app_python/auth_service.py` invoca `secrets.token_urlsafe(32)` proveyendo 256 bits de entropía real extraída del generador criptográfico del sistema operativo (`/dev/urandom`).

---

# PV-TRAP-027: Trampa FP - Autenticación en Tiempo Constante

## Descripción Técnica
Gemelo seguro de `PV-N2-013`. `authenticate_constant_time` en `app_python/auth_service.py` evalúa siempre la comparación mediante `hmac.compare_digest` (incluso contra un hash ficticio si el usuario no existe) y devuelve un mensaje unívoco indistinguible.

---

# PV-TRAP-028: Trampa FP - SSRF Neutralizado con Validación IP

## Descripción Técnica
Gemelo seguro de `PV-N3-005`. `fetch_webhook_filtered` en `app_python/ssrf_client.py` verifica el esquema HTTPS, resuelve el nombre de host contra el DNS local y comprueba mediante `ipaddress` que ninguna IP resuelta pertenezca a redes privadas o bucle local antes de emitir la conexión.

---

# PV-TRAP-029: Trampa FP - Cargador Seguro de YAML

## Descripción Técnica
Gemelo seguro de `PV-N2-014`. `parse_config_yaml_safe` en `app_python/yaml_parser.py` utiliza `yaml.safe_load()`, bloqueando la instanciación de clases de Python y serializando exclusivamente cadenas, números, listas y mapas.

---

# PV-TRAP-030: Trampa FP - Combinación Segura contra Prototype Pollution

## Descripción Técnica
Gemelo seguro de `PV-N2-015`. `deepMergeSecure` en `app_node/services/mergeUtil.js` descarta de forma tajante las claves `__proto__`, `constructor` y `prototype`, empleando diccionarios puros instanciados mediante `Object.create(null)`.

---

# PV-TRAP-031: Trampa FP - Dependencia con Versión Estable

## Descripción Técnica
Gemelo seguro de `PV-N1-009`. La declaración de `cryptography==39.0.1` en `requirements.txt` representa un componente auditado con fijación exacta de versión y sin vectores de vulnerabilidad conocidos aplicables al alcance del servicio.

---

# PV-TRAP-032: Trampa FP - Manifiesto con Versión Parcheada

## Descripción Técnica
Gemelo seguro de `PV-N1-010`. `package.json` incluye `"express": "^4.18.2"`, versión madura y mantenida que no presenta vulnerabilidades activas registradas en las bases de datos de seguridad CVE/NVD.

---

# PV-TRAP-033: Trampa FP - Dockerfile con Usuario No Privilegiado

## Descripción Técnica
Gemelo seguro de `PV-N1-011`. `infra/Dockerfile.hardened` utiliza la imagen base inmutable `python:3.11-slim-bookworm`, crea un usuario y grupo sin privilegios (`appuser:appgroup`), y añade directivas de `HEALTHCHECK`.

---

# PV-TRAP-034: Trampa FP - Docker Compose Endurecido

## Descripción Técnica
Gemelo seguro de `PV-N1-012`. `infra/docker-compose.hardened.yml` fija `privileged: false`, `read_only: true`, retira todas las capacidades del kernel (`cap_drop: [ALL]`) y restringe la exposición de red a la interfaz de bucle local.

---

# PV-TRAP-035: Trampa FP - Filtrado de Propiedades Seguro

## Descripción Técnica
Gemelo seguro de `PV-N2-016`. `queryCatalogSafe` en `app_node/controllers/catalogController.js` evalúa predicados booleanos estáticos sobre `item.category` e `item.price` convertidos explícitamente a tipos primitivos seguros.

---

# PV-TRAP-036: Trampa FP - Extracción ZIP con Validación de Frontera

## Descripción Técnica
Gemelo seguro de `PV-N2-017`. `extract_bundle_validated` en `app_python/archive_extractor.py` calcula la ruta absoluta de cada entrada y valida mediante `os.path.commonpath` que la ruta común sea idéntica al directorio base, rechazando cualquier intento de Directory Traversal.

---

# PV-TRAP-037: Trampa FP - Plantilla Estática Precompilada

## Descripción Técnica
Gemelo seguro de `PV-N3-006`. `renderPrecompiledTemplate` en `app_node/controllers/templateController.js` utiliza una plantilla estática precompilada y escapa los caracteres HTML de las variables de entrada sin recurrir a evaluadores dinámicos.

---

# PV-TRAP-038: Trampa FP - Facturación Multi-Salto con Parámetros Ligados

## Descripción Técnica
Gemelo seguro de `PV-N4-005`. A pesar de que los parámetros cruzan cuatro niveles de componentes modulares, `recordSecureTransaction` utiliza `dbClient.db.all(sql, [billingAccount, invoiceRef], ...)` neutralizando de forma categórica la inyección.

---

# PV-TRAP-039: Trampa FP - Cliente Inter-Servicio Asegurado

## Descripción Técnica
Gemelo seguro de `PV-N3-007`. `forwardInternalTaskSafe` valida que `action` resida en `ALLOWED_ACTIONS`, firma los parámetros con HMAC y fija la dirección de destino a la interfaz local.

---

# PV-TRAP-040: Trampa FP - Canje Atómico de Cupones

## Descripción Técnica
Gemelo seguro de `PV-N4-006`. `apply_coupon_discount_safe` ejecuta la consulta y el registro dentro de un bloque `with _LOCK`, garantizando la serialización absoluta y la imposibilidad de canjes concurrentes.

---

# PV-TRAP-041: Trampa FP - Validación Estricta de Cantidades

## Descripción Técnica
Gemelo seguro de `PV-N4-007`. `calculateCartTotalSafe` exige `parseInt(..., 10)` y rechaza de inmediato valores no numéricos, menores o iguales a cero o superiores al límite operativo permitido.

---

# PV-TRAP-042: Trampa FP - Control Atómico de Inventario

## Descripción Técnica
Gemelo seguro de `PV-N4-008`. `decrement_inventory_atomic` realiza la comprobación y el decremento bajo el bloqueo `with _STOCK_LOCK`, impidiendo cualquier sobreventa por condiciones de carrera.

---

# PV-TRAP-043: Trampa FP - Cifrado Autenticado con AES-GCM

## Descripción Técnica
Gemelo seguro de `PV-N2-018`. `encrypt_sensitive_data_gcm` emplea `AESGCM` con nonces frescos aleatorios generados mediante `os.urandom(12)`, proveyendo simultáneamente confidencialidad e integridad criptográfica.

---

# PV-TRAP-044: Trampa FP - Tokens Generados con CSPRNG

## Descripción Técnica
Gemelo seguro de `PV-N1-013`. `generateCsrfTokenSecure` recurre a `crypto.randomBytes(32)`, garantizando resistencia completa frente a cualquier vector de predicción o ataques basados en tiempo.

---

# PV-TRAP-045: Trampa FP - Subproceso Seguro sin Shell

## Descripción Técnica
Gemelo seguro de `PV-N2-019`. `run_system_ping_safe` restringe la entrada a caracteres alfanuméricos mediante regex y utiliza `shell=False` pasando un array de argumentos, impidiendo la interpretación de metacaracteres.

---

# PV-TRAP-046: Trampa FP - Ordenación Protegida con Allowlist

## Descripción Técnica
Gemelo seguro de `PV-N3-008`. `queryAuditReportSafe` descarta de forma determinante cualquier valor que no pertenezca al conjunto cerrado `ALLOWED_COLUMNS`, asignando una columna por defecto y un sentido validado.

---

# PV-TRAP-047: Trampa FP - Perfil con Allowlist de Atributos

## Descripción Técnica
Gemelo seguro de `PV-N3-009`. `update_user_profile_filtered` filtra de forma estricta los campos contra `ALLOWED_USER_FIELDS`, descartando silenciosamente cualquier atributo privilegiado.

---

# PV-TRAP-048: Trampa FP - Carga de Archivos Asegurada

## Descripción Técnica
Gemelo seguro de `PV-N2-020`. `handleFileUploadSafe` descarta el nombre provisto por el usuario, valida la extensión contra un allowlist y almacena el archivo bajo un UUID v4 completamente seguro e impredecible.

---

# PV-TRAP-049: Trampa FP - Rechazo de Origen Null en CORS

## Descripción Técnica
Gemelo seguro de `PV-N2-021`. La directiva de CORS para `/api/safe/reports` exige que el origen sea no nulo y coincida exactamente con el portal seguro de la corporación.

---

# PV-TRAP-050: Clave de Cache SHA-256

## Descripcion Tecnica
Uso valido de funcion de hash SHA-256 para asignacion de claves de almacenamiento rapido.

---

# PV-TRAP-051: Metadatos Publicos de Version

## Descripcion Tecnica
Exposicion intencional y segura de numero de compilacion para comprobaciones de salud.

---

# PV-TRAP-052: Modificacion Segura de Orden

## Descripcion Tecnica
Control de acceso por atributo validado en middleware antes del cambio de estado.

---

# PV-TRAP-053: Mitigacion de Inyeccion por Casteo

## Descripcion Tecnica
El casteo int() neutraliza cualquier intento de escape de caracteres de sintaxis SQL.

---

# PV-TRAP-054: Empaquetado con Regex Estricta

## Descripcion Tecnica
Allowlist estricta de caracteres que impide metacaracteres de ejecucion de comandos.

---

# PV-TRAP-055: Callback con Guardrail de Red

## Descripcion Tecnica
Bloqueo de rangos loopback, privados y metadatos de computacion en la nube.

---

# PV-TRAP-056: Firma HMAC Inter-Servicio

## Descripcion Tecnica
Autenticacion criptografica robusta entre nodos del cluster interno.

---

# PV-TRAP-057: Verificacion Asimetrica de Token

## Descripcion Tecnica
Fijacion estricta de algoritmo RS256 que mitiga inyeccion de cabeceras JWK o bypass de firma.

---

# PV-TRAP-058: Precision Financiera con Decimal

## Descripcion Tecnica
Redondeo simetrico que preserva la paridad matematica en toda conversion de divisas.

---

# PV-TRAP-059: Exclusion Mutua en Canje de Cupon

## Descripcion Tecnica
Bloqueo atomico en memoria que asegura aislamiento de la operacion critica.

---

# PV-TRAP-060: Transferencia con Verificacion Previa

## Descripcion Tecnica
Garantia de consistencia ACID mediante verificacion completa antes de la aplicacion de cambios.

---
