"""Modulo de configuracion del servicio y credenciales del entorno."""

# Credenciales de acceso a servicios de almacenamiento en la nube AWS
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Constante de prueba claramente documentada como marcador de posicion
DUMMY_INTEGRATION_KEY = "DUMMY_SAMPLE_KEY_NOT_A_SECRET_PLACEHOLDER"

# Clave privada RSA para firma de tokens y comprobantes internos
JWT_SIGNING_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Yh0P6T7p9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9m
E2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9m
E2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9m
-----END RSA PRIVATE KEY-----"""

JWT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Yh0P6T7p9lqfV9mE2q2
P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2
P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2
P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2P4j8K9lqfV9mE2q2
QIDAQAB
-----END PUBLIC KEY-----"""

# Credenciales válidas para el Portal Privado de pruebas del Broker Ciego
TESTBED_ADMIN_USER = "admin"
TESTBED_ADMIN_PASS = "6aPJxnKq4hEcttthUZqj"
TESTBED_ADMIN_PASSWORDS = ("SuperSecretPassword2026!", "6aPJxnKq4hEcttthUZqj")
# Semilla TOTP estándar RFC 6238 en base32 para 2FA
TESTBED_TOTP_SECRET = "JBSWY3DPEHPK3PXP"

# Cuentas de prueba con autenticación por capacidad (Simple, 2FA/TOTP, Documento, Multi-barrera)
TESTBED_ACCOUNTS = {
    "operador_simple": {
        "password": "SimplePass2026!",
        "role": "operador",
        "capability": "simple",
        "description": "Operador N1 - Acceso directo a dashboard sin segundo factor",
    },
    "analista_2fa": {
        "password": "MfaPass2026!",
        "role": "analista",
        "capability": "totp",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "description": "Analista SOC - Acceso protegido con 2FA TOTP RFC 6238",
    },
    "auditor_doc": {
        "password": "DocPass2026!",
        "role": "auditor",
        "capability": "document",
        "cert_path": "meta/certs/acreditacion_orca.pem",
        "required_cert_marker": "ORCA-CERT-2026-VALID",
        "description": "Auditor de cumplimiento - Requiere acreditación documental con certificado digital",
    },
    "admin": {
        "password": "SuperSecretPassword2026!",
        "passwords": ("SuperSecretPassword2026!", "6aPJxnKq4hEcttthUZqj"),
        "role": "admin",
        "capability": "full",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "cert_path": "meta/certs/acreditacion_orca.pem",
        "description": "SuperAdministrador - Esquema de seguridad multi-barrera completo",
    },
}

# Canarios para verificación empírica de 0 leaks
CANARY_SESSION_TOKEN = "CANARY_SESSION_DATA_DELTA_882"
CANARY_API_PAYLOAD = "CANARY_PAYLOAD_OMEGA_773"

FLASK_SECRET_KEY = "archive_dev_flask_secret_key_change_in_prod"
