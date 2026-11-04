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

# Canarios para verificación empírica de 0 leaks
CANARY_SESSION_TOKEN = "CANARY_SESSION_DATA_DELTA_882"
CANARY_API_PAYLOAD = "CANARY_PAYLOAD_OMEGA_773"

FLASK_SECRET_KEY = "insecure_dev_flask_secret_key_change_in_prod"
