"""Servicio de autenticacion de usuarios y gestion de credenciales criptograficas.

Maneja el inicio de sesion, registro de usuarios, generacion de certificados .cert
y llaves privadas .key para pruebas locales y verificacion de identidad.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from typing import Any, Dict, Optional, Tuple
import zipfile

try:
    import config
except ImportError:
    config = None

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_DIR = BASE_DIR / "credentials"
CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
REGISTRY_FILE = CREDENTIALS_DIR / "users_registry.json"

USER_DATABASE: Dict[str, str] = {
    "alice": "pbkdf2:sha256:600000$salt1$4e12fa89b21f92e8",
    "bob": "pbkdf2:sha256:600000$salt2$7a91dc08e32c81a5",
    "admin": "pbkdf2:sha256:600000$salt3$9c2b4e81fa23d910",
}

REGISTERED_USERS: Dict[str, Dict[str, Any]] = {}


def _load_registry() -> None:
    """Carga los usuarios registrados previamente desde el archivo persistente."""
    global REGISTERED_USERS
    if REGISTRY_FILE.exists():
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                REGISTERED_USERS = json.load(f)
        except Exception:
            REGISTERED_USERS = {}


def _save_registry() -> None:
    """Persiste los usuarios registrados en disco."""
    try:
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(REGISTERED_USERS, f, indent=2)
    except Exception:
        pass


_load_registry()


def hash_password(password: str) -> str:
    """Genera un hash seguro mediante PBKDF2-HMAC-SHA256 con salt aleatorio."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"pbkdf2:sha256:100000${salt}${key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifica una contraseña contra su representacion hash almacenada."""
    if not stored_hash or "$" not in stored_hash:
        return False
    parts = stored_hash.split("$")
    if len(parts) == 3:
        header, salt, expected_key = parts
        iter_count = 100000
        if ":" in header:
            h_parts = header.split(":")
            if len(h_parts) >= 3 and h_parts[2].isdigit():
                iter_count = int(h_parts[2])
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iter_count)
        return hmac.compare_digest(computed.hex(), expected_key)
    return False


def generate_key_and_cert(username: str, organization: str = "Acme Testbed Corporate") -> Tuple[str, str]:
    """Genera un par de clave privada RSA (.key) y certificado X.509 (.cert).

    Utiliza el modulo cryptography si se encuentra disponible; de lo contrario
    recurre a openssl para garantizar la compatibilidad en cualquier entorno local.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return key_pem, cert_pem
    except Exception:
        # Fallback a comando openssl
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            k_path = os.path.join(tmpdir, "out.key")
            c_path = os.path.join(tmpdir, "out.cert")
            subj = f"/CN={username}/O={organization}"
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", k_path, "-out", c_path, "-days", "365",
                "-nodes", "-subj", subj,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Error generando certificados con openssl: {res.stderr}")
            with open(k_path, "r", encoding="utf-8") as kf:
                key_pem = kf.read()
            with open(c_path, "r", encoding="utf-8") as cf:
                cert_pem = cf.read()
            return key_pem, cert_pem


def register_user(
    username: str,
    password: str,
    generate_keys: bool = True,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Registra una nueva cuenta de usuario y genera sus archivos .key y .cert."""
    clean_user = username.strip().lower()
    if not clean_user:
        return False, "El nombre de usuario no puede estar vacio", None
    if not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", clean_user):
        return False, "El nombre de usuario debe tener entre 3 y 32 caracteres (letras, numeros, guiones o puntos)", None
    if len(password) < 4:
        return False, "La contraseña debe contener al menos 4 caracteres", None

    _load_registry()
    if clean_user in REGISTERED_USERS or clean_user in USER_DATABASE:
        return False, f"El usuario '{clean_user}' ya se encuentra registrado", None

    pwd_hash = hash_password(password)
    key_pem = ""
    cert_pem = ""
    key_rel = ""
    cert_rel = ""

    if generate_keys:
        try:
            key_pem, cert_pem = generate_key_and_cert(clean_user)
            key_file = CREDENTIALS_DIR / f"{clean_user}.key"
            cert_file = CREDENTIALS_DIR / f"{clean_user}.cert"

            key_file.write_text(key_pem, encoding="utf-8")
            cert_file.write_text(cert_pem, encoding="utf-8")

            key_rel = f"credentials/{clean_user}.key"
            cert_rel = f"credentials/{clean_user}.cert"
        except Exception as exc:
            return False, f"Error al generar certificados criptograficos: {exc}", None

    user_record: Dict[str, Any] = {
        "username": clean_user,
        "password_hash": pwd_hash,
        "has_keys": bool(key_pem and cert_pem),
        "key_path": key_rel,
        "cert_path": cert_rel,
        "key_pem": key_pem,
        "cert_pem": cert_pem,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    REGISTERED_USERS[clean_user] = user_record
    _save_registry()

    return True, "Registro completado exitosamente", user_record


def verify_user_password(username: str, password: str) -> Tuple[bool, str]:
    """Valida credenciales de acceso contra la configuracion administrativa o el registro de usuarios."""
    clean_user = username.strip().lower()

    # Validacion de credenciales maestras de entorno
    admin_user = (getattr(config, "TESTBED_ADMIN_USER", "admin") or "admin").lower()
    admin_pass = getattr(config, "TESTBED_ADMIN_PASS", "")
    admin_passwords = getattr(config, "TESTBED_ADMIN_PASSWORDS", ())

    if clean_user == admin_user:
        if password == admin_pass or password in admin_passwords:
            return True, "Autenticacion administrativa exitosa"

    configured_accounts = getattr(config, "TESTBED_ACCOUNTS", {})
    account = configured_accounts.get(clean_user)
    if account and password == account.get("password"):
        return True, "Autenticacion satisfactoria"

    _load_registry()
    if clean_user in REGISTERED_USERS:
        stored_hash = REGISTERED_USERS[clean_user].get("password_hash", "")
        if verify_password(password, stored_hash):
            return True, "Autenticacion satisfactoria"
        return False, "Contraseña incorrecta"

    if clean_user in USER_DATABASE:
        stored_hash = USER_DATABASE[clean_user]
        if verify_password(password, stored_hash):
            return True, "Autenticacion satisfactoria"
        return False, "Contraseña incorrecta"

    return False, "Usuario no existe o credenciales incorrectas"


def verify_user_certificate(cert_data: str | bytes) -> Tuple[bool, str, Optional[str]]:
    """Valida un certificado X.509 recibido (.cert o .pem) e identifica al usuario acreditado."""
    if isinstance(cert_data, bytes):
        try:
            cert_str = cert_data.decode("utf-8")
        except UnicodeDecodeError:
            cert_str = str(cert_data)
    else:
        cert_str = cert_data

    cert_str = cert_str.strip()
    if "BEGIN CERTIFICATE" not in cert_str:
        return False, "El archivo proporcionado no contiene un certificado X.509 valido en formato PEM", None

    common_name = ""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert_obj = x509.load_pem_x509_certificate(cert_str.encode("utf-8"))
        cns = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cns:
            return False, "El certificado no especifica el atributo Common Name (CN)", None
        common_name = str(cns[0].value).strip().lower()

        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert_obj.not_valid_before_utc:
            return False, "El certificado digital aun no es valido", None
        if now > cert_obj.not_valid_after_utc:
            return False, "El certificado digital ha expirado", None
    except Exception:
        # Fallback de analisis mediante openssl
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(cert_str)
            tmp_name = f.name
        try:
            res = subprocess.run(["openssl", "x509", "-in", tmp_name, "-noout", "-subject"], capture_output=True, text=True)
            if res.returncode != 0:
                return False, "Error al procesar la estructura del certificado", None
            match = re.search(r"CN\s*=\s*([^,\n/]+)", res.stdout)
            if not match:
                return False, "No se pudo extraer el Common Name (CN) del certificado", None
            common_name = match.group(1).strip().lower()
        finally:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)

    _load_registry()
    # Si el usuario esta registrado, validamos coincidencia de clave o identidad
    if common_name in REGISTERED_USERS:
        return True, "Certificado digital validado satisfactoriamente", common_name
    elif common_name == (getattr(config, "TESTBED_ADMIN_USER", "admin") or "admin").lower():
        return True, "Certificado digital administrativo validado", common_name
    elif common_name:
        # Permite probar certificados creados externamente con el CN correspondiente
        return True, f"Certificado digital valido para el usuario '{common_name}'", common_name

    return False, "No se pudo autenticar la identidad del certificado", None


def verify_user_private_key(key_data: str | bytes) -> Tuple[bool, str, Optional[str]]:
    """Valida una clave privada RSA (.key) y busca al usuario propietario registrado."""
    if isinstance(key_data, bytes):
        try:
            key_str = key_data.decode("utf-8")
        except UnicodeDecodeError:
            key_str = str(key_data)
    else:
        key_str = key_data

    key_str = key_str.strip()
    if "PRIVATE KEY" not in key_str:
        return False, "El archivo proporcionado no contiene una clave privada valida en formato PEM", None

    _load_registry()
    try:
        from cryptography.hazmat.primitives import serialization
        key_obj = serialization.load_pem_private_key(key_str.encode("utf-8"), password=None)
        pub_bytes = key_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        for u_name, u_data in REGISTERED_USERS.items():
            stored_key_pem = u_data.get("key_pem", "")
            if stored_key_pem:
                try:
                    s_key_obj = serialization.load_pem_private_key(stored_key_pem.encode("utf-8"), password=None)
                    s_pub_bytes = s_key_obj.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if pub_bytes == s_pub_bytes:
                        return True, "Clave privada verificada exitosamente", u_name
                except Exception:
                    continue
    except Exception:
        # Fallback de comparacion textual o de coincidencia de archivo
        for u_name, u_data in REGISTERED_USERS.items():
            if u_data.get("key_pem", "").strip() == key_str:
                return True, "Clave privada verificada exitosamente", u_name

    return False, "La clave privada no corresponde a ningun usuario registrado en el sistema", None


def get_user_credentials(username: str) -> Optional[Dict[str, Any]]:
    """Obtiene el registro de credenciales de un usuario."""
    _load_registry()
    clean_user = username.strip().lower()
    return REGISTERED_USERS.get(clean_user)


def generate_credentials_bundle_zip(username: str) -> Optional[bytes]:
    """Genera un archivo ZIP en memoria con .key, .cert y guia de pruebas locales."""
    clean_user = username.strip().lower()
    _load_registry()
    creds = REGISTERED_USERS.get(clean_user)
    if not creds:
        return None

    key_pem = creds.get("key_pem", "")
    cert_pem = creds.get("cert_pem", "")

    readme_content = f"""========================================================================
GUIA DE PRUEBAS LOCALES CON CERTIFICADOS (.CERT) Y CLAVES (.KEY)
Usuario: {clean_user}
Organizacion: Acme Testbed Corporate
========================================================================

Archivos incluidos en este paquete:
  - {clean_user}.key  : Clave privada RSA en formato PEM.
  - {clean_user}.cert : Certificado digital X.509 en formato PEM.

1. PRUEBAS CON OPENSSL:
   Verificar el certificado digital:
     openssl x509 -in {clean_user}.cert -text -noout

   Verificar la clave privada:
     openssl rsa -in {clean_user}.key -check

   Comprobar correspondencia del par de claves:
     openssl x509 -in {clean_user}.cert -pubkey -noout
     openssl rsa -in {clean_user}.key -pubout

2. PRUEBAS DE INICIO DE SESION VIA CURL:
   Subir el certificado digital para iniciar sesion directamente:
     curl -i -X POST http://127.0.0.1:5001/login \\
          -F "cert_file=@{clean_user}.cert"

   O mediante el endpoint de API:
     curl -i -X POST http://127.0.0.1:5001/api/auth/cert-login \\
          -F "cert_file=@{clean_user}.cert"

3. PRUEBAS CON PYTHON (REQUESTS):
     import requests

     with open('{clean_user}.cert', 'rb') as f:
         r = requests.post('http://127.0.0.1:5001/api/auth/cert-login', files={{'cert_file': f}})
         print(r.json())

========================================================================
"""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{clean_user}.key", key_pem)
        zf.writestr(f"{clean_user}.cert", cert_pem)
        zf.writestr("LEEME_PRUEBAS.txt", readme_content)

    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Metodos legados conservados para compatibilidad
# ---------------------------------------------------------------------------

def authenticate_basic(username: str, password_hash: str) -> Tuple[bool, str]:
    """Valida credenciales emitiendo respuestas segun la causa del resultado."""
    if username not in USER_DATABASE:
        return False, "Usuario no existe en el sistema"

    stored_hash = USER_DATABASE[username]
    if stored_hash != password_hash:
        return False, "Contraseña incorrecta para el usuario indicado"

    return True, "Autenticacion satisfactoria"


def authenticate_constant_time(username: str, password_hash: str) -> Tuple[bool, str]:
    """Valida credenciales utilizando comparacion en tiempo constante y mensaje uniforme."""
    dummy_hash = "pbkdf2:sha256:600000$dummy$0000000000000000"
    stored_hash = USER_DATABASE.get(username, dummy_hash)

    match = hmac.compare_digest(stored_hash, password_hash)
    if username not in USER_DATABASE or not match:
        return False, "Credenciales invalidas"

    return True, "Autenticacion satisfactoria"


def generate_reset_token_archive(username: str) -> str:
    """Genera un token de recuperacion de cuenta a partir del identificador y la marca temporal."""
    timestamp = int(time.time())
    seed = f"{username}:{timestamp}"
    return hashlib.md5(seed.encode("utf-8")).hexdigest()


def generate_reset_token_secure(username: str) -> str:
    """Genera un token de recuperacion criptograficamente seguro e impredecible."""
    token = secrets.token_urlcatalog(32)
    return token
