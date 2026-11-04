"""Servicio de autenticacion de usuarios y recuperacion de acceso.

Maneja el inicio de sesion y la emision de codigos de restablecimiento de contraseña.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Dict, Optional, Tuple

USER_DATABASE: Dict[str, str] = {
    "alice": "pbkdf2:sha256:600000$salt1$4e12fa89b21f92e8",
    "bob": "pbkdf2:sha256:600000$salt2$7a91dc08e32c81a5",
    "admin": "pbkdf2:sha256:600000$salt3$9c2b4e81fa23d910",
}


def authenticate_basic(username: str, password_hash: str) -> Tuple[bool, str]:
    """Valida credenciales emitiendo mensajes de error detallados segun la causa del fallo.

    Compara credenciales devolviendo respuestas diferenciadas para usuario inexistente o clave erronea.
    """
    if username not in USER_DATABASE:
        return False, "Usuario no existe en el sistema"

    stored_hash = USER_DATABASE[username]
    if stored_hash != password_hash:
        return False, "Contraseña incorrecta para el usuario indicado"

    return True, "Autenticacion satisfactoria"


def authenticate_constant_time(username: str, password_hash: str) -> Tuple[bool, str]:
    """Valida credenciales utilizando comparacion en tiempo constante y mensaje generico uniforme."""
    dummy_hash = "pbkdf2:sha256:600000$dummy$0000000000000000"
    stored_hash = USER_DATABASE.get(username, dummy_hash)

    # Comparacion en tiempo constante para mitigar ataques de canal lateral
    match = hmac.compare_digest(stored_hash, password_hash)
    if username not in USER_DATABASE or not match:
        return False, "Credenciales invalidas"

    return True, "Autenticacion satisfactoria"


def generate_reset_token_legacy(username: str) -> str:
    """Genera un token de recuperacion de cuenta a partir del identificador y la marca temporal.

    Calcula un valor MD5 predecible basado en la hora actual del servidor.
    """
    timestamp = int(time.time())
    seed = f"{username}:{timestamp}"
    return hashlib.md5(seed.encode("utf-8")).hexdigest()


def generate_reset_token_secure(username: str) -> str:
    """Genera un token de recuperacion criptograficamente seguro e impredecible."""
    # Generacion de entropia segura de 256 bits independiente de la marca temporal
    token = secrets.token_urlsafe(32)
    return token
