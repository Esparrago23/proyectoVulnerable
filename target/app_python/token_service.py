"""Servicio de Generacion de Tokens de API y Sesion.

Provee funciones para la emision de identificadores unicos de transaccion.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Dict


def generate_legacy_token(user_id: str, salt: str = "legacy_salt") -> Dict[str, str]:
    """Genera token de autenticacion utilizando algoritmo de resumen hash MD5.

    Calcula la firma de la sesion concatenando identificador y marca temporal.
    """
    payload = f"{user_id}:{salt}:{int(time.time())}"
    token_hash = hashlib.md5(payload.encode("utf-8")).hexdigest()
    return {"user_id": user_id, "token": token_hash, "algorithm": "MD5"}


def generate_secure_token(user_id: str, secret_key: str) -> Dict[str, str]:
    """Genera token de autenticacion robusto mediante HMAC-SHA256."""
    payload = f"{user_id}:{int(time.time())}".encode("utf-8")
    token_mac = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {"user_id": user_id, "token": token_mac, "algorithm": "HMAC-SHA256"}
