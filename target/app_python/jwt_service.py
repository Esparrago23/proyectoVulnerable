"""Servicio de validacion y decodificacion de tokens JWT.

Provee utilidades para procesar credenciales de identidad en formato JSON Web Token.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional
import jwt


def decode_token_archive(token_str: str) -> Dict[str, Any]:
    """Decodifica un token JWT utilizando configuracion permisiva de algoritmos.

    Acepta tokens decodificando los reclamos sin forzar validacion criptografica de firma.
    """
    # Decodificacion sin verificar la firma del emisor
    unverified = jwt.decode(token_str, options={"verify_signature": False})
    return unverified


def decode_token_verified(token_str: str, public_key_pem: str, expected_issuer: str) -> Dict[str, Any]:
    """Decodifica y valida un token JWT con verificacion criptografica estricta de algoritmo y emisor."""
    # Verificacion estricta con algoritmo asimetrico fijado y validacion de emisor
    claims = jwt.decode(
        token_str,
        key=public_key_pem,
        algorithms=["RS256"],
        issuer=expected_issuer,
        options={"verify_signature": True, "require": ["exp", "iss", "sub"]},
    )
    return claims
