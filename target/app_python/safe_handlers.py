"""Manejadores de integracion y utilidades seguras del backend en Python.

Implementa procesamiento de webhooks externos y recuperacion de sesion.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from typing import Any, Dict

from flask import Blueprint, jsonify, request

import config

safe_bp = Blueprint("safe_handlers", __name__)

ALLOWED_PARTNER_DOMAINS = {"api.github.com", "httpbin.org"}


# ---------------------------------------------------------------------------
# Webhook de integracion con lista blanca de dominios y resolucion de red
# ---------------------------------------------------------------------------

def safe_webhook_fetch(target_url: str) -> Dict[str, Any]:
    """Descarga segura de webhook con validación estricta de esquema, dominio e IP.

    Valida exhaustivamente esquema HTTPS, allowlist de hostnames y resolucion
    DNS impidiendo acceso a rangos de red internos, direcciones loopback
    y servicios de metadatos de proveedores de nube.
    """
    parsed = urllib.parse.urlsplit(target_url)

    # 1. Esquema estrictamente HTTPS
    if parsed.scheme.lower() != "https":
        raise ValueError("Esquema no permitido: solo HTTPS es admitido")

    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname not in ALLOWED_PARTNER_DOMAINS:
        raise ValueError(f"Dominio no autorizado por allowlist: {hostname}")

    # 2. Resolución DNS y verificación de IP (anti-DNS rebinding / RFC 1918 / AWS metadata)
    try:
        addr_info = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Fallo en resolución DNS para {hostname}: {exc}") from exc

    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_str)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            raise ValueError(f"Acceso denegado a red privada/restringida: {ip_str}")

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "SecureTestbedClient/1.0"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read(1024)
        return {
            "status": "success",
            "http_code": resp.status,
            "bytes_read": len(body),
        }


@safe_bp.route("/api/safe/webhook", methods=["POST"])
def safe_webhook_endpoint():
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "Parámetro 'url' requerido"}), 400

    try:
        result = safe_webhook_fetch(url)
        return jsonify(result)
    except ValueError as val_err:
        return jsonify({"error": f"URL rechazada: {val_err}"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Restauracion de sesion autenticada mediante firma criptografica HMAC y JSON
# ---------------------------------------------------------------------------

def safe_session_restore(payload_b64: str, signature: str) -> Dict[str, Any]:
    """Restaura sesión utilizando JSON estricto y validación de firma HMAC-SHA256.

    Valida la integridad de los datos mediante firma HMAC-SHA256 en tiempo constante;
    reconstruye el estado de sesion exclusivamente mediante deserializacion JSON,
    rechazando cualquier formato binario o ejecutable no seguro.
    """
    secret = config.FLASK_SECRET_KEY.encode("utf-8")
    try:
        raw_bytes = base64.b64decode(payload_b64)
    except Exception as exc:
        raise ValueError("Payload base64 inválido") from exc

    expected_sig = hmac.new(secret, raw_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature or ""):
        raise ValueError("Firma HMAC inválida o manipulada")

    try:
        parsed_data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Formato JSON corrupto en estado de sesión") from exc

    if not isinstance(parsed_data, dict):
        raise ValueError("El estado de sesión debe ser un diccionario JSON")

    return parsed_data


@safe_bp.route("/api/safe/session/restore", methods=["POST"])
def safe_session_restore_endpoint():
    data = request.get_json(silent=True) or {}
    payload_b64 = data.get("session_data")
    signature = data.get("signature")

    if not payload_b64 or not signature:
        return jsonify({"error": "Se requieren los campos 'session_data' y 'signature'"}), 400

    try:
        restored = safe_session_restore(payload_b64, signature)
        return jsonify({"status": "restored", "session": restored})
    except ValueError as val_err:
        return jsonify({"error": f"Firma HMAC inválida: {val_err}"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
