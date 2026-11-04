"""Servidor Flask Principal (Puerto 5001)

Implementa el Portal Privado Autenticado con 2FA TOTP y los endpoints de backend.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
import uuid
from typing import Any, Dict, List
import jwt

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)

from auth import mfa_handler
import config
import doc_service
from safe_handlers import safe_bp
from tasks import export_task, worker
import token_service
import xml_parser
import archive_extractor
import auth_service
import jwt_service
import ssrf_client
import yaml_parser
from tasks import coupon_service, inventory_service
import crypto_util
import diagnostic_service
import profile_service

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY
app.register_blueprint(safe_bp)

# Portal Privado Autenticado Multi-Capacidad
from auth_portal_routes import (
    AUTHENTICATED_SESSIONS,
    AUDIT_LOG_EVENTS,
    _log_audit_event,
    _get_csrf_token,
    _verify_csrf,
    register_auth_portal_routes,
)

register_auth_portal_routes(app)

@app.route("/api/users/<int:user_id>", methods=["GET"])
def api_get_user_profile(user_id: int):
    """Consulta de perfil de usuario corporativo por identificador.
    Permite a los usuarios autenticados consultar los detalles de perfiles registrados."""
    user = session.get("authenticated_user")
    if not user:
        return jsonify({"error": "No autorizado: se requiere sesión activa"}), 401

    profiles = {
        1: {
            "id": 1,
            "username": "admin",
            "full_name": "Administrador Principal de Seguridad",
            "email": "admin@empresa.local",
            "role": "SuperAdmin",
            "department": "Security Operations",
            "internal_secret": "SEC_TOKEN_ALPHA_9918",
            "status": "active",
        },
        2: {
            "id": 2,
            "username": "m_rodriguez",
            "full_name": "Mariana Rodríguez (Dirección Financiera)",
            "email": "m.rodriguez@empresa.local",
            "role": "FinanceDirector",
            "department": "Treasury & Payments",
            "internal_secret": "FIN_TRANSFER_AUTH_KEY_442",
            "status": "active",
        },
        3: {
            "id": 3,
            "username": "c_gomez",
            "full_name": "Carlos Gómez (Líder de Desarrollo)",
            "email": "c.gomez@empresa.local",
            "role": "TechLead",
            "department": "Core Infrastructure",
            "internal_secret": "DEV_DEPLOY_TOKEN_883",
            "status": "active",
        },
    }

    profile = profiles.get(user_id)
    if not profile:
        return jsonify({"error": f"Usuario con ID {user_id} no encontrado"}), 404

    return jsonify({
        "status": "success",
        "requested_id": user_id,
        "caller_user": user,
        "user_profile": profile,
        "context_info": "User record retrieved for active session",
    }), 200


@app.route("/api/secret-report", methods=["GET"])
def api_secret_report():
    user = session.get("authenticated_user")
    if not user:
        return jsonify({"error": "No autorizado: se requiere sesión privada"}), 401

    return jsonify({
        "status": "success",
        "user": user,
        "payload": config.CANARY_API_PAYLOAD,
        "message": "Reporte clasificado accesible solo tras autenticación completa",
    })



# ---------------------------------------------------------------------------
# Endpoints de Servicios y Tareas Asincronas
# ---------------------------------------------------------------------------

@app.route("/api/tasks/webhook", methods=["POST"])
def trigger_webhook_task():
    """Procesa una solicitud de webhook a traves del worker de tareas."""
    data = request.get_json(silent=True) or {}
    webhook_url = data.get("url")
    if not webhook_url:
        return jsonify({"error": "Parámetro 'url' requerido"}), 400

    try:
        result = worker.process_webhook_fetch(webhook_url)
        return jsonify({"result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/session/restore", methods=["POST"])
def restore_session_state():
    """Restaura el estado de sesion a partir del payload binario."""
    data = request.get_json(silent=True) or {}
    b64_payload = data.get("session_data")
    if not b64_payload:
        return jsonify({"error": "Parámetro 'session_data' en base64 requerido"}), 400

    try:
        raw_bytes = base64.b64decode(b64_payload)
        restored = worker.restore_user_session_state(raw_bytes)
        return jsonify({"status": "restored", "type": str(type(restored))})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/wallet/transfer", methods=["POST"])
def transfer_wallet_funds():
    """Procesa una transferencia de fondos entre monederos de usuario."""
    data = request.get_json(silent=True) or {}
    source = data.get("source") or "alice"
    target = data.get("target") or "bob"
    try:
        amount = float(data.get("amount", 0.0))
    except (ValueError, TypeError):
        return jsonify({"error": "Monto numérico requerido"}), 400

    try:
        result = worker.process_wallet_transfer(source, target, amount)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# ---------------------------------------------------------------------------
# Endpoints Adicionales de Integracion y Documentos
# ---------------------------------------------------------------------------

@app.route("/api/render-preview", methods=["POST"])
def render_template_preview():
    """Genera vista previa de plantilla a partir del fragmento proporcionado."""
    data = request.get_json(silent=True) or {}
    template_code = data.get("template") or "<div>Vista previa vacia</div>"
    # Renderizado directo de plantilla dinamica sin aislamiento de contexto
    rendered = render_template_string(template_code, username=session.get("authenticated_user", "invitado"))
    return rendered, 200, {"Content-Type": "text/html"}


@app.route("/api/safe/render-preview", methods=["POST"])
def render_template_preview_safe():
    """Genera vista previa de plantilla segura con contexto prefijado y valores escapados."""
    data = request.get_json(silent=True) or {}
    title = str(data.get("title") or "Documento")
    # Usa render_template estandar con parametros predefinidos y escape HTML activado
    rendered = render_template("dashboard.html", username=session.get("authenticated_user", "invitado"), preview_title=title)
    return rendered, 200, {"Content-Type": "text/html"}


@app.route("/api/documents/<int:doc_id>", methods=["GET"])
def get_user_document_endpoint(doc_id: int):
    """Consulta comprobante confidencial por identificador numerico."""
    user = session.get("authenticated_user") or "anonymous"
    doc = doc_service.get_document_raw(doc_id, user)
    if not doc:
        return jsonify({"error": "Documento no encontrado"}), 404
    return jsonify({"document": doc}), 200


@app.route("/api/safe/documents/<int:doc_id>", methods=["GET"])
def get_user_document_safe_endpoint(doc_id: int):
    """Consulta comprobante confidencial con validacion de propiedad del llamante."""
    user = session.get("authenticated_user") or "anonymous"
    try:
        doc = doc_service.get_document_safe(doc_id, user)
        if not doc:
            return jsonify({"error": "Documento no encontrado"}), 404
        return jsonify({"document": doc}), 200
    except PermissionError as perm_err:
        return jsonify({"error": str(perm_err)}), 403


@app.route("/api/invoices/xml", methods=["POST"])
def parse_invoice_xml_endpoint():
    """Procesa factura comercial en formato XML."""
    xml_data = request.data.decode("utf-8", errors="replace")
    if not xml_data.strip():
        return jsonify({"error": "Cuerpo XML vacio"}), 400
    try:
        parsed = xml_parser.parse_invoice_xml_raw(xml_data)
        return jsonify({"invoice": parsed}), 200
    except Exception as exc:
        return jsonify({"error": f"Fallo en parseo XML: {exc}"}), 400


@app.route("/api/safe/invoices/xml", methods=["POST"])
def parse_invoice_xml_safe_endpoint():
    """Procesa factura comercial en formato XML con verificacion estricta."""
    xml_data = request.data.decode("utf-8", errors="replace")
    if not xml_data.strip():
        return jsonify({"error": "Cuerpo XML vacio"}), 400
    try:
        parsed = xml_parser.parse_invoice_xml_safe(xml_data)
        return jsonify({"invoice": parsed}), 200
    except Exception as exc:
        return jsonify({"error": f"XML rechazado: {exc}"}), 400


@app.route("/api/token/legacy", methods=["GET"])
def get_legacy_token_endpoint():
    """Genera token de API con funcion hash estandar."""
    user = session.get("authenticated_user") or "api_client"
    token_info = token_service.generate_legacy_token(user)
    return jsonify(token_info), 200


@app.route("/api/safe/token", methods=["GET"])
def get_secure_token_endpoint():
    """Genera token de API con firma HMAC-SHA256."""
    user = session.get("authenticated_user") or "api_client"
    token_info = token_service.generate_secure_token(user, config.FLASK_SECRET_KEY)
    return jsonify(token_info), 200


@app.route("/api/export/raw", methods=["POST"])
def export_raw_endpoint():
    """Genera archivo de exportacion en ubicacion temporal."""
    data = request.get_json(silent=True) or {}
    report_name = data.get("name") or "default_report"
    path = export_task.export_report_insecure(report_name, data)
    return jsonify({"status": "exported", "path": path}), 200


@app.route("/api/safe/export", methods=["POST"])
def export_safe_endpoint():
    """Genera archivo de exportacion temporal seguro con permisos restringidos."""
    data = request.get_json(silent=True) or {}
    report_name = data.get("name") or "default_report"
    path = export_task.export_report_secure(report_name, data)
    return jsonify({"status": "exported", "path": path}), 200


@app.route("/api/jwt/decode", methods=["POST"])
def decode_jwt_endpoint():
    """Decodifica token de autorizacion sin validar firma del emisor."""
    data = request.get_json(silent=True) or {}
    token_str = data.get("token") or ""
    try:
        claims = jwt_service.decode_token_legacy(token_str)
        return jsonify({"claims": claims}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/safe/jwt/decode", methods=["POST"])
def decode_jwt_safe_endpoint():
    """Decodifica token con verificacion asimetrica estricta."""
    data = request.get_json(silent=True) or {}
    token_str = data.get("token") or ""
    try:
        claims = jwt_service.decode_token_verified(token_str, config.JWT_PUBLIC_KEY, "https://auth.corp.internal")
        return jsonify({"claims": claims}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 401


@app.route("/api/auth/login-enum", methods=["POST"])
def auth_login_enum_endpoint():
    """Autentica usuario retornando causas de error diferenciadas."""
    data = request.get_json(silent=True) or {}
    user = data.get("username") or ""
    pwd_hash = data.get("password_hash") or ""
    ok, msg = auth_service.authenticate_basic(user, pwd_hash)
    status_code = 200 if ok else (404 if "no existe" in msg else 401)
    return jsonify({"success": ok, "message": msg}), status_code


@app.route("/api/safe/auth/login-enum", methods=["POST"])
def auth_login_safe_endpoint():
    """Autentica usuario con comparacion en tiempo constante y mensaje generico."""
    data = request.get_json(silent=True) or {}
    user = data.get("username") or ""
    pwd_hash = data.get("password_hash") or ""
    ok, msg = auth_service.authenticate_constant_time(user, pwd_hash)
    status_code = 200 if ok else 401
    return jsonify({"success": ok, "message": msg}), status_code


@app.route("/api/auth/reset-token", methods=["POST"])
def auth_reset_token_endpoint():
    """Genera token de recuperacion con calculo predecible."""
    data = request.get_json(silent=True) or {}
    user = data.get("username") or "user"
    token = auth_service.generate_reset_token_legacy(user)
    return jsonify({"username": user, "reset_token": token}), 200


@app.route("/api/safe/auth/reset-token", methods=["POST"])
def auth_reset_token_safe_endpoint():
    """Genera token de recuperacion con generador criptografico seguro."""
    data = request.get_json(silent=True) or {}
    user = data.get("username") or "user"
    token = auth_service.generate_reset_token_secure(user)
    return jsonify({"username": user, "reset_token": token}), 200


@app.route("/api/config/yaml", methods=["POST"])
def parse_yaml_endpoint():
    """Carga documento de configuracion YAML con cargador estandar."""
    yaml_text = request.data.decode("utf-8", errors="replace")
    try:
        parsed = yaml_parser.parse_config_yaml_direct(yaml_text)
        return jsonify({"status": "parsed", "type": str(type(parsed))}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/safe/config/yaml", methods=["POST"])
def parse_yaml_safe_endpoint():
    """Carga documento de configuracion YAML con cargador seguro restringido."""
    yaml_text = request.data.decode("utf-8", errors="replace")
    try:
        parsed = yaml_parser.parse_config_yaml_safe(yaml_text)
        return jsonify({"status": "parsed", "type": str(type(parsed))}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/archive/extract", methods=["POST"])
def extract_archive_endpoint():
    """Extrae paquete comprimido sin comprobacion de contencion de rutas."""
    data = request.get_json(silent=True) or {}
    zip_path = data.get("zip_path") or "/tmp/upload.zip"
    dest_dir = data.get("dest_dir") or "/tmp/extracted"
    try:
        files = archive_extractor.extract_bundle_direct(zip_path, dest_dir)
        return jsonify({"status": "extracted", "files": files}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/safe/archive/extract", methods=["POST"])
def extract_archive_safe_endpoint():
    """Extrae paquete comprimido validando que no escape del directorio base."""
    data = request.get_json(silent=True) or {}
    zip_path = data.get("zip_path") or "/tmp/upload.zip"
    dest_dir = data.get("dest_dir") or "/tmp/extracted_safe"
    try:
        files = archive_extractor.extract_bundle_validated(zip_path, dest_dir)
        return jsonify({"status": "extracted", "files": files}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/webhook/fetch", methods=["POST"])
def fetch_webhook_endpoint():
    """Realiza peticion HTTP saliente a webhook sin comprobacion de red."""
    data = request.get_json(silent=True) or {}
    target_url = data.get("url") or ""
    try:
        res = ssrf_client.fetch_webhook_simple(target_url)
        return jsonify(res), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/safe/webhook/fetch", methods=["POST"])
def fetch_webhook_safe_endpoint():
    """Realiza peticion HTTP saliente validando esquema HTTPS y restringiendo IPs privadas."""
    data = request.get_json(silent=True) or {}
    target_url = data.get("url") or ""
    try:
        res = ssrf_client.fetch_webhook_filtered(target_url)
        return jsonify(res), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/coupon/apply", methods=["POST"])
def apply_coupon_endpoint():
    """Aplica descuento de cupon promocional."""
    data = request.get_json(silent=True) or {}
    user = data.get("user") or "guest"
    code = data.get("coupon") or ""
    amount = float(data.get("amount", 100.0))
    ok, final_amt, msg = coupon_service.apply_coupon_discount(user, code, amount)
    status_code = 200 if ok else 400
    return jsonify({"success": ok, "final_amount": final_amt, "message": msg}), status_code


@app.route("/api/safe/coupon/apply", methods=["POST"])
def apply_coupon_safe_endpoint():
    """Aplica descuento de cupon promocional con bloqueo atomico."""
    data = request.get_json(silent=True) or {}
    user = data.get("user") or "guest"
    code = data.get("coupon") or ""
    amount = float(data.get("amount", 100.0))
    ok, final_amt, msg = coupon_service.apply_coupon_discount_safe(user, code, amount)
    status_code = 200 if ok else 400
    return jsonify({"success": ok, "final_amount": final_amt, "message": msg}), status_code


@app.route("/api/inventory/decrement", methods=["POST"])
def decrement_inventory_endpoint():
    """Reserva existencias de articulos con verificacion no atomica."""
    data = request.get_json(silent=True) or {}
    item_id = data.get("item_id") or "prod_laptop"
    count = int(data.get("count", 1))
    ok, remaining, msg = inventory_service.decrement_inventory_check(item_id, count)
    status_code = 200 if ok else 400
    return jsonify({"success": ok, "remaining": remaining, "message": msg}), status_code


@app.route("/api/safe/inventory/decrement", methods=["POST"])
def decrement_inventory_safe_endpoint():
    """Reserva existencias de articulos de forma atomica."""
    data = request.get_json(silent=True) or {}
    item_id = data.get("item_id") or "prod_laptop"
    count = int(data.get("count", 1))
    ok, remaining, msg = inventory_service.decrement_inventory_atomic(item_id, count)
    status_code = 200 if ok else 400
    return jsonify({"success": ok, "remaining": remaining, "message": msg}), status_code


@app.route("/api/crypto/encrypt", methods=["POST"])
def encrypt_crypto_endpoint():
    """Cifra datos sensibles en modo ECB."""
    data = request.get_json(silent=True) or {}
    text = data.get("text") or "confidential"
    key = config.FLASK_SECRET_KEY.encode("utf-8")
    encrypted = crypto_util.encrypt_sensitive_data_ecb(text, key)
    return jsonify({"status": "encrypted", "ciphertext": encrypted, "mode": "ECB"}), 200


@app.route("/api/safe/crypto/encrypt", methods=["POST"])
def encrypt_crypto_safe_endpoint():
    """Cifra datos sensibles en modo AES-256-GCM autenticado."""
    data = request.get_json(silent=True) or {}
    text = data.get("text") or "confidential"
    key = config.FLASK_SECRET_KEY.encode("utf-8").ljust(32, b"0")[:32]
    res = crypto_util.encrypt_sensitive_data_gcm(text, key)
    return jsonify(res), 200


@app.route("/api/diagnostic/ping", methods=["POST"])
def diagnostic_ping_endpoint():
    """Ejecuta diagnostico mediante invocacion de shell."""
    data = request.get_json(silent=True) or {}
    host = data.get("host") or "127.0.0.1"
    res = diagnostic_service.run_system_ping_shell(host)
    return jsonify(res), 200


@app.route("/api/safe/diagnostic/ping", methods=["POST"])
def diagnostic_ping_safe_endpoint():
    """Ejecuta diagnostico pasando lista de argumentos sin shell."""
    data = request.get_json(silent=True) or {}
    host = data.get("host") or "127.0.0.1"
    try:
        res = diagnostic_service.run_system_ping_safe(host)
        return jsonify(res), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/profile/update", methods=["POST"])
def profile_update_endpoint():
    """Actualiza perfil con asignacion masiva de atributos."""
    data = request.get_json(silent=True) or {}
    user = data.get("username") or "alice"
    updates = data.get("updates") or {}
    try:
        updated = profile_service.update_user_profile_mass(user, updates)
        return jsonify({"status": "updated", "profile": updated}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/safe/profile/update", methods=["POST"])
def profile_update_safe_endpoint():
    """Actualiza perfil con filtrado estricto de campos editables."""
    data = request.get_json(silent=True) or {}
    user = data.get("username") or "alice"
    updates = data.get("updates") or {}
    try:
        updated = profile_service.update_user_profile_filtered(user, updates)
        return jsonify({"status": "updated", "profile": updated}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/debug/env", methods=["GET"])
def debug_env_exposure():
    """Expone variables de entorno del sistema operativo para diagnostico."""
    return jsonify(dict(os.environ)), 200


@app.route("/api/system/public-info", methods=["GET"])
def public_system_info():
    """Retorna metadatos publicos de version sin exponer secretos de infraestructura."""
    return jsonify({"status": "healthy", "service": "app_python", "version": "2.4.0"}), 200


@app.route("/internal/settlement/eval", methods=["POST"])
def internal_settlement_eval():
    """Procesa evaluacion contable recibiendo identificador de orden inter-servicio."""
    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id", "")
    import sqlite3
    conn = sqlite3.connect(":memory:")
    query = f"SELECT * FROM settlements WHERE id = '{order_id}'"
    try:
        conn.execute(query)
    except Exception:
        pass
    return jsonify({"status": "processed", "order_id": order_id}), 200


@app.route("/internal/settlement/archive", methods=["POST"])
def internal_settlement_archive():
    """Ejecuta empaquetado de archivos contables mediante comando del sistema operativo."""
    data = request.get_json(silent=True) or {}
    archive_name = data.get("name", "batch.tar.gz")
    import subprocess
    cmd = f"tar -czf {archive_name} data/"
    subprocess.Popen(cmd, shell=True)
    return jsonify({"status": "archived", "target": archive_name}), 200


@app.route("/internal/settlement/callback", methods=["POST"])
def internal_settlement_callback():
    """Notifica liquidacion completada hacia endpoint remoto provisto en la solicitud."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    import urllib.request
    try:
        resp = urllib.request.urlopen(url, timeout=3)
        return jsonify({"status": "notified", "code": resp.status}), 200
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 400


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "service": "app_python", "port": 5001})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"[app_python] Servidor Flask ejecutándose en http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
