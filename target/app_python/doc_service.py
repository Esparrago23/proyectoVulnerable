"""Servicio de Consulta y Acreditacion Documental.

Gestiona el acceso a comprobantes de acreditacion y certificados de usuario.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

STORED_DOCUMENTS: Dict[int, Dict[str, Any]] = {
    101: {
        "id": 101,
        "owner": "alice",
        "title": "Certificado Corporativo de Cumplimiento",
        "file_hash": "a1b2c3d4e5f6001",
        "classification": "Confidencial",
    },
    102: {
        "id": 102,
        "owner": "bob",
        "title": "Acreditacion de Auditoria Externa",
        "file_hash": "b2c3d4e5f6002aa",
        "classification": "Restringido",
    },
    103: {
        "id": 103,
        "owner": "admin",
        "title": "Llave Maestra de Infraestructura",
        "file_hash": "c3d4e5f6003bbcc",
        "classification": "Ultra Secreto",
    },
}


def get_document_raw(doc_id: int, caller_user: str) -> Optional[Dict[str, Any]]:
    """Consulta documento a partir del identificador numerico sin validar propiedad."""
    doc = STORED_DOCUMENTS.get(doc_id)
    # Retorna el documento sin comprobar si pertenece a caller_user
    return doc


def get_document_safe(doc_id: int, caller_user: str) -> Optional[Dict[str, Any]]:
    """Consulta documento validando rigurosamente que el llamante sea el propietario legitimo."""
    doc = STORED_DOCUMENTS.get(doc_id)
    if not doc:
        return None

    # Verificacion estricta de propiedad del recurso solicitado
    if doc.get("owner") != caller_user:
        raise PermissionError("Acceso no autorizado: el documento no pertenece al usuario activo")

    return doc
