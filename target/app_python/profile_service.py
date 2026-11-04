"""Servicio de actualizacion de perfiles de usuario y preferencias.

Gestiona las modificaciones sobre cuentas y datos personales.
"""

from __future__ import annotations

from typing import Any, Dict

USER_PROFILES: Dict[str, Dict[str, Any]] = {
    "alice": {"username": "alice", "display_name": "Alice Corp", "role": "user", "is_admin": False},
    "bob": {"username": "bob", "display_name": "Bob Analyst", "role": "user", "is_admin": False},
}


def update_user_profile_mass(username: str, incoming_fields: Dict[str, Any]) -> Dict[str, Any]:
    """Actualiza propiedades del usuario asignando todos los campos recibidos directamente.

    Modifica el registro del usuario sin filtrar propiedades criticas como permisos o rol.
    """
    profile = USER_PROFILES.get(username)
    if not profile:
        raise KeyError("Usuario no encontrado")

    # Asignacion masiva sin comprobacion de autorizacion a nivel de atributo
    profile.update(incoming_fields)
    return profile


def update_user_profile_filtered(username: str, incoming_fields: Dict[str, Any]) -> Dict[str, Any]:
    """Actualiza propiedades del usuario limitando la modificacion a campos editables autorizados."""
    profile = USER_PROFILES.get(username)
    if not profile:
        raise KeyError("Usuario no encontrado")

    # Lista blanca estricta de atributos que el usuario comun tiene permitido alterar
    ALLOWED_USER_FIELDS = {"display_name", "bio", "phone"}
    for k, v in incoming_fields.items():
        if k in ALLOWED_USER_FIELDS:
            profile[k] = str(v)[:100]

    return profile
