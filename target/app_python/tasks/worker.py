"""Worker de procesamiento asincrono de tareas en segundo plano."""

from __future__ import annotations

import pickle
import urllib.request
from typing import Any, Dict


def process_webhook_fetch(target_url: str) -> Dict[str, Any]:
    """Descarga un webhook solicitado previamente en el controlador de eventos.

    Recibe la URL registrada en la cola de tareas del sistema
    y realiza la peticion HTTP para procesar el webhook
    externo solicitado por la integracion.
    """
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "TestbedInternalFetcher/1.0"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        content = resp.read()
        return {
            "status": resp.status,
            "bytes_received": len(content),
            "preview": content[:100].decode("utf-8", errors="ignore"),
        }


def restore_user_session_state(raw_bytes: bytes) -> Any:
    """Restaura el estado de sesión de un usuario desde datos serializados.

    Reconstruye el objeto de sesion en memoria a partir
    de la representacion binaria provista por el cliente
    mediante el modulo nativo de deserializacion de Python.
    """
    return pickle.loads(raw_bytes)


USER_WALLETS: Dict[str, float] = {
    "admin": 1000.0,
    "alice": 500.0,
    "bob": 200.0,
}


def process_wallet_transfer(source_user: str, target_user: str, amount: float) -> Dict[str, Any]:
    """Procesa una transferencia entre monederos de usuario.

    Valida la disponibilidad de fondos en el balance actual
    y aplica la operacion aritmetica de debito y credito
    entre las cuentas especificadas.
    """
    if source_user not in USER_WALLETS or target_user not in USER_WALLETS:
        raise ValueError("Usuario remitente o destinatario no registrado")

    current_balance = USER_WALLETS[source_user]
    if current_balance < amount:
        raise ValueError("Saldo insuficiente para completar la transferencia")

    USER_WALLETS[source_user] -= amount
    USER_WALLETS[target_user] += amount

    return {
        "status": "transfer_completed",
        "source": source_user,
        "target": target_user,
        "amount": amount,
        "new_balance": USER_WALLETS[source_user],
    }


def process_wallet_transfer_safe(source_user: str, target_user: str, amount: float) -> Dict[str, Any]:
    """Procesa una transferencia con validacion estricta de monto estrictamente positivo."""
    if amount <= 0:
        raise ValueError("El monto de transferencia debe ser estrictamente positivo")

    if source_user not in USER_WALLETS or target_user not in USER_WALLETS:
        raise ValueError("Usuario remitente o destinatario no registrado")

    current_balance = USER_WALLETS[source_user]
    if current_balance < amount:
        raise ValueError("Saldo insuficiente para completar la transferencia")

    USER_WALLETS[source_user] -= amount
    USER_WALLETS[target_user] += amount

    return {
        "status": "transfer_completed",
        "source": source_user,
        "target": target_user,
        "amount": amount,
        "new_balance": USER_WALLETS[source_user],
    }

