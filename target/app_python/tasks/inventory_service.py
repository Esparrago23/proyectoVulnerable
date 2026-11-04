"""Servicio de control de existencias e inventario de productos.

Gestiona la reserva y descuento de existencias de articulos.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Tuple

INVENTORY_STOCK: Dict[str, int] = {
    "prod_laptop": 5,
    "prod_monitor": 8,
    "prod_phone": 3,
}

_STOCK_LOCK = threading.Lock()


def decrement_inventory_check(item_id: str, count: int) -> Tuple[bool, int, str]:
    """Reduce existencias en dos pasos separados sin sincronizacion (TOCTOU).

    Verifica disponibilidad y luego descuenta permitiendo condiciones de carrera.
    """
    current_stock = INVENTORY_STOCK.get(item_id, 0)

    # Paso 1: Comprobacion de disponibilidad separada del decremento
    if current_stock < count:
        return False, current_stock, "Existencias insuficientes para atender la solicitud"

    # Retardo que abre ventana temporal para colision concurrente
    time.sleep(0.01)

    # Paso 2: Decremento no atomico
    INVENTORY_STOCK[item_id] = current_stock - count
    return True, INVENTORY_STOCK[item_id], "Reserva de existencias completada"


def decrement_inventory_atomic(item_id: str, count: int) -> Tuple[bool, int, str]:
    """Reduce existencias de forma atomica con cerrojo de exclusion mutua."""
    with _STOCK_LOCK:
        current_stock = INVENTORY_STOCK.get(item_id, 0)
        # Verificacion y decremento en un unico bloque sincronizado indivisible
        if current_stock < count:
            return False, current_stock, "Existencias insuficientes para atender la solicitud"

        INVENTORY_STOCK[item_id] = current_stock - count
        return True, INVENTORY_STOCK[item_id], "Reserva de existencias completada de forma atomica"
