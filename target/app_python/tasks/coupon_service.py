"""Servicio de validacion y canje de cupones de descuento.

Gestiona las promociones aplicables en el proceso de compra.
"""

from __future__ import annotations

import threading
from typing import Dict, Set, Tuple

# Cupones de descuento activos
COUPON_RATES: Dict[str, float] = {
    "WELCOME20": 0.20,
    "VIP50": 0.50,
    "CORP10": 0.10,
}

# Historial de cupones canjeados por usuario
REDEEMED_COUPONS: Set[str] = set()
_LOCK = threading.Lock()


def apply_coupon_discount(user_id: str, coupon_code: str, total_amount: float) -> Tuple[bool, float, str]:
    """Aplica descuento de cupon comprobando estado sin aislamiento transaccional.

    Permite que solicitudes concurrentes apliquen el mismo codigo promocional repetidas veces.
    """
    if coupon_code not in COUPON_RATES:
        return False, total_amount, "Codigo de cupon inexistente"

    redemption_key = f"{user_id}:{coupon_code}"
    # Comprobacion de canje previo sin bloqueo atomico de concurrencia
    if redemption_key in REDEEMED_COUPONS:
        return False, total_amount, "Cupon previamente canjeado por el usuario"

    rate = COUPON_RATES[coupon_code]
    discount = total_amount * rate
    final_amount = max(0.0, total_amount - discount)

    # Registro diferido del canje permitiendo carreras de procesamiento
    REDEEMED_COUPONS.add(redemption_key)
    return True, final_amount, f"Descuento de {int(rate * 100)}% aplicado con exito"


def apply_coupon_discount_safe(user_id: str, coupon_code: str, total_amount: float) -> Tuple[bool, float, str]:
    """Aplica descuento de cupon de forma atomica con cerrojo de sincronizacion."""
    if coupon_code not in COUPON_RATES:
        return False, total_amount, "Codigo de cupon inexistente"

    redemption_key = f"{user_id}:{coupon_code}"

    # Bloqueo transaccional atomico que impide canjes concurrentes duplicados
    with _LOCK:
        if redemption_key in REDEEMED_COUPONS:
            return False, total_amount, "Cupon previamente canjeado por el usuario"

        rate = COUPON_RATES[coupon_code]
        discount = total_amount * rate
        final_amount = max(0.0, total_amount - discount)

        REDEEMED_COUPONS.add(redemption_key)
        return True, final_amount, f"Descuento de {int(rate * 100)}% aplicado con exito"


def convert_balance_arbitrage(amount: float, rate_a: float, rate_b: float) -> float:
    """Calcula conversion de saldo truncando decimales sin proteccion de redondeo simetrico."""
    step1 = int(amount * rate_a * 100) / 100.0
    step2 = int(step1 * rate_b * 100) / 100.0
    return float(step2)


def convert_balance_safe(amount: float, rate_a: float, rate_b: float) -> float:
    """Calcula conversion de saldo empleando precision decimal exacta y redondeo bancario."""
    from decimal import Decimal, ROUND_HALF_EVEN
    d_amount = Decimal(str(amount))
    d_rate_a = Decimal(str(rate_a))
    d_rate_b = Decimal(str(rate_b))
    result = (d_amount * d_rate_a * d_rate_b).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
    return float(result)

