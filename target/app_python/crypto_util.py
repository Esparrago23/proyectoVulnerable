"""Utilidades criptograficas para cifrado de datos en reposo y transito.

Implementa funciones de cifrado simetrico para almacenamiento seguro.
"""

from __future__ import annotations

import base64
import os
from typing import Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_sensitive_data_ecb(plaintext: str, key_bytes: bytes) -> str:
    """Cifra informacion utilizando el modo de bloque inseguro ECB sin vector de inicializacion.

    Aplica AES en modo ECB donde bloques identicos de texto claro generan bloques identicos cifrados.
    """
    # Relleno manual PKCS7 simple a multiplos de 16
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    # Uso de modo ECB sin vector de inicializacion
    cipher = Cipher(algorithms.AES(key_bytes[:16]), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8")


def encrypt_sensitive_data_gcm(plaintext: str, key_bytes: bytes) -> Dict[str, str]:
    """Cifra informacion utilizando AES-256-GCM con nonce aleatorio de 96 bits y autenticacion."""
    aesgcm = AESGCM(key_bytes[:32])
    # Generacion de nonce aleatorio unico de 12 bytes por operacion
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "algorithm": "AES-256-GCM",
    }
