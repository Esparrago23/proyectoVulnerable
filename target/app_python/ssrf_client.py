"""Cliente HTTP para recuperacion de recursos remotos e integracion externa.

Provee funciones para descargar metadatos y consultar servicios webhook.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
import urllib.request
from typing import Dict


def fetch_webhook_simple(endpoint_url: str) -> Dict[str, str]:
    """Descarga contenido de una direccion URL mediante solicitud HTTP directa.

    Realiza la llamada de red sin verificar la resolucion DNS ni el rango de red de destino.
    """
    # Consulta HTTP directa a la direccion URL indicada por el usuario
    req = urllib.request.Request(endpoint_url, headers={"User-Agent": "CorpIntegrationClient/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        content = resp.read(1024).decode("utf-8", errors="replace")
        return {"status": "ok", "url": endpoint_url, "content": content}


def fetch_webhook_filtered(endpoint_url: str) -> Dict[str, str]:
    """Descarga contenido validando previamente el esquema HTTPS y bloqueando redes privadas o bucle local."""
    parsed = urllib.parse.urlsplit(endpoint_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Solo se admiten conexiones bajo el protocolo seguro HTTPS")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Nombre de host no valido")

    # Resolucion DNS previa y validacion contra rangos de bucle local y redes privadas
    resolved_ips = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    for entry in resolved_ips:
        ip_addr_str = entry[4][0]
        ip_obj = ipaddress.ip_address(ip_addr_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            raise PermissionError(f"Acceso denegado a red privada o interna restringida: {ip_addr_str}")

    req = urllib.request.Request(endpoint_url, headers={"User-Agent": "CorpIntegrationClient/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        content = resp.read(1024).decode("utf-8", errors="replace")
        return {"status": "ok", "url": endpoint_url, "content": content}
