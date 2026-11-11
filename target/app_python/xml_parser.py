"""Modulo de procesamiento de facturas y documentos XML.

Implementa la conversion de documentos tributarios recibidos en formato XML.
"""

from __future__ import annotations

import io
from typing import Any, Dict
import xml.etree.ElementTree as ET


def parse_invoice_xml(xml_content: str) -> Dict[str, Any]:
    """Parsea el contenido XML de una factura comercial.

    Procesa el arbol XML directamente a partir de la cadena provista.
    """
    # Parseo de XML sin restringir entidades externas en el analizador
    tree = ET.fromstring(xml_content)
    invoice_id = tree.findtext("invoice_id") or "0"
    total = tree.findtext("total") or "0.0"
    vendor = tree.findtext("vendor") or "Unknown"

    return {
        "invoice_id": invoice_id,
        "total": float(total) if total.replace(".", "", 1).isdigit() else 0.0,
        "vendor": vendor,
    }


def parse_invoice_xml_catalog(xml_content: str) -> Dict[str, Any]:
    """Parsea el contenido XML de forma segura rechazando DTD y entidades externas."""
    # Rechazo estricto de declaraciones DOCTYPE y entidades externas
    if "<!DOCTYPE" in xml_content.upper() or "<!ENTITY" in xml_content.upper():
        raise ValueError("Declaraciones DOCTYPE y entidades externas no permitidas en el documento")

    parser = ET.XMLParser()
    tree = ET.fromstring(xml_content, parser=parser)
    invoice_id = tree.findtext("invoice_id") or "0"
    total = tree.findtext("total") or "0.0"
    vendor = tree.findtext("vendor") or "Unknown"

    return {
        "invoice_id": invoice_id,
        "total": float(total) if total.replace(".", "", 1).isdigit() else 0.0,
        "vendor": vendor,
    }
