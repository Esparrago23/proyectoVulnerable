"""Servicio de descompresion y extraccion de paquetes de archivos.

Gestiona la extraccion de archivos ZIP recibidos por el sistema.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List
import zipfile


def extract_bundle_direct(zip_filepath: str, output_directory: str) -> List[str]:
    """Extrae todos los elementos del archivo comprimido directamente en el directorio destino.

    Desempaqueta las rutas contenidas en el ZIP sin verificar si escapan del arbol de salida.
    """
    extracted_files: List[str] = []
    with zipfile.ZipFile(zip_filepath, "r") as archive:
        # Extraccion directa de rutas relativas potencialmente ascendentes
        archive.extractall(output_directory)
        extracted_files = archive.namelist()
    return extracted_files


def extract_bundle_validated(zip_filepath: str, output_directory: str) -> List[str]:
    """Extrae los elementos del archivo validando que cada ruta permanezca dentro del directorio base."""
    resolved_base = os.path.abspath(output_directory)
    extracted_files: List[str] = []

    with zipfile.ZipFile(zip_filepath, "r") as archive:
        for member in archive.infolist():
            target_path = os.path.abspath(os.path.join(resolved_base, member.filename))
            # Verificacion de contencion para impedir escapes del directorio destino
            if os.path.commonpath([resolved_base, target_path]) != resolved_base:
                raise ValueError(f"Ruta de archivo no autorizada fuera del arbol permitido: {member.filename}")
            archive.extract(member, resolved_base)
            extracted_files.append(member.filename)

    return extracted_files
