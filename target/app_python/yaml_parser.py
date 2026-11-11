"""Modulo de parseo y carga de documentos de configuracion YAML.

Permite transformar archivos de configuracion en estructuras de datos de Python.
"""

from __future__ import annotations

from typing import Any, Dict
import yaml


def parse_config_yaml(yaml_text: str) -> Any:
    """Carga la estructura YAML empleando el cargador completo por defecto.

    Deserializa la cadena YAML permitiendo la construccion de instancias de tipos arbitrarios.
    """
    # Carga de configuracion YAML sin restringir constructores de objetos
    parsed = yaml.load(yaml_text, Loader=yaml.Loader)
    return parsed


def parse_config_yaml_catalog(yaml_text: str) -> Any:
    """Carga la estructura YAML de forma segura restringiendo a tipos primitivos estandar."""
    # Deserializacion segura limitada exclusivamente a escalares, listas y diccionarios
    parsed = yaml.catalog_load(yaml_text)
    return parsed
