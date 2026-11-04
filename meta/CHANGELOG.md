# Registro de Cambios: Proyecto Vulnerable

## [2.0.0] - 2026-11-02
### Reestructuración y Cimientos Anti-Fuga (Fase S0)
- **Separación en dos niveles**: Se dividió el repositorio en `target/` (código de aplicación para escaneo ciego) y `meta/` (ground truth, fichas y documentación técnica).
- **Linter anti-fugas**: Implementación de `scripts/lint_hints.py` para garantizar 0 pistas, comentarios delatadores (`VULNERABILIDAD N1`, `FP Trap`, etc.) o metadatos soplados en el árbol de código.
- **Limpieza de pistas**: Eliminación de 55 comentarios delatadores en `target/`, preservando exactamente los rangos de líneas ejecutables para compatibilidad con las 22 fichas existentes.
- **Sincronizador ampliado**: `scripts/sync_catalog.py` actualizado para compilar desde `meta/cases/`, calcular hashes SHA-256 en `meta/manifest.json`, sincronizar `target/` hacia `demo/backend/benchmarks/fixtures/proyecto_vulnerable` y metadatos hacia `demo/backend/benchmarks/fixtures/proyecto_vulnerable_meta`.
- **Compatibilidad**: Conservación íntegra de los 22 casos canónicos (`PV-N1-001` a `PV-N4-004` y `PV-TRAP-001` a `PV-TRAP-006`).
