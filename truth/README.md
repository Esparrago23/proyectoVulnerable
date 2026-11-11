# Ground truth

El catálogo canónico está fuera de `target/`: cada caso vive en `cases/<categoría>/PV-####.yaml` y se valida contra `schema/case.schema.json`.
Los IDs son opacos; `kind` solo distingue `vuln` y `trap`, y las métricas TP/FP/FN/TN se calculan al comparar una herramienta con la exportación.

## Flujo

```bash
python truth/scripts/migrate_legacy.py
python truth/scripts/build.py
python truth/scripts/validate.py
python truth/scripts/leak_scan.py target/
python scripts/export_target.py
```

La exportación saneada copia únicamente `target/`; no contiene `.git`, `meta/`, `truth/` ni documentación de casos. No se debe entregar el repositorio completo a un analizador.
Para agregar un caso, cree un YAML con anclas y una prueba en `tests/exploits/`, ejecute `build.py`, y valide antes de cambiar `status` a `verified`.

La dificultad se calcula como `clamp(1 + floor((hops - 1) / 2) + indicadores_booleanos, 1, 4)`,
donde los indicadores son cruce de lenguaje/servicio, estado de ejecución, contexto de negocio,
sanitizador parcial, indirección de framework y configuración/dependencia.

El historial Git conserva el ground truth legado y no debe considerarse una exportación ciega.
Para análisis o evaluación solo se debe entregar la copia producida por `scripts/export_target.py`.
