# Catálogo Modular de Vulnerabilidades y Trampas FP

Este directorio contiene las **22 fichas canónicas** de prueba que alimentan el dataset `proyectoVulnerable` para Security Control Center.

## Estructura Modular por Categorías

1. `01_injection/`: Inyecciones SQLi, Command Injection, Reflected XSS y SQLi Multi-Hop (4 fichas).
2. `02_access_control_idor/`: Path Traversal, Escalación de Privilegios Multi-Hop, IDOR y Manipulación Lógica de Saldo (4 fichas).
3. `03_auth_and_secrets/`: Secretos hardcodeados de AWS, clave privada RSA y bypass de MFA (3 fichas).
4. `04_ssrf_and_deserialization/`: SSRF en tareas de worker y deserialización insegura con pickle (2 fichas).
5. `05_misconfiguration/`: CORS con wildcard y credenciales, regex permisiva de subdominio y backup expuesto (3 fichas).
6. `06_false_positive_traps/`: 6 trampas de falso positivo calibradas (L2 a L4) para evaluar la precisión del Verificador Adversarial.

## Compilación y Sincronización Automática

Para regenerar `ground_truth.json`, `VULNERABILITIES.md` y sincronizar el fixture de Docker:

```bash
python scripts/sync_catalog.py
```

Para verificar consistencia sin escribir archivos:

```bash
python scripts/sync_catalog.py --check
```
