# Banco de Pruebas de Seguridad: Proyecto Vulnerable Escalonado (v2.0)

Este repositorio es un banco de pruebas controlado y reproducible diseñado para evaluar escáneres estáticos (SAST, SCA, Secret Scanning, IaC), agentes de razonamiento semántico y verificadores dinámicos.

---

## 1. Arquitectura en Dos Niveles (Separación Anti-Fuga)

Para evitar la contaminación de modelos LLM y escáneres (fuga de respuestas por comentarios delatadores o lectura del ground truth en el árbol escaneado), el proyecto se divide estrictamente en dos niveles:

```
proyectoVulnerable/
├── target/                     # CÓDIGO OBJETIVO: Lo que se entrega a escáneres y agentes
│   ├── app_node/               # Microservicio Express (puerto 3001)
│   ├── app_python/             # Microservicio Flask (puerto 5001) con 2FA TOTP
│   ├── .env.backup             # Backup expuesto de configuración
│   ├── package.json            # Dependencias Node.js
│   ├── requirements.txt        # Dependencias Python
│   └── README.md               # Documentación neutral de la aplicación corporativa
├── meta/                       # METADATOS: Ground truth y evaluación (aislado de escaneo)
│   ├── cases/                  # 22 Fichas modulares en Markdown con YAML frontmatter
│   ├── auth/                   # Escenarios de autenticación y modos de inicio de sesión
│   ├── pentest/                # Escenarios de verificación dinámica y pentesting
│   ├── ground_truth.json       # Ground truth compilado para el motor de matching
│   ├── VULNERABILITIES.md      # Catálogo técnico de referencia
│   ├── CHANGELOG.md            # Registro de versiones y adiciones
│   └── manifest.json           # Hashes SHA-256 para validación de sincronización
└── scripts/
    ├── sync_catalog.py         # Compilador de ground truth y sincronizador de fixtures
    └── lint_hints.py           # Linter anti-fugas (asegura 0 pistas en target/)
```

---

## 2. Comandos de Gestión

### Validar Neutralidad del Código (Linter Anti-Fugas)
```bash
python scripts/lint_hints.py
```

### Compilar Catálogo y Sincronizar Fixtures
```bash
python scripts/sync_catalog.py
```

Para verificar sin escribir cambios:
```bash
python scripts/sync_catalog.py --check
```

---

## 3. Ejecución de Microservicios (`target/`)

### Servicio Node.js (Puerto 3001)
```bash
cd target/app_node
npm install
node server.js
```

### Servicio Python (Puerto 5001)
```bash
cd target/app_python
pip install -r ../requirements.txt
python app.py
```
