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
├── truth/                      # Ground truth fuera del árbol analizable
│   ├── cases/                  # Un YAML por caso, con IDs opacos
│   ├── schema/                 # JSON Schema y reglas de matching
│   ├── generated/              # Salidas reproducibles, no editadas a mano
│   └── scripts/                # Validación, construcción y escaneo anti-fugas
└── scripts/
    └── export_target.py        # Exportación saneada para herramientas
```

---

## 2. Comandos de Gestión

### Validar el ground truth y la neutralidad
```bash
python truth/scripts/validate.py
python truth/scripts/leak_scan.py target/
```

### Regenerar las salidas
```bash
python truth/scripts/build.py
```

### Entregar código a un analizador
```bash
python scripts/export_target.py
```

La exportación no incluye `.git`, `meta/`, `truth/` ni documentación de casos.

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
