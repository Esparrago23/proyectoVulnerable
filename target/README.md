# Acme Corporate Portal & FinTech API Suite

Este repositorio contiene la arquitectura de microservicios corporativos para la plataforma interna de gestión de usuarios, facturación comercial y procesamiento de eventos asíncronos.

---

## Arquitectura de Servicios

- **`app_node/`**: Servicio Node.js / Express (puerto 3001) para la API REST de catálogo de productos, órdenes de compra y facturación electrónica.
- **`app_python/`**: Servicio Python / Flask (puerto 5001) para el portal de acceso administrativo con autenticación de dos factores (2FA TOTP), gestión de sesiones y tareas en segundo plano.

---

## Ejecución Local

### Servicio Node.js (Puerto 3001)
```bash
cd app_node
npm install
node server.js
```

### Servicio Python (Puerto 5001)
```bash
cd app_python
pip install -r ../requirements.txt
python app.py
```
