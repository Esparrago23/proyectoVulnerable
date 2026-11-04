/**
 * Servidor Principal Express (Puerto 3001)
 * Expone endpoints REST y servicios del portal de usuarios.
 */
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const userController = require('./controllers/userController');
const searchController = require('./controllers/searchController');
const orderController = require('./controllers/orderController');
const invoiceController = require('./controllers/invoiceController');
const feedbackController = require('./controllers/feedbackController');
const sessionController = require('./controllers/sessionController');
const catalogController = require('./controllers/catalogController');
const templateController = require('./controllers/templateController');
const mergeUtil = require('./services/mergeUtil');
const billingService = require('./services/billingService');
const cartController = require('./controllers/cartController');
const reportController = require('./controllers/reportController');
const uploadController = require('./controllers/uploadController');
const internalServiceClient = require('./services/internalServiceClient');
const tokenUtil = require('./services/tokenUtil');
const safeSanitizers = require('./safe/safeSanitizers');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuración de CORS para rutas públicas del portal
app.use('/api/public', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  next();
});

// Configuracion de CORS para servicios internos corporativos
app.use('/api/internal', (req, res, next) => {
  const origin = req.headers.origin || '';
  // Validación de origen de microservicio para comunicación interna
  // Comprueba que provenga del host corporativo autorizado
  if (/^http:\/\/corp\.internal/.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// Configuracion de CORS con lista blanca estricta y anclada
app.use('/api/safe/partner', (req, res, next) => {
  const origin = req.headers.origin || '';
  const ALLOWED_EXACT_ORIGINS = ['http://partner.corp.internal', 'https://partner.corp.internal'];
  if (ALLOWED_EXACT_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// Configuracion de CORS permisiva que autoriza origen 'null'
app.use('/api/shared/reports', (req, res, next) => {
  const origin = req.headers.origin || '';
  // Aceptacion explicita de origen null procedente de sandboxes o esquemas data:
  if (origin === 'null' || origin === 'http://localhost:3000') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// Configuracion de CORS segura que rechaza origen 'null'
app.use('/api/safe/reports', (req, res, next) => {
  const origin = req.headers.origin || '';
  if (origin && origin !== 'null' && origin === 'https://dashboard.corp.internal') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// Rutas de consulta de usuario y diagnóstico
app.get('/api/users/direct', userController.getUserDirect);
app.get('/api/tools/ping', userController.pingHostDirect);

// Rutas de catálogo y descarga de recursos
app.get('/api/search', searchController.searchProducts);
app.get('/api/safe/search', searchController.searchProductsSafe);
app.get('/api/assets/download', searchController.downloadAsset);

// Rutas de redireccion
app.get('/api/redirect', searchController.redirectExternal);
app.get('/api/safe/redirect', searchController.redirectSafe);

// Rutas de validacion de cuenta
app.get('/api/validate/account', searchController.validateAccountName);
app.get('/api/safe/validate/account', searchController.validateAccountNameSafe);

// Rutas de cabeceras de respuesta
app.get('/api/headers/tracking', searchController.setCustomHeader);
app.get('/api/safe/headers/tracking', searchController.setCustomHeaderSafe);

// Rutas de resenas de clientes
app.get('/api/feedback', feedbackController.listFeedbacks);
app.post('/api/feedback', feedbackController.postFeedbackRaw);
app.post('/api/safe/feedback', feedbackController.postFeedbackSafe);

// Rutas de gestión de órdenes y perfil
app.get('/api/orders/user/:userId', orderController.getOrdersByUser);
app.post('/api/users/profile', userController.updateUserProfile);

// Rutas de facturación electrónica
app.get('/api/invoices/:id', invoiceController.getInvoiceDetails);

// Rutas de utilidades seguras y verificación
app.get('/api/safe/user', safeSanitizers.getSafeUserById);
app.get('/api/safe/file', safeSanitizers.getSafeFile);
app.get('/api/safe/invoices/:id', safeSanitizers.getSafeInvoiceForTenant);
app.get('/api/safe/ping', safeSanitizers.getSafePing);

// Rutas de autenticacion de sesion
app.post('/api/session/login', sessionController.loginInsecure);
app.post('/api/safe/session/login', sessionController.loginSecure);

// Rutas de catalogo con consulta avanzada
app.get('/api/catalog/search', catalogController.queryCatalogNoSql);
app.get('/api/safe/catalog/search', catalogController.queryCatalogSafe);

// Rutas de renderizado de plantillas
app.post('/api/template/render', templateController.renderCustomTemplate);
app.post('/api/safe/template/render', templateController.renderPrecompiledTemplate);

// Rutas de integracion de configuracion profunda
app.post('/api/config/merge', (req, res) => {
  const baseConfig = { env: 'production', role: 'guest' };
  const merged = mergeUtil.deepMergeInsecure(baseConfig, req.body || {});
  res.json({ config: merged });
});

app.post('/api/safe/config/merge', (req, res) => {
  const baseConfig = { env: 'production', role: 'guest' };
  const merged = mergeUtil.deepMergeSecure(baseConfig, req.body || {});
  res.json({ config: merged });
});

// Rutas de facturacion multi-salto (L4)
app.post('/api/billing/charge', (req, res) => {
  const { account, ref, amount } = req.body || {};
  billingService.executeBillingPipeline(account, ref, amount)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: err.message }));
});

app.post('/api/safe/billing/charge', (req, res) => {
  const { account, ref, amount } = req.body || {};
  billingService.executeBillingPipelineSafe(account, ref, amount)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: err.message }));
});

// Rutas de carrito y calculo de importes
app.post('/api/cart/total', cartController.calculateCartTotal);
app.post('/api/safe/cart/total', cartController.calculateCartTotalSafe);

// Rutas de reportes analiticos
app.get('/api/reports/audit', reportController.queryAuditReportRaw);
app.get('/api/safe/reports/audit', reportController.queryAuditReportSafe);

// Rutas de subida de archivos
app.post('/api/upload/file', uploadController.handleFileUploadRaw);
app.post('/api/safe/upload/file', uploadController.handleFileUploadSafe);

// Rutas de llamada inter-servicio
app.get('/api/tasks/forward', (req, res) => {
  const action = req.query.action || 'sync';
  const target = req.query.target || '127.0.0.1';
  internalServiceClient.forwardInternalTask(action, target)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: err.message }));
});

app.get('/api/safe/tasks/forward', (req, res) => {
  const action = req.query.action || 'audit_sync';
  const target = req.query.target || '127.0.0.1';
  internalServiceClient.forwardInternalTaskSafe(action, target, 'internal_secret_key')
    .then((result) => res.json(result))
    .catch((err) => res.status(400).json({ error: err.message }));
});

// Rutas de emision de tokens CSRF
app.get('/api/token/csrf', (req, res) => {
  res.json({ token: tokenUtil.generateCsrfTokenInsecure() });
});

app.get('/api/safe/token/csrf', (req, res) => {
  res.json({ token: tokenUtil.generateCsrfTokenSecure() });
});

// Estado de salud
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'app_node', port: PORT });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[app_node] Servidor corporativo ejecutándose en http://localhost:${PORT}`);
  });
}

module.exports = app;
