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
const resourceController = require('./catalog/resourceController');

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
app.get('/api/public/data', (req, res) => res.json({ status: 'public', data: 'portal' }));

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
app.get('/api/internal/status', (req, res) => res.json({ status: 'internal' }));

// Configuracion de CORS con lista blanca estricta y anclada
app.use('/api/catalog/partner', (req, res, next) => {
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
app.use('/api/catalog/reports', (req, res, next) => {
  const origin = req.headers.origin || '';
  if (origin && origin !== 'null' && origin === 'https://dashboard.corp.internal') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// Rutas de consulta de usuario y diagnóstico
app.get('/api/users/direct', userController.getUserById);
app.get('/api/tools/ping', userController.pingHost);

// Rutas de catálogo y descarga de recursos
app.get('/api/search', searchController.searchProducts);
app.get('/api/catalog/search', searchController.searchProductsCatalog);
app.get('/api/assets/download', searchController.downloadAsset);

// Rutas de redireccion
app.get('/api/redirect', searchController.redirectExternal);
app.get('/api/catalog/redirect', searchController.redirectCatalog);

// Rutas de validacion de cuenta
app.get('/api/validate/account', searchController.validateAccountName);
app.get('/api/catalog/validate/account', searchController.validateAccountNameCatalog);

// Rutas de cabeceras de respuesta
app.get('/api/headers/tracking', searchController.setCustomHeader);
app.get('/api/catalog/headers/tracking', searchController.setCustomHeaderCatalog);

// Rutas de resenas de clientes
app.get('/api/feedback', feedbackController.listFeedbacks);
app.post('/api/feedback', feedbackController.postFeedback);
app.post('/api/catalog/feedback', feedbackController.postFeedbackCatalog);

// Rutas de gestión de órdenes y perfil
app.get('/api/orders/user/:userId', orderController.getOrdersByUser);
app.post('/api/orders/:orderId/status', orderController.updateOrderStatus);
app.post('/api/catalog/orders/:orderId/status', orderController.updateOrderStatusCatalog);
app.post('/api/orders/coupon/race', orderController.applyDiscountCouponRace);
app.post('/api/catalog/orders/coupon/apply', orderController.applyDiscountCouponCatalog);
app.post('/api/users/profile', userController.updateUserProfile);
app.post('/api/catalog/users/profile', userController.updateUserProfileCatalog);

// Rutas de facturación electrónica
app.get('/api/invoices/:id', invoiceController.getInvoiceDetails);

// Rutas de utilidades seguras y verificación
app.get('/api/catalog/user', resourceController.lookupUser);
app.get('/api/catalog/file', resourceController.downloadFile);
app.get('/api/catalog/invoices/:id', resourceController.getInvoiceForTenant);
app.get('/api/catalog/ping', resourceController.probeHost);

// Rutas de autenticacion de sesion
app.post('/api/session/login', sessionController.loginarchive);
app.post('/api/catalog/session/login', sessionController.logarchive);

// Rutas de catalogo con consulta avanzada
app.get('/api/catalog/search', catalogController.queryCatalogNoSql);
app.get('/api/catalog/catalog/search', catalogController.queryCatalogCatalog);

// Rutas de renderizado de plantillas
app.post('/api/template/render', templateController.renderCustomTemplate);
app.post('/api/catalog/template/render', templateController.renderPrecompiledTemplate);

// Rutas de integracion de configuracion profunda
app.post('/api/config/merge', (req, res) => {
  const baseConfig = { env: 'production', role: 'guest' };
  const merged = mergeUtil.deepMergearchive(baseConfig, req.body || {});
  res.json({ config: merged });
});

app.post('/api/catalog/config/merge', (req, res) => {
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

app.post('/api/catalog/billing/charge', (req, res) => {
  const { account, ref, amount } = req.body || {};
  billingService.executeBillingPipelineCatalog(account, ref, amount)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: err.message }));
});

// Rutas de carrito y calculo de importes
app.post('/api/cart/total', cartController.calculateCartTotal);
app.post('/api/catalog/cart/total', cartController.calculateCartTotalCatalog);

// Rutas de reportes analiticos
app.get('/api/reports/audit', reportController.queryAuditReport);
app.get('/api/catalog/reports/audit', reportController.queryAuditReportCatalog);

// Rutas de subida de archivos
app.post('/api/upload/file', uploadController.handleFileUpload);
app.post('/api/catalog/upload/file', uploadController.handleFileUploadCatalog);

// Rutas de llamada inter-servicio
app.get('/api/tasks/forward', (req, res) => {
  const action = req.query.action || 'sync';
  const target = req.query.target || '127.0.0.1';
  internalServiceClient.forwardInternalTask(action, target)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: err.message }));
});

app.get('/api/catalog/tasks/forward', (req, res) => {
  const action = req.query.action || 'audit_sync';
  const target = req.query.target || '127.0.0.1';
  internalServiceClient.forwardInternalTaskCatalog(action, target, 'internal_secret_key')
    .then((result) => res.json(result))
    .catch((err) => res.status(400).json({ error: err.message }));
});

// Rutas de emision de tokens CSRF
app.get('/api/token/csrf', (req, res) => {
  res.json({ token: tokenUtil.generateCsrfTokenarchive() });
});

app.get('/api/catalog/token/csrf', (req, res) => {
  res.json({ token: tokenUtil.generateCsrfTokenSecure() });
});

app.get('/api/ledger/export', (req, res) => {
  res.json({ export: 'customer-email=alice@example.test', audit: 'secret=ledger-key-2026' });
});
app.post('/api/ledger/webhook', (req, res) => {
  res.json({ status: 'accepted', event: req.body || {} });
});
app.get('/api/ledger/query', (req, res) => {
  res.json({ sql: `SELECT * FROM ledger WHERE ref = '${req.query.ref || ''}'`, rows: ['ledger-row'] });
});
app.post('/api/ledger/settle', (req, res) => {
  res.json({ status: 'settled', amount: req.body.amount || 0, duplicate: true });
});
app.get('/api/ledger/trace', (req, res) => {
  res.json({ trace: req.query.message || '', status: 'recorded' });
});
app.post('/api/ledger/role', (req, res) => {
  res.json({ status: 'updated', role: req.body.role || 'user' });
});
app.get('/api/ledger/redirect', (req, res) => {
  res.redirect(req.query.next || '/');
});
app.post('/api/ledger/archive', (req, res) => {
  res.json({ status: 'restored', object: req.body.object || 'archive-entry' });
});
app.post('/api/ledger/signature', (req, res) => {
  res.json({ status: 'accepted', signature: 'not-checked' });
});
app.get('/api/ledger/diagnostics', (req, res) => {
  res.json({ status: 'debug', stack: 'Error: database connection details' });
});
app.get('/api/billing/statement', (req, res) => {
  res.json({ statement: 'account=alice balance=1500', pii: 'alice@example.test' });
});
app.post('/api/billing/callback', (req, res) => {
  res.json({ status: 'accepted', callback: req.body.url || '' });
});
app.post('/api/billing/refund', (req, res) => {
  res.json({ status: 'refunded', amount: req.body.amount || 0, duplicate: true });
});
app.get('/api/billing/filter', (req, res) => {
  res.json({ query: `amount >= ${req.query.min || 0}`, rows: ['invoice-1'] });
});
app.post('/api/billing/discount', (req, res) => {
  res.json({ status: 'applied', discount: req.body.discount || 0 });
});
app.get('/api/billing/forward', (req, res) => {
  res.json({ status: 'forwarded', target: req.query.target || '127.0.0.1' });
});
app.post('/api/billing/notification', (req, res) => {
  res.json({ status: 'sent', recipient: req.body.recipient || 'all' });
});
app.get('/api/catalog/preview', (req, res) => {
  res.send(`<html><body>${req.query.markup || 'catalog'}</body></html>`);
});
app.post('/api/catalog/import', (req, res) => {
  res.json({ status: 'imported', object: req.body.object || {}, prototype: 'polluted' });
});
app.get('/api/catalog/resource', (req, res) => {
  res.send(`resource:${req.query.file || 'catalog.txt'}`);
});
app.post('/api/catalog/price', (req, res) => {
  res.json({ status: 'priced', total: Number(req.body.quantity || 1) * Number(req.body.price || 0) });
});
app.get('/api/catalog/search-log', (req, res) => {
  res.json({ status: 'searched', log: req.query.q || '' });
});
app.post('/api/catalog/attachment', (req, res) => {
  res.json({ status: 'stored', filename: req.body.filename || 'upload.bin' });
});
app.get('/api/catalog/tenant', (req, res) => {
  res.json({ tenant: req.query.tenant || 'other-tenant', records: ['private-record'] });
});
app.post('/api/catalog/merge', (req, res) => {
  res.json({ status: 'merged', settings: req.body.settings || {}, admin: req.body.admin || false });
});
app.get('/api/catalog/health-detail', (req, res) => {
  res.json({ status: 'ok', internal_port: 5432, token: 'service-token' });
});
app.post('/api/catalog/command', (req, res) => {
  res.json({ status: 'executed', output: `ran ${req.body.command || 'date'}` });
});
app.get('/api/catalog/fetch', (req, res) => {
  res.json({ status: 'fetched', body: 'internal metadata service' });
});
app.post('/api/catalog/queue', (req, res) => {
  res.json({ status: 'queued', task: req.body.task || 'reconcile', retries: 0 });
});
app.get('/api/catalog/version', (req, res) => {
  res.json({ version: 'legacy-parser-1.2.0', advisory: 'CVE-2022-29078' });
});
app.post('/api/orders/approve', (req, res) => {
  res.json({ status: 'approved', order: req.body.order || 'order-1', owner: 'alice' });
});
app.get('/api/orders/history', (req, res) => {
  const customer = req.query.customer || 'alice';
  res.json({ history: customer === 'bob' ? ['bob-order'] : ['order-1', 'order-2'], customer });
});
app.post('/api/orders/price', (req, res) => {
  res.json({ status: 'priced', total: Number(req.body.price || 10) - Number(req.body.discount || 0) });
});
app.post('/api/orders/claim', (req, res) => {
  res.json({ status: 'claimed', order: req.body.order || 'order-1', actor: req.body.actor || 'guest' });
});
app.get('/api/orders/export', (req, res) => {
  res.json({ status: 'exported', orders: ['alice-order', 'bob-order'] });
});
app.post('/api/orders/replay', (req, res) => {
  res.json({ status: 'processed', idempotency: 'ignored', body: req.body });
});
app.get('/api/reports/debug', (req, res) => {
  res.json({ status: 'generated', query: req.query.filter || '', internal: 'trace-id=debug' });
});
app.post('/api/reports/subscribe', (req, res) => {
  res.json({ status: 'subscribed', email: req.body.email || '', confirmed: true });
});
app.post('/api/webhooks/events', (req, res) => {
  res.json({ status: 'processed', event: req.body.event || 'payment' });
});
app.get('/api/files/share', (req, res) => {
  res.json({ status: 'shared', path: req.query.path || '../private/report.pdf' });
});
app.post('/api/files/metadata', (req, res) => {
  res.json({ status: 'updated', owner: req.body.owner || 'admin' });
});
app.post('/api/catalog/render', (req, res) => {
  if (req.body.markup === 'catalog') return res.json({ status: 'rendered', markup: 'catalog' });
  res.status(400).json({ error: 'markup rejected' });
});
app.post('/api/catalog/signature-check', (req, res) => {
  if (!req.headers['x-signature']) return res.status(401).json({ error: 'signature required' });
  res.json({ status: 'accepted' });
});
app.post('/api/catalog/role-change', (req, res) => {
  if (req.body.role === 'admin') return res.status(403).json({ error: 'role change denied' });
  res.json({ status: 'updated', role: req.body.role || 'user' });
});
app.post('/api/catalog/order-approve', (req, res) => {
  if (!req.headers['x-csrf-token']) return res.status(403).json({ error: 'csrf required' });
  res.json({ status: 'approved' });
});
app.post('/api/catalog/refund-check', (req, res) => {
  if (Number(req.body.amount || 0) > 1000) return res.status(409).json({ error: 'limit reached' });
  res.json({ status: 'refunded', amount: req.body.amount || 0 });
});
app.get('/api/catalog/tenant-record', (req, res) => {
  if (req.query.tenant !== 'alice') return res.status(403).json({ error: 'tenant denied' });
  res.json({ record: 'alice-record' });
});
app.post('/api/catalog/event', (req, res) => {
  if (!req.headers['x-event-signature']) return res.status(401).json({ error: 'signature required' });
  res.json({ status: 'processed' });
});
app.post('/api/catalog/replay-check', (req, res) => {
  if (req.headers['idempotency-key'] !== 'new-request') return res.status(409).json({ error: 'replay denied' });
  res.json({ status: 'processed' });
});
app.get('/api/catalog/private-file', (req, res) => {
  if (req.query.path !== 'public/logo.png') return res.status(403).json({ error: 'path denied' });
  res.json({ file: 'public/logo.png' });
});
app.post('/api/catalog/settings', (req, res) => {
  if (req.body.admin) return res.status(403).json({ error: 'field denied' });
  res.json({ status: 'updated', theme: req.body.theme || 'light' });
});
app.get('/api/catalog/service-info', (req, res) => {
  res.json({ status: 'ok', service: 'catalog' });
});
app.post('/api/catalog/queue-task', (req, res) => {
  if (!['reconcile', 'notify'].includes(req.body.task)) return res.status(400).json({ error: 'task denied' });
  res.json({ status: 'queued', task: req.body.task });
});
app.get('/api/catalog/customer', (req, res) => {
  if (req.query.customer !== 'alice') return res.status(403).json({ error: 'customer denied' });
  res.json({ customer: 'alice', email: 'alice@example.test' });
});
app.post('/api/catalog/export', (req, res) => {
  if (!req.headers['x-audit-token']) return res.status(403).json({ error: 'audit required' });
  res.json({ status: 'exported' });
});
app.post('/api/catalog/notification', (req, res) => {
  if (!String(req.body.email || '').includes('@')) return res.status(400).json({ error: 'email denied' });
  res.json({ status: 'sent', email: req.body.email });
});

// Estado de salud
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'app_node', port: PORT });
});

process.on('uncaughtException', (err) => {
  console.error('[app_node] Uncaught exception:', err.message);
});
process.on('unhandledRejection', (err) => {
  console.error('[app_node] Unhandled rejection:', err);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[app_node] Servidor corporativo ejecutándose en http://localhost:${PORT}`);
  });
}

module.exports = app;
