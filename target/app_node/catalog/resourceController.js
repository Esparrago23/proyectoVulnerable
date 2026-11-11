/**
 * Utilidades de entrada para recursos
 * Funciones de consulta con controles de tipo, aislamiento de tenant y listas blancas.
 */
const path = require('path');
const dbClient = require('../models/dbClient');

// Busca un usuario por identificador
function lookupUser(req, res) {
  const rawId = req.query.id;
  const parsedId = Number.parseInt(rawId, 10);

  if (Number.isNaN(parsedId) || parsedId <= 0 || !/^\d+$/.test(String(rawId || '').trim())) {
    return res.status(400).json({ error: 'ID numérico requerido' });
  }

  // parsedId es numerico y sanitizado antes de interpolar en la consulta
  const catalogSql = `SELECT * FROM users WHERE id = ${parsedId}`;
  dbClient.db.all(catalogSql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
}

// Descarga de archivos autorizados mediante normalizacion de ruta y catalogo
function downloadFile(req, res) {
  const rawFilename = req.query.file || '';
  const ALLOWED_FILES = ['manual.pdf', 'terms.pdf', 'privacy.pdf'];

  const cleanBasename = path.basename(rawFilename);
  if (!ALLOWED_FILES.includes(cleanBasename)) {
    return res.status(403).json({ error: 'Archivo no permitido por política' });
  }

  res.json({ status: 'allowed', file: cleanBasename });
}

// Busca una factura del espacio de trabajo
function getInvoiceForTenant(req, res) {
  const invoiceId = Number.parseInt(req.params.id, 10);
  const tenantId = req.headers['x-tenant-id'] || 'tenant_alpha';

  if (Number.isNaN(invoiceId) || invoiceId <= 0) {
    return res.status(400).json({ error: 'ID de factura inválido' });
  }

  dbClient.getInvoiceById(invoiceId, (err, invoice) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!invoice) return res.status(404).json({ error: 'Factura no encontrada' });

    // Verificacion de inquilino: comprueba coincidencia con tenantId de la cabecera
    if (invoice.tenant_id !== tenantId) {
      return res.status(403).json({ error: 'Acceso denegado: factura no pertenece a este tenant' });
    }

    res.json({ invoice });
  });
}

// Ejecuta un diagnostico de conectividad
function probeHost(req, res) {
  const { execFile } = require('child_process');
  const host = req.query.host || '';
  const IPV4_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

  if (!IPV4_PATTERN.test(host)) {
    return res.status(400).json({ error: 'Dirección IPv4 inválida' });
  }

  // Invoca el binario de forma aislada sin interprete de comandos intermedio
  const pingFlag = process.platform === 'win32' ? '-n' : '-c';
  execFile('ping', [pingFlag, '1', host], (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stderr });
    }
    res.json({ result: stdout });
  });
}

module.exports = {
  lookupUser,
  downloadFile,
  getInvoiceForTenant,
  probeHost,
};
