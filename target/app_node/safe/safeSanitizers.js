/**
 * Modulo de Sanitizacion y Validacion Estricta de Entradas
 * Funciones de consulta con controles de tipo, aislamiento de tenant y listas blancas.
 */
const path = require('path');
const dbClient = require('../models/dbClient');

// Consulta de usuario con conversion y validacion estricta de entero
function getSafeUserById(req, res) {
  const rawId = req.query.id;
  const parsedId = Number.parseInt(rawId, 10);

  if (Number.isNaN(parsedId) || parsedId <= 0 || !/^\d+$/.test(String(rawId || '').trim())) {
    return res.status(400).json({ error: 'ID numérico requerido' });
  }

  // parsedId es numerico y sanitizado antes de interpolar en la consulta
  const safeSql = `SELECT * FROM users WHERE id = ${parsedId}`;
  dbClient.db.all(safeSql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
}

// Descarga de archivos autorizados mediante normalizacion de ruta y catalogo
function getSafeFile(req, res) {
  const rawFilename = req.query.file || '';
  const ALLOWED_FILES = ['manual.pdf', 'terms.pdf', 'privacy.pdf'];

  const cleanBasename = path.basename(rawFilename);
  if (!ALLOWED_FILES.includes(cleanBasename)) {
    return res.status(403).json({ error: 'Archivo no permitido por política' });
  }

  res.json({ status: 'allowed', file: cleanBasename });
}

// Consulta de factura con validacion estricta de pertenencia al inquilino
function getSafeInvoiceForTenant(req, res) {
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

// Diagnostico de conectividad ping con validacion estricta de formato IPv4
function getSafePing(req, res) {
  const { execFile } = require('child_process');
  const host = req.query.host || '';
  const IPV4_STRICT_REGEX = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

  if (!IPV4_STRICT_REGEX.test(host)) {
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
  getSafeUserById,
  getSafeFile,
  getSafeInvoiceForTenant,
  getSafePing,
};
