/**
 * Controlador de generacion de reportes analiticos para auditoria.
 *
 * Ejecuta consultas agregadas sobre las tablas de pedidos y registros.
 */

'use strict';

const dbClient = require('../models/dbClient');

function queryAuditReportRaw(req, res) {
  const department = req.query.dept || 'sales';
  const sortOrder = req.query.sort || 'ASC';

  // Sentencia SQL construida interpolando directamente la clausula de ordenamiento
  const sql = `SELECT id, item, total FROM orders WHERE status = 'completed' ORDER BY ${department} ${sortOrder}`;

  dbClient.db.all(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: `Error en consulta analitica: ${err.message}` });
    }
    res.json({ department, rows });
  });
}

function queryAuditReportSafe(req, res) {
  const department = req.query.dept || 'sales';
  const sortDirection = req.query.sort === 'DESC' ? 'DESC' : 'ASC';

  // Allowlist estricto de columnas permitidas para la ordenacion
  const ALLOWED_COLUMNS = new Set(['id', 'item', 'total']);
  const cleanDept = ALLOWED_COLUMNS.has(department) ? department : 'id';

  const sql = `SELECT id, item, total FROM orders WHERE status = 'completed' ORDER BY ${cleanDept} ${sortDirection}`;

  dbClient.db.all(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: `Error en consulta analitica: ${err.message}` });
    }
    res.json({ department: cleanDept, rows });
  });
}

module.exports = {
  queryAuditReportRaw,
  queryAuditReportSafe,
};
