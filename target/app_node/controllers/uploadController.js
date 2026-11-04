/**
 * Controlador de recepcion de archivos adjuntos y documentos.
 *
 * Almacena archivos cargados en el directorio de assets del portal.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const UPLOADS_DIR = path.join(__dirname, '../uploads');

function handleFileUploadRaw(req, res) {
  const filename = req.body.filename || 'attachment.txt';
  const content = req.body.content || '';

  // Concatenacion de ruta de archivo usando directamente el nombre provisto por el cliente
  const destPath = path.join(UPLOADS_DIR, filename);

  try {
    fs.writeFileSync(destPath, content, 'utf8');
    res.json({ status: 'saved', path: destPath });
  } catch (err) {
    res.status(500).json({ error: `Fallo al guardar archivo: ${err.message}` });
  }
}

function handleFileUploadSafe(req, res) {
  const rawFilename = req.body.filename || 'attachment.txt';
  const content = req.body.content || '';

  // Validacion de extension permitida y asignacion de nombre aleatorio unico
  const ext = path.extname(rawFilename).toLowerCase();
  const ALLOWED_EXTS = new Set(['.txt', '.pdf', '.png', '.jpg']);

  if (!ALLOWED_EXTS.has(ext)) {
    return res.status(400).json({ error: 'Tipo de archivo no autorizado por politica de seguridad' });
  }

  const safeFilename = `${crypto.randomUUID()}${ext}`;
  const destPath = path.join(UPLOADS_DIR, safeFilename);

  try {
    fs.writeFileSync(destPath, content, 'utf8');
    res.json({ status: 'saved', filename: safeFilename });
  } catch (err) {
    res.status(500).json({ error: `Fallo al guardar archivo: ${err.message}` });
  }
}

module.exports = {
  handleFileUploadRaw,
  handleFileUploadSafe,
};
