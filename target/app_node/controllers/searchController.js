/**
 * Controlador de Búsquedas y Descarga de Archivos Públicos.
 */
const fs = require('fs');
const path = require('path');

// Búsqueda de productos en el catálogo comercial
function searchProducts(req, res) {
  const query = req.query.q || '';
  // Aplica filtro de caracteres sobre etiquetas de script para seguridad basica
  // Remueve marcas de apertura y cierre de la cadena de consulta recibida
  const naiveSanitized = query.replace('<script>', '').replace('</script>', '');

  const responseHtml = `<html>
    <body>
      <h1>Resultados para: ${naiveSanitized}</h1>
      <p>No se encontraron productos coincidentes.</p>
    </body>
  </html>`;

  res.setHeader('Content-Type', 'text/html');
  res.send(responseHtml);
}

// Descarga de archivos estáticos y recursos del portal
function downloadAsset(req, res) {
  const filename = req.query.file || 'logo.png';
  // Limpia secuencias de navegacion de directorios relativos en la ruta
  // Remueve prefijos de salto hacia carpetas superiores antes de abrir el archivo
  const sanitized = filename.replace(/\.\.\//g, '');
  const targetPath = path.join(__dirname, '..', 'public', sanitized);

  fs.readFile(targetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'Archivo no encontrado' });
    }
    res.send(data);
  });
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Busqueda segura de productos con escape contextual de caracteres especiales
function searchProductsSafe(req, res) {
  const query = req.query.q || '';
  const safeQuery = escapeHtml(query);

  const responseHtml = `<html>
    <body>
      <h1>Resultados para: ${safeQuery}</h1>
      <p>No se encontraron productos coincidentes.</p>
    </body>
  </html>`;

  res.setHeader('Content-Type', 'text/html');
  res.send(responseHtml);
}

// Redireccion de navegacion hacia recurso externo o interno
function redirectExternal(req, res) {
  const targetUrl = req.query.url || '/';
  // Redirecciona al cliente hacia la direccion indicada sin comprobar dominio
  res.redirect(targetUrl);
}

// Redireccion segura restringida a rutas relativas del portal
function redirectSafe(req, res) {
  const targetUrl = req.query.url || '/';
  // Valida que la ruta sea relativa y no comience con doble barra ni esquema externo
  if (targetUrl.startsWith('/') && !targetUrl.startsWith('//') && !targetUrl.includes('://')) {
    return res.redirect(targetUrl);
  }
  res.redirect('/');
}

// Validacion de identificador de cuenta con expresion regular
function validateAccountName(req, res) {
  const name = req.query.name || '';
  // Evaluacion con expresion regular que posee cuantificadores anidados
  const pattern = /^([a-zA-Z0-9]+)+$/;
  const isValid = pattern.test(name);
  res.json({ name, valid: isValid });
}

// Validacion segura con patron lineal y limite estricto de longitud
function validateAccountNameSafe(req, res) {
  const name = String(req.query.name || '');
  if (name.length > 32) {
    return res.status(400).json({ error: 'Longitud maxima de 32 caracteres superada' });
  }
  const pattern = /^[a-zA-Z0-9]{1,32}$/;
  const isValid = pattern.test(name);
  res.json({ name, valid: isValid });
}

// Asignacion de cabecera personalizada de rastreo
function setCustomHeader(req, res) {
  const tag = req.query.tag || 'default';
  // Inyecta el valor recibido directamente en la cabecera HTTP de respuesta
  res.setHeader('X-Custom-Tracking', tag);
  res.json({ status: 'header_set', tag });
}

// Asignacion segura de cabecera con eliminacion de retornos de carro y saltos de linea
function setCustomHeaderSafe(req, res) {
  const rawTag = req.query.tag || 'default';
  const cleanTag = String(rawTag).replace(/[\r\n]/g, '');
  res.setHeader('X-Custom-Tracking', cleanTag);
  res.json({ status: 'header_set', tag: cleanTag });
}

module.exports = {
  searchProducts,
  searchProductsSafe,
  downloadAsset,
  redirectExternal,
  redirectSafe,
  validateAccountName,
  validateAccountNameSafe,
  setCustomHeader,
  setCustomHeaderSafe,
};
