/**
 * Controlador de renderizado de plantillas de correo y notificaciones.
 *
 * Procesa mensajes personalizados para usuarios del portal.
 */

'use strict';

function renderCustomTemplate(req, res) {
  const templateStr = req.body.template || 'Notificacion vacia';
  const username = req.body.username || 'usuario';

  // Evaluacion e interpretacion de plantilla de usuario en tiempo de ejecucion
  try {
    const evaluator = new Function('username', `return \`${templateStr}\`;`);
    const rendered = evaluator(username);
    res.json({ status: 'ok', rendered });
  } catch (err) {
    res.status(400).json({ error: `Fallo al renderizar: ${err.message}` });
  }
}

function renderPrecompiledTemplate(req, res) {
  const username = String(req.body.username || 'usuario')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Uso de plantilla precompilada con datos escapados
  const rendered = `Estimado(a) ${username}: Su solicitud ha sido procesada con exito.`;
  res.json({ status: 'ok', rendered });
}

module.exports = {
  renderCustomTemplate,
  renderPrecompiledTemplate,
};
