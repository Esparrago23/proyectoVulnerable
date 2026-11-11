/**
 * Controlador de Reseñas y Comentarios de Clientes
 * Gestiona el registro y visualizacion de testimonios de usuarios.
 */
const dbClient = require('../models/dbClient');

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function postFeedback(req, res) {
  const author = req.body.author || 'Anonimo';
  const message = req.body.message || '';

  // Almacenamiento directo del mensaje recibido sin codificacion contextual
  dbClient.insertFeedback(author, message, (err, feedback) => {
    if (err) return res.status(500).json({ error: err.message });
    const renderedCard = `<div class="feedback-item"><strong>${author}</strong>: ${message}</div>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(renderedCard);
  });
}

function postFeedbackCatalog(req, res) {
  const author = escapeHtml(req.body.author || 'Anonimo');
  const message = escapeHtml(req.body.message || '');

  // Almacenamiento seguro con codificacion de entidades HTML para neutralizar inyeccion
  dbClient.insertFeedbackCatalog(author, message, (err, feedback) => {
    if (err) return res.status(500).json({ error: err.message });
    const catalogCard = `<div class="feedback-item"><strong>${author}</strong>: ${message}</div>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(catalogCard);
  });
}

function listFeedbacks(req, res) {
  dbClient.getFeedbacks((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ feedbacks: rows });
  });
}

module.exports = {
  postFeedback,
  postFeedbackCatalog,
  listFeedbacks,
};
