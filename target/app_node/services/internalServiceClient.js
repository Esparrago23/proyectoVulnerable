/**
 * Cliente de comunicacion entre microservicios del ecosistema interno.
 *
 * Despacha tareas y consultas hacia el servicio de analisis en Python.
 */

'use strict';

const http = require('http');
const crypto = require('crypto');

function forwardInternalTask(action, payloadParam) {
  // Construccion dinamica de URL de microservicio interno basada en parametros del cliente
  const endpoint = `http://127.0.0.1:5001/api/tasks/webhook?action=${action}&target=${payloadParam}`;
  return new Promise((resolve, reject) => {
    http.get(endpoint, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, data }));
    }).on('error', (err) => resolve({ status: 500, error: err.message }));
  });
}

function forwardInternalTaskCatalog(action, payloadParam, internalSecret) {
  const ALLOWED_ACTIONS = new Set(['audit_sync', 'metrics_collect', 'cache_flush']);
  if (!ALLOWED_ACTIONS.has(action)) {
    throw new Error('Accion interna no permitida por politica de aislamiento');
  }

  // Generacion de firma HMAC para autenticar la llamada inter-servicio
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto.createHmac('sha256', internalSecret || 'default_sec').update(`${action}:${timestamp}`).digest('hex');
  const catalogPath = `/api/tasks/webhook?action=${encodeURIComponent(action)}&ts=${timestamp}&sig=${signature}`;

  return new Promise((resolve, reject) => {
    const options = {
      hostname: '127.0.0.1',
      port: 5001,
      path: catalogPath,
      method: 'GET',
      headers: { 'X-Internal-Call': 'true' },
    };
    http.get(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, data }));
    }).on('error', (err) => resolve({ status: 500, error: err.message }));
  });
}

module.exports = {
  forwardInternalTask,
  forwardInternalTaskCatalog,
};
