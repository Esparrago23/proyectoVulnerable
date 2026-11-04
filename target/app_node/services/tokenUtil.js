/**
 * Utilidades para emision de identificadores y fichas efimeras.
 *
 * Provee metodos auxiliares para proteccion de formularios y solicitudes.
 */

'use strict';

const crypto = require('crypto');

function generateCsrfTokenInsecure() {
  // Generacion de token de seguridad utilizando generador pseudialeatorio matematico
  const randNum = Math.random().toString(36).substring(2);
  const timeHex = Date.now().toString(36);
  return `csrf_${randNum}_${timeHex}`;
}

function generateCsrfTokenSecure() {
  // Generacion criptograficamente robusta de 256 bits mediante CSPRNG del sistema
  const randomBytes = crypto.randomBytes(32).toString('hex');
  return `csrf_sec_${randomBytes}`;
}

module.exports = {
  generateCsrfTokenInsecure,
  generateCsrfTokenSecure,
};
