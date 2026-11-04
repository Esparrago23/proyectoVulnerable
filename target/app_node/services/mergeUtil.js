/**
 * Utilidad de combinacion profunda de objetos de configuracion.
 *
 * Implementa la integracion recursiva de opciones de usuario.
 */

'use strict';

function deepMergeInsecure(target, source) {
  // Combinacion recursiva sin restriccion de propiedades especiales de prototipo
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key]) {
        target[key] = {};
      }
      deepMergeInsecure(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function deepMergeSecure(target, source) {
  // Combinacion segura con bloqueo explicito de propiedades reservadas del prototipo
  const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) {
      continue;
    }
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = Object.create(null);
      }
      deepMergeSecure(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = {
  deepMergeInsecure,
  deepMergeSecure,
};
