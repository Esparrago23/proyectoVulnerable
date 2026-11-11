/**
 * Controlador de Usuarios: Operaciones de consulta y perfil de usuarios.
 */
const { exec } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const dbClient = require('../models/dbClient');

// Consulta de usuario por identificador unico en ruta GET
function getUserById(req, res) {
  const userId = req.query.id;
  // Ejecuta la consulta SQL con el parametro recibido
  const sql = "SELECT * FROM users WHERE id = " + userId;
  dbClient.db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
}

// Diagnostico de disponibilidad de red hacia host destino
function pingHost(req, res) {
  const targetHost = req.query.host || '127.0.0.1';
  // Invoca el comando ping del sistema para evaluar respuesta de red
  const pingFlag = process.platform === 'win32' ? '-n 1' : '-c 1';
  const command = `ping ${pingFlag} ${targetHost}`;
  exec(command, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stderr, result: stdout || stderr || err.message });
    }
    res.json({ result: stdout });
  });
}

// Actualizacion de atributos de perfil del usuario corporativo
function updateUserProfile(req, res) {
  const RoleService = require('../services/roleService');
  const userId = req.body.userId || req.query.id;
  const profileUpdates = req.body || {};

  RoleService.processProfileUpdate(userId, profileUpdates, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true, user: result });
  });
}

function updateUserProfileCatalog(req, res) {
  const RoleService = require('../services/roleService');
  const userId = req.body.userId || req.query.id;
  const profileUpdates = req.body || {};

  RoleService.processProfileUpdateCatalog(userId, profileUpdates, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true, user: result });
  });
}

module.exports = {
  getUserById,
  pingHost,
  updateUserProfile,
  updateUserProfileCatalog,
};
