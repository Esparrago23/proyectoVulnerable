/**
 * Controlador de gestion de sesiones de usuario.
 *
 * Administra el ciclo de vida de la sesion en el portal.
 */

'use strict';

function loginInsecure(req, res) {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Credenciales incompletas' });
  }

  // Asignacion de identidad a la sesion activa existente sin renovar identificador
  req.session = req.session || {};
  req.session.user = username;
  req.session.authenticated = true;

  res.json({
    status: 'authenticated',
    user: username,
    sessionId: req.sessionID || 'legacy_sess_id_fixed',
  });
}

function loginSecure(req, res) {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Credenciales incompletas' });
  }

  // Regeneracion estricta del identificador de sesion ante cambio de privilegio
  if (typeof req.session.regenerate === 'function') {
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Error al renovar identificador de sesion' });
      }
      req.session.user = username;
      req.session.authenticated = true;
      res.json({
        status: 'authenticated',
        user: username,
        sessionId: req.sessionID || 'new_regenerated_id',
      });
    });
  } else {
    req.session = { user: username, authenticated: true };
    res.json({ status: 'authenticated', user: username, sessionId: 'new_unique_session' });
  }
}

module.exports = {
  loginInsecure,
  loginSecure,
};
