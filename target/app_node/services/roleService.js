/**
 * Servicio de Asignación de Roles y Perfiles
 * Conecta los controladores de usuario con la capa de persistencia DAO.
 */
const dbClient = require('../models/dbClient');

class RoleService {
  /**
   * Actualiza los atributos del perfil de usuario.
   * Procesa la actualizacion de campos recibidos en la peticion de perfil.
   * Aplica las propiedades suministradas sobre el objeto de usuario.
   */
  static processProfileUpdate(userId, profileUpdates, callback) {
    if (!userId) {
      return callback(new Error('ID de usuario requerido'), null);
    }

    // Combina atributos del perfil entrante con los valores por defecto
    const mergedProfile = Object.assign({ role: 'user', updated_at: new Date().toISOString() }, profileUpdates);

    // Persiste los datos a traves del cliente DAO
    dbClient.updateUserProfile(userId, mergedProfile, (err, updatedUser) => {
      if (err) return callback(err, null);
      callback(null, updatedUser);
    });
  }

  /**
   * Actualizacion segura de perfil mediante lista blanca de campos permitidos (DTO).
   * Impide la modificacion de atributos privilegiados como rol o permisos.
   */
  static processProfileUpdateSafe(userId, profileUpdates, callback) {
    if (!userId) {
      return callback(new Error('ID de usuario requerido'), null);
    }

    const ALLOWED_MUTABLE_KEYS = ['display_name', 'bio', 'theme'];
    const safeUpdates = {};
    for (const key of ALLOWED_MUTABLE_KEYS) {
      if (Object.prototype.hasOwnProperty.call(profileUpdates, key)) {
        safeUpdates[key] = profileUpdates[key];
      }
    }

    // El rol permanece inmutable y fijado a su valor legitimo
    const cleanProfile = Object.assign({ role: 'user', updated_at: new Date().toISOString() }, safeUpdates);

    dbClient.updateUserProfile(userId, cleanProfile, (err, updatedUser) => {
      if (err) return callback(err, null);
      callback(null, updatedUser);
    });
  }
}

module.exports = RoleService;
