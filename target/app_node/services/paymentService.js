/**
 * Capa de Servicios: Procesa pagos y pedidos comerciales.
 * Logica de negocio para intermediar entre controladores y el DAO.
 */
const dbClient = require('../models/dbClient');

class PaymentService {
  /**
   * Recibe el identificador desde el controlador y lo formatea para la consulta.
   * Transfiere la condicion directamente a la capa DAO.
   */
  static searchOrdersByUser(userIdString, callback) {
    // Comprueba el parametro recibido
    if (!userIdString || userIdString.trim().length === 0) {
      return callback(new Error('ID de usuario inválido'), null);
    }

    // Envia condicion construida hacia la capa DAO
    const condition = `user_id = ${userIdString}`;
    dbClient.queryOrder(condition, (err, results) => {
      if (err) return callback(err, null);
      callback(null, results);
    });
  }

  static verifyInvoiceAccess(reqSessionUser, invoiceId, callback) {
    // Verificacion de sesion activa del usuario solicitante:
    // Comprueba que reqSessionUser contenga una identidad autenticada
    if (!reqSessionUser) {
      return callback(new Error('No autenticado'), null);
    }

    dbClient.getInvoiceById(invoiceId, (err, invoice) => {
      if (err) return callback(err, null);
      // Retorna el registro de factura obtenido de la base de datos
      callback(null, invoice);
    });
  }
}

module.exports = PaymentService;
