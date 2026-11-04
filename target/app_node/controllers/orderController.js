/**
 * Controlador de Órdenes: Gestión de pedidos y compras de clientes.
 * Enruta las peticiones de consulta hacia la capa de servicios de pago.
 */
const PaymentService = require('../services/paymentService');

function getOrdersByUser(req, res) {
  // Input no confiable recibido en el controlador
  const userId = req.params.userId || req.query.userId;

  // Llama a la capa de servicio (salto hacia services/paymentService.js)
  PaymentService.searchOrdersByUser(userId, (err, orders) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json({ orders });
  });
}

module.exports = {
  getOrdersByUser,
};
