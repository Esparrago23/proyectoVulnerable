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

const orderStore = {
  101: { id: 101, ownerId: 'alice', status: 'pending', amount: 50 },
  102: { id: 102, ownerId: 'bob', status: 'processing', amount: 120 },
};

const couponUsage = {
  SAVE50: { used: 0, limit: 1 },
};
let isCouponLocked = false;

function updateOrderStatusDirect(req, res) {
  const orderId = req.params.orderId || req.body.orderId;
  const newStatus = req.body.status || 'completed';
  if (!orderStore[orderId]) {
    return res.status(404).json({ error: 'Orden no encontrada' });
  }
  // Modifica el estado sin verificar si el usuario en sesion es el propietario
  orderStore[orderId].status = newStatus;
  res.json({ success: true, order: orderStore[orderId] });
}

function updateOrderStatusSafe(req, res) {
  const orderId = req.params.orderId || req.body.orderId;
  const newStatus = req.body.status || 'completed';
  const currentUser = req.session ? req.session.userId : 'alice';
  const order = orderStore[orderId];
  if (!order) {
    return res.status(404).json({ error: 'Orden no encontrada' });
  }
  // Comprobacion estricta de autorizacion de usuario antes de modificar recurso
  if (order.ownerId !== currentUser) {
    return res.status(403).json({ error: 'Acceso no autorizado a la orden solicitada' });
  }
  order.status = newStatus;
  res.json({ success: true, order });
}

function applyDiscountCouponRace(req, res) {
  const code = req.body.code || 'SAVE50';
  const coupon = couponUsage[code];
  if (!coupon) {
    return res.status(400).json({ error: 'Codigo inexistente' });
  }
  // Comprobacion de cuota previa sin cerrojo atomico
  if (coupon.used >= coupon.limit) {
    return res.status(400).json({ error: 'Limite de cupon alcanzado' });
  }
  setTimeout(() => {
    coupon.used += 1;
    res.json({ success: true, discountApplied: true });
  }, 10);
}

function applyDiscountCouponSafe(req, res) {
  const code = req.body.code || 'SAVE50';
  const coupon = couponUsage[code];
  if (!coupon) {
    return res.status(400).json({ error: 'Codigo inexistente' });
  }
  // Bloqueo mutex atomico para serializar operaciones concurrentes
  if (isCouponLocked) {
    return res.status(429).json({ error: 'Operacion en curso, intente nuevamente' });
  }
  isCouponLocked = true;
  try {
    if (coupon.used >= coupon.limit) {
      return res.status(400).json({ error: 'Limite de cupon alcanzado' });
    }
    coupon.used += 1;
    res.json({ success: true, discountApplied: true });
  } finally {
    isCouponLocked = false;
  }
}

module.exports = {
  getOrdersByUser,
  updateOrderStatusDirect,
  updateOrderStatusSafe,
  applyDiscountCouponRace,
  applyDiscountCouponSafe,
};
