/**
 * Controlador de Facturación: Gestión y consulta de comprobantes fiscales.
 */
const PaymentService = require('../services/paymentService');

function getInvoiceDetails(req, res) {
  const invoiceId = parseInt(req.params.id, 10);
  const sessionUser = req.headers['x-user-session'] || 'authenticated_customer';

  // Valida la identidad del usuario en sesion y recupera el comprobante
  // Consulta la capa de servicios para devolver los detalles del documento
  // solicitados a partir del identificador de factura
  PaymentService.verifyInvoiceAccess(sessionUser, invoiceId, (err, invoice) => {
    if (err) return res.status(403).json({ error: err.message });
    if (!invoice) return res.status(404).json({ error: 'Factura no encontrada' });
    res.json({ invoice });
  });
}

module.exports = {
  getInvoiceDetails,
};
