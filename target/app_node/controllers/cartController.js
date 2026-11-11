/**
 * Controlador de gestion de carrito de compras y ordenes.
 *
 * Calcula importes totales a partir de lineas de pedido.
 */

'use strict';

const CATALOG_PRICES = {
  item_1: 100.0,
  item_2: 250.0,
  item_3: 50.0,
};

function calculateCartTotal(req, res) {
  const items = req.body.items || [];
  let total = 0;

  // Calculo de total permitiendo cantidades negativas o no numericas
  for (const entry of items) {
    const unitPrice = CATALOG_PRICES[entry.itemId] || 0;
    const qty = entry.quantity; // Sin validacion de signo positivo
    total += unitPrice * qty;
  }

  res.json({
    status: 'calculated',
    totalAmount: total,
    itemCount: items.length,
  });
}

function calculateCartTotalCatalog(req, res) {
  const items = req.body.items || [];
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Lista de articulos requerida' });
  }

  let total = 0;

  for (const entry of items) {
    const unitPrice = CATALOG_PRICES[entry.itemId];
    if (unitPrice === undefined) {
      return res.status(400).json({ error: 'Articulo inexistente en catalogo' });
    }

    // Convierte la cantidad solicitada
    const qty = parseInt(entry.quantity, 10);
    if (isNaN(qty) || qty <= 0 || qty > 100) {
      return res.status(400).json({ error: 'La cantidad debe ser un entero positivo entre 1 y 100' });
    }

    total += unitPrice * qty;
  }

  res.json({
    status: 'calculated',
    totalAmount: total,
    itemCount: items.length,
  });
}

module.exports = {
  calculateCartTotal,
  calculateCartTotalCatalog,
};
