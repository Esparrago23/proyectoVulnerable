/**
 * Controlador de catalogo de articulos con consultas de agregacion.
 *
 * Gestiona la busqueda y filtrado avanzado de productos.
 */

'use strict';

// Coleccion simulada en memoria para pruebas
const INVENTORY = [
  { id: 1, name: 'Servidor Rack 1U', category: 'hardware', price: 1200 },
  { id: 2, name: 'Switch Gestionable 24P', category: 'network', price: 450 },
  { id: 3, name: 'Licencia Antivirus Enterprise', category: 'software', price: 80 },
];

function queryCatalogNoSql(req, res) {
  const userFilter = req.query.filter || 'true';

  // Evaluacion dinamica de clausula de seleccion sin parametrizacion
  try {
    const filterFn = new Function('item', `return ${userFilter};`);
    const results = INVENTORY.filter(filterFn);
    res.json({ results });
  } catch (err) {
    res.status(400).json({ error: `Fallo en evaluacion de consulta: ${err.message}` });
  }
}

function queryCatalogSafe(req, res) {
  const category = String(req.query.category || '').toLowerCase();
  const maxPrice = Number(req.query.max_price) || 10000;

  // Filtrado determinista con comparaciones directas de propiedades
  const results = INVENTORY.filter((item) => {
    const matchCat = category ? item.category === category : true;
    const matchPrice = item.price <= maxPrice;
    return matchCat && matchPrice;
  });

  res.json({ results });
}

module.exports = {
  queryCatalogNoSql,
  queryCatalogSafe,
};
