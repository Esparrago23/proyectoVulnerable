/**
 * Capa de Acceso a Datos (DAO)
 * Servicios de persistencia y ejecucion de consultas a la base de datos.
 */
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(':memory:');

// Inicializar tablas en memoria
db.serialize(() => {
  db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, balance REAL)`);
  db.run(`CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL, status TEXT)`);
  db.run(`CREATE TABLE invoices (id INTEGER PRIMARY KEY, tenant_id TEXT, amount REAL, customer_name TEXT)`);

  db.run(`INSERT INTO users VALUES (1, 'alice', 'user', 1500.0)`);
  db.run(`INSERT INTO users VALUES (2, 'bob', 'user', 350.0)`);
  db.run(`INSERT INTO users VALUES (3, 'admin', 'administrator', 99999.0)`);

  db.run(`INSERT INTO orders VALUES (101, 1, 'Laptop Pro', 1200.0, 'completed')`);
  db.run(`INSERT INTO orders VALUES (102, 2, 'Mechanical Keyboard', 150.0, 'pending')`);

  db.run(`INSERT INTO invoices VALUES (501, 'tenant_alpha', 4500.0, 'Alpha Corp')`);
  db.run(`INSERT INTO invoices VALUES (502, 'tenant_beta', 12000.0, 'Beta Industries')`);

  db.run(`CREATE TABLE feedback (id INTEGER PRIMARY KEY, author TEXT, message TEXT)`);
  db.run(`INSERT INTO feedback VALUES (1, 'alice', 'Excelente atencion del equipo de soporte')`);
});

/**
 * Consulta de ordenes segun condiciones dinamicas de filtrado:
 * Ejecuta la sentencia SQL en base a los criterios recibidos del servicio.
 */
function queryOrder(rawCondition, callback) {
  const query = `SELECT * FROM orders WHERE ${rawCondition}`;
  // Ejecuta la consulta SQL construida dinamicamente contra la base de datos
  db.all(query, (err, rows) => {
    if (err) return callback(err, null);
    callback(null, rows);
  });
}

function getInvoiceById(invoiceId, callback) {
  // Recupera la factura por su identificador numerico primario
  // Retorna el registro correspondiente encontrado en la tabla
  const query = `SELECT * FROM invoices WHERE id = ?`;
  db.get(query, [invoiceId], (err, row) => {
    if (err) return callback(err, null);
    callback(null, row);
  });
}

function updateUserProfile(userId, profileData, callback) {
  // Salto 3 de 3: Actualiza campos en SQLite según lo indicado por la capa superior
  const newRole = profileData.role || 'user';
  const query = `UPDATE users SET role = ? WHERE id = ?`;
  db.run(query, [newRole, userId], function(err) {
    if (err) return callback(err, null);
    db.get(`SELECT id, username, role, balance FROM users WHERE id = ?`, [userId], (err2, row) => {
      if (err2) return callback(err2, null);
      callback(null, row);
    });
  });
}

function queryOrderCatalog(userId, callback) {
  // Consulta parametrizada con marcadores de posicion para neutralizar inyeccion
  const query = `SELECT * FROM orders WHERE user_id = ?`;
  db.all(query, [userId], (err, rows) => {
    if (err) return callback(err, null);
    callback(null, rows);
  });
}

function insertFeedback(author, message, callback) {
  // Insercion directa de comentario sin sanitizacion previa en la capa de datos
  const query = `INSERT INTO feedback (author, message) VALUES ('${author}', '${message}')`;
  db.run(query, function(err) {
    if (err) return callback(err, null);
    callback(null, { id: this.lastID, author, message });
  });
}

function insertFeedbackCatalog(author, message, callback) {
  // Insercion parametrizada con valores ligados
  const query = `INSERT INTO feedback (author, message) VALUES (?, ?)`;
  db.run(query, [author, message], function(err) {
    if (err) return callback(err, null);
    callback(null, { id: this.lastID, author, message });
  });
}

function getFeedbacks(callback) {
  db.all(`SELECT id, author, message FROM feedback ORDER BY id DESC`, (err, rows) => {
    if (err) return callback(err, null);
    callback(null, rows);
  });
}

module.exports = {
  db,
  queryOrder,
  queryOrderCatalog,
  getInvoiceById,
  updateUserProfile,
  insertFeedback,
  insertFeedbackCatalog,
  getFeedbacks,
};
