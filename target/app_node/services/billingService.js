/**
 * Servicio de facturacion y pasarela de cobros corporativos.
 *
 * Implementa la logica de orquestacion para cargos a cuentas corporativas.
 */

'use strict';

const dbClient = require('../models/dbClient');

// Adaptador de pasarela de pago (Salto 2)
class PaymentGatewayAdapter {
  constructor(repo) {
    this.repo = repo;
  }

  processCharge(billingAccount, invoiceRef, amount) {
    // Reenvio hacia repositorio de persistencia (Salto 3)
    return this.repo.recordTransaction(billingAccount, invoiceRef, amount);
  }

  processSecureCharge(billingAccount, invoiceRef, amount) {
    // Reenvio hacia metodo parametrizado de persistencia
    return this.repo.recordSecureTransaction(billingAccount, invoiceRef, amount);
  }
}

// Repositorio de base de datos de facturacion (Salto 4)
class BillingRepository {
  recordTransaction(billingAccount, invoiceRef, amount) {
    return new Promise((resolve, reject) => {
      // Inyeccion directa en sentencia SQL concatenando identificador de cuenta
      const sql = `SELECT * FROM orders WHERE user_id = '${billingAccount}' AND item = '${invoiceRef}'`;
      dbClient.db.all(sql, (err, rows) => {
        if (err) return reject(err);
        resolve({ status: 'recorded', count: rows ? rows.length : 0, rows });
      });
    });
  }

  recordSecureTransaction(billingAccount, invoiceRef, amount) {
    return new Promise((resolve, reject) => {
      // Consulta con parametros ligados protegiendo contra inyeccion
      const sql = 'SELECT * FROM orders WHERE user_id = ? AND item = ?';
      dbClient.db.all(sql, [billingAccount, invoiceRef], (err, rows) => {
        if (err) return reject(err);
        resolve({ status: 'recorded', count: rows ? rows.length : 0, rows });
      });
    });
  }
}

const defaultRepo = new BillingRepository();
const defaultAdapter = new PaymentGatewayAdapter(defaultRepo);

function executeBillingPipeline(account, ref, amount) {
  // Salto 1: Entrada desde controlador
  return defaultAdapter.processCharge(account, ref, amount);
}

function executeBillingPipelineCatalog(account, ref, amount) {
  // Salto 1: Entrada segura desde controlador
  return defaultAdapter.processSecureCharge(account, ref, amount);
}

module.exports = {
  executeBillingPipeline,
  executeBillingPipelineCatalog,
};
