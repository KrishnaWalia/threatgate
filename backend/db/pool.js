const mysql = require('mysql2/promise');

// A pool, not a single connection — Express handles concurrent
// requests, and each one grabs a connection, uses it, and returns
// it, instead of every request fighting over one socket.
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'threatgate',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  dateStrings: true,
});

module.exports = pool;
