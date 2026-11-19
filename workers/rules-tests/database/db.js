// Test fixture for workers/rules/pathos-database.yml (JavaScript). Not executed.
const { Sequelize, Op } = require("sequelize");
const mysql = require("mysql2");

const pool = mysql.createPool({ host: "db", user: "app", password: process.env.DB_PASSWORD });

function sql(req, res) {
  // ruleid: pathos.database.javascript.sql-string-building
  pool.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows));
  // ruleid: pathos.database.javascript.sql-string-building
  pool.query(`DELETE FROM sessions WHERE user_id = ${req.params.id}`);
  const q = "UPDATE users SET email = '" + req.body.email + "'";
  // ruleid: pathos.database.javascript.sql-string-building
  pool.execute(q);
  // ok: pathos.database.javascript.sql-string-building
  pool.query("SELECT * FROM users WHERE name = ?", [req.query.name]);
  // ok: pathos.database.javascript.sql-string-building
  console.log("selected " + req.query.name);
}

async function seq(sequelize, User, req) {
  // ruleid: pathos.database.javascript.sequelize-literal
  const a = await User.findAll({ order: Sequelize.literal("score " + req.query.dir) });
  // ruleid: pathos.database.javascript.sequelize-literal
  const b = await User.findAll({ where: sequelize.literal(`id = ${req.params.id}`) });
  // ok: pathos.database.javascript.sequelize-literal
  const c = await User.findAll({ order: Sequelize.literal("score DESC") });
  // ruleid: pathos.database.javascript.sql-string-building
  const d = await sequelize.query("SELECT * FROM users WHERE id = " + req.params.id);
  // ok: pathos.database.javascript.sql-string-building
  const e = await sequelize.query("SELECT * FROM users WHERE id = :id", { replacements: { id: req.params.id } });
  return [a, b, c, d, e];
}

async function knexRaw(knex, req) {
  // ruleid: pathos.database.javascript.sql-string-building
  return knex("users").whereRaw(`SELECT id FROM users WHERE name = '${req.query.name}'`);
}

async function mongo(Users, req) {
  // ruleid: pathos.database.javascript.nosql-injection
  const u = await Users.findOne({ username: req.body.username, password: req.body.password });
  // ruleid: pathos.database.javascript.nosql-injection
  const v = await Users.find(req.query);
  // ok: pathos.database.javascript.nosql-injection
  const w = await Users.findOne({ username: String(req.body.username) });
  return [u, v, w];
}

// ruleid: pathos.database.connection-string-hardcoded-password
const MONGO_URL = "mongodb+srv://app:fixture-mongo-pass-not-real@cluster0.example.net/app";
// ok: pathos.database.connection-string-hardcoded-password
const MONGO_URL_ENV = `mongodb+srv://app:${process.env.MONGO_PASSWORD}@cluster0.example.net/app`;
// ruleid: pathos.database.connection-string-tls-disabled
const MONGO_INSECURE = "mongodb://db.internal:27017/app?tls=true&tlsAllowInvalidCertificates=true";

module.exports = { sql, seq, knexRaw, mongo, MONGO_URL, MONGO_URL_ENV, MONGO_INSECURE };
