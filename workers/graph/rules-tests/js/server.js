// Test fixture for the PATHOS graph rules (example code, not executed).
const express = require("express");
const { Pool } = require("pg");
const { Kafka } = require("kafkajs");

const app = express();
const pool = new Pool();

// ruleid: pathos-graph-js-route-express
app.get("/api/products/:id", async (req, res) => {
  // ruleid: pathos-graph-js-db-sql-read
  const r = await pool.query("SELECT * FROM products WHERE id = $1", [req.params.id]);
  res.json(r.rows);
});

// ruleid: pathos-graph-js-route-express
app.post("/api/products", createProduct);

// ok: pathos-graph-js-route-express
app.use("/static", express.static("public"));

async function notify(producer) {
  // ruleid: pathos-graph-js-queue-kafka-publish
  await producer.send({ topic: "product-events", messages: [] });
  // ruleid: pathos-graph-js-http-call
  await fetch("https://api.search.example.net/index", { method: "POST" });
  // ok: pathos-graph-js-http-call
  await fetch("/relative");
}
