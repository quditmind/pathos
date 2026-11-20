// Example shop storefront backend (test fixture for pathos-graph; not run).
const express = require("express");
const { listProducts } = require("./catalog");

const app = express();

app.get("/store/products", async (req, res) => {
  res.json(await listProducts());
});

app.listen(3000);
