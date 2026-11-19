// Deliberately vulnerable sample for the worker-sast fixture tests.
const express = require("express");
const fs = require("fs");
const { exec } = require("child_process");

const app = express();

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

app.get("/file", (req, res) => {
  fs.readFile(req.query.path, (err, data) => res.send(data));
});

app.get("/search", (req, res) => {
  const re = new RegExp(req.query.pattern);
  const settings = {};
  settings[req.query.key] = req.query.value;
  res.json({ match: re.test("sample"), settings });
});

app.listen(3000);
