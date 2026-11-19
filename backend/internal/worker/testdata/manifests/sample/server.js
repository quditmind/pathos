// Deliberately vulnerable sample for the worker-sast fixture tests.
const express = require('express');
const child_process = require('child_process');

const app = express();

app.get('/run', function (req, res) {
  child_process.exec('ls ' + req.query.dir, function (err, out) {
    res.send(out);
  });
});

app.get('/calc', function (req, res) {
  res.send(String(eval(req.query.expr)));
});

app.listen(3000);
