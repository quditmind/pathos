import express from "express";
import helmet from "helmet";

// ok: pathos.misconfig.express.helmet-missing, pathos.misconfig.express.x-powered-by
const app = express();
app.use(helmet());
app.disable("x-powered-by");

app.get("/", (_req, res) => {
  res.send("hello");
});

app.listen(8080);
