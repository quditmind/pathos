const express = require("express");
const session = require("express-session");
const cors = require("cors");

// ruleid: pathos.misconfig.express.helmet-missing, pathos.misconfig.express.x-powered-by
const app = express();

// ruleid: pathos.misconfig.express.cors-any-origin
app.use(cors());
// ruleid: pathos.misconfig.express.cors-any-origin
app.use(cors({ origin: "*" }));
// ruleid: pathos.misconfig.express.cors-any-origin
app.use(cors({ origin: true, credentials: true }));
// ok: pathos.misconfig.express.cors-any-origin
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));

// ruleid: pathos.misconfig.express.trust-proxy-all
app.set("trust proxy", true);
// ok: pathos.misconfig.express.trust-proxy-all
app.set("trust proxy", 1);

// ruleid: pathos.misconfig.express.insecure-cookie
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: false } }));

app.get("/login", (req, res) => {
  // ruleid: pathos.misconfig.express.insecure-cookie
  res.cookie("sid", "value", { httpOnly: false, secure: true });
  // ok: pathos.misconfig.express.insecure-cookie
  res.cookie("pref", "dark", { httpOnly: true, secure: true, sameSite: "lax" });
  // ruleid: pathos.misconfig.express.cors-any-origin
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.send("ok");
});

app.listen(3000);
