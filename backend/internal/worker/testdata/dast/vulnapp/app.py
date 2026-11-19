# Deliberately vulnerable web application used ONLY to generate the
# worker-dast test fixtures (backend/internal/worker/testdata/dast). It runs
# in a container on an internal Docker network that has no route to the
# internet (see README.md in this directory). Never deploy it.
#
# Flaws: SQL injection (/item, /api/users/<id>), reflected XSS (/search,
# /greet), missing security headers and a cookie without HttpOnly, exposed
# files (/.git/config, /backup.zip, /admin/), a hidden debug parameter
# (/hidden?debug=...), an API that answers 500 on some inputs, and a TLS
# listener with a self-signed certificate that accepts TLS 1.0 and weak
# ciphers.
import html  # noqa: F401  (deliberately NOT used to escape output)
import os
import sqlite3
import ssl
import threading

from flask import Flask, jsonify, make_response, request
from werkzeug.serving import make_server

app = Flask(__name__)
DB = "/tmp/vulnapp.db"


def init_db():
    con = sqlite3.connect(DB)
    con.execute("DROP TABLE IF EXISTS items")
    con.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    con.executemany("INSERT INTO items VALUES (?, ?, ?)", [(1, "apple", "s1"), (2, "pear", "s2"), (3, "plum", "s3")])
    con.commit()
    con.close()


def query(sql):
    con = sqlite3.connect(DB)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


@app.route("/")
def index():
    resp = make_response("""<html><head><title>vulnapp</title></head><body>
<h1>Test shop</h1>
<a href="/search?q=apple">search</a> <a href="/item?id=1">item 1</a> <a href="/item?id=2">item 2</a>
<a href="/hidden">hidden</a> <a href="/openapi.json">api</a>
<form action="/greet" method="post"><input name="name" value="guest"><input type="submit"></form>
</body></html>""")
    resp.set_cookie("session", "abc123")  # no HttpOnly, no Secure, no SameSite
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return "<html><body><p>Results for: " + q + "</p></body></html>"  # reflected XSS


@app.route("/greet", methods=["GET", "POST"])
def greet():
    name = request.values.get("name", "")
    return "<html><body>Hello " + name + "</body></html>"  # reflected XSS


@app.route("/item")
def item():
    i = request.args.get("id", "1")
    try:
        rows = query("SELECT id, name FROM items WHERE id = " + i)  # SQL injection
    except sqlite3.Error as e:
        return "<html><body>database error: " + str(e) + "</body></html>", 500
    return "<html><body>" + "".join("<p>%s %s</p>" % r for r in rows) + "</body></html>"


@app.route("/hidden")
def hidden():
    if "debug" in request.args:  # any value turns on debug output
        return "<html><body>debug mode: config dump DB=/tmp/vulnapp.db</body></html>"
    return "<html><body>nothing here</body></html>"


@app.route("/.git/config")
def git_config():
    return '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.invalid/shop.git\n', 200, {"Content-Type": "text/plain"}


@app.route("/backup.zip")
def backup():
    return b"PK\x05\x06" + b"\x00" * 18, 200, {"Content-Type": "application/zip"}


@app.route("/admin/")
def admin():
    return "<html><head><title>Index of /admin</title></head><body><h1>Index of /admin</h1><a href='users.sql'>users.sql</a></body></html>"


# --- API (described by /openapi.json) --------------------------------------

@app.route("/api/users/<uid>")
def api_user(uid):
    try:
        rows = query("SELECT id, name FROM items WHERE id = " + uid)  # SQL injection
    except sqlite3.Error as e:
        return jsonify(error=str(e)), 500
    if not rows:
        return jsonify(error="not found"), 404
    return jsonify(id=rows[0][0], name=rows[0][1])


@app.route("/api/echo")
def api_echo():
    msg = request.args.get("msg", "")
    if len(msg) > 20:
        raise ValueError("message too long")  # unhandled: 500
    return jsonify(msg=msg, length=len(msg))


@app.route("/api/items", methods=["POST"])
def api_items():
    body = request.get_json(silent=True) or {}
    # Accepts any type and answers with a body that does not match the schema.
    return jsonify(created=body.get("name"), count="many"), 201


OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "vulnapp", "version": "1.0"},
    "servers": [{"url": "/"}],
    "paths": {
        "/api/users/{uid}": {"get": {"parameters": [{"name": "uid", "in": "path", "required": True, "schema": {"type": "integer"}}],
                                     "responses": {"200": {"description": "user", "content": {"application/json": {"schema": {
                                         "type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
                                         "required": ["id", "name"]}}}},
                                                   "404": {"description": "not found"}}}},
        "/api/echo": {"get": {"parameters": [{"name": "msg", "in": "query", "required": True, "schema": {"type": "string"}}],
                              "responses": {"200": {"description": "echo", "content": {"application/json": {"schema": {
                                  "type": "object", "properties": {"msg": {"type": "string"}, "length": {"type": "integer"}}}}}}}}},
        "/api/items": {"post": {"requestBody": {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}}},
            "responses": {"201": {"description": "created", "content": {"application/json": {"schema": {
                "type": "object", "properties": {"created": {"type": "string"}, "count": {"type": "integer"}},
                "required": ["created", "count"]}}}}}}},
    },
}


@app.route("/openapi.json")
def openapi():
    return jsonify(OPENAPI)


def serve_tls():
    # Self-signed certificate (created by the container entrypoint), TLS 1.0
    # allowed and weak ciphers enabled: findings for testssl.sh and SSLyze.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
    make_server("0.0.0.0", 443, app, threaded=True, ssl_context=ctx).serve_forever()


if __name__ == "__main__":
    init_db()
    if os.path.exists("/tmp/cert.pem"):
        threading.Thread(target=serve_tls, daemon=True).start()
    make_server("0.0.0.0", 80, app, threaded=True).serve_forever()
