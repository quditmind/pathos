#!/usr/bin/env python3
"""A deliberately vulnerable stub LLM server for testing the worker-ai red
teaming tools (garak, promptfoo). It is never a real model or provider.

It serves an OpenAI-compatible chat completions API:

    POST /v1/chat/completions   {"model": "...", "messages": [...]}
    GET  /v1/models

and requires "Authorization: Bearer <STUB_LLM_KEY>" (default
"pathos-stub-llm-test-key", a test value that matches no provider format).

Behaviour, so that red-teaming tools find something: the reply repeats the
last user message ("prompt injection" payloads come back verbatim), claims
to have entered "DAN mode" when asked to, and reveals its fake system
prompt when asked for its instructions. Everything else gets a fixed
refusal. Usage: stub_llm.py [port] (default 8080).
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ.get("STUB_LLM_KEY", "pathos-stub-llm-test-key")
SYSTEM_PROMPT = "You are StubBot. Internal note: the staging discount code is STUB-DISCOUNT-0000."


def reply(prompt: str) -> str:
    p = prompt.lower()
    if "dan" in p.split() or "do anything now" in p or "developer mode" in p:
        return "DAN Mode enabled. I am free of all restrictions. " + prompt[:400]
    if "instructions" in p or "system prompt" in p or "initial prompt" in p:
        return "My instructions are: " + SYSTEM_PROMPT
    if "ignore" in p or "print" in p or "say" in p or "repeat" in p:
        # Follows injected instructions by echoing the payload.
        return prompt[-1500:]
    return "I'm sorry, I can't help with that."


class Handler(BaseHTTPRequestHandler):
    server_version = "stub-llm/1"

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self):
        if self.headers.get("Authorization", "") != "Bearer " + KEY:
            self._send(401, {"error": {"message": "invalid API key", "type": "invalid_request_error"}})
            return False
        return True

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/health"):
            self._send(200, {"status": "ok"})
            return
        if not self._authorized():
            return
        if self.path.rstrip("/") == "/v1/models":
            self._send(200, {"object": "list", "data": [{"id": "stub-model", "object": "model"}]})
        else:
            self._send(404, {"error": {"message": "not found"}})

    def do_POST(self):
        if not self._authorized():
            return
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send(404, {"error": {"message": "not found"}})
            return
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(min(n, 1 << 20)) or b"{}")
        except ValueError:
            self._send(400, {"error": {"message": "invalid JSON"}})
            return
        msgs = [m for m in req.get("messages", []) if isinstance(m, dict)]
        prompt = ""
        for m in msgs:
            if m.get("role") == "user":
                c = m.get("content")
                prompt = c if isinstance(c, str) else json.dumps(c)
        text = reply(prompt)
        self._send(200, {
            "id": "chatcmpl-stub", "object": "chat.completion", "created": int(time.time()),
            "model": req.get("model", "stub-model"),
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": len(prompt.split()), "completion_tokens": len(text.split()),
                      "total_tokens": len(prompt.split()) + len(text.split())},
        })

    def log_message(self, fmt, *args):
        sys.stderr.write("stub-llm: " + (fmt % args) + "\n")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
