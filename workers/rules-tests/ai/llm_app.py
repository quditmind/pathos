# Test fixture for workers/rules/pathos-ai.yml (Python). Not executed.
# The API keys below are obviously fake fixture values.
import json
import os
import subprocess

import anthropic
import joblib
import numpy as np
import openai
import torch
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from transformers import AutoModelForCausalLM

SYSTEM = "You are a support assistant. Answer only questions about orders."


def prompts(client, user, question, doc):
    # ok: pathos.ai.python.dynamic-system-prompt
    ok = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
    # ruleid: pathos.ai.python.dynamic-system-prompt
    bad = [{"role": "system", "content": f"You help {user.name}. Context: {doc}"}]
    # ruleid: pathos.ai.python.dynamic-system-prompt
    msg = SystemMessage(content="Follow these rules: " + doc)
    # ruleid: pathos.ai.python.dynamic-system-prompt
    r = client.messages.create(model="m", max_tokens=100, system=f"Summarise for {user.role}", messages=ok)
    # ok: pathos.ai.python.dynamic-system-prompt
    r2 = client.messages.create(model="m", max_tokens=100, system=SYSTEM, messages=ok)
    return ok, bad, msg, r, r2


def run_tool(client, cursor, question):
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}])
    code = resp.choices[0].message.content
    # ruleid: pathos.ai.python.llm-output-execution
    exec(code)
    call = resp.choices[0].message.tool_calls[0]
    args = json.loads(call.function.arguments)
    # ruleid: pathos.ai.python.llm-output-execution
    subprocess.run(args["command"], shell=True)
    # ruleid: pathos.ai.python.llm-output-execution
    cursor.execute(args["sql"])
    # ok: pathos.ai.python.llm-output-execution
    cursor.execute("SELECT name FROM products WHERE id = %s", (args["id"],))
    # ok: pathos.ai.python.llm-output-execution
    print(code)


def load_models(path):
    # ruleid: pathos.ai.python.unsafe-model-load
    m1 = torch.load(path)
    # ok: pathos.ai.python.unsafe-model-load
    m2 = torch.load(path, weights_only=True)
    # ruleid: pathos.ai.python.unsafe-model-load
    m3 = joblib.load(path)
    # ruleid: pathos.ai.python.unsafe-model-load
    m4 = np.load(path, allow_pickle=True)
    # ok: pathos.ai.python.unsafe-model-load
    m5 = np.load(path)
    # ruleid: pathos.ai.python.trust-remote-code
    m6 = AutoModelForCausalLM.from_pretrained("org/model", trust_remote_code=True)
    # ok: pathos.ai.python.trust-remote-code
    m7 = AutoModelForCausalLM.from_pretrained("org/model", trust_remote_code=True, revision="0123456789abcdef0123456789abcdef01234567")
    # ok: pathos.ai.python.trust-remote-code
    m8 = AutoModelForCausalLM.from_pretrained("org/model")
    return m1, m2, m3, m4, m5, m6, m7, m8


def clients():
    # ruleid: pathos.ai.python.hardcoded-llm-api-key
    c1 = openai.OpenAI(api_key="fixture-llm-key-not-real-0001")
    # ruleid: pathos.ai.python.hardcoded-llm-api-key
    c2 = ChatOpenAI(model="m", api_key="fixture-llm-key-not-real-0002")
    # ok: pathos.ai.python.hardcoded-llm-api-key
    c3 = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    # ok: pathos.ai.python.hardcoded-llm-api-key
    c4 = anthropic.Anthropic(api_key="your-api-key-here")
    # ruleid: pathos.ai.python.llm-api-key-in-environment
    os.environ["OPENAI_API_KEY"] = "fixture-llm-key-not-real-0003"
    # ok: pathos.ai.python.llm-api-key-in-environment
    os.environ["LOG_LEVEL"] = "debug-level-verbose"
    return c1, c2, c3, c4
