// Test fixture for workers/rules/pathos-ai.yml (TypeScript). Not executed.
// The API keys below are obviously fake fixture values.
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import { createOpenAI } from "@ai-sdk/openai";
import { generateText } from "ai";
import { execSync } from "child_process";

const SYSTEM = "You are a support assistant. Answer only questions about orders.";

export async function prompts(client: OpenAI, userName: string, doc: string, question: string) {
  // ok: pathos.ai.javascript.dynamic-system-prompt
  const ok = [{ role: "system", content: SYSTEM }, { role: "user", content: question }];
  // ruleid: pathos.ai.javascript.dynamic-system-prompt
  const bad = [{ role: "system", content: `You help ${userName}. Context: ${doc}` }];
  const anthropic = new Anthropic();
  // ruleid: pathos.ai.javascript.dynamic-system-prompt
  const r = await anthropic.messages.create({ model: "m", max_tokens: 100, system: "Rules: " + doc, messages: [] });
  return [ok, bad, r];
}

export async function runTool(client: OpenAI, db: any, question: string) {
  const resp = await client.chat.completions.create({ model: "m", messages: [{ role: "user", content: question }] });
  const code = resp.choices[0].message.content ?? "";
  // ruleid: pathos.ai.javascript.llm-output-execution
  eval(code);
  const args = JSON.parse(resp.choices[0].message.tool_calls![0].function.arguments);
  // ruleid: pathos.ai.javascript.llm-output-execution
  execSync(args.command);
  // ruleid: pathos.ai.javascript.llm-output-execution
  await db.query(args.sql);
  // ok: pathos.ai.javascript.llm-output-execution
  await db.query("SELECT name FROM products WHERE id = $1", [args.id]);
  const { text } = await generateText({ model: "m", prompt: question });
  // ruleid: pathos.ai.javascript.llm-output-execution
  new Function(text)();
  // ok: pathos.ai.javascript.llm-output-execution
  console.log(text);
}

export function clients() {
  // ruleid: pathos.ai.javascript.hardcoded-llm-api-key
  const a = new OpenAI({ apiKey: "fixture-llm-key-not-real-0004" });
  // ruleid: pathos.ai.javascript.hardcoded-llm-api-key
  const b = createOpenAI({ apiKey: "fixture-llm-key-not-real-0005" });
  // ok: pathos.ai.javascript.hardcoded-llm-api-key
  const c = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  // ok: pathos.ai.javascript.hardcoded-llm-api-key
  const d = new OpenAI({ apiKey: "your-api-key-here" });
  return [a, b, c, d];
}
