// Settings and the API token. The token lives only in VS Code SecretStorage
// (the OS keychain), keyed by the PATHOS origin so a token is never sent to
// a different server after pathos.url changes.

import * as vscode from "vscode";
import { validateBaseUrl } from "./api";

export const SECTION = "pathos";

export interface Settings {
  /** Raw pathos.url (validated later). */
  url: string;
  refreshIntervalMinutes: number;
  maxFindings: number;
}

export function readSettings(): Settings {
  const c = vscode.workspace.getConfiguration(SECTION);
  const interval = Number(c.get<number>("refreshIntervalMinutes", 0));
  const max = Number(c.get<number>("maxFindings", 5000));
  return {
    url: String(c.get<string>("url", "") ?? "").trim(),
    refreshIntervalMinutes: Number.isFinite(interval) && interval > 0 ? Math.min(interval, 1440) : 0,
    maxFindings: Number.isFinite(max) && max > 0 ? Math.min(Math.floor(max), 20_000) : 5000,
  };
}

function secretKey(baseUrl: string): string {
  return `pathos.apiToken:${baseUrl}`;
}

export class TokenStore {
  constructor(private readonly secrets: vscode.SecretStorage) {}

  async get(baseUrl: string): Promise<string | undefined> {
    return (await this.secrets.get(secretKey(validateBaseUrl(baseUrl)))) || undefined;
  }

  async set(baseUrl: string, token: string): Promise<void> {
    await this.secrets.store(secretKey(validateBaseUrl(baseUrl)), token);
  }

  async clear(baseUrl: string): Promise<void> {
    await this.secrets.delete(secretKey(validateBaseUrl(baseUrl)));
  }
}
