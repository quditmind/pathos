// Activation and wiring. Kept thin: API, mapping and HTML building live in
// pure modules that are unit-tested without VS Code.

import { randomBytes } from "node:crypto";
import * as vscode from "vscode";
import { describeError, findingWebUrl, PathosApiError, PathosClient, PathosConfigError, validateBaseUrl } from "./api";
import { readSettings, TokenStore } from "./config";
import { buildDetailsHtml } from "./details";
import {
  allowedStatusTargets,
  diagnosticLevel,
  diagnosticMessage,
  displayPath,
  findingPathSegments,
  matchRepositories,
  MIN_REASON_LENGTH,
  parseGitConfigRemotes,
  severityLabel,
  statusNeedsReason,
  zeroBasedLine,
  type GroupingMode,
} from "./mapping";
import { FindingsTreeProvider, type Node } from "./tree";
import type { Finding, FindingStatus, Repository } from "./types";

const REPO_KEY = "pathos.repository";
const GROUPING_KEY = "pathos.grouping";

interface StoredRepository {
  baseUrl: string;
  id: string;
  fullName: string;
  /** Workspace folder the finding paths are relative to. */
  folder?: string;
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  needs_review: "Needs review",
  false_positive: "False positive",
  fixed: "Fixed",
};

// Minimal subset of the vscode.git extension API (version 1).
interface GitRemote {
  fetchUrl?: string;
  pushUrl?: string;
}
interface GitRepository {
  rootUri: vscode.Uri;
  state: { remotes: GitRemote[] };
}
interface GitApi {
  repositories: GitRepository[];
}

class PathosExtension implements vscode.Disposable {
  private readonly log = vscode.window.createOutputChannel("PATHOS", { log: true });
  private readonly diagnostics = vscode.languages.createDiagnosticCollection("pathos");
  private readonly tokens: TokenStore;
  private readonly tree: FindingsTreeProvider;
  private readonly view: vscode.TreeView<Node>;
  private readonly status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  private readonly disposables: vscode.Disposable[] = [];
  private findings: Finding[] = [];
  private uris = new Map<string, vscode.Uri>();
  private byFile = new Map<string, Finding[]>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private refreshing: Promise<void> | undefined;
  private refreshAgain = false;
  private panel: vscode.WebviewPanel | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.tokens = new TokenStore(context.secrets);
    const grouping = context.workspaceState.get<GroupingMode>(GROUPING_KEY) === "file" ? "file" : "severity";
    this.tree = new FindingsTreeProvider({ resolveUri: (f) => this.uris.get(f.id) }, grouping);
    this.view = vscode.window.createTreeView("pathos.findings", { treeDataProvider: this.tree, showCollapseAll: true });
    this.status.command = "pathos.refresh";
    this.status.name = "PATHOS";
    this.disposables.push(this.log, this.diagnostics, this.tree, this.view, this.status);
  }

  activate(): void {
    const cmd = (id: string, fn: (...args: unknown[]) => unknown) =>
      this.disposables.push(vscode.commands.registerCommand(id, fn));
    cmd("pathos.setToken", () => this.setToken());
    cmd("pathos.clearToken", () => this.clearToken());
    cmd("pathos.selectRepository", () => this.selectRepository(true));
    cmd("pathos.refresh", () => this.refresh(true));
    cmd("pathos.toggleGrouping", () => this.toggleGrouping());
    cmd("pathos.openFinding", (arg) => this.openFinding(arg));
    cmd("pathos.showDetails", (arg) => this.showDetails(arg));
    cmd("pathos.openInPathos", (arg) => this.openInPathos(arg));
    cmd("pathos.requestReview", (arg) => this.requestReview(arg));
    cmd("pathos.changeStatus", (arg) => this.changeStatus(arg));

    this.disposables.push(
      vscode.languages.registerCodeActionsProvider({ scheme: "file" }, this.codeActions(), {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
      }),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration("pathos.url")) {
          this.clearFindings();
          void this.updateContext().then(() => this.refresh(false));
        }
        if (e.affectsConfiguration("pathos.refreshIntervalMinutes")) this.scheduleRefresh();
        if (e.affectsConfiguration("pathos.maxFindings")) void this.refresh(false);
      }),
      vscode.workspace.onDidChangeWorkspaceFolders(() => void this.refresh(false)),
    );
    this.scheduleRefresh();
    void this.updateContext().then(() => this.refresh(false));
  }

  dispose(): void {
    if (this.timer) clearInterval(this.timer);
    this.panel?.dispose();
    for (const d of this.disposables) d.dispose();
  }

  // -------------------------------------------------------------------------
  // Configuration and token

  private baseUrlOrUndefined(): string | undefined {
    try {
      return validateBaseUrl(readSettings().url);
    } catch {
      return undefined;
    }
  }

  private async updateContext(): Promise<void> {
    const base = this.baseUrlOrUndefined();
    const token = base ? await this.tokens.get(base) : undefined;
    await vscode.commands.executeCommand("setContext", "pathos.configured", !!(base && token));
    await vscode.commands.executeCommand("setContext", "pathos.urlSet", !!base);
  }

  /** A client, or undefined (with a message when interactive) if not configured. */
  private async client(interactive: boolean): Promise<PathosClient | undefined> {
    const settings = readSettings();
    let base: string;
    try {
      base = validateBaseUrl(settings.url);
    } catch (e) {
      if (interactive || settings.url) {
        const open = "Open settings";
        void vscode.window.showWarningMessage(describeError(e), open).then((c) => {
          if (c === open) void vscode.commands.executeCommand("workbench.action.openSettings", "pathos.url");
        });
      }
      return undefined;
    }
    const token = await this.tokens.get(base);
    if (!token) {
      if (interactive) {
        const set = "Set API token";
        const c = await vscode.window.showWarningMessage(`No PATHOS API token is set for ${base}.`, set);
        if (c === set) return (await this.setToken()) ? this.client(false) : undefined;
      }
      return undefined;
    }
    try {
      return new PathosClient({ baseUrl: base, token, fetch: (i, init) => fetch(i, init), timeoutMs: 30_000 });
    } catch (e) {
      if (interactive) void vscode.window.showErrorMessage(describeError(e));
      return undefined;
    }
  }

  private async setToken(): Promise<boolean> {
    let base: string;
    try {
      base = validateBaseUrl(readSettings().url);
    } catch (e) {
      const open = "Open settings";
      const c = await vscode.window.showWarningMessage(`${describeError(e)} Set pathos.url first.`, open);
      if (c === open) void vscode.commands.executeCommand("workbench.action.openSettings", "pathos.url");
      return false;
    }
    const token = await vscode.window.showInputBox({
      title: "PATHOS API token",
      prompt: `Paste a PATHOS REST API token for ${base} (user menu → API tokens (MCP): "REST API: read" to view findings, "read and write" to change status or request reviews). It is stored in the OS keychain.`,
      password: true,
      ignoreFocusOut: true,
      placeHolder: "pathos_pat_…",
      validateInput: (v) => (!v.trim() ? "Enter the token" : /\s/.test(v.trim()) ? "The token must not contain spaces" : undefined),
    });
    if (!token) return false;
    await this.tokens.set(base, token.trim());
    this.log.info(`API token stored for ${base}`);
    await this.updateContext();
    void this.refresh(true);
    return true;
  }

  private async clearToken(): Promise<void> {
    const base = this.baseUrlOrUndefined();
    if (!base) {
      void vscode.window.showInformationMessage("pathos.url is not set; there is no token to clear.");
      return;
    }
    await this.tokens.clear(base);
    this.clearFindings();
    await this.updateContext();
    void vscode.window.showInformationMessage(`PATHOS API token for ${base} removed.`);
  }

  // -------------------------------------------------------------------------
  // Repository selection

  private storedRepository(base: string): StoredRepository | undefined {
    const r = this.context.workspaceState.get<StoredRepository>(REPO_KEY);
    return r && r.baseUrl === base && r.id ? r : undefined;
  }

  private async rememberRepository(base: string, repo: Repository, folder?: vscode.WorkspaceFolder): Promise<StoredRepository> {
    const stored: StoredRepository = { baseUrl: base, id: repo.id, fullName: repo.full_name, folder: folder?.uri.toString() };
    await this.context.workspaceState.update(REPO_KEY, stored);
    await vscode.commands.executeCommand("setContext", "pathos.hasRepository", true);
    return stored;
  }

  private async gitApi(): Promise<GitApi | undefined> {
    try {
      const ext = vscode.extensions.getExtension<{ getAPI(v: 1): GitApi }>("vscode.git");
      if (!ext) return undefined;
      const exports = ext.isActive ? ext.exports : await ext.activate();
      return exports?.getAPI(1);
    } catch {
      return undefined;
    }
  }

  /** Remote URLs of a workspace folder: vscode.git first, .git/config as fallback. */
  private async remotesOf(folder: vscode.WorkspaceFolder, git: GitApi | undefined): Promise<string[]> {
    const urls = new Set<string>();
    const root = folder.uri.toString().replace(/\/$/, "");
    for (const repo of git?.repositories ?? []) {
      const r = repo.rootUri.toString().replace(/\/$/, "");
      if (r === root || root.startsWith(r + "/") || r.startsWith(root + "/")) {
        for (const rem of repo.state.remotes) {
          if (rem.fetchUrl) urls.add(rem.fetchUrl);
          if (rem.pushUrl) urls.add(rem.pushUrl);
        }
      }
    }
    if (urls.size === 0) for (const u of await this.readGitConfig(folder.uri)) urls.add(u);
    return [...urls];
  }

  private async readGitConfig(folder: vscode.Uri): Promise<string[]> {
    const fs = vscode.workspace.fs;
    const text = async (u: vscode.Uri) => new TextDecoder().decode(await fs.readFile(u));
    try {
      let gitDir = vscode.Uri.joinPath(folder, ".git");
      const st = await fs.stat(gitDir);
      if (st.type & vscode.FileType.File) {
        // Worktree or submodule: ".git" is a file "gitdir: <path>".
        const m = /^gitdir:\s*(.+)$/m.exec(await text(gitDir));
        if (!m || folder.scheme !== "file") return [];
        const p = m[1].trim();
        gitDir = /^([a-zA-Z]:)?[\\/]/.test(p) ? vscode.Uri.file(p) : vscode.Uri.joinPath(folder, p);
        try {
          const common = (await text(vscode.Uri.joinPath(gitDir, "commondir"))).trim();
          if (common) gitDir = /^([a-zA-Z]:)?[\\/]/.test(common) ? vscode.Uri.file(common) : vscode.Uri.joinPath(gitDir, common);
        } catch {
          // not a worktree
        }
      }
      return parseGitConfigRemotes(await text(vscode.Uri.joinPath(gitDir, "config")));
    } catch {
      return [];
    }
  }

  /**
   * Detects the repository from the git remotes of the workspace folders.
   * Interactive: always lets the user confirm or pick manually.
   */
  private async selectRepository(interactive: boolean): Promise<StoredRepository | undefined> {
    const client = await this.client(interactive);
    if (!client) return undefined;
    let repos: Repository[];
    try {
      repos = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Window, title: "PATHOS: loading repositories" },
        () => client.listRepositories(),
      );
    } catch (e) {
      this.reportError(e, "Loading repositories", interactive);
      return undefined;
    }
    const folders = vscode.workspace.workspaceFolders ?? [];
    const git = await this.gitApi();
    const matches: { repo: Repository; folder: vscode.WorkspaceFolder; by: string }[] = [];
    for (const folder of folders) {
      const remotes = await this.remotesOf(folder, git);
      this.log.debug(`${folder.name}: ${remotes.length} git remote(s)`);
      for (const m of matchRepositories(remotes, repos)) {
        if (!matches.some((x) => x.repo.id === m.repository.id)) matches.push({ repo: m.repository, folder, by: m.by });
      }
    }
    if (!interactive) {
      if (matches.length === 1) {
        this.log.info(`Detected PATHOS repository ${matches[0].repo.full_name} (matched by ${matches[0].by})`);
        return this.rememberRepository(client.baseUrl, matches[0].repo, matches[0].folder);
      }
      if (matches.length === 0 && repos.length > 0 && folders.length > 0) {
        this.tree.setFindings([], "No PATHOS repository matches this workspace's git remote. Use “Select repository”.");
      } else if (matches.length > 1) {
        this.tree.setFindings([], "Several PATHOS repositories match this workspace. Use “Select repository”.");
      }
      return undefined;
    }

    type Item = vscode.QuickPickItem & { repo?: Repository; folder?: vscode.WorkspaceFolder };
    const matchedIds = new Set(matches.map((m) => m.repo.id));
    const items: Item[] = [];
    if (matches.length) {
      items.push({ label: "Detected from git remote", kind: vscode.QuickPickItemKind.Separator });
      for (const m of matches) items.push(this.repoItem(m.repo, m.folder));
      items.push({ label: "All repositories", kind: vscode.QuickPickItemKind.Separator });
    }
    for (const r of repos) if (!matchedIds.has(r.id)) items.push(this.repoItem(r));
    if (items.length === 0) {
      void vscode.window.showInformationMessage("Your PATHOS account cannot see any repositories.");
      return undefined;
    }
    const picked = await vscode.window.showQuickPick(items, {
      title: "PATHOS: select repository",
      placeHolder: "Repository whose findings are shown for this workspace",
      matchOnDescription: true,
      matchOnDetail: true,
    });
    if (!picked?.repo) return undefined;
    let folder = picked.folder;
    if (!folder && folders.length === 1) folder = folders[0];
    if (!folder && folders.length > 1) {
      folder = await vscode.window.showWorkspaceFolderPick({ placeHolder: "Workspace folder that contains this repository" });
    }
    const stored = await this.rememberRepository(client.baseUrl, picked.repo, folder);
    void this.refresh(true);
    return stored;
  }

  private repoItem(r: Repository, folder?: vscode.WorkspaceFolder): vscode.QuickPickItem & { repo: Repository; folder?: vscode.WorkspaceFolder } {
    return {
      label: r.full_name,
      description: [r.display_name, r.repository_key].filter(Boolean).join(" · "),
      detail: r.url ?? undefined,
      repo: r,
      folder,
    };
  }

  // -------------------------------------------------------------------------
  // Findings, diagnostics, tree

  private scheduleRefresh(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    const minutes = readSettings().refreshIntervalMinutes;
    if (minutes > 0) this.timer = setInterval(() => void this.refresh(false), minutes * 60_000);
  }

  private refresh(interactive: boolean): Promise<void> {
    if (this.refreshing) {
      this.refreshAgain = true;
      return this.refreshing;
    }
    this.refreshing = this.doRefresh(interactive).finally(() => {
      this.refreshing = undefined;
      if (this.refreshAgain) {
        this.refreshAgain = false;
        void this.refresh(false);
      }
    });
    return this.refreshing;
  }

  private async doRefresh(interactive: boolean): Promise<void> {
    const client = await this.client(interactive);
    if (!client) {
      this.clearFindings();
      return;
    }
    let repo = this.storedRepository(client.baseUrl);
    await vscode.commands.executeCommand("setContext", "pathos.hasRepository", !!repo);
    if (!repo) {
      repo = await this.selectRepository(false);
      if (!repo) {
        if (interactive) {
          const pick = "Select repository";
          const c = await vscode.window.showInformationMessage("No PATHOS repository is selected for this workspace.", pick);
          if (c === pick) await this.selectRepository(true);
        }
        return;
      }
    }
    const settings = readSettings();
    this.status.text = "$(sync~spin) PATHOS";
    this.status.show();
    try {
      const page = await vscode.window.withProgress(
        { location: { viewId: "pathos.findings" }, title: "PATHOS: loading findings" },
        () => client.listOpenFindings(repo.id, settings.maxFindings),
      );
      const folder = this.folderFor(repo);
      await this.publish(page.items, folder, client.baseUrl);
      const note = page.truncated ? `Showing the first ${page.items.length} findings (pathos.maxFindings).` : undefined;
      this.tree.setFindings(page.items, note);
      this.view.description = repo.fullName;
      this.view.message = page.items.length === 0 ? `No open findings in ${repo.fullName}.` : undefined;
      this.status.text = `$(shield) PATHOS ${page.items.length}`;
      this.status.tooltip = `${repo.fullName}: ${page.items.length} open finding(s). Click to refresh.`;
      this.log.info(`Loaded ${page.items.length} open finding(s) of ${repo.fullName}${page.truncated ? " (truncated)" : ""}`);
    } catch (e) {
      this.status.text = "$(warning) PATHOS";
      this.status.tooltip = describeError(e, "Loading findings");
      if (e instanceof PathosApiError && e.kind === "not_found") {
        // Repository deleted or no longer visible: forget it.
        await this.context.workspaceState.update(REPO_KEY, undefined);
        this.clearFindings();
      }
      this.reportError(e, "Loading findings", interactive);
    }
  }

  private folderFor(repo: StoredRepository): vscode.WorkspaceFolder | undefined {
    const folders = vscode.workspace.workspaceFolders ?? [];
    return folders.find((f) => f.uri.toString() === repo.folder) ?? (folders.length === 1 ? folders[0] : undefined);
  }

  private async publish(findings: Finding[], folder: vscode.WorkspaceFolder | undefined, base: string): Promise<void> {
    this.findings = findings;
    const uris = new Map<string, vscode.Uri>();
    if (folder) {
      const exists = new Map<string, Promise<boolean>>();
      const check = (u: vscode.Uri) => {
        const k = u.toString();
        let p = exists.get(k);
        if (!p) {
          p = Promise.resolve(vscode.workspace.fs.stat(u)).then(
            (s) => (s.type & vscode.FileType.File) !== 0,
            () => false,
          );
          exists.set(k, p);
        }
        return p;
      };
      await Promise.all(
        findings.map(async (f) => {
          const segs = findingPathSegments(f.file_path);
          if (!segs) return;
          const uri = vscode.Uri.joinPath(folder.uri, ...segs);
          if (await check(uri)) uris.set(f.id, uri);
        }),
      );
    }
    this.uris = uris;
    const byUri = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[]; findings: Finding[] }>();
    for (const f of findings) {
      const uri = uris.get(f.id);
      if (!uri) continue;
      const line = zeroBasedLine(f.start_line);
      const d = new vscode.Diagnostic(new vscode.Range(line, 0, line, 10_000), diagnosticMessage(f), toVsSeverity(f.severity));
      d.source = "PATHOS";
      d.code = { value: f.rule_id || f.id, target: vscode.Uri.parse(findingWebUrl(base, f.id)) };
      const k = uri.toString();
      const entry = byUri.get(k) ?? { uri, diags: [], findings: [] };
      entry.diags.push(d);
      entry.findings.push(f);
      byUri.set(k, entry);
    }
    this.diagnostics.clear();
    this.byFile = new Map();
    for (const [k, e] of byUri) {
      this.diagnostics.set(e.uri, e.diags);
      this.byFile.set(k, e.findings);
    }
  }

  private clearFindings(): void {
    this.findings = [];
    this.uris = new Map();
    this.byFile = new Map();
    this.diagnostics.clear();
    this.tree.setFindings([]);
    this.view.description = undefined;
    this.view.message = undefined;
    this.status.hide();
  }

  private async toggleGrouping(): Promise<void> {
    const next: GroupingMode = this.tree.grouping === "severity" ? "file" : "severity";
    this.tree.setGrouping(next);
    await this.context.workspaceState.update(GROUPING_KEY, next);
  }

  private codeActions(): vscode.CodeActionProvider {
    return {
      provideCodeActions: (doc, range) => {
        const list = this.byFile.get(doc.uri.toString()) ?? [];
        const actions: vscode.CodeAction[] = [];
        for (const f of list) {
          const line = zeroBasedLine(f.start_line);
          if (line < range.start.line || line > range.end.line) continue;
          const short = (f.title || "finding").slice(0, 60);
          const details = new vscode.CodeAction(`PATHOS: Show details of “${short}”`, vscode.CodeActionKind.QuickFix);
          details.command = { command: "pathos.showDetails", title: "Show details", arguments: [f] };
          const open = new vscode.CodeAction(`PATHOS: Open “${short}” in PATHOS`, vscode.CodeActionKind.QuickFix);
          open.command = { command: "pathos.openInPathos", title: "Open in PATHOS", arguments: [f] };
          actions.push(details, open);
        }
        return actions;
      },
    };
  }

  // -------------------------------------------------------------------------
  // Finding commands

  /** The finding of a tree node or code action argument, or a quick pick. */
  private async findingArg(arg: unknown, title: string): Promise<Finding | undefined> {
    if (arg && typeof arg === "object") {
      const a = arg as { kind?: string; finding?: Finding; id?: string };
      if (a.kind === "finding" && a.finding) return a.finding;
      if (typeof a.id === "string" && "severity" in a) return a as Finding;
    }
    if (this.findings.length === 0) {
      void vscode.window.showInformationMessage("No PATHOS findings are loaded. Run “PATHOS: Refresh findings” first.");
      return undefined;
    }
    const active = vscode.window.activeTextEditor;
    const activeKey = active?.document.uri.toString();
    const items = this.findings.map((f) => {
      const p = displayPath(f.file_path);
      return {
        label: f.title || "Untitled finding",
        description: `${severityLabel(f.severity)}${p ? ` · ${p}${f.start_line ? `:${f.start_line}` : ""}` : ""}`,
        f,
        here: activeKey !== undefined && this.uris.get(f.id)?.toString() === activeKey,
      };
    });
    items.sort((a, b) => Number(b.here) - Number(a.here));
    const picked = await vscode.window.showQuickPick(items, { title, matchOnDescription: true });
    return picked?.f;
  }

  private async openFinding(arg: unknown): Promise<void> {
    const f = await this.findingArg(arg, "PATHOS: open finding");
    if (!f) return;
    const uri = this.uris.get(f.id);
    if (!uri) return this.showDetails(f);
    const line = zeroBasedLine(f.start_line);
    const pos = new vscode.Position(line, 0);
    await vscode.window.showTextDocument(uri, { selection: new vscode.Range(pos, pos), preview: true });
  }

  private async openInPathos(arg: unknown): Promise<void> {
    const f = await this.findingArg(arg, "PATHOS: open finding in PATHOS");
    const base = this.baseUrlOrUndefined();
    if (!f || !base) return;
    await vscode.env.openExternal(vscode.Uri.parse(findingWebUrl(base, f.id)));
  }

  private async showDetails(arg: unknown): Promise<void> {
    let f = await this.findingArg(arg, "PATHOS: finding details");
    const base = this.baseUrlOrUndefined();
    if (!f || !base) return;
    const client = await this.client(false);
    if (client) {
      try {
        f = await client.getFinding(f.id); // adds the code snippet
      } catch (e) {
        this.log.warn(`Could not load finding details: ${describeError(e)}`);
      }
    }
    if (!this.panel) {
      this.panel = vscode.window.createWebviewPanel("pathos.finding", "PATHOS finding", vscode.ViewColumn.Beside, {
        enableScripts: false,
        enableCommandUris: false,
        enableForms: false,
        localResourceRoots: [],
      });
      this.panel.onDidDispose(() => (this.panel = undefined));
    }
    this.panel.title = `PATHOS: ${(f.title || "finding").slice(0, 40)}`;
    this.panel.webview.html = buildDetailsHtml(f, { webUrl: findingWebUrl(base, f.id), nonce: randomBytes(16).toString("base64") });
    this.panel.reveal(undefined, true);
  }

  private async changeStatus(arg: unknown): Promise<void> {
    const f = await this.findingArg(arg, "PATHOS: change finding status");
    if (!f) return;
    const targets = allowedStatusTargets(f.status);
    if (targets.length === 0) {
      void vscode.window.showInformationMessage(
        f.status === "accepted_risk"
          ? "Accepted risk can only be changed through a risk acceptance in PATHOS."
          : `The status ${f.status} cannot be changed manually.`,
      );
      return;
    }
    const picked = await vscode.window.showQuickPick(
      targets.map((s) => ({
        label: STATUS_LABELS[s],
        description: statusNeedsReason(s) ? "reason required" : undefined,
        status: s,
      })),
      { title: `Change status of “${f.title}” (now ${f.status.replace(/_/g, " ")})` },
    );
    if (!picked) return;
    const required = statusNeedsReason(picked.status);
    const reason = await vscode.window.showInputBox({
      title: `Reason for ${picked.label.toLowerCase()}`,
      prompt: required ? `Required, at least ${MIN_REASON_LENGTH} characters. Recorded in the status history.` : "Optional. Recorded in the status history.",
      ignoreFocusOut: true,
      validateInput: (v) =>
        required && v.trim().length < MIN_REASON_LENGTH ? `Enter at least ${MIN_REASON_LENGTH} characters` : v.length > 4000 ? "At most 4000 characters" : undefined,
    });
    if (reason === undefined) return;
    const client = await this.client(true);
    if (!client) return;
    try {
      await client.changeStatus(f.id, picked.status, reason);
      void vscode.window.showInformationMessage(`Status changed to ${picked.label.toLowerCase()}.`);
      void this.refresh(false);
    } catch (e) {
      this.reportError(e, "Changing the status", true);
    }
  }

  private async requestReview(arg: unknown): Promise<void> {
    const f = await this.findingArg(arg, "PATHOS: request Human Eye review");
    if (!f) return;
    const reason = await vscode.window.showInputBox({
      title: `Request a Human Eye review of “${f.title}”`,
      prompt: "Optional reason for the reviewers",
      ignoreFocusOut: true,
      validateInput: (v) => (v.length > 2000 ? "At most 2000 characters" : undefined),
    });
    if (reason === undefined) return;
    const client = await this.client(true);
    if (!client) return;
    try {
      const res = await client.requestHumanReview(f.id, reason);
      void vscode.window.showInformationMessage(
        res.created.length ? "Human Eye review requested." : "This finding already has a Human Eye review.",
      );
      void this.refresh(false);
    } catch (e) {
      this.reportError(e, "Requesting a review", true);
    }
  }

  // -------------------------------------------------------------------------

  private reportError(e: unknown, action: string, interactive: boolean): void {
    const msg = describeError(e, action);
    const rid = e instanceof PathosApiError && e.requestId ? ` (request ${e.requestId})` : "";
    this.log.error(`${action}: ${e instanceof Error ? e.message : String(e)}${rid}`);
    const unauthorized = e instanceof PathosApiError && e.kind === "unauthorized";
    if (!interactive && !unauthorized && !(e instanceof PathosConfigError)) return;
    if (unauthorized || (e instanceof PathosApiError && e.kind === "read_only")) {
      const set = "Set API token";
      void vscode.window.showErrorMessage(msg, set).then((c) => {
        if (c === set) void this.setToken();
      });
      return;
    }
    void vscode.window.showErrorMessage(msg);
  }
}

function toVsSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (diagnosticLevel(severity)) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const ext = new PathosExtension(context);
  context.subscriptions.push(ext);
  ext.activate();
}

export function deactivate(): void {
  // Disposables are released through context.subscriptions.
}
