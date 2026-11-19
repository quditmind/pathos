// "Findings" tree view: severity → file → finding, or file → finding.

import * as vscode from "vscode";
import { displayPath, groupByFile, groupBySeverity, severityLabel, type GroupingMode } from "./mapping";
import type { Finding } from "./types";

export type Node =
  | { kind: "severity"; severity: string; count: number; files: { path: string; findings: Finding[] }[] }
  | { kind: "file"; path: string; findings: Finding[]; parentKey: string }
  | { kind: "finding"; finding: Finding }
  | { kind: "message"; text: string };

const SEVERITY_ICONS: Record<string, [string, string]> = {
  critical: ["error", "errorForeground"],
  high: ["error", "list.errorForeground"],
  medium: ["warning", "list.warningForeground"],
  low: ["info", "notificationsInfoIcon.foreground"],
  info: ["circle-outline", "descriptionForeground"],
};

function severityIcon(severity: string): vscode.ThemeIcon {
  const [icon, color] = SEVERITY_ICONS[String(severity).toLowerCase()] ?? SEVERITY_ICONS.info;
  return new vscode.ThemeIcon(icon, new vscode.ThemeColor(color));
}

export interface TreeHost {
  /** Workspace file of a finding, when it exists locally. */
  resolveUri(f: Finding): vscode.Uri | undefined;
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<Node> {
  private readonly changed = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.changed.event;
  private findings: Finding[] = [];
  private message: string | undefined;

  constructor(
    private readonly host: TreeHost,
    private mode: GroupingMode,
  ) {}

  get grouping(): GroupingMode {
    return this.mode;
  }

  setGrouping(mode: GroupingMode): void {
    this.mode = mode;
    this.changed.fire(undefined);
  }

  setFindings(findings: Finding[], message?: string): void {
    this.findings = findings;
    this.message = message;
    this.changed.fire(undefined);
  }

  dispose(): void {
    this.changed.dispose();
  }

  getChildren(node?: Node): Node[] {
    if (!node) {
      const top: Node[] = this.message ? [{ kind: "message", text: this.message }] : [];
      if (this.mode === "file") {
        return top.concat(groupByFile(this.findings).map((g) => ({ kind: "file" as const, ...g, parentKey: "" })));
      }
      return top.concat(groupBySeverity(this.findings).map((g) => ({ kind: "severity" as const, ...g })));
    }
    if (node.kind === "severity") {
      return node.files.map((g) => ({ kind: "file" as const, ...g, parentKey: node.severity }));
    }
    if (node.kind === "file") {
      return node.findings.map((finding) => ({ kind: "finding" as const, finding }));
    }
    return [];
  }

  getTreeItem(node: Node): vscode.TreeItem {
    switch (node.kind) {
      case "message": {
        const item = new vscode.TreeItem(node.text, vscode.TreeItemCollapsibleState.None);
        item.iconPath = new vscode.ThemeIcon("info");
        return item;
      }
      case "severity": {
        const item = new vscode.TreeItem(severityLabel(node.severity), vscode.TreeItemCollapsibleState.Expanded);
        item.id = `sev:${node.severity}`;
        item.description = String(node.count);
        item.iconPath = severityIcon(node.severity);
        return item;
      }
      case "file": {
        const label = node.path || "(no file location)";
        const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Expanded);
        item.id = `file:${node.parentKey}:${node.path}`;
        item.description = String(node.findings.length);
        const uri = node.findings.length ? this.host.resolveUri(node.findings[0]) : undefined;
        if (uri) {
          item.resourceUri = uri;
          item.iconPath = vscode.ThemeIcon.File;
        } else {
          item.iconPath = new vscode.ThemeIcon(node.path ? "file" : "package");
        }
        return item;
      }
      case "finding": {
        const f = node.finding;
        const item = new vscode.TreeItem(f.title || "Untitled finding", vscode.TreeItemCollapsibleState.None);
        item.id = `finding:${f.id}`;
        const bits: string[] = [];
        if (f.start_line) bits.push(`line ${f.start_line}`);
        if (this.mode === "file") bits.push(severityLabel(f.severity));
        if (typeof f.risk_score === "number") bits.push(`risk ${Math.round(f.risk_score)}`);
        item.description = bits.join(" · ");
        // Plain string tooltip: scanner text is untrusted and never rendered as Markdown.
        const path = displayPath(f.file_path);
        item.tooltip = [
          f.title,
          `${severityLabel(f.severity)}${f.rule_id ? ` · ${f.rule_id}` : ""}`,
          path ? `${path}${f.start_line ? `:${f.start_line}` : ""}` : "",
        ]
          .filter(Boolean)
          .join("\n");
        item.iconPath = severityIcon(f.severity);
        item.contextValue = "pathosFinding";
        item.command = { command: "pathos.openFinding", title: "Open", arguments: [node] };
        return item;
      }
    }
  }
}
