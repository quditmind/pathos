import { describe, expect, it } from "vitest";
import {
  allowedStatusTargets,
  diagnosticLevel,
  diagnosticMessage,
  findingPathSegments,
  formatCwes,
  groupByFile,
  groupBySeverity,
  matchRepositories,
  normalizeRemoteUrl,
  parseGitConfigRemotes,
  severityRank,
  zeroBasedLine,
} from "../src/mapping";
import type { Finding, Repository } from "../src/types";

function finding(p: Partial<Finding> & { id: string }): Finding {
  return { repository_id: "r", title: p.id, severity: "medium", status: "open", ...p };
}

describe("normalizeRemoteUrl", () => {
  const want = "github.com/example-org/payments-api";
  it.each([
    "https://github.com/example-org/payments-api",
    "https://github.com/example-org/payments-api.git",
    "https://github.com/Example-Org/Payments-API/",
    "https://user:secret@github.com/example-org/payments-api.git",
    "https://GitHub.com:443/example-org/payments-api",
    "http://github.com/example-org/payments-api",
    "ssh://git@github.com/example-org/payments-api.git",
    "ssh://git@ssh.github.com:443/example-org/payments-api.git",
    "git+ssh://git@github.com/example-org/payments-api",
    "git://github.com/example-org/payments-api.git",
    "git@github.com:example-org/payments-api.git",
    "git@github.com:/example-org/payments-api.git",
    "github.com:example-org/payments-api",
  ])("%s", (url) => {
    expect(normalizeRemoteUrl(url)).toBe(want);
  });

  it("handles self-hosted GitLab with subgroups and ports", () => {
    expect(normalizeRemoteUrl("ssh://git@gitlab.example.com:2222/group/sub/repo.git")).toBe("gitlab.example.com/group/sub/repo");
    expect(normalizeRemoteUrl("https://gitlab.example.com/group/sub/repo")).toBe("gitlab.example.com/group/sub/repo");
  });

  it("unifies Azure DevOps variants", () => {
    const want = "dev.azure.com/org/project/repo";
    expect(normalizeRemoteUrl("https://dev.azure.com/org/project/_git/repo")).toBe(want);
    expect(normalizeRemoteUrl("https://org@dev.azure.com/org/project/_git/repo")).toBe(want);
    expect(normalizeRemoteUrl("git@ssh.dev.azure.com:v3/org/project/repo")).toBe(want);
    expect(normalizeRemoteUrl("https://org.visualstudio.com/project/_git/repo")).toBe(want);
    expect(normalizeRemoteUrl("https://org.visualstudio.com/DefaultCollection/project/_git/repo")).toBe(want);
  });

  it("rejects local paths and unknown schemes", () => {
    for (const bad of ["", "   ", "/srv/git/repo.git", "../repo", "file:///srv/git/repo.git", "C:\\repos\\x", "C:/repos/x", "https://github.com"]) {
      expect(normalizeRemoteUrl(bad), bad).toBeNull();
    }
    expect(normalizeRemoteUrl(undefined)).toBeNull();
  });
});

describe("matchRepositories", () => {
  const repos: Repository[] = [
    { id: "1", full_name: "example-org/payments-api", url: "https://github.com/example-org/payments-api" },
    { id: "2", full_name: "example-org/web", url: "https://github.com/example-org/web" },
    { id: "3", full_name: "example-org/payments-api", url: "https://gitlab.example.com/example-org/payments-api" },
    { id: "4", full_name: "team/uploaded", url: null, source_type: "upload" },
  ];

  it("matches by normalized URL", () => {
    const m = matchRepositories(["git@github.com:Example-Org/payments-api.git"], repos);
    expect(m.map((x) => [x.repository.id, x.by])).toEqual([["1", "url"]]);
  });

  it("falls back to the full name when no URL matches", () => {
    const m = matchRepositories(["git@mirror.internal:team/uploaded.git"], repos);
    expect(m.map((x) => [x.repository.id, x.by])).toEqual([["4", "name"]]);
  });

  it("returns several candidates for an ambiguous name", () => {
    const m = matchRepositories(["https://elsewhere.example.com/example-org/payments-api"], repos);
    expect(m.map((x) => x.repository.id).sort()).toEqual(["1", "3"]);
  });

  it("returns nothing without remotes or matches", () => {
    expect(matchRepositories([], repos)).toEqual([]);
    expect(matchRepositories(["/local/path"], repos)).toEqual([]);
    expect(matchRepositories(["https://github.com/other/thing"], repos)).toEqual([]);
  });
});

describe("parseGitConfigRemotes", () => {
  it("reads url and pushurl of every remote", () => {
    const cfg = `[core]
\trepositoryformatversion = 0
\turl = not-a-remote
[remote "origin"]
\turl = git@github.com:example-org/payments-api.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[remote "upstream"]
\turl = "https://github.com/upstream/payments-api"
\tpushurl = ssh://git@github.com/upstream/payments-api.git
# comment
[branch "main"]
\tremote = origin
`;
    expect(parseGitConfigRemotes(cfg)).toEqual([
      "git@github.com:example-org/payments-api.git",
      "https://github.com/upstream/payments-api",
      "ssh://git@github.com/upstream/payments-api.git",
    ]);
  });
});

describe("severity", () => {
  it("maps severities to diagnostic levels", () => {
    expect(diagnosticLevel("critical")).toBe("error");
    expect(diagnosticLevel("HIGH")).toBe("error");
    expect(diagnosticLevel("medium")).toBe("warning");
    expect(diagnosticLevel("low")).toBe("information");
    expect(diagnosticLevel("info")).toBe("hint");
    expect(diagnosticLevel("weird")).toBe("hint");
  });
  it("ranks critical first and unknown last", () => {
    expect(["info", "x", "critical", "low", "high", "medium"].sort((a, b) => severityRank(a) - severityRank(b))).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "info",
      "x",
    ]);
  });
  it("formats CWEs and messages", () => {
    expect(formatCwes(["79", "CWE-79", "cwe-89: SQL injection"])).toEqual(["CWE-79", "CWE-89"]);
    expect(formatCwes(null)).toEqual([]);
    expect(diagnosticMessage(finding({ id: "a", title: "SQL\ninjection", severity: "high", cwe: ["89"], risk_score: 81.6 }))).toBe(
      "[High] SQL injection (CWE-89) risk 82",
    );
  });
});

describe("paths and lines", () => {
  it("maps file paths to safe relative segments", () => {
    expect(findingPathSegments("src/app.ts")).toEqual(["src", "app.ts"]);
    expect(findingPathSegments("./src//app.ts")).toEqual(["src", "app.ts"]);
    expect(findingPathSegments("/src/app.ts")).toEqual(["src", "app.ts"]);
    expect(findingPathSegments("src\\win\\app.ts")).toEqual(["src", "win", "app.ts"]);
    for (const bad of [undefined, "", "  ", "../etc/passwd", "src/../../x", "C:/x/y", "https://x/y", "."]) {
      expect(findingPathSegments(bad), String(bad)).toBeNull();
    }
  });
  it("converts lines", () => {
    expect(zeroBasedLine(1)).toBe(0);
    expect(zeroBasedLine(42)).toBe(41);
    expect(zeroBasedLine(null)).toBe(0);
    expect(zeroBasedLine(0)).toBe(0);
    expect(zeroBasedLine(-5)).toBe(0);
  });
});

describe("status changes", () => {
  it("follows the documented transitions", () => {
    expect(allowedStatusTargets("open")).toEqual(["in_progress", "needs_review", "false_positive", "fixed"]);
    expect(allowedStatusTargets("needs_review")).toEqual(["open", "in_progress", "false_positive", "fixed"]);
    expect(allowedStatusTargets("fixed")).toEqual(["open"]);
    expect(allowedStatusTargets("accepted_risk")).toEqual([]);
  });
});

describe("grouping", () => {
  const fs = [
    finding({ id: "1", severity: "low", file_path: "b.ts", start_line: 5 }),
    finding({ id: "2", severity: "critical", file_path: "a.ts", start_line: 9 }),
    finding({ id: "3", severity: "critical", file_path: "./a.ts", start_line: 2 }),
    finding({ id: "4", severity: "high" }),
    finding({ id: "5", severity: "low", file_path: "a.ts", start_line: 1 }),
  ];

  it("groups by severity, then file", () => {
    const g = groupBySeverity(fs);
    expect(g.map((x) => [x.severity, x.count])).toEqual([
      ["critical", 2],
      ["high", 1],
      ["low", 2],
    ]);
    expect(g[0].files).toEqual([{ path: "a.ts", findings: [fs[2], fs[1]] }]);
    expect(g[1].files[0].path).toBe("");
    expect(g[2].files.map((f) => f.path)).toEqual(["a.ts", "b.ts"]);
  });

  it("groups by file with findings sorted by line, files without path last", () => {
    const g = groupByFile(fs);
    expect(g.map((x) => x.path)).toEqual(["a.ts", "b.ts", ""]);
    expect(g[0].findings.map((f) => f.id)).toEqual(["5", "3", "2"]);
  });
});
