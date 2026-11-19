import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronDown, ChevronRight, Grid3x3 } from "lucide-react";
import type { ScanTypeCoverage } from "@/api/types";
import { Alert, Badge, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { categoryName } from "@/lib/findingCategories";
import { useScanTypes } from "./api";

type Filter = "" | "runnable" | "import-only" | "none";

function status(t: ScanTypeCoverage): { tone: "success" | "warning" | "neutral"; label: string } {
  if (t.runnable) return { tone: "success", label: t.runnable_tools === 1 ? "1 tool runnable" : `${t.runnable_tools} tools runnable` };
  if (t.importable) return { tone: "warning", label: "Import only" };
  return { tone: "neutral", label: "Generic import only" };
}

function matches(t: ScanTypeCoverage, f: Filter): boolean {
  switch (f) {
    case "runnable":
      return t.runnable;
    case "import-only":
      return !t.runnable && t.importable;
    case "none":
      return !t.runnable && !t.importable;
  }
  return true;
}

/**
 * Scan coverage: the 25 scan types, the tools that cover each, which of
 * them a live worker of this deployment can run, and the import formats
 * that carry their results (GET /api/v1/scan-types).
 */
export function ScanCoveragePage() {
  const q = useScanTypes();
  const [filter, setFilter] = useState<Filter>("");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const items = q.data?.items ?? [];
  const rows = items.filter((t) => matches(t, filter));
  const runnable = items.filter((t) => t.runnable).length;
  const importOnly = items.filter((t) => !t.runnable && t.importable).length;

  return (
    <>
      <PageHeader
        title="Scan coverage"
        description="The scan types PATHOS reports on, the tools that cover each, which of them an online worker can run in this deployment, and the formats you can import results in."
      />
      {q.error && <div className="mb-3"><Alert>{q.error.message}</Alert></div>}
      {q.isPending ? <Skeleton className="h-64" /> : !items.length ? (
        <Card><EmptyState icon={<Grid3x3 />} title="No scan types" /></Card>
      ) : (
        <>
          <div className="mb-3 grid gap-3 sm:grid-cols-3">
            <Card className="p-4"><div className="text-[12px] text-muted-foreground">Runnable now</div><div className="text-xl font-semibold">{runnable} of {items.length}</div><div className="text-[12px] text-muted-foreground">scan types with a tool on an online worker</div></Card>
            <Card className="p-4"><div className="text-[12px] text-muted-foreground">Import only</div><div className="text-xl font-semibold">{importOnly}</div><div className="text-[12px] text-muted-foreground">results importable in a dedicated format</div></Card>
            <Card className="p-4"><div className="text-[12px] text-muted-foreground">Workers online</div><div className="text-xl font-semibold">{q.data?.workers_online ?? 0}</div><div className="text-[12px] text-muted-foreground"><Link to="/configurations/scanners" className="underline">Scanners &amp; workers</Link></div></Card>
          </div>
          <Card>
            <div className="flex items-center justify-between gap-2 border-b border-border p-3">
              <span className="text-[12px] text-muted-foreground">
                Generic formats for every type: {(q.data?.generic_import_formats ?? []).map((f) => f.label).join(", ") || "none"}
              </span>
              <Select aria-label="Filter scan types" value={filter} onChange={(e) => setFilter(e.target.value as Filter)}>
                <option value="">All {items.length} scan types</option>
                <option value="runnable">Runnable now</option>
                <option value="import-only">Import only</option>
                <option value="none">Generic import only</option>
              </Select>
            </div>
            <Table>
              <thead>
                <tr><Th>Scan type</Th><Th>Finding categories</Th><Th>Tools</Th><Th>Import formats</Th><Th>Status</Th></tr>
              </thead>
              <tbody>
                {rows.map((t) => {
                  const st = status(t);
                  const expanded = !!open[t.id];
                  return (
                    <ScanTypeRows key={t.id} t={t} expanded={expanded} st={st} toggle={() => setOpen((o) => ({ ...o, [t.id]: !o[t.id] }))} />
                  );
                })}
              </tbody>
            </Table>
          </Card>
        </>
      )}
    </>
  );
}

function ScanTypeRows({ t, expanded, st, toggle }: { t: ScanTypeCoverage; expanded: boolean; st: ReturnType<typeof status>; toggle: () => void }) {
  return (
    <>
      <tr>
        <Td>
          <button type="button" className="flex items-start gap-1 text-left" onClick={toggle} aria-expanded={expanded} aria-label={`${t.name} details`}>
            {expanded ? <ChevronDown className="mt-0.5 size-3.5 shrink-0" /> : <ChevronRight className="mt-0.5 size-3.5 shrink-0" />}
            <span>
              <span className="font-medium">{t.name}</span>
              <span className="block text-[12px] text-muted-foreground">{t.description}</span>
            </span>
          </button>
        </Td>
        <Td className="text-[12px]">{t.categories.length ? t.categories.map(categoryName).join(", ") : "—"}</Td>
        <Td className="text-[12px]">{t.tools.length ? `${t.runnable_tools} of ${t.tools.length} runnable` : "No tool integrated"}</Td>
        <Td className="text-[12px]">{t.import_formats.length ? t.import_formats.map((f) => f.label).join(", ") : "Generic formats"}</Td>
        <Td><Badge tone={st.tone}>{st.label}</Badge></Td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} className="border-b border-border bg-surface-muted/40 px-3 py-2.5">
            {t.note && <p className="mb-2 text-[12px] text-muted-foreground">{t.note}</p>}
            {t.tools.length === 0 ? (
              <p className="text-[12px] text-muted-foreground">No tool is integrated for this scan type yet; import results from other tools.</p>
            ) : (
              <ul className="grid gap-1 sm:grid-cols-2">
                {t.tools.map((tool) => (
                  <li key={tool.key} className="flex flex-wrap items-center gap-1.5 text-[12px]">
                    <span className="font-medium">{tool.name}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{tool.license_spdx}</span>
                    {tool.runnable ? (
                      <Badge tone="success">{tool.source === "server" ? "active" : `${tool.workers} worker${tool.workers === 1 ? "" : "s"}`}</Badge>
                    ) : tool.adapter_available ? (
                      <Badge tone="warning">no online worker</Badge>
                    ) : (
                      <Badge>catalogued</Badge>
                    )}
                    {tool.source === "plugin" && <Badge>operator plugin</Badge>}
                    {tool.intrusive && <Badge tone="danger">intrusive</Badge>}
                    {!tool.intrusive && tool.network === "target" && <Badge tone="warning">contacts target</Badge>}
                    {tool.decision === "restricted" && <Badge tone="danger">license-restricted</Badge>}
                  </li>
                ))}
              </ul>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
