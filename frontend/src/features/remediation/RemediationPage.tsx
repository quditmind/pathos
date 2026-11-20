import { useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Bookmark, Trash2, Users, Wrench } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Input, Label, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { formatDateTime } from "@/lib/utils";
import {
  filterKeys,
  isFeatureDisabled,
  itemStatuses,
  manualStatuses,
  priorities,
  statusLabel,
  useBulkUpdate,
  useDeleteView,
  useItems,
  useSaveView,
  useViews,
  type BulkUpdate,
  type ItemFilters,
  type ItemStatus,
  type Priority,
  type RemediationItem,
} from "./api";
import { RemediationFrame, UserPicker, useOption } from "./shared";

/** Search params of /remediation (the workspace filters). */
export function validateRemediationSearch(s: Record<string, unknown>): ItemFilters {
  const out: ItemFilters = {};
  for (const k of filterKeys) if (typeof s[k] === "string" && s[k]) out[k] = s[k] as string;
  return out;
}

const statusTone: Record<ItemStatus, "neutral" | "success" | "warning" | "danger"> = {
  open: "neutral",
  planned: "neutral",
  in_progress: "warning",
  fix_submitted: "warning",
  verifying: "warning",
  closed: "success",
  wont_fix: "neutral",
};

export function StatusBadge({ status }: { status: ItemStatus }) {
  return <Badge tone={statusTone[status] ?? "neutral"}>{statusLabel[status] ?? status}</Badge>;
}

export function DueDate({ item }: { item: Pick<RemediationItem, "due_at" | "due_source" | "overdue"> }) {
  if (!item.due_at) return <span className="text-muted-foreground">—</span>;
  return (
    <span className={item.overdue ? "text-danger" : undefined}>
      {formatDateTime(item.due_at).split(",")[0]}
      <span className="ml-1 text-[11px] text-muted-foreground">({item.due_source === "sla" ? "SLA" : item.due_source === "manual" ? "set by hand" : "—"})</span>
      {item.overdue && <Badge tone="danger" className="ml-1">Overdue</Badge>}
    </span>
  );
}

/**
 * Remediation workspace (/remediation, PATHOS 3.0 M8): one item per finding
 * or group, with owner, due date (from the SLA engine), status, fix PR and
 * the last verification. Server-side filters and sort, saved views, bulk
 * assign / status / due date / priority with confirmation.
 */
export function RemediationPage() {
  const search = useSearch({ strict: false }) as ItemFilters;
  const navigate = useNavigate();
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursors, setCursors] = useState<string[]>([]);
  const list = useItems(search, cursor);
  const disabled = isFeatureDisabled(list.error);
  const set = (patch: Partial<ItemFilters>) => {
    // Functional update: two quick changes in a row both apply.
    const merge = (prev: Record<string, unknown>) => {
      const next: Record<string, unknown> = { ...prev };
      for (const [k, v] of Object.entries(patch)) {
        if (v) next[k] = v;
        else delete next[k];
      }
      return next;
    };
    setCursor(undefined);
    setCursors([]);
    void navigate({ to: "/remediation", search: ((prev: Record<string, unknown>) => merge(prev)) as never, replace: true });
  };
  return (
    <RemediationFrame
      title="Remediation workspace"
      description="Track every fix from finding to proof: owner, due date from the SLA, secure fix guidance, fix pull request and a targeted rescan that closes the item only when the finding is gone."
      disabled={disabled}
    >
      <Filters search={search} set={set} />
      {list.isError ? (
        <ErrorPanel error={list.error} title="Remediation items could not be loaded" />
      ) : list.isPending ? (
        <LoadingSkeleton rows={6} label="Loading remediation items" />
      ) : (
        <ItemsTable
          items={list.data.items}
          filtered={Object.keys(search).some((k) => k !== "sort")}
          hasNext={!!list.data.next_cursor}
          hasPrev={cursors.length > 0}
          onNext={() => {
            setCursors((c) => [...c, cursor ?? ""]);
            setCursor(list.data.next_cursor ?? undefined);
          }}
          onPrev={() => {
            const prev = cursors[cursors.length - 1];
            setCursors((c) => c.slice(0, -1));
            setCursor(prev || undefined);
          }}
        />
      )}
    </RemediationFrame>
  );
}

function Filters({ search, set }: { search: ItemFilters; set: (p: Partial<ItemFilters>) => void }) {
  const { me } = useSession();
  const [q, setQ] = useState(search.q ?? "");
  useEffect(() => setQ(search.q ?? ""), [search.q]);
  const owner = search.unassigned === "true" ? "none" : search.owner_id === me.user.id ? "me" : search.owner_id ? "other" : "";
  return (
    <div className="mb-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            set({ q: q.trim() || undefined });
          }}
        >
          <Input aria-label="Search remediation items" placeholder="Search title, file or rule…" value={q} onChange={(e) => setQ(e.target.value)} className="w-60" />
        </form>
        <Select aria-label="Status" value={search.status ?? ""} onChange={(e) => set({ status: e.target.value || undefined })}>
          <option value="">Any status</option>
          {itemStatuses.map((s) => (
            <option key={s} value={s}>{statusLabel[s]}</option>
          ))}
        </Select>
        <Select
          aria-label="Owner"
          value={owner}
          onChange={(e) => {
            const v = e.target.value;
            set({ owner_id: v === "me" ? me.user.id : undefined, unassigned: v === "none" ? "true" : undefined });
          }}
        >
          <option value="">Any owner</option>
          <option value="me">Assigned to me</option>
          <option value="none">Unassigned</option>
          {owner === "other" && <option value="other">Selected owner</option>}
        </Select>
        <Select aria-label="Priority" value={search.priority ?? ""} onChange={(e) => set({ priority: e.target.value || undefined })}>
          <option value="">Any priority</option>
          {priorities.map((p) => (
            <option key={p} value={p} className="capitalize">{p}</option>
          ))}
        </Select>
        <RepoFilter value={search.repository_id} onChange={(v) => set({ repository_id: v })} />
        {search.application_id && (
          <span className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-[12.5px]">
            One application only
            <button type="button" className="text-primary hover:underline" onClick={() => set({ application_id: undefined })}>
              Clear
            </button>
          </span>
        )}
        {search.threat_id && (
          <span className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-[12.5px]">
            One threat only
            <button type="button" className="text-primary hover:underline" onClick={() => set({ threat_id: undefined })}>
              Clear
            </button>
          </span>
        )}
        <label className="flex items-center gap-1.5 text-[13px]">
          <input type="checkbox" className="accent-[var(--primary)]" checked={search.overdue === "true"} onChange={(e) => set({ overdue: e.target.checked ? "true" : undefined })} />
          Overdue only
        </label>
        <Select aria-label="Sort" value={search.sort ?? "due_at"} onChange={(e) => set({ sort: e.target.value === "due_at" ? undefined : e.target.value })}>
          <option value="due_at">Due date (soonest first)</option>
          <option value="-due_at">Due date (latest first)</option>
          <option value="priority">Priority</option>
          <option value="-created_at">Newest</option>
        </Select>
      </div>
      <SavedViews search={search} apply={(f) => set({ ...Object.fromEntries(filterKeys.map((k) => [k, undefined])), ...f })} />
    </div>
  );
}

function SavedViews({ search, apply }: { search: ItemFilters; apply: (f: ItemFilters) => void }) {
  const views = useViews();
  const save = useSaveView();
  const del = useDeleteView();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const [deleting, setDeleting] = useState<{ id: string; name: string } | null>(null);
  return (
    <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
      <span className="text-muted-foreground">Saved views:</span>
      {views.isError && <span className="text-muted-foreground">not available</span>}
      {views.data?.length === 0 && <span className="text-muted-foreground">none yet</span>}
      {views.data?.map((v) => (
        <span key={v.id} className="inline-flex items-center gap-0.5 rounded-md border border-border">
          <button type="button" className="px-2 py-0.5 hover:text-primary" onClick={() => apply(v.filters as ItemFilters)} title={v.shared ? `Shared by ${v.owner_email}` : undefined}>
            {v.name}
            {v.shared && <span className="ml-1 text-[11px] text-muted-foreground">(shared)</span>}
          </button>
          <button type="button" aria-label={`Delete view ${v.name}`} className="px-1 text-muted-foreground hover:text-danger" onClick={() => setDeleting(v)}>
            <Trash2 className="size-3.5" />
          </button>
        </span>
      ))}
      <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>
        <Bookmark /> Save current view
      </Button>
      <Dialog
        open={open}
        onOpenChange={setOpen}
        title="Save view"
        description="Saves the current filters and sort."
        footer={
          <>
            <Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              disabled={!name.trim() || save.isPending}
              onClick={() =>
                save.mutate(
                  { name: name.trim(), filters: search, shared },
                  {
                    onSuccess: () => {
                      toast.success(`View "${name.trim()}" saved`);
                      setOpen(false);
                      setName("");
                    },
                  },
                )
              }
            >
              Save
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <Label htmlFor="view-name">Name</Label>
            <Input id="view-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </div>
          <label className="flex items-center gap-1.5 text-[13px]">
            <input type="checkbox" className="accent-[var(--primary)]" checked={shared} onChange={(e) => setShared(e.target.checked)} />
            Share with the organization
          </label>
          {save.error && <ErrorPanel error={save.error} />}
        </div>
      </Dialog>
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete saved view"
        confirmLabel="Delete"
        pending={del.isPending}
        error={del.error?.message}
        onConfirm={() =>
          deleting &&
          del.mutate(deleting.id, {
            onSuccess: () => {
              toast.success(`View "${deleting.name}" deleted`);
              setDeleting(null);
            },
          })
        }
      >
        Delete the view “{deleting?.name}”? Items are not changed.
      </ConfirmDialog>
    </div>
  );
}

function ItemsTable({
  items,
  filtered,
  hasNext,
  hasPrev,
  onNext,
  onPrev,
}: {
  items: RemediationItem[];
  filtered: boolean;
  hasNext: boolean;
  hasPrev: boolean;
  onNext: () => void;
  onPrev: () => void;
}) {
  const { can } = useSession();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const manage = can("remediation.manage");
  useEffect(() => setSelected(new Set()), [items]);
  if (!items.length) {
    return (
      <EmptyStateCard icon={<Wrench />} title={filtered ? "No items match these filters" : "No remediation items yet"}>
        {filtered
          ? "Clear a filter to see more items."
          : "Items appear here when someone creates them from findings (Findings → select → Create remediation items, or POST /api/v1/remediation/items). Each item tracks one finding or a group of findings to a verified fix."}
      </EmptyStateCard>
    );
  }
  const all = items.every((i) => selected.has(i.id));
  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  return (
    <>
      {manage && selected.size > 0 && <BulkBar ids={[...selected]} onDone={() => setSelected(new Set())} />}
      <Card>
        <Table>
          <thead>
            <tr>
              {manage && (
                <Th className="w-8">
                  <input
                    type="checkbox"
                    aria-label="Select all items on this page"
                    className="accent-[var(--primary)]"
                    checked={all}
                    onChange={() => setSelected(all ? new Set() : new Set(items.map((i) => i.id)))}
                  />
                </Th>
              )}
              <Th>Item</Th>
              <Th>Status</Th>
              <Th>Priority</Th>
              <Th>Owner</Th>
              <Th>Due</Th>
              <Th>Fix</Th>
              <Th>Verification</Th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.id} className={selected.has(i.id) ? "bg-primary/5" : undefined}>
                {manage && (
                  <Td>
                    <input type="checkbox" aria-label={`Select ${i.title}`} className="accent-[var(--primary)]" checked={selected.has(i.id)} onChange={() => toggle(i.id)} />
                  </Td>
                )}
                <Td className="max-w-md">
                  <Link to="/remediation/items/$id" params={{ id: i.id }} className="text-[12.5px] text-primary hover:underline">
                    {i.title}
                  </Link>
                  <div className="flex flex-wrap items-center gap-1 text-[11.5px] text-muted-foreground">
                    {i.top_severity && <SeverityBadge value={i.top_severity} />}
                    <span>{i.repository_name || i.application_name}</span>
                    <span>· {i.open_finding_count}/{i.finding_count} finding(s) open</span>
                  </div>
                </Td>
                <Td><StatusBadge status={i.status} /></Td>
                <Td className="text-[12px] capitalize">{i.priority}</Td>
                <Td className="text-[12px]">{i.owner_email || <span className="text-muted-foreground">Unassigned</span>}</Td>
                <Td className="whitespace-nowrap text-[12px]"><DueDate item={i} /></Td>
                <Td className="text-[12px]">
                  {i.fix_pull_request?.pr_url ? (
                    <a href={i.fix_pull_request.pr_url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                      Fix PR ({i.fix_pull_request.status})
                    </a>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </Td>
                <Td className="text-[12px]">
                  {i.last_verification ? (
                    <span>{i.last_verification.result ? resultLabel[i.last_verification.result] : i.last_verification.status}</span>
                  ) : (
                    <span className="text-muted-foreground">Not verified</span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      {(hasNext || hasPrev) && (
        <div className="mt-2 flex justify-end gap-2">
          <Button size="sm" variant="secondary" disabled={!hasPrev} onClick={onPrev}>Previous</Button>
          <Button size="sm" variant="secondary" disabled={!hasNext} onClick={onNext}>Next</Button>
        </div>
      )}
    </>
  );
}

export const resultLabel: Record<string, string> = {
  fixed: "Fixed (proven)",
  still_present: "Still present",
  regressed: "Regression found",
  inconclusive: "Inconclusive",
};

function BulkBar({ ids, onDone }: { ids: string[]; onDone: () => void }) {
  const { me, can } = useSession();
  const bulk = useBulkUpdate();
  const [owner, setOwner] = useOption();
  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [due, setDue] = useState("");
  const [pending, setPending] = useState<{ body: BulkUpdate; what: string } | null>(null);
  const ask = (body: Omit<BulkUpdate, "ids">, what: string) => setPending({ body: { ids, ...body }, what });
  return (
    <Card className="mb-2 flex flex-wrap items-end gap-3 p-3 text-[13px]" role="region" aria-label="Bulk actions">
      <span className="font-medium">{ids.length} selected</span>
      <Button size="sm" variant="secondary" onClick={() => ask({ owner_id: me.user.id }, `assign ${ids.length} item(s) to you`)}>
        <Users /> Assign to me
      </Button>
      {can("users.read") && (
        <div className="flex items-end gap-1">
          <UserPicker value={owner} onChange={setOwner} label="Assign to" />
          <Button size="sm" variant="secondary" disabled={!owner} onClick={() => owner && ask({ owner_id: owner.value }, `assign ${ids.length} item(s) to ${owner.label}`)}>
            Assign
          </Button>
        </div>
      )}
      <div className="flex items-end gap-1">
        <Select aria-label="Set status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Set status…</option>
          {manualStatuses.map((s) => (
            <option key={s} value={s}>{statusLabel[s]}</option>
          ))}
        </Select>
        <Button size="sm" variant="secondary" disabled={!status} onClick={() => ask({ status: status as ItemStatus }, `set ${ids.length} item(s) to ${statusLabel[status as ItemStatus]}`)}>
          Apply
        </Button>
      </div>
      <div className="flex items-end gap-1">
        <Select aria-label="Set priority" value={priority} onChange={(e) => setPriority(e.target.value)}>
          <option value="">Set priority…</option>
          {priorities.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </Select>
        <Button size="sm" variant="secondary" disabled={!priority} onClick={() => ask({ priority: priority as Priority }, `set the priority of ${ids.length} item(s) to ${priority}`)}>
          Apply
        </Button>
      </div>
      <div className="flex items-end gap-1">
        <Input type="date" aria-label="Set due date" value={due} onChange={(e) => setDue(e.target.value)} />
        <Button size="sm" variant="secondary" disabled={!due} onClick={() => ask({ due_at: new Date(`${due}T23:59:59Z`).toISOString() }, `set the due date of ${ids.length} item(s) to ${due}`)}>
          Apply
        </Button>
      </div>
      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title="Apply to selected items"
        confirmLabel="Apply"
        destructive={false}
        pending={bulk.isPending}
        error={bulk.error?.message}
        onConfirm={() =>
          pending &&
          bulk.mutate(pending.body, {
            onSuccess: (r) => {
              toast.success(`${r?.updated ?? ids.length} item(s) updated`);
              setPending(null);
              onDone();
            },
          })
        }
      >
        This will {pending?.what}. The change is recorded in the audit log.
      </ConfirmDialog>
    </Card>
  );
}
