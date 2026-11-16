import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type {
  AssetField,
  AssetSettings,
  Classification,
  ClassificationKind,
  DirectoryTeam,
  DirectoryUser,
  Tag,
  TagColor,
  TagSearchResult,
} from "@/api/types";

export function useAssetSettings() {
  return useQuery({ queryKey: ["asset-settings"], queryFn: () => api<AssetSettings>("/api/v1/asset-settings"), staleTime: 60_000 });
}

/** Active (non-archived) entries of a catalog, in configured order. */
export function catalog(settings: AssetSettings | undefined, kind: ClassificationKind, includeArchived = false): Classification[] {
  return [...(settings?.classifications?.[kind] ?? [])]
    .filter((c) => includeArchived || !c.archived)
    .sort((a, b) => a.sort_order - b.sort_order || a.label.localeCompare(b.label));
}

/** Label for a catalog key; falls back to the key itself. */
export function catalogLabel(settings: AssetSettings | undefined, kind: ClassificationKind, key: string | null | undefined): string {
  if (!key) return "";
  return settings?.classifications?.[kind]?.find((c) => c.key === key)?.label ?? key;
}

export function catalogEntry(settings: AssetSettings | undefined, kind: ClassificationKind, key: string | null | undefined) {
  return key ? settings?.classifications?.[kind]?.find((c) => c.key === key) : undefined;
}

function useInvalidateSettings() {
  const qc = useQueryClient();
  return () => void qc.invalidateQueries({ queryKey: ["asset-settings"] });
}

export function useUpdateAssetSettings() {
  const invalidate = useInvalidateSettings();
  return useMutation({
    mutationFn: (body: { required_fields?: AssetField[]; scan_on_import?: boolean; repository_key_prefix?: string }) =>
      api<AssetSettings>("/api/v1/asset-settings", { method: "PATCH", body }),
    onSuccess: invalidate,
  });
}

export interface ClassificationInput {
  kind?: ClassificationKind;
  key?: string;
  label?: string;
  description?: string;
  color?: string;
  sort_order?: number;
  archived?: boolean;
}

export function useCreateClassification() {
  const invalidate = useInvalidateSettings();
  return useMutation({
    mutationFn: (body: ClassificationInput) => api<Classification>("/api/v1/asset-classifications", { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useUpdateClassification() {
  const invalidate = useInvalidateSettings();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: ClassificationInput }) =>
      api<Classification>(`/api/v1/asset-classifications/${id}`, { method: "PATCH", body }),
    onSuccess: invalidate,
  });
}

export function directoryUsers(q: string, signal?: AbortSignal) {
  const p = new URLSearchParams({ limit: "20" });
  if (q) p.set("q", q);
  return api<{ items: DirectoryUser[] }>(`/api/v1/directory/users?${p}`, { signal }).then((r) => r.items);
}

export function directoryTeams(q: string, signal?: AbortSignal) {
  const p = new URLSearchParams({ limit: "20" });
  if (q) p.set("q", q);
  return api<{ items: DirectoryTeam[] }>(`/api/v1/directory/teams?${p}`, { signal }).then((r) => r.items);
}

export function searchTags(q: string, signal?: AbortSignal) {
  const p = new URLSearchParams({ limit: "50" });
  if (q) p.set("q", q);
  return api<{ items: TagSearchResult[] }>(`/api/v1/tags?${p}`, { signal }).then((r) => r.items);
}

export interface TagInput {
  name?: string;
  color?: TagColor;
  description?: string;
}

function useInvalidateTags() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["tag-categories"] });
    void qc.invalidateQueries({ queryKey: ["repositories"] });
    void qc.invalidateQueries({ queryKey: ["repository"] });
  };
}

export function useCreateTag() {
  const invalidate = useInvalidateTags();
  return useMutation({
    mutationFn: ({ categoryId, body }: { categoryId: string; body: TagInput }) =>
      api<Tag>(`/api/v1/tag-categories/${categoryId}/tags`, { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useUpdateTag() {
  const invalidate = useInvalidateTags();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: TagInput }) => api<Tag>(`/api/v1/tags/${id}`, { method: "PATCH", body }),
    onSuccess: invalidate,
  });
}

export function useDeleteTag() {
  const invalidate = useInvalidateTags();
  return useMutation({ mutationFn: (id: string) => api<void>(`/api/v1/tags/${id}`, { method: "DELETE" }), onSuccess: invalidate });
}
