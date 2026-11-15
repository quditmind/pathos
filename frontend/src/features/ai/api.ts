import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { AIConfiguration, AIProvider, AIReview, ApiToken, McpServer, Page } from "@/api/types";

export const useAIProviders = () =>
  useQuery({ queryKey: ["ai-providers"], queryFn: () => api<Page<AIProvider>>("/api/v1/ai/providers").then((r) => r.items) });
export const useAIConfigs = () =>
  useQuery({ queryKey: ["ai-configs"], queryFn: () => api<Page<AIConfiguration>>("/api/v1/ai/configurations").then((r) => r.items) });
export const useAIReviews = (status: string) =>
  useQuery({
    queryKey: ["ai-reviews", status],
    queryFn: () => api<Page<AIReview>>(`/api/v1/ai/reviews${status ? `?status=${status}` : ""}`).then((r) => r.items),
  });
export const useFindingReviews = (id: string | undefined) =>
  useQuery({
    queryKey: ["finding-reviews", id],
    queryFn: () => api<{ items: AIReview[]; ai_status: string }>(`/api/v1/findings/${id}/ai-reviews`),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data?.ai_status === "queued" ? 3000 : false),
  });
export const useTokens = () =>
  useQuery({ queryKey: ["tokens"], queryFn: () => api<{ items: ApiToken[]; mcp_url: string }>("/api/v1/me/tokens") });
export const useMcpServers = () =>
  useQuery({ queryKey: ["mcp-servers"], queryFn: () => api<Page<McpServer>>("/api/v1/mcp-servers").then((r) => r.items) });

export function useAIMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["ai-providers", "ai-configs", "ai-reviews", "finding-reviews", "tokens", "mcp-servers", "findings", "finding", "dashboard"])
        void qc.invalidateQueries({ queryKey: [k] });
    },
  });
}
