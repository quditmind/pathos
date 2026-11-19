/** The 15 CodeGraph views (contract: the `view` parameter). The engine returns the subset; the UI renders each. */
export const codegraphViews = [
  "architecture",
  "call_graph",
  "data_flow",
  "api",
  "dependencies",
  "deployment",
  "ownership",
  "trust_boundaries",
  "internet_exposure",
  "findings_overlay",
  "sbom",
  "datastores",
  "external_services",
  "secrets_and_config",
  "change_impact",
] as const;
export type CodeGraphView = (typeof codegraphViews)[number];
export const isCodeGraphView = (v: unknown): v is CodeGraphView => typeof v === "string" && (codegraphViews as readonly string[]).includes(v);

export const viewInfo: Record<CodeGraphView, { label: string; description: string }> = {
  architecture: { label: "Architecture", description: "Services, modules, data stores and external services, and how they connect." },
  call_graph: { label: "Call graph", description: "Functions and the calls between them." },
  data_flow: { label: "Data flow", description: "Where data is read, written, published and consumed." },
  api: { label: "API & endpoints", description: "Routes and API operations, the handlers behind them and their exposure." },
  dependencies: { label: "Dependencies", description: "Imports between modules and the third-party components they use." },
  deployment: { label: "Deployment", description: "Containers and infrastructure resources, and what is deployed as what." },
  ownership: { label: "Ownership", description: "Applications, repositories and their owners (the context graph as a layer)." },
  trust_boundaries: { label: "Trust boundaries", description: "Trust boundaries and the edges that cross them." },
  internet_exposure: { label: "Internet exposure", description: "Internet-exposed entry points and what they reach." },
  findings_overlay: { label: "Findings overlay", description: "Nodes with open findings, with their severity." },
  sbom: { label: "SBOM", description: "Components from the SBOM and the code that depends on them." },
  datastores: { label: "Data stores", description: "Databases, caches and queues, and the code that uses them." },
  external_services: { label: "External services", description: "Third-party services the application calls." },
  secrets_and_config: { label: "Secrets & configuration", description: "Where secrets and configuration are referenced. Secret values are never stored or shown." },
  change_impact: { label: "Change impact", description: "What changed between two snapshots, and what it touches." },
};
