import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { OrganizationSwitcher } from "./OrganizationSwitcher";
import { OrganizationsAdminPage } from "./OrganizationsAdminPage";

afterEach(() => vi.unstubAllGlobals());

const two = {
  multi_tenant: true,
  installation_admin: false,
  active_organization_id: "o1",
  items: [
    { organization_id: "o1", name: "Acme", slug: "acme", status: "active", user_id: "u1", user_status: "active" },
    { organization_id: "o2", name: "Globex", slug: "globex", status: "active", user_id: "u2", user_status: "active" },
  ],
};

describe("organization switcher", () => {
  it("is hidden on single-organization installs", async () => {
    const api = mockApi({ "GET /api/v1/me/organizations": () => ({ ...two, multi_tenant: false, items: [two.items[0]] }) });
    const { container } = renderApp(<OrganizationSwitcher />);
    await waitFor(() => expect(api.calls.length).toBe(1));
    expect(container.textContent).toBe("");
  });

  it("switches the session and reloads the app", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const api = mockApi({
      "GET /api/v1/me/organizations": () => two,
      "POST /api/v1/me/organization": () => ({ active_organization_id: "o2" }),
    });
    renderApp(<OrganizationSwitcher />);
    const trigger = await screen.findByRole("button", { name: "Switch organization" });
    expect(trigger).toHaveTextContent("Acme");
    fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false });
    fireEvent.click(await screen.findByText("Globex"));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    const post = api.calls.find((c) => c.method === "POST");
    expect(post?.body).toEqual({ organization_id: "o2" });
  });
});

describe("installation organizations page", () => {
  it("explains that only installation administrators manage organizations", async () => {
    mockApi({ "GET /api/v1/me/organizations": () => two });
    renderApp(<OrganizationsAdminPage />);
    expect(await screen.findByText("Only installation administrators manage organizations.")).toBeInTheDocument();
  });

  it("lists organizations and requires the slug to delete a suspended one", async () => {
    const api = mockApi({
      "GET /api/v1/me/organizations": () => ({ ...two, installation_admin: true }),
      "GET /api/v1/installation/organizations": () => ({
        items: [
          { id: "o1", name: "Acme", slug: "acme", status: "active", suspended_at: null, suspended_reason: "", created_at: "2026-11-01T00:00:00Z", users: 4, repositories: 12 },
          { id: "o3", name: "Initech", slug: "initech", status: "suspended", suspended_at: "2026-11-02T00:00:00Z", suspended_reason: "contract ended", created_at: "2026-11-01T00:00:00Z", users: 1, repositories: 0 },
        ],
      }),
      "GET /api/v1/installation/audit-logs": () => ({ items: [] }),
      "DELETE /api/v1/installation/organizations/o3": () => ({ deleted: true, rows: 10, objects: 0 }),
    });
    renderApp(<OrganizationsAdminPage />);
    expect(await screen.findByText("Initech")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    const confirm = await screen.findByRole("button", { name: "Delete permanently" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Type the slug/), { target: { value: "initech" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(api.calls.some((c) => c.method === "DELETE")).toBe(true));
    expect(api.calls.find((c) => c.method === "DELETE")?.body).toEqual({ confirm_slug: "initech" });
  });
});
