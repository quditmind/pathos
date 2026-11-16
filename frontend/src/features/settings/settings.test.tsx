import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { AuthField } from "@/api/types";
import { AuthFields, authFieldBody, missingAuthFields } from "./AuthFields";

const fields: AuthField[] = [
  { name: "username", label: "Atlassian e-mail", type: "text", required: true, secret: false, help: "" },
  { name: "token", label: "API token", type: "password", required: true, secret: true, help: "Read-only scope" },
  { name: "private_key_pem", label: "Certificate private key", type: "textarea", required: false, secret: true, help: "PEM" },
  { name: "github_app_id", label: "App ID", type: "number", required: false, secret: false, help: "" },
  { name: "organizations", label: "Allowed organizations", type: "list", required: false, secret: false, help: "" },
  { name: "client_secret", label: "Client secret", type: "text", required: false, secret: true, help: "" },
];

describe("dynamic auth-method fields", () => {
  it("renders an input per declared field with the right control", () => {
    const onChange = vi.fn();
    render(<AuthFields fields={fields} values={{}} onChange={onChange} />);
    expect(screen.getByLabelText(/Atlassian e-mail/)).toHaveAttribute("type", "text");
    expect(screen.getByLabelText(/^API token/)).toHaveAttribute("type", "password");
    expect(screen.getByLabelText(/Client secret/)).toHaveAttribute("type", "password"); // secret text → password
    expect(screen.getByLabelText(/Certificate private key/).tagName).toBe("TEXTAREA");
    expect(screen.getByLabelText(/App ID/)).toHaveAttribute("type", "number");
    expect(screen.getByLabelText(/Allowed organizations/).tagName).toBe("TEXTAREA");
    expect(screen.getByLabelText(/^API token/)).toHaveAttribute("aria-required", "true");
    expect(screen.getByText("Read-only scope")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^API token/), { target: { value: "s3cr3t" } });
    expect(onChange).toHaveBeenCalledWith("token", "s3cr3t");
  });

  it("marks secrets optional when rotating", () => {
    render(<AuthFields fields={fields} values={{}} onChange={() => undefined} optionalSecrets />);
    expect(screen.getByLabelText(/^API token/)).not.toHaveAttribute("aria-required");
    expect(screen.getAllByText(/Leave blank to keep/).length).toBe(3);
  });

  it("builds the request body with numbers and lists", () => {
    const body = authFieldBody(fields, { username: " a@b.c ", token: "t", github_app_id: "42", organizations: "acme\nwidgets, tools\n", client_secret: "" });
    expect(body).toEqual({ username: "a@b.c", token: "t", github_app_id: 42, organizations: ["acme", "widgets", "tools"] });
    expect(missingAuthFields(fields, { username: "x" })).toEqual(["API token"]);
    expect(authFieldBody(fields.filter((f) => f.secret), { token: "", client_secret: "n" }, { skipBlankSecrets: true })).toEqual({ client_secret: "n" });
  });
});
