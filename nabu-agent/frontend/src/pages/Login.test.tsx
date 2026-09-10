import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Login } from "./Login";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

describe("Login", () => {
  it("shows the SSO button only when the IdP is configured", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      Promise.resolve(path === "/auth/providers" ? { oidc: true } : {}));
    render(<Login />);
    expect(await screen.findByText(/Sign in with SSO/)).toBeInTheDocument();
  });

  it("posts credentials to /auth/login on submit", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      Promise.resolve(path === "/auth/providers" ? { oidc: false } : {}));
    render(<Login />);
    await userEvent.type(screen.getByPlaceholderText("email"), "a@b.io");
    await userEvent.type(screen.getByPlaceholderText("password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(vi.mocked(api)).toHaveBeenCalledWith("/auth/login",
      expect.objectContaining({ method: "POST" }));
  });
});
