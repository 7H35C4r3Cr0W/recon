import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Users } from "./Users";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

describe("Users admin", () => {
  it("lists accounts and creates a user", async () => {
    vi.mocked(api).mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/users" && (!init || init.method === undefined)) {
        return Promise.resolve({ users: [{ id: "u1", email: "admin@nabu.local", display_name: "admin",
          role: "admin", auth_source: "local", is_active: true }] });
      }
      return Promise.resolve({});
    });
    render(<Users />);
    expect(await screen.findByText("admin@nabu.local")).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("email"), { target: { value: "op@corp.local" } });
    fireEvent.change(screen.getByPlaceholderText("temp password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByText("Create"));
    await waitFor(() => expect(api).toHaveBeenCalledWith("/users",
      expect.objectContaining({ method: "POST" })));
  });
});
