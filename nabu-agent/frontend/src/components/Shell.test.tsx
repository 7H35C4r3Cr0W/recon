import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Shell } from "./Shell";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

describe("Shell", () => {
  it("renders nav, the signed-in user, and the unread feed badge", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      Promise.resolve(path === "/auth/me" ? { email: "admin@nabu.local" } : { unread_count: 3 }));
    render(<MemoryRouter><Shell /></MemoryRouter>);
    expect(await screen.findByText("admin@nabu.local")).toBeInTheDocument();
    expect(screen.getByText("Projects")).toBeInTheDocument();
    expect(screen.getByText("Help")).toBeInTheDocument();
    expect(await screen.findByText("3")).toBeInTheDocument(); // unread badge
  });
});
