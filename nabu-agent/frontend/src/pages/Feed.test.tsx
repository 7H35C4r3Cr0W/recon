import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Feed } from "./Feed";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

describe("Feed", () => {
  it("renders feed items with state + findings", async () => {
    vi.mocked(api).mockResolvedValue({
      items: [{ run_id: "r1", project_id: "p1", project: "Proj A", state: "scanning",
                run_kind: "agent", target: "10.0.0.5", findings: 2, attention: false, live: true, ts: null }],
    });
    render(<MemoryRouter><Feed /></MemoryRouter>);
    expect(await screen.findByText(/Proj A/)).toBeInTheDocument();
    expect(screen.getByText("scanning")).toBeInTheDocument();
    expect(screen.getByText(/2 findings/)).toBeInTheDocument();
  });

  it("shows the empty state", async () => {
    vi.mocked(api).mockResolvedValue({ items: [] });
    render(<MemoryRouter><Feed /></MemoryRouter>);
    expect(await screen.findByText(/No activity yet/)).toBeInTheDocument();
  });
});
