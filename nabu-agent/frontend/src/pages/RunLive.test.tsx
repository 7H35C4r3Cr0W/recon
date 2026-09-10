import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { RunLive } from "./RunLive";
import { api } from "../api/client";
import { connectRun, RunEvent } from "../ws/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));
vi.mock("../components/RunGraph", () => ({ RunGraph: () => <div data-testid="graph" /> }));

let captured: ((e: RunEvent) => void) | null = null;
vi.mock("../ws/client", () => ({
  connectRun: vi.fn((_id: string, onEvent: (e: RunEvent) => void) => {
    captured = onEvent;
    return { close: vi.fn(), onopen: null, onclose: null } as unknown as WebSocket;
  }),
}));

function renderRun() {
  return render(
    <MemoryRouter initialEntries={["/runs/r1"]}>
      <Routes><Route path="/runs/:runId" element={<RunLive />} /></Routes>
    </MemoryRouter>,
  );
}

function fireApproval() {
  const ev = {
    type: "approval.required", run_id: "r1", seq: 1, ts: null,
    data: { node_id: "run-r1", checkpoint_id: "cp1", message: "20 live hosts exceed the threshold" },
  } as unknown as RunEvent;
  act(() => captured?.(ev));
}

describe("RunLive approval gate", () => {
  it("shows the banner and POSTs approve", async () => {
    vi.mocked(connectRun).mockClear();
    vi.mocked(api).mockResolvedValue({});
    renderRun();
    fireApproval();

    expect(await screen.findByText(/Approval required/)).toBeInTheDocument();
    expect(screen.getByText(/20 live hosts exceed/)).toBeInTheDocument();

    fireEvent.click(screen.getByText(/Approve fan-out/));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/runs/r1/checkpoints/cp1/approve", { method: "POST" }));
  });

  it("POSTs reject when rejected", async () => {
    vi.mocked(api).mockResolvedValue({});
    renderRun();
    fireApproval();

    fireEvent.click(await screen.findByText(/Reject/));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/runs/r1/checkpoints/cp1/reject", { method: "POST" }));
  });
});
