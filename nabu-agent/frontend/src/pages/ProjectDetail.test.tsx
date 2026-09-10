import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ProjectDetail } from "./ProjectDetail";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={["/projects/p1"]}>
      <Routes><Route path="/projects/:projectId" element={<ProjectDetail />} /></Routes>
    </MemoryRouter>,
  );
}

describe("ProjectDetail", () => {
  it("lists past runs with an open-map link and a report link", async () => {
    vi.mocked(api).mockImplementation((path: string) => {
      if (path.endsWith("/scope")) return Promise.resolve({ scope: [{ id: "s1", target: "10.10.10.0/29", kind: "cidr" }] });
      if (path.endsWith("/runs")) return Promise.resolve({ runs: [{ id: "run9", state: "done", target: "10.10.10.0/29", kind: "scan" }] });
      return Promise.resolve({});
    });
    renderDetail();

    // the run appears with its state, and links to its live map + to the report/outputs area
    expect(await screen.findByText("done")).toBeInTheDocument();
    const mapLink = screen.getByText(/Open map/).closest("a");
    expect(mapLink).toHaveAttribute("href", "/projects/p1/runs/run9");
    const reportLink = screen.getByText(/Report & outputs/).closest("a");
    expect(reportLink).toHaveAttribute("href", "/projects/p1/report");
  });

  it("shows the empty runs state", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path.endsWith("/runs") ? Promise.resolve({ runs: [] }) : Promise.resolve({ scope: [] }));
    renderDetail();
    expect(await screen.findByText(/No runs yet/)).toBeInTheDocument();
  });
});
