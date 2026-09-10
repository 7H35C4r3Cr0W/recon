import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Report } from "./Report";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

function renderReport() {
  return render(
    <MemoryRouter initialEntries={["/projects/p1/report"]}>
      <Routes><Route path="/projects/:projectId/report" element={<Report />} /></Routes>
    </MemoryRouter>,
  );
}

describe("Report page", () => {
  it("renders the findings table + the rendered report", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path.includes("/findings")
        ? Promise.resolve({ findings: [{ value: "MS17-010 SMB RCE", port: 445, _host: "10.10.10.5", _category: "vulnerable" }] })
        : Promise.resolve({ markdown: "# Combined Recon Report\n\n## Summary\n\n- one host" }),
    );
    renderReport();
    expect(await screen.findByText(/MS17-010 SMB RCE/)).toBeInTheDocument();
    expect(screen.getByText("vulnerable")).toBeInTheDocument();
    expect(screen.getByText("10.10.10.5")).toBeInTheDocument();
    expect(screen.getByText("Combined Recon Report")).toBeInTheDocument();
  });

  it("shows friendly empty states", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path.includes("/findings") ? Promise.resolve({ findings: [] }) : Promise.resolve({ markdown: "" }));
    renderReport();
    expect(await screen.findByText(/No findings yet/)).toBeInTheDocument();
    expect(screen.getByText(/No report yet/)).toBeInTheDocument();
  });
});
