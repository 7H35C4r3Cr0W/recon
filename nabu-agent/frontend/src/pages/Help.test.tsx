import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Help } from "./Help";

const present = (re: RegExp) => expect(screen.getAllByText(re).length).toBeGreaterThan(0);

describe("Help", () => {
  it("documents the key topics", () => {
    render(<Help />);
    expect(screen.getByText(/What is Nabu Agent/)).toBeInTheDocument();
    expect(screen.getByText(/Getting started/)).toBeInTheDocument();
    expect(screen.getByText(/Run kinds/)).toBeInTheDocument();
    expect(screen.getByText(/Attaching the LLM/)).toBeInTheDocument();
    expect(screen.getByText(/Safety/)).toBeInTheDocument();
  });

  it("renders the visual diagrams", () => {
    render(<Help />);
    present(/how a run flows/);
    present(/anatomy of a run/);
    present(/what the colours mean/);
    present(/the safety gate/);
    // the human-gated attack branch is spelled out visually
    present(/Attack proposed/);
    present(/Human approval/);
  });
});
