import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Help } from "./Help";

describe("Help", () => {
  it("documents the key topics", () => {
    render(<Help />);
    expect(screen.getByText(/What is Nabu Agent/)).toBeInTheDocument();
    expect(screen.getByText(/Getting started/)).toBeInTheDocument();
    expect(screen.getByText(/Run kinds/)).toBeInTheDocument();
    expect(screen.getByText(/Attaching the LLM/)).toBeInTheDocument();
    expect(screen.getByText(/Safety/)).toBeInTheDocument();
  });
});
