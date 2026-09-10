import { describe, it, expect } from "vitest";
import { NODE_COLORS } from "./nodeColors";

describe("NODE_COLORS", () => {
  it("maps every node state to a hex colour", () => {
    for (const state of ["queued", "active", "stuck", "error", "done"] as const) {
      expect(NODE_COLORS[state]).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });
  it("uses green for active and teal/blue for done (distinct)", () => {
    expect(NODE_COLORS.active).not.toBe(NODE_COLORS.done);
  });
});
