import { describe, expect, it, vi } from "vitest";
import { connectRun } from "./client";

describe("connectRun", () => {
  it("opens a WebSocket to the run's /ws path", () => {
    const created: string[] = [];
    class FakeWS { onmessage: unknown; constructor(url: string) { created.push(url); } close() {} }
    vi.stubGlobal("WebSocket", FakeWS as unknown as typeof WebSocket);
    connectRun("run-abc", () => {});
    expect(created[0]).toContain("/ws/runs/run-abc");
    expect(created[0].startsWith("ws")).toBe(true);
    vi.unstubAllGlobals();
  });
});
