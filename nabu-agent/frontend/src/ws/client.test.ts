import { afterEach, describe, expect, it, vi } from "vitest";
import { connectRun } from "./client";

class FakeWS {
  onopen: (() => void) | null = null;
  onmessage: ((m: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(public url: string) { sockets.push(this); }
  close() { this.closed = true; }
}
let sockets: FakeWS[] = [];

afterEach(() => { sockets = []; vi.useRealTimers(); vi.unstubAllGlobals(); });

function stub() {
  sockets = [];
  vi.stubGlobal("WebSocket", FakeWS as unknown as typeof WebSocket);
}

describe("connectRun", () => {
  it("opens a WebSocket to the run's /ws path", () => {
    stub();
    connectRun("run-abc", () => {});
    expect(sockets[0].url).toContain("/ws/runs/run-abc");
    expect(sockets[0].url.startsWith("ws")).toBe(true);
  });

  it("reconnects with backoff after an unexpected close", () => {
    vi.useFakeTimers();
    stub();
    const conn = connectRun("r1", () => {});
    expect(sockets.length).toBe(1);
    sockets[0].onclose?.();            // socket drops mid-run
    vi.advanceTimersByTime(1000);      // first backoff elapses
    expect(sockets.length).toBe(2);    // a new socket was opened
    conn.close();
  });

  it("does NOT reconnect after a 'done' event or after close()", () => {
    vi.useFakeTimers();
    stub();
    const conn = connectRun("r1", () => {});
    sockets[0].onmessage?.({ data: JSON.stringify({ type: "done", seq: 9, run_id: "r1", ts: 0, data: {} }) });
    sockets[0].onclose?.();
    vi.advanceTimersByTime(30000);
    expect(sockets.length).toBe(1);    // finished → no reconnect
    conn.close();
  });
});
