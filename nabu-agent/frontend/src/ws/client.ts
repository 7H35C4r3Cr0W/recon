// WebSocket client bound to the canonical run-event envelope (see backend events/schema.py).
// The server replays the durable backlog by seq on every connect, then live-tails — so this client
// RECONNECTS with backoff if the socket drops mid-run and relies on the caller de-duping by `seq`
// (RunLive skips any event whose seq it has already applied), which makes a re-replay idempotent.
export type RunEventType =
  | "run.status" | "task.created" | "task.updated" | "log.line" | "finding.added"
  | "usage" | "checkpoint.requested" | "checkpoint.decided" | "approval.required"
  | "heartbeat" | "error" | "done";

export interface RunEvent {
  type: RunEventType;
  run_id: string;
  seq: number;
  ts: number;
  data: Record<string, unknown>;
  agent_id?: string | null;
  task_id?: string | null;
}

export type RunStatus = "connecting" | "live" | "reconnecting" | "done" | "closed";
export interface RunConn { close(): void; }

// Connect to a run's live feed, auto-reconnecting until the run reaches 'done' or close() is called.
export function connectRun(
  runId: string,
  onEvent: (e: RunEvent) => void,
  onStatus?: (s: RunStatus) => void,
): RunConn {
  let stopped = false;
  let finished = false;
  let ws: WebSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let backoff = 1000;

  function open() {
    if (stopped) return;
    onStatus?.(backoff === 1000 ? "connecting" : "reconnecting");
    ws = new WebSocket(`${location.origin.replace(/^http/, "ws")}/ws/runs/${runId}`);
    ws.onopen = () => { backoff = 1000; onStatus?.("live"); };
    ws.onmessage = (m) => {
      let e: RunEvent;
      try { e = JSON.parse(m.data) as RunEvent; } catch { return; }
      if (e.type === "done") finished = true;
      onEvent(e);
    };
    ws.onclose = () => {
      if (stopped) return;
      if (finished) { onStatus?.("done"); return; }
      onStatus?.("reconnecting");
      timer = setTimeout(open, backoff);
      backoff = Math.min(backoff * 2, 15000);  // cap reconnect backoff at 15s
    };
    ws.onerror = () => { try { ws?.close(); } catch { /* onclose handles retry */ } };
  }

  open();
  return {
    close() {
      stopped = true;
      if (timer) clearTimeout(timer);
      try { ws?.close(); } catch { /* already closed */ }
      onStatus?.("closed");
    },
  };
}
