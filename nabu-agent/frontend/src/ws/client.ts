// WebSocket client bound to the canonical run-event envelope (see backend events/schema.py).
// Replay-by-seq then live-tail; the hub sends a heartbeat every ~20s. Full client lands in Phase 2.
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

export function connectRun(runId: string, onEvent: (e: RunEvent) => void): WebSocket {
  const ws = new WebSocket(`${location.origin.replace(/^http/, "ws")}/ws/runs/${runId}`);
  ws.onmessage = (m) => onEvent(JSON.parse(m.data) as RunEvent);
  return ws;
}
