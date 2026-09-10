// Live node-state colours for the BloodHound-style map. Mirrors backend events.NodeState.
export type NodeState = "queued" | "active" | "stuck" | "error" | "done";

export const NODE_COLORS: Record<NodeState, string> = {
  queued: "#8394a0", // grey — created, not started
  active: "#2f9e57", // green (glowing) — running / where the run is now
  stuck: "#b7791f",  // yellow — blocked / awaiting approval / missing tool
  error: "#d05050",  // red — failed / tool error
  done: "#2b7fb8",   // teal/blue — completed
};
