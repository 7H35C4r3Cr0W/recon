// Shortest directed path between two nodes over an edge list, as an ordered list of node ids
// (empty when the target is unreachable from the root). BFS gives the fewest-hop chain, which is
// what "how did the run reach this asset" wants on the BloodHound-style map. Pure + Qt/DOM-free so
// it is unit-tested directly and reused by RunGraph for click-to-highlight-attack-path.
export interface PathEdge { source: string; target: string; }

export function shortestPath(edges: PathEdge[], rootId: string, targetId: string): string[] {
  if (rootId === targetId) return [rootId];
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    const list = adj.get(e.source);
    if (list) list.push(e.target);
    else adj.set(e.source, [e.target]);
  }
  const prev = new Map<string, string>();
  const seen = new Set<string>([rootId]);
  const queue: string[] = [rootId];
  while (queue.length) {
    const cur = queue.shift() as string;
    for (const next of adj.get(cur) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      prev.set(next, cur);
      if (next === targetId) {
        const path = [next];
        let at = cur;
        while (at !== rootId) { path.unshift(at); at = prev.get(at) as string; }
        path.unshift(rootId);
        return path;
      }
      queue.push(next);
    }
  }
  return [];
}

// Map of node id -> the next node id along the path. An edge is "on the path" iff
// next.get(edge.source) === edge.target — an O(1) check with no delimiter to get wrong.
export function pathNext(path: string[]): Map<string, string> {
  const next = new Map<string, string>();
  for (let i = 0; i < path.length - 1; i++) next.set(path[i], path[i + 1]);
  return next;
}
