import { describe, it, expect } from "vitest";
import { shortestPath, pathNext } from "./graphPath";

// A small recon graph: target -> agent -> services -> finding(cred) -> DC host -> ldap -> finding
const EDGES = [
  { source: "t", target: "a_nmap" },
  { source: "a_nmap", target: "s_http" },
  { source: "a_nmap", target: "s_smb" },
  { source: "s_smb", target: "a_smb" },
  { source: "a_smb", target: "f_cred" },
  { source: "f_cred", target: "h_dc" },
  { source: "h_dc", target: "s_ldap" },
  { source: "s_ldap", target: "f_dcsync" },
];

describe("shortestPath", () => {
  it("returns [root] when root === target", () => {
    expect(shortestPath(EDGES, "t", "t")).toEqual(["t"]);
  });

  it("finds the fewest-hop chain from the root to a deep node", () => {
    expect(shortestPath(EDGES, "t", "f_dcsync")).toEqual([
      "t", "a_nmap", "s_smb", "a_smb", "f_cred", "h_dc", "s_ldap", "f_dcsync",
    ]);
  });

  it("reaches a shallow branch without walking the other branch", () => {
    expect(shortestPath(EDGES, "t", "s_http")).toEqual(["t", "a_nmap", "s_http"]);
  });

  it("returns [] for an unreachable node", () => {
    expect(shortestPath(EDGES, "t", "nope")).toEqual([]);
  });

  it("respects edge direction (no path against the arrows)", () => {
    expect(shortestPath(EDGES, "f_dcsync", "t")).toEqual([]);
  });

  it("prefers the shorter of two routes to the same node", () => {
    const twoRoutes = [
      { source: "t", target: "x" },      // 1 hop
      { source: "t", target: "m" },
      { source: "m", target: "x" },      // 2 hops
    ];
    expect(shortestPath(twoRoutes, "t", "x")).toEqual(["t", "x"]);
  });
});

describe("pathNext", () => {
  it("maps each node to its successor on the path", () => {
    const next = pathNext(["t", "a_nmap", "s_http"]);
    expect(next.get("t")).toBe("a_nmap");
    expect(next.get("a_nmap")).toBe("s_http");
    expect(next.has("s_http")).toBe(false);   // last node has no successor
    expect(next.size).toBe(2);
  });

  it("is empty for a single-node or empty path", () => {
    expect(pathNext(["t"]).size).toBe(0);
    expect(pathNext([]).size).toBe(0);
  });
});
