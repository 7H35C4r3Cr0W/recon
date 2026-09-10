import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";

afterEach(() => vi.unstubAllGlobals());

describe("api()", () => {
  it("returns parsed JSON on success", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ hello: "world" }) }));
    expect(await api<{ hello: string }>("/x")).toEqual({ hello: "world" });
  });

  it("throws the error-envelope message on failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false, status: 403, json: () => Promise.resolve({ code: "scope_violation", message: "out of scope" }),
    }));
    await expect(api("/x")).rejects.toThrow("out of scope");
  });

  it("prefixes /api and sends same-origin credentials", async () => {
    const f = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) });
    vi.stubGlobal("fetch", f);
    await api("/feed");
    expect(f).toHaveBeenCalledWith("/api/feed", expect.objectContaining({ credentials: "same-origin" }));
  });
});
