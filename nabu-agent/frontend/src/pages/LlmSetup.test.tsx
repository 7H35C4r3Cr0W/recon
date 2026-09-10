import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { LlmSetup } from "./LlmSetup";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

const CFG = {
  provider: "openai_compatible", configured: false, base_url: "", model: "gpt-5.1",
  organization: null, has_api_key: false, temperature: 0.2, max_output_tokens: 4096,
  context_window: 128000, timeout_read_s: 120, tls_verify: true, env_prefix: "NABU_LLM_",
  required_env: ["NABU_LLM_BASE_URL", "NABU_LLM_API_KEY", "NABU_LLM_MODEL"],
};

describe("LlmSetup", () => {
  it("shows setup steps and reports test-fire metrics", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path === "/admin/llm/config"
        ? Promise.resolve(CFG)
        : Promise.resolve({ ok: true, configured: true, latency_ms: 42, model: "gpt-5.1",
            finish_reason: "stop", content: "OK",
            usage: { prompt_tokens: 7, completion_tokens: 1, total_tokens: 8, estimated: false } }));

    render(<LlmSetup />);
    expect(await screen.findByText(/Connect the LLM brain/)).toBeInTheDocument();
    expect(screen.getByText(/NABU_LLM_BASE_URL/)).toBeInTheDocument();   // the env instructions

    fireEvent.click(screen.getByRole("button", { name: /Test connection/ }));
    expect(await screen.findByText(/connection OK/)).toBeInTheDocument();
    expect(screen.getByText(/42 ms/)).toBeInTheDocument();
    expect(screen.getByText(/total 8/)).toBeInTheDocument();
    expect(api).toHaveBeenCalledWith("/admin/llm/test", expect.objectContaining({ method: "POST" }));
  });

  it("surfaces a failed test-fire with its reason", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path === "/admin/llm/config"
        ? Promise.resolve(CFG)
        : Promise.resolve({ ok: false, configured: false, error: "LLM not configured — set NABU_LLM_BASE_URL" }));
    render(<LlmSetup />);
    fireEvent.click(await screen.findByRole("button", { name: /Test connection/ }));
    expect(await screen.findByText(/test failed/)).toBeInTheDocument();
    expect(screen.getByText(/set NABU_LLM_BASE_URL/)).toBeInTheDocument();
  });
});
