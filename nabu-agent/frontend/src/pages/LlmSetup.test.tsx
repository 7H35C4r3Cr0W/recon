import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { LlmSetup } from "./LlmSetup";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

const CFG = {
  source: "none", saved: false, provider: "openai_compatible", configured: false, base_url: "",
  model: "gpt-5.1", organization: "", has_api_key: false, temperature: 0.2, max_output_tokens: 4096,
  context_window: 128000, timeout_read_s: 120, tls_verify: true, env_prefix: "NABU_LLM_",
  required_env: ["NABU_LLM_BASE_URL", "NABU_LLM_API_KEY", "NABU_LLM_MODEL"],
};
const fillUrl = () => fireEvent.change(screen.getByPlaceholderText(/llm\.internal/), { target: { value: "https://x/v1" } });

describe("LlmSetup", () => {
  it("shows the steps + form and reports test-fire metrics", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path === "/admin/llm/config"
        ? Promise.resolve(CFG)
        : Promise.resolve({ ok: true, configured: true, latency_ms: 42, model: "gpt-5.1",
            finish_reason: "stop", content: "OK",
            usage: { prompt_tokens: 7, completion_tokens: 1, total_tokens: 8, estimated: false } }));

    render(<LlmSetup />);
    expect(await screen.findByText(/Connect the LLM brain/)).toBeInTheDocument();
    expect(screen.getByText(/How to attach it/)).toBeInTheDocument();        // the steps
    expect(screen.getByText(/NABU_LLM_BASE_URL/)).toBeInTheDocument();        // env alternative still offered

    fillUrl();
    fireEvent.click(screen.getByRole("button", { name: /Test connection/ }));
    expect(await screen.findByText(/Connection OK/)).toBeInTheDocument();
    expect(screen.getByText(/42 ms/)).toBeInTheDocument();
    expect(screen.getByText(/total 8/)).toBeInTheDocument();
    expect(api).toHaveBeenCalledWith("/admin/llm/test", expect.objectContaining({ method: "POST" }));
  });

  it("saves the config (PUT) and confirms attach", async () => {
    const puts: any[] = [];
    vi.mocked(api).mockImplementation((path: string, init?: any) => {
      if (path === "/admin/llm/config" && init?.method === "PUT") { puts.push(JSON.parse(init.body)); return Promise.resolve({ ok: true, ...CFG, saved: true, source: "saved", base_url: "https://x/v1", configured: true }); }
      return Promise.resolve(CFG);
    });
    render(<LlmSetup />);
    fireEvent.change(await screen.findByPlaceholderText(/llm\.internal/), { target: { value: "https://x/v1" } });
    fireEvent.click(screen.getByRole("button", { name: /Save & attach/ }));
    await waitFor(() => expect(screen.getByText(/brain is attached/)).toBeInTheDocument());
    expect(puts[0].base_url).toBe("https://x/v1");
  });

  it("surfaces a failed test-fire with its reason", async () => {
    vi.mocked(api).mockImplementation((path: string) =>
      path === "/admin/llm/config"
        ? Promise.resolve(CFG)
        : Promise.resolve({ ok: false, configured: false, error: "could not connect to the endpoint" }));
    render(<LlmSetup />);
    fireEvent.change(await screen.findByPlaceholderText(/llm\.internal/), { target: { value: "https://x/v1" } });
    fireEvent.click(screen.getByRole("button", { name: /Test connection/ }));
    expect(await screen.findByText(/Test failed/)).toBeInTheDocument();
    expect(screen.getByText(/could not connect/)).toBeInTheDocument();
  });
});
