import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AttackGate } from "./AttackGate";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ api: vi.fn() }));

const CMD = "crackmapexec smb 10.10.10.5 -u admin -p pw -x whoami";
const ACTION = { id: "smb-cme-exec", title: "CME exec", category: "exploit", command: CMD,
  unfilled: [], tool: "crackmapexec", runs_on: "attacker", executable: true };

describe("AttackGate", () => {
  let checkpoints: any[];

  beforeEach(() => {
    checkpoints = [];
    vi.mocked(api).mockImplementation((path: string) => {
      if (path.includes("/scope")) return Promise.resolve({ scope: [{ target: "10.10.10.5", is_entry: true }] });
      if (path.endsWith("/runs")) return Promise.resolve({ runs: [{ id: "run1" }] });
      if (path.includes("/catalog")) return Promise.resolve({ services: [{ service: "smb", label: "SMB", actions: [ACTION] }] });
      if (path.includes("/credentials")) return Promise.resolve({ credentials: [] });
      if (path.includes("/attack-proposals")) {
        checkpoints.push({ id: "cp1", kind: "exploit", status: "proposed", target: "10.10.10.5",
          action_id: ACTION.id, service: "smb", command: CMD,
          gate: { platform_enabled: true, project_enabled: true, needs_exploit_confirm: true, needs_credential: false } });
        return Promise.resolve({ checkpoint_id: "cp1", command: CMD, status: "proposed" });
      }
      if (path.includes("/checkpoints")) return Promise.resolve({ checkpoints });
      return Promise.resolve({});
    });
  });

  it("proposes a runnable action, then gates approval behind the exploit confirmation", async () => {
    render(<AttackGate projectId="p1" />);

    // the runnable action shows with its command preview + a Propose button
    expect(await screen.findByText("CME exec")).toBeInTheDocument();
    expect(screen.getAllByText(CMD).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText("Propose"));

    // a gated proposal card appears with the danger-styled approve control, disabled until confirmed
    const approve = await screen.findByText("Approve & run");
    expect(approve).toBeDisabled();

    // ticking the exploit confirmation enables it
    fireEvent.click(screen.getByRole("checkbox"));
    await waitFor(() => expect(approve).not.toBeDisabled());
  });

  it("tells the user to run recon first when there is no run", async () => {
    vi.mocked(api).mockImplementation((path: string) => {
      if (path.endsWith("/runs")) return Promise.resolve({ runs: [] });
      return Promise.resolve({ scope: [], services: [], credentials: [], checkpoints: [] });
    });
    render(<AttackGate projectId="p1" />);
    expect(await screen.findByText(/Run recon on an in-scope target first/)).toBeInTheDocument();
  });
});
