"""Build the BloodHound-style live run map (Cytoscape.js elements) from a run's state.

Node ids are stable so the frontend can re-colour a node when a ``task.updated`` event arrives:
    run-<run_id>            the run/supervisor node
    host-<ip>               a scanned host (single-target = one host)
    svc-<ip>-<port>-<proto> a discovered service
    agent-<task_id>         a per-service enum / research / writer agent
    finding-<key>           a finding
    report-<run_id>         the report node

Edges show hand-offs: run → host → service → agent → finding → report. Each node carries
``data.state`` (a :class:`nabu_agent.events.NodeState` value) which the frontend colours; live
``task.updated`` events then recolour nodes without a full refresh.
"""

from __future__ import annotations

from typing import Any

from nabu_agent.events.schema import NodeState


def _node(nid: str, label: str, kind: str, state: NodeState, **extra: Any) -> dict[str, Any]:
    return {"data": {"id": nid, "label": label, "kind": kind, "state": state.value, **extra}}


def _edge(src: str, dst: str) -> dict[str, Any]:
    return {"data": {"id": f"{src}->{dst}", "source": src, "target": dst}}


def build_run_map(
    run_id: str,
    target: str,
    services: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    findings: list[dict[str, Any]] | None = None,
    *,
    run_state: NodeState = NodeState.ACTIVE,
) -> dict[str, list[dict[str, Any]]]:
    """Assemble nodes + edges for the current run. ``services``/``tasks``/``findings`` are the
    JSON read-models (ServiceDTO rows, agent_task rows, finding rows)."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    run_nid = f"run-{run_id}"
    nodes.append(_node(run_nid, "recon run", "run", run_state))

    host_nid = f"host-{target}"
    nodes.append(_node(host_nid, target, "host", NodeState.ACTIVE))
    edges.append(_edge(run_nid, host_nid))

    _STATE = {  # agent_task.state / shell_outcome → node colour
        "queued": NodeState.QUEUED, "running": NodeState.ACTIVE, "done": NodeState.DONE,
        "failed": NodeState.ERROR, "blocked": NodeState.STUCK, "skipped": NodeState.STUCK,
        "cancelled": NodeState.STUCK,
    }

    svc_by_port: dict[int, str] = {}
    for s in services:
        port = int(s.get("port", 0))
        svc_nid = f"svc-{target}-{port}-{s.get('proto', 'tcp')}"
        svc_by_port[port] = svc_nid
        label = f"{port}/{s.get('service') or s.get('proto', 'tcp')}"
        nodes.append(_node(svc_nid, label, "service", NodeState.DONE,
                           product=s.get("product", ""), version=s.get("version", "")))
        edges.append(_edge(host_nid, svc_nid))

    for t in tasks:
        tid = str(t.get("id") or t.get("arq_job_id") or t.get("role"))
        agent_nid = f"agent-{tid}"
        st = _STATE.get(str(t.get("state", "queued")), NodeState.QUEUED)
        role = t.get("role", "agent")
        nodes.append(_node(agent_nid, f"{role} agent", "agent", st, role=role,
                           shell_outcome=t.get("shell_outcome")))
        parent = svc_by_port.get(int(t.get("port") or 0), host_nid)
        edges.append(_edge(parent, agent_nid))

    for i, f in enumerate(findings or []):
        fid = f"finding-{f.get('engine_key', i)}"
        cat = f.get("_category") or f.get("category") or "info"
        state = NodeState.ERROR if cat == "vulnerable" else NodeState.DONE
        nodes.append(_node(fid, str(f.get("value", "finding"))[:40], "finding", state, category=cat))
        port = int(f.get("port") or 0)
        edges.append(_edge(svc_by_port.get(port, host_nid), fid))

    return {"nodes": nodes, "edges": edges}
