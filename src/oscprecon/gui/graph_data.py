from __future__ import annotations

from typing import Any

from oscprecon import finding_severity
from oscprecon import findings as findings_mod
from oscprecon.creds import redact
from oscprecon.profile import Profile
from oscprecon.references import match as ref_match

# Cytoscape "elements" builder: turn a Profile (target + services + findings.json + creds.json),
# overlaid with the user's graph.json (drawn edges, node positions, per-node status/notes), into the
# {nodes, edges} JSON the vendored Cytoscape.js renders. Pure data — no Qt — so it is unit-testable.
# Visual framing (which finding is "notable") comes from the centralized, conservative
# finding_severity classifier — an open port / version / EDB hit is never framed as a weakness.

_VALID_STATUS = frozenset({"new", "investigating", "done", "dead-end"})


def _service_id(port: int, proto: str) -> str:
    return f"service-{port}-{proto}"


def _edge(source: str, target: str, edge_type: str, eid: str, label: str = "") -> dict[str, Any]:
    data: dict[str, Any] = {"id": eid, "source": source, "target": target, "type": edge_type}
    if label:
        data["label"] = label
    return {"data": data}


def build_elements(profile: Profile) -> dict[str, list[dict[str, Any]]]:
    graph = profile.load_graph()
    overrides = graph.get("node_overrides", {})
    overrides = overrides if isinstance(overrides, dict) else {}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(node_id: str, node_type: str, label: str, extra: dict[str, Any]) -> None:
        data: dict[str, Any] = {"id": node_id, "type": node_type, "label": label, **extra}
        node: dict[str, Any] = {"data": data}
        override = overrides.get(node_id)
        if isinstance(override, dict):
            status = override.get("status")
            if isinstance(status, str) and status in _VALID_STATUS:
                data["status"] = status
            note = override.get("note")
            if isinstance(note, str) and note:
                data["note"] = note
            position = override.get("position")
            if isinstance(position, list) and len(position) == 2:
                node["position"] = {"x": position[0], "y": position[1]}
        nodes.append(node)
        node_ids.add(node_id)

    target = profile.target
    tlabel = f"{target.ip}\n{target.hostname}" if target.hostname else target.ip
    add_node("target", "target", tlabel, {"ip": target.ip})

    module_service: dict[str, str] = {}  # module name -> first service node that owns it
    for svc in profile.discovered_services:
        sid = _service_id(svc.port, svc.proto.value)
        if sid in node_ids:  # a profile can list the same port twice — keep one node
            continue
        label = f"{svc.port}/{svc.proto.value} {svc.service}".strip()
        add_node(sid, "service", label, {"proto": svc.proto.value, "port": svc.port})
        edges.append(_edge("target", sid, "has-service", f"e-has-{sid}"))
        ref = ref_match(svc)
        if ref is not None and ref.module and ref.module not in module_service:
            module_service[ref.module] = sid

    for index, finding in enumerate(findings_mod.load_findings(profile.directory)):
        fid = f"finding-{index}"
        kind = str(finding.get("kind", ""))
        value = str(finding.get("value", ""))
        module = str(finding.get("module", ""))
        detail = str(finding.get("detail", ""))
        label = f"{kind}: {value}" if kind else (value or "finding")
        category = finding_severity.classify(kind, value, detail)
        extra: dict[str, Any] = {"module": module, "detail": detail, "category": category}
        if finding_severity.is_notable(category):
            extra["notable"] = True  # anon access / exposure / relay-risk -> highlighted ring
        add_node(fid, "finding", label, extra)
        parent = module_service.get(module, "target")
        edges.append(_edge(parent, fid, "exposes-finding", f"e-find-{index}"))

    for index, cred in enumerate(profile.credentials()):
        cid = f"cred-{index}"
        who = cred.username + (f"@{cred.domain}" if cred.domain else "")
        add_node(
            cid,
            "credential",
            who or "credential",
            {"source": cred.source, "secret": redact(cred.secret)},
        )
        edges.append(_edge("target", cid, "references-credential", f"e-cred-{index}"))

    # user-drawn relates-to edges — skip any whose endpoints no longer exist (a finding was removed)
    user_edges = graph.get("user_edges", [])
    if isinstance(user_edges, list):
        for index, user_edge in enumerate(user_edges):
            if not isinstance(user_edge, dict):
                continue
            src, dst = str(user_edge.get("from", "")), str(user_edge.get("to", ""))
            if src in node_ids and dst in node_ids:
                label = str(user_edge.get("label", ""))
                edges.append(_edge(src, dst, "relates-to", f"e-user-{index}", label))

    return {"nodes": nodes, "edges": edges}
