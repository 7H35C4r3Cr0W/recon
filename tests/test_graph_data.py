from pathlib import Path

from oscprecon import findings as findings_mod
from oscprecon.gui.graph_data import build_elements
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "htb-active", Target(ip="10.10.10.100", hostname="active.htb"))
    prof.set_services(
        [
            DiscoveredService(445, Proto.TCP, "microsoft-ds"),
            DiscoveredService(161, Proto.UDP, "snmp"),
        ]
    )
    findings_mod.add_findings(
        prof.directory,
        [
            {
                "module": "smb",
                "kind": "share",
                "value": "SYSVOL",
                "detail": "readable",
                "discovered_at": "t",
            },
            {
                "module": "snmp",
                "kind": "community",
                "value": "public",
                "detail": "",
                "discovered_at": "t",
            },
        ],
    )
    prof.add_credential(
        Credential(
            username="svc", secret="Sup3rSecret", domain="active.htb", source="smb-anon-enum"
        )
    )
    return prof


def test_build_elements_structure(tmp_path: Path) -> None:
    els = build_elements(_profile(tmp_path))
    by_id = {n["data"]["id"]: n for n in els["nodes"]}
    assert by_id["target"]["data"]["type"] == "target"
    assert by_id["target"]["data"]["label"] == "10.10.10.100\nactive.htb"
    assert by_id["service-445-tcp"]["data"]["proto"] == "tcp"
    assert by_id["service-161-udp"]["data"]["proto"] == "udp"
    has = {
        (e["data"]["source"], e["data"]["target"])
        for e in els["edges"]
        if e["data"]["type"] == "has-service"
    }
    assert ("target", "service-445-tcp") in has
    assert ("target", "service-161-udp") in has


def test_findings_link_to_owning_service(tmp_path: Path) -> None:
    els = build_elements(_profile(tmp_path))
    finds = [n for n in els["nodes"] if n["data"]["type"] == "finding"]
    assert "share: SYSVOL" in {n["data"]["label"] for n in finds}
    smb_fid = next(n["data"]["id"] for n in finds if n["data"]["module"] == "smb")
    smb_edge = next(
        e
        for e in els["edges"]
        if e["data"]["target"] == smb_fid and e["data"]["type"] == "exposes-finding"
    )
    assert smb_edge["data"]["source"] == "service-445-tcp"  # module -> owning service
    snmp_fid = next(n["data"]["id"] for n in finds if n["data"]["module"] == "snmp")
    snmp_edge = next(e for e in els["edges"] if e["data"]["target"] == snmp_fid)
    assert snmp_edge["data"]["source"] == "service-161-udp"


def test_credential_is_redacted(tmp_path: Path) -> None:
    els = build_elements(_profile(tmp_path))
    cred = next(n for n in els["nodes"] if n["data"]["type"] == "credential")
    assert cred["data"]["label"] == "svc@active.htb"
    assert cred["data"]["secret"] == "<redacted len=11>"
    assert "Sup3rSecret" not in str(els)  # the secret never reaches the graph


def test_graph_overrides_and_user_edges(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.save_graph(
        {
            "user_edges": [
                {"from": "cred-0", "to": "service-445-tcp", "label": "found here"},
                {"from": "cred-0", "to": "service-999-nope"},  # dangling endpoint -> dropped
            ],
            "node_overrides": {
                "service-445-tcp": {
                    "status": "investigating",
                    "note": "weird shares",
                    "position": [320, 180],
                }
            },
        }
    )
    els = build_elements(prof)
    svc = next(n for n in els["nodes"] if n["data"]["id"] == "service-445-tcp")
    assert svc["data"]["status"] == "investigating"
    assert svc["data"]["note"] == "weird shares"
    assert svc["position"] == {"x": 320, "y": 180}
    relates = [e for e in els["edges"] if e["data"]["type"] == "relates-to"]
    assert len(relates) == 1  # the dangling edge is filtered out
    assert relates[0]["data"]["label"] == "found here"


def test_invalid_status_is_ignored(tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.save_graph({"node_overrides": {"target": {"status": "bogus"}}})
    target = next(n for n in build_elements(prof)["nodes"] if n["data"]["id"] == "target")
    assert "status" not in target["data"]  # only new/investigating/done/dead-end are accepted


def test_profile_graph_persistence_roundtrip(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    assert prof.load_graph() == {"user_edges": [], "node_overrides": {}}  # default when absent
    prof.save_graph(
        {"user_edges": [{"from": "a", "to": "b"}], "node_overrides": {"a": {"status": "done"}}}
    )
    reloaded = prof.load_graph()
    assert reloaded["user_edges"] == [{"from": "a", "to": "b"}]
    assert reloaded["node_overrides"]["a"]["status"] == "done"
